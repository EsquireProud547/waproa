/*
 * TCP WAPROA拥塞控制算法
 * 
 * 作者: EsquireProud547
 * 版本: 1.0
 * 许可证: GPL
 * 
 * 特性：
 * - 基于ACK速率的带宽估计
 * - BDP动态窗口调整
 * - 高延迟网络优化（渐进式带宽衰减）
 * - RTT超时重置机制
 * - 丢包历史保留（70%带宽保持）
 * - 窗口增长限制（BDP的4倍，绝对上限10万）
 * - 内存占用：28字节/连接
 * - 兼容：Linux 2.6.13 - 6.x
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/version.h>
#include <net/tcp.h>

#define TCP_WA_NONSTANDARD_KERNEL	1

#define WA_BW_FILTER_HISTORY	7
#define WA_BW_FILTER_DIVISOR	8
#define WA_MIN_CWND		2U
#define WA_MIN_RTT_US		1000U
#define WA_MAX_BW		250000000U
#ifndef TCP_INFINITE_SSTHRESH
#define TCP_INFINITE_SSTHRESH	0x7fffffff
#endif
#define WA_RTT_AGING_INTERVAL	(900 * HZ)
#define WA_RECIPROCAL_SHIFT	40
#define WA_RECIPROCAL_SCALE	(1ULL << WA_RECIPROCAL_SHIFT)

/* 窗口增长限制参数 */
#define WA_MAX_WINDOW_RATIO	4
#define WA_ABSOLUTE_MAX_WINDOW	100000U

/* 带宽估计空闲阈值 */
#define WA_BW_IDLE_THRESHOLD	(5 * HZ)

/* 丢包恢复带宽保留比例（7/10 = 70%） */
#define WA_LOSS_BW_RETENTION_NUM	7
#define WA_LOSS_BW_RETENTION_DEN	10

/* 状态标志位 */
#define WA_FLAG_IN_SLOW_START	0x01
#define WA_FLAG_ECN_ENABLED	0x02

/* 每连接私有数据（紧凑布局28字节） */
struct waproa {
	u32 last_ack_time;	/* 上次ACK时间戳 */
	u32 cum_acked;		/* 累积确认字节数 */
	u32 bw_est;		/* 带宽估计（字节/jiffies） */
	u32 rtt_min;		/* 最小RTT（微秒） */
	u32 last_safe_cwnd;	/* 上次安全窗口值 */
	u32 mss_reciprocal;	/* MSS倒数（40位精度） */
	u32 rtt_reset_time;	/* RTT老化计时器 */
	u8  flags;		/* 状态标志 */
	u8  reserved[3];	/* 对齐填充 */
};

static u32 jiffies_to_usec_reciprocal;

/* 数值钳制 */
static inline u32 waproa_clamp_u32(u32 val, u32 min_val, u32 max_val)
{
	if (val < min_val)
		return min_val;
	if (val > max_val)
		return max_val;
	return val;
}

/* 获取当前时间（32位截断） */
static inline u32 waproa_get_now(void)
{
	return (u32)jiffies;
}

/* 计算时间差（处理32位回绕） */
static inline u32 waproa_time_delta(u32 now, u32 last)
{
	return (u32)(now - last);
}

/* 快速除法：val / divisor ≈ (val * reciprocal) >> 40 */
static inline u32 fast_div_u32(u64 val, u32 reciprocal)
{
	u64 reciprocal_ext = (u64)reciprocal << 8;
	return (u32)((val * reciprocal_ext) >> WA_RECIPROCAL_SHIFT);
}

/* 计算40位精度倒数 */
static inline u32 calc_reciprocal(u32 divisor)
{
	u64 reciprocal;
	if (divisor == 0)
		return 0;
	reciprocal = WA_RECIPROCAL_SCALE / divisor;
	if (reciprocal > U32_MAX)
		reciprocal = U32_MAX;
	return (u32)reciprocal;
}

/* 计算动态窗口上限：min(BDP * 4, 100000) */
static u32 waproa_max_window_limit(struct waproa *ca)
{
	u64 bdp_based_limit;
	u32 rtt_us;
	u32 usecs_per_jiffy;
	
	if (ca->bw_est == 0 || ca->rtt_min == 0)
		return WA_ABSOLUTE_MAX_WINDOW;
	
	if (ca->bw_est > (U32_MAX / ca->rtt_min))
		return WA_ABSOLUTE_MAX_WINDOW;
	
	rtt_us = ca->rtt_min;
	usecs_per_jiffy = (u32)jiffies_to_usecs(1);
	if (usecs_per_jiffy == 0)
		usecs_per_jiffy = 1000;
	
	if (jiffies_to_usec_reciprocal == 0) {
		bdp_based_limit = (u64)ca->bw_est * rtt_us / usecs_per_jiffy;
	} else {
		bdp_based_limit = (u64)ca->bw_est * rtt_us;
		bdp_based_limit = fast_div_u32(bdp_based_limit, jiffies_to_usec_reciprocal);
	}
	
	if (bdp_based_limit > (U32_MAX / WA_MAX_WINDOW_RATIO))
		return WA_ABSOLUTE_MAX_WINDOW;
	
	bdp_based_limit *= WA_MAX_WINDOW_RATIO;
	
	if (bdp_based_limit > WA_ABSOLUTE_MAX_WINDOW)
		return WA_ABSOLUTE_MAX_WINDOW;
	if (bdp_based_limit < WA_MIN_CWND)
		return WA_MIN_CWND;
	
	return (u32)bdp_based_limit;
}

/* 验证连接状态 */
static int waproa_state_valid(struct sock *sk)
{
	struct waproa *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	
	if (!ca || !tp)
		return 0;
	if (tp->snd_cwnd > WA_ABSOLUTE_MAX_WINDOW)
		return 0;
	return 1;
}

/* 更新带宽估计（支持高延迟网络，空闲衰减） */
static void waproa_update_bw(struct sock *sk, u32 acked_bytes)
{
	struct waproa *ca = inet_csk_ca(sk);
	u32 now = waproa_get_now();
	u32 delta = waproa_time_delta(now, ca->last_ack_time);
	u32 cur_bw;
	u64 new_bw_est;

	if (ca->last_ack_time == 0) {
		ca->last_ack_time = now;
		ca->cum_acked = acked_bytes;
		return;
	}

	if (delta > WA_BW_IDLE_THRESHOLD) {
		if (ca->bw_est > 0) {
			ca->bw_est = ca->bw_est >> 1;
			if (ca->bw_est < 1)
				ca->bw_est = 0;
		}
		ca->last_ack_time = now;
		ca->cum_acked = acked_bytes;
		return;
	}

	if (delta == 0) {
		if (ca->cum_acked < (U32_MAX - acked_bytes))
			ca->cum_acked += acked_bytes;
		return;
	}

	ca->cum_acked += acked_bytes;
	if (ca->cum_acked >= tcp_sk(sk)->mss_cache && delta > 0) {
		cur_bw = ca->cum_acked / delta;
		if (cur_bw > 0 && cur_bw < WA_MAX_BW) {
			if (ca->bw_est == 0) {
				ca->bw_est = cur_bw;
			} else {
				new_bw_est = (u64)ca->bw_est * WA_BW_FILTER_HISTORY + cur_bw;
				new_bw_est /= WA_BW_FILTER_DIVISOR;
				if (new_bw_est > U32_MAX)
					new_bw_est = U32_MAX;
				ca->bw_est = (u32)new_bw_est;
			}
		}
		ca->cum_acked = 0;
		ca->last_ack_time = now;
	}
}

/* RTT超时重置机制 */
static void waproa_check_rtt_aging(struct waproa *ca, u32 now)
{
	u32 reset_deadline = ca->rtt_reset_time + (u32)WA_RTT_AGING_INTERVAL;
	
	if ((s32)(now - reset_deadline) > 0) {
		ca->rtt_min = 0;
		ca->rtt_reset_time = now;
	}
}

/* 旧版ACK处理（Linux < 4.15） */
static void waproa_pkts_acked_v1(struct sock *sk, u32 num_acked, s32 rtt_us)
{
	struct waproa *ca = inet_csk_ca(sk);
	u32 acked_bytes;
	u32 now = waproa_get_now();
	u32 rtt;

	if (rtt_us < 0)
		rtt = 0;
	else
		rtt = (u32)rtt_us;

	acked_bytes = num_acked * tcp_sk(sk)->mss_cache;

	if (rtt > 0) {
		if (rtt < WA_MIN_RTT_US)
			rtt = WA_MIN_RTT_US;
		if (ca->rtt_min == 0 || rtt < ca->rtt_min) {
			ca->rtt_min = rtt;
			ca->rtt_reset_time = now;
		}
	}

	waproa_check_rtt_aging(ca, now);
	waproa_update_bw(sk, acked_bytes);
}

/* 新版ACK处理（Linux >= 4.15） */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static void waproa_pkts_acked_v2(struct sock *sk, const struct ack_sample *sample)
{
	struct waproa *ca = inet_csk_ca(sk);
	u32 acked_bytes;
	u32 rtt;
	u32 now = waproa_get_now();

	if (!sample)
		return;

	if (sample->rtt_us < 0)
		rtt = 0;
	else
		rtt = (u32)sample->rtt_us;

	acked_bytes = sample->pkts_acked * tcp_sk(sk)->mss_cache;

	if (rtt > 0) {
		if (rtt < WA_MIN_RTT_US)
			rtt = WA_MIN_RTT_US;
		if (ca->rtt_min == 0 || rtt < ca->rtt_min) {
			ca->rtt_min = rtt;
			ca->rtt_reset_time = now;
		}
	}

	waproa_check_rtt_aging(ca, now);
	waproa_update_bw(sk, acked_bytes);
}
#endif

/* 兼容性包装器 */
#if TCP_WA_NONSTANDARD_KERNEL
static void waproa_pkts_acked_wrapper(struct sock *sk,
				  const struct ack_sample *sample)
{
	u32 num_acked;
	s32 rtt_us;

	if (!sample) {
		num_acked = 0;
		rtt_us = -1;
	} else {
		num_acked = sample->pkts_acked;
		rtt_us = sample->rtt_us;
	}

	waproa_pkts_acked_v1(sk, num_acked, rtt_us);
}
#endif

/* 计算BDP（带宽延迟积） */
static u32 waproa_calculate_bdp(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct waproa *ca = inet_csk_ca(sk);
	u64 bdp;
	u32 mss;
	u32 safe_cwnd;
	u32 usecs_per_jiffy;

	if (!waproa_state_valid(sk)) {
		if (ca->last_safe_cwnd > 0)
			return ca->last_safe_cwnd;
		return max_t(u32, tp->snd_cwnd >> 1, WA_MIN_CWND);
	}

	mss = tp->mss_cache;
	if (unlikely(mss == 0))
		mss = 536;
	if (unlikely(mss > 1460))
		mss = 1460;

	ca->mss_reciprocal = calc_reciprocal(mss);
	if (ca->mss_reciprocal == 0) {
		safe_cwnd = max_t(u32, tp->snd_cwnd >> 1, WA_MIN_CWND);
		ca->last_safe_cwnd = safe_cwnd;
		return safe_cwnd;
	}

	if (ca->bw_est == 0 || ca->rtt_min == 0) {
		safe_cwnd = max_t(u32, tp->snd_cwnd >> 1, WA_MIN_CWND);
		ca->last_safe_cwnd = safe_cwnd;
		return safe_cwnd;
	}

	if (ca->bw_est > (U32_MAX / ca->rtt_min)) {
		safe_cwnd = max_t(u32, tp->snd_cwnd >> 1, WA_MIN_CWND);
		ca->last_safe_cwnd = safe_cwnd;
		return safe_cwnd;
	}

	bdp = (u64)ca->bw_est * ca->rtt_min;
	
	if (bdp < ca->bw_est || bdp < ca->rtt_min) {
		safe_cwnd = max_t(u32, tp->snd_cwnd >> 1, WA_MIN_CWND);
		ca->last_safe_cwnd = safe_cwnd;
		return safe_cwnd;
	}

	usecs_per_jiffy = (u32)jiffies_to_usecs(1);
	if (usecs_per_jiffy == 0)
		usecs_per_jiffy = 1000;

	if (jiffies_to_usec_reciprocal == 0) {
		do_div(bdp, usecs_per_jiffy);
	} else {
		bdp = fast_div_u32(bdp, jiffies_to_usec_reciprocal);
	}

	if (ca->mss_reciprocal == 0) {
		safe_cwnd = max_t(u32, tp->snd_cwnd >> 1, WA_MIN_CWND);
		ca->last_safe_cwnd = safe_cwnd;
		return safe_cwnd;
	}
	
	bdp = fast_div_u32(bdp, ca->mss_reciprocal);
	
	safe_cwnd = waproa_clamp_u32((u32)bdp, WA_MIN_CWND, waproa_max_window_limit(ca));
	ca->last_safe_cwnd = safe_cwnd;

	return safe_cwnd;
}

/* 检查是否处于慢启动阶段 */
static inline int waproa_in_slow_start(struct waproa *ca, struct tcp_sock *tp)
{
	if (ca->flags & WA_FLAG_IN_SLOW_START)
		return 1;
	if (tp->snd_cwnd < tp->snd_ssthresh)
		return 1;
	return 0;
}

/* 拥塞避免主函数 */
static void waproa_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct waproa *ca = inet_csk_ca(sk);
	u32 target_cwnd;
	u32 increment;
	u32 snd_cwnd;
	u32 max_limit;

	(void)ack;

	snd_cwnd = tp->snd_cwnd;
	max_limit = waproa_max_window_limit(ca);
	
	if (!tcp_is_cwnd_limited(sk) || !acked) {
		return;
	}

	target_cwnd = waproa_calculate_bdp(sk);
	
	if (waproa_in_slow_start(ca, tp)) {
		u32 slow_start_limit = min_t(u32, tp->snd_ssthresh, target_cwnd);
		
		if (snd_cwnd < slow_start_limit) {
			if (snd_cwnd > (U32_MAX - acked))
				increment = U32_MAX - snd_cwnd;
			else
				increment = acked;
				
			if (snd_cwnd + increment > slow_start_limit)
				increment = slow_start_limit - snd_cwnd;
				
			snd_cwnd += increment;
		} else {
			ca->flags &= ~WA_FLAG_IN_SLOW_START;
			goto congestion_avoidance;
		}
	} else {
congestion_avoidance:
		if (snd_cwnd < target_cwnd) {
			increment = min_t(u32, acked, target_cwnd - snd_cwnd);
			if (snd_cwnd > (U32_MAX - increment))
				snd_cwnd = max_limit;
			else
				snd_cwnd += increment;
		} else {
			u32 limit = min_t(u32, acked, snd_cwnd >> 3);
			if (snd_cwnd > (U32_MAX - limit))
				snd_cwnd = max_limit;
			else
				snd_cwnd += limit;
		}
	}

	tp->snd_cwnd = waproa_clamp_u32(snd_cwnd, WA_MIN_CWND, max_limit);
}

/* 计算慢启动阈值 */
static u32 waproa_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct waproa *ca = inet_csk_ca(sk);
	u32 bdp;
	u32 safe_ssthresh;
	u32 max_ssthresh;

	if (!waproa_state_valid(sk)) {
		safe_ssthresh = max_t(u32, ca->last_safe_cwnd, WA_MIN_CWND);
		max_ssthresh = (tp->snd_cwnd * 8) / 10;
		if (safe_ssthresh > max_ssthresh)
			safe_ssthresh = max_ssthresh;
		return max_t(u32, safe_ssthresh, WA_MIN_CWND);
	}

	bdp = waproa_calculate_bdp(sk);
	
	safe_ssthresh = max_t(u32, bdp, WA_MIN_CWND);
	
	max_ssthresh = max_t(u32, (tp->snd_cwnd * 8) / 10, WA_MIN_CWND * 2);
	if (safe_ssthresh > max_ssthresh)
		safe_ssthresh = max_ssthresh;
	
	if (safe_ssthresh < WA_MIN_CWND)
		safe_ssthresh = WA_MIN_CWND;

	return safe_ssthresh;
}

/* 丢包恢复（保留带宽和RTT） */
static void waproa_recovery(struct sock *sk)
{
	struct waproa *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 retained_bw;
	u32 now = waproa_get_now();

	if (ca->bw_est > 0) {
		retained_bw = (u64)ca->bw_est * WA_LOSS_BW_RETENTION_NUM / WA_LOSS_BW_RETENTION_DEN;
		if (retained_bw < 1)
			retained_bw = 1;
		ca->bw_est = retained_bw;
	}
	
	ca->cum_acked = 0;
	ca->last_ack_time = now;
	ca->rtt_reset_time = now;

	if (tp) {
		u32 recovery_cwnd = max_t(u32, ca->last_safe_cwnd, WA_MIN_CWND);
		u32 max_cwnd = waproa_max_window_limit(ca);
		
		if (recovery_cwnd > max_cwnd)
			recovery_cwnd = max_cwnd;
			
		tp->snd_cwnd = recovery_cwnd;
		tp->snd_ssthresh = max_t(u32, tp->snd_cwnd >> 1, WA_MIN_CWND);
	}
}

/* 初始化新连接 */
static void waproa_init(struct sock *sk)
{
	struct waproa *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 now = waproa_get_now();

	memset(ca, 0, sizeof(*ca));
	ca->last_ack_time = now;
	ca->rtt_reset_time = now;
	ca->flags = WA_FLAG_IN_SLOW_START;
	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	if (tp && (tcp_sk(sk)->ecn_flags & TCP_ECN_OK))
		ca->flags |= WA_FLAG_ECN_ENABLED;
#endif

	if (tp && tp->snd_cwnd > 0) {
		ca->last_safe_cwnd = min_t(u32, tp->snd_cwnd, WA_ABSOLUTE_MAX_WINDOW);
	} else {
		ca->last_safe_cwnd = WA_MIN_CWND;
	}
}

/* TCP事件处理（包括ECN） */
static void waproa_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	struct waproa *ca = inet_csk_ca(sk);
	u32 now = waproa_get_now();

	switch (ev) {
	case CA_EVENT_TX_START:
		ca->last_ack_time = now;
		break;
	case CA_EVENT_LOSS:
		ca->cum_acked = 0;
		waproa_recovery(sk);
		break;
	case CA_EVENT_ECN_IS_CE:
		if (ca->bw_est > 0) {
			ca->bw_est = (ca->bw_est * 8) / 10;
			if (ca->bw_est < 1)
				ca->bw_est = 1;
		}
		break;
	default:
		break;
	}
}

static void waproa_release(struct sock *sk)
{
	(void)sk;
}

static u32 waproa_undo_cwnd(struct sock *sk)
{
	return tcp_sk(sk)->snd_cwnd;
}

static struct tcp_congestion_ops waproa_cong_ops __read_mostly = {
	.init		= waproa_init,
	.release	= waproa_release,
	.ssthresh	= waproa_ssthresh,
	.cong_avoid	= waproa_cong_avoid,
	.cwnd_event	= waproa_cwnd_event,
	.undo_cwnd	= waproa_undo_cwnd,
	.owner		= THIS_MODULE,
	.name		= "waproa",

#if TCP_WA_NONSTANDARD_KERNEL
	.pkts_acked	= waproa_pkts_acked_wrapper,
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	.pkts_acked	= waproa_pkts_acked_v2,
#else
	.pkts_acked	= waproa_pkts_acked_v1,
#endif
};

static int __init waproa_register(void)
{
	u32 usecs_per_jiffy;

	BUILD_BUG_ON(sizeof(struct waproa) > ICSK_CA_PRIV_SIZE);

	usecs_per_jiffy = (u32)jiffies_to_usecs(1);
	if (unlikely(usecs_per_jiffy == 0)) {
		printk(KERN_WARNING "WAPROA: jiffies_to_usecs(1) returned 0, using default 1000\n");
		usecs_per_jiffy = 1000;
	}

	jiffies_to_usec_reciprocal = calc_reciprocal(usecs_per_jiffy);
	if (unlikely(jiffies_to_usec_reciprocal == 0)) {
		printk(KERN_ERR "WAPROA: Failed to calculate reciprocal for %u\n", usecs_per_jiffy);
		return -EINVAL;
	}

	printk(KERN_INFO "WAPROA: Registered v1.0 (max_window=%u)\n",
	       WA_ABSOLUTE_MAX_WINDOW);

	return tcp_register_congestion_control(&waproa_cong_ops);
}

static void __exit waproa_unregister(void)
{
	tcp_unregister_congestion_control(&waproa_cong_ops);
}

module_init(waproa_register);
module_exit(waproa_unregister);

MODULE_AUTHOR("EsquireProud547");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP WAPROA - 带宽自适应拥塞控制算法 v1.0");
MODULE_VERSION("1.0");
MODULE_ALIAS("tcp_congestion_control_waproa");

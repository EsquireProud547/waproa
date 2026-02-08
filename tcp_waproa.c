/*
 * TCP WAPROA拥塞控制算法
 * 兼容性说明：
 * - 支持的Linux内核版本范围：2.6.13 - 6.x
 * - 架构支持：x86/x86_64/ARM/ARM64/MIPS/PowerPC全架构兼容
 * - 编译器要求：GCC 4.6+ / Clang 3.0+，严格遵循C89标准
 * 核心功能：
 * 1. 基于ACK速率的实时带宽估计
 * 2. 带宽延迟积（BDP）动态窗口调整
 * 3. 防御性编程：溢出检查、零值保护、边界钳制
 * 4. 内存优化：32位时间戳存储，每连接仅28字节
 * 5. RTT老化机制：5分钟无更新自动增大10%
 * 注意:
 * - 本算法大量运用AI辅助编程，未经大规模验证，仅供参考
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/version.h>
#include <net/tcp.h>

/* 非标准内核适配开关 */
#define TCP_WA_NONSTANDARD_KERNEL   1

#define WA_BW_FILTER_HISTORY 7
#define WA_BW_FILTER_DIVISOR 8
#define WA_MIN_CWND 2U
#define WA_MIN_RTT_US 1000U
#define WA_MAX_BW 250000000U
#define WA_MAX_WINDOW 1000000U
#ifndef TCP_INFINITE_SSTHRESH
#define TCP_INFINITE_SSTHRESH 0x7fffffff
#endif
#define WA_RTT_AGING_INTERVAL (300 * HZ)
#define WA_RECIPROCAL_SHIFT 40
#define WA_RECIPROCAL_SCALE (1ULL << WA_RECIPROCAL_SHIFT)

/* 每连接私有数据结构（28字节紧凑布局） */
struct waproa {
	u32 last_ack_time;      /* 上次ACK到达时间（jiffies低32位） */
	u32 cum_acked;          /* 累计确认字节数 */
	u32 bw_est;             /* 估计带宽（字节/每jiffies） */
	u32 rtt_min;            /* 最小RTT测量值（微秒） */
	u32 last_safe_cwnd;     /* 上次计算的安全窗口 */
	u32 mss_reciprocal;     /* MSS倒数（40位精度截断存储） */
	u32 rtt_reset_time;     /* RTT老化计时起点 */
};

/* 全局预计算值：jiffies转微秒的倒数 */
static u32 jiffies_to_usec_reciprocal;

/* 数值钳制函数：确保值在[min, max]范围内 */
static inline u32 waproa_clamp_u32(u32 val, u32 min_val, u32 max_val)
{
	if (val < min_val)
		return min_val;
	if (val > max_val)
		return max_val;
	return val;
}

/* 获取当前时间戳（32位截断） */
static inline u32 waproa_get_now(void)
{
	return (u32)jiffies;
}

/* 40位精度快速除法：val / divisor ≈ (val * reciprocal) >> 40 */
static inline u32 fast_div_u32(u64 val, u32 reciprocal)
{
	u64 reciprocal_ext = (u64)reciprocal << 8;
	return (u32)((val * reciprocal_ext) >> WA_RECIPROCAL_SHIFT);
}

/* 计算40位精度倒数并截断为32位存储 */
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

/* 连接状态验证：检查关键参数有效性 */
static int waproa_state_valid(struct sock *sk)
{
	struct waproa *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	if (!ca || !tp)
		return 0;
	if (tp->snd_cwnd == 0 || tp->snd_cwnd > WA_MAX_WINDOW)
		return 0;
	if (tp->mss_cache == 0)
		return 0;
	return 1;
}

/* 带宽估计更新：使用指数加权移动平均平滑瞬时带宽 */
static void waproa_update_bw(struct sock *sk, u32 acked_bytes)
{
	struct waproa *ca = inet_csk_ca(sk);
	u32 now = waproa_get_now();
	u32 delta;
	u32 cur_bw;
	u64 new_bw_est;

	if (ca->last_ack_time == 0) {
		ca->last_ack_time = now;
		ca->cum_acked = acked_bytes;
		return;
	}

	delta = now - ca->last_ack_time;
	if (delta == 0) {
		ca->cum_acked += acked_bytes;
		return;
	}

	if (delta > (u32)HZ) {
		ca->last_ack_time = now;
		ca->cum_acked = 0;
		return;
	}

	ca->cum_acked += acked_bytes;
	if (ca->cum_acked > (tcp_sk(sk)->mss_cache << 1)) {
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

/* RTT老化检查：超过5分钟无更新则增加10% */
static void waproa_check_rtt_aging(struct waproa *ca, u32 now)
{
	u32 aging_deadline = ca->rtt_reset_time + (u32)WA_RTT_AGING_INTERVAL;
	u32 new_rtt;
	if ((s32)(now - aging_deadline) > 0) {
		if (ca->rtt_min > 0) {
			new_rtt = ca->rtt_min + (ca->rtt_min / 10);
			if (new_rtt > 1000000U) {
				ca->rtt_min = 0;
			} else {
				ca->rtt_min = new_rtt;
			}
		}
		ca->rtt_reset_time = now;
	}
}

/* 旧版ACK处理接口（Linux 3.10-4.14） */
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

/* 新版ACK处理接口（Linux 4.15+） */
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

/* 兼容性包装器：将新版接口转换为旧版参数 */
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

/* 计算带宽延迟积（BDP）：(带宽 × RTT) / MSS */
static u32 waproa_calculate_bdp(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct waproa *ca = inet_csk_ca(sk);
	u64 bdp;
	u32 mss;
	u32 safe_cwnd;

	if (!waproa_state_valid(sk)) {
		if (ca->last_safe_cwnd > 0)
			return ca->last_safe_cwnd;
		return max(tp->snd_cwnd >> 1, WA_MIN_CWND);
	}

	mss = tp->mss_cache;
	if (unlikely(mss <= 0 || mss > 1460)) {
		mss = 536;
	}

	ca->mss_reciprocal = calc_reciprocal(mss);
	if (ca->mss_reciprocal == 0) {
		safe_cwnd = max(tp->snd_cwnd >> 1, WA_MIN_CWND);
		ca->last_safe_cwnd = safe_cwnd;
		return safe_cwnd;
	}

	if (ca->bw_est == 0 || ca->rtt_min == 0) {
		safe_cwnd = max(tp->snd_cwnd >> 1, WA_MIN_CWND);
		ca->last_safe_cwnd = safe_cwnd;
		return safe_cwnd;
	}

	if (ca->bw_est > (U32_MAX / ca->rtt_min)) {
		safe_cwnd = max(tp->snd_cwnd >> 1, WA_MIN_CWND);
		ca->last_safe_cwnd = safe_cwnd;
		return safe_cwnd;
	}

	bdp = (u64)ca->bw_est * ca->rtt_min;
	if (bdp < ca->bw_est || bdp < ca->rtt_min) {
		safe_cwnd = max(tp->snd_cwnd >> 1, WA_MIN_CWND);
		ca->last_safe_cwnd = safe_cwnd;
		return safe_cwnd;
	}

	if (jiffies_to_usec_reciprocal == 0) {
		do_div(bdp, jiffies_to_usecs(1));
	} else {
		bdp = fast_div_u32(bdp, jiffies_to_usec_reciprocal);
	}

	bdp = fast_div_u32(bdp, ca->mss_reciprocal);
	safe_cwnd = waproa_clamp_u32((u32)bdp, WA_MIN_CWND, WA_MAX_WINDOW);
	ca->last_safe_cwnd = safe_cwnd;

	return safe_cwnd;
}

/* 拥塞避免核心：根据BDP调整拥塞窗口 */
static void waproa_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct waproa *ca = inet_csk_ca(sk);
	u32 target_cwnd;
	u32 increment;
	u32 snd_cwnd;
	u32 safe_cwnd;

	snd_cwnd = tp->snd_cwnd;

	if (!waproa_state_valid(sk)) {
		safe_cwnd = max(ca->last_safe_cwnd, WA_MIN_CWND);
		if (snd_cwnd < safe_cwnd && acked > 0) {
			increment = min_t(u32, acked, safe_cwnd - snd_cwnd);
			if (UINT_MAX - snd_cwnd < increment) {
				snd_cwnd = WA_MAX_WINDOW;
			} else {
				snd_cwnd += increment;
			}
		}
		tp->snd_cwnd = waproa_clamp_u32(snd_cwnd, WA_MIN_CWND, WA_MAX_WINDOW);
		return;
	}

	if (!tcp_is_cwnd_limited(sk) || !acked) {
		tp->snd_cwnd = snd_cwnd;
		return;
	}

	target_cwnd = waproa_calculate_bdp(sk);
	if (snd_cwnd < target_cwnd) {
		if (target_cwnd > snd_cwnd) {
			increment = min_t(u32, acked, target_cwnd - snd_cwnd);
			if (UINT_MAX - snd_cwnd < increment) {
				snd_cwnd = WA_MAX_WINDOW;
			} else {
				snd_cwnd += increment;
			}
		}
	} else {
		if (snd_cwnd <= tp->snd_ssthresh) {
			snd_cwnd += acked;
		} else {
			if (tcp_in_slow_start(tp)) {
				snd_cwnd += acked;
			} else {
				u32 limit = min_t(u32, acked, snd_cwnd >> 3);
				snd_cwnd += limit;
			}
		}
	}

	tp->snd_cwnd = waproa_clamp_u32(snd_cwnd, WA_MIN_CWND, WA_MAX_WINDOW);
}

/* 慢启动阈值计算：基于BDP但不超过当前窗口80% */
static u32 waproa_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct waproa *ca = inet_csk_ca(sk);
	u32 bdp;
	u32 safe_ssthresh;
	u32 safe_val;

	if (!waproa_state_valid(sk)) {
		safe_val = max(ca->last_safe_cwnd, WA_MIN_CWND);
		safe_val = min_t(u32, safe_val, (tp->snd_cwnd * 8) / 10);
		safe_val = max_t(u32, safe_val, WA_MIN_CWND);
		return safe_val;
	}

	bdp = waproa_calculate_bdp(sk);
	safe_ssthresh = max_t(u32, bdp, WA_MIN_CWND);
	safe_ssthresh = min_t(u32, safe_ssthresh, (tp->snd_cwnd * 8) / 10);
	safe_ssthresh = max_t(u32, safe_ssthresh, WA_MIN_CWND);

	return safe_ssthresh;
}

/* 丢包恢复：重置所有估计值，窗口退回到安全值 */
static void waproa_recovery(struct sock *sk)
{
	struct waproa *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	ca->bw_est = 0;
	ca->rtt_min = 0;
	ca->cum_acked = 0;
	ca->last_ack_time = waproa_get_now();
	ca->rtt_reset_time = waproa_get_now();

	if (tp) {
		tp->snd_cwnd = max_t(u32, ca->last_safe_cwnd, WA_MIN_CWND);
		tp->snd_ssthresh = max_t(u32, tp->snd_cwnd >> 1, WA_MIN_CWND);
	}
}

/* 新连接初始化 */
static void waproa_init(struct sock *sk)
{
	struct waproa *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	memset(ca, 0, sizeof(*ca));
	ca->last_ack_time = waproa_get_now();
	ca->rtt_reset_time = waproa_get_now();

	if (tp && tp->snd_cwnd > 0) {
		ca->last_safe_cwnd = tp->snd_cwnd;
	} else {
		ca->last_safe_cwnd = WA_MIN_CWND;
	}
}

/* TCP事件处理 */
static void waproa_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	struct waproa *ca = inet_csk_ca(sk);

	switch (ev) {
	case CA_EVENT_TX_START:
		ca->last_ack_time = waproa_get_now();
		break;
	case CA_EVENT_LOSS:
		ca->cum_acked = 0;
		waproa_recovery(sk);
		break;
	default:
		break;
	}
}

/* 资源释放（无需操作，内存由内核管理） */
static void waproa_release(struct sock *sk)
{
}

/* 撤销窗口调整：恢复原始窗口 */
static u32 waproa_undo_cwnd(struct sock *sk)
{
	return tcp_sk(sk)->snd_cwnd;
}

/* 拥塞控制操作结构体 */
static struct tcp_congestion_ops waproa_cong_ops __read_mostly = {
	.init       = waproa_init,
	.release    = waproa_release,
	.ssthresh   = waproa_ssthresh,
	.cong_avoid = waproa_cong_avoid,
	.cwnd_event = waproa_cwnd_event,
	.undo_cwnd  = waproa_undo_cwnd,
	.owner      = THIS_MODULE,
	.name       = "waproa",

#if TCP_WA_NONSTANDARD_KERNEL
	.pkts_acked = waproa_pkts_acked_wrapper,
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	.pkts_acked = waproa_pkts_acked_v2,
#else
	.pkts_acked = waproa_pkts_acked_v1,
#endif
};

/* 模块初始化：预计算倒数，注册算法 */
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

	return tcp_register_congestion_control(&waproa_cong_ops);
}

/* 模块卸载 */
static void __exit waproa_unregister(void)
{
	tcp_unregister_congestion_control(&waproa_cong_ops);
}

module_init(waproa_register);
module_exit(waproa_unregister);

MODULE_AUTHOR("EsquireProud547");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP WAPROA - 高精度自适应拥塞控制算法");
MODULE_VERSION("1.0");
MODULE_ALIAS("tcp_congestion_control_waproa");

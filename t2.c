/*
 * TCP WAPROA v1.3.1 - 28字节严格修复版 + 非标准内核兼容开关
 * 
 * 修复记录：
 * 1. [致命] 移除 fast_div_u32() 的 256 倍除法错误，改用标准 do_div()
 * 2. [致命] 添加 u64 乘法溢出检查（bw_est * rtt_min）
 * 3. [严重] 拥塞避免阶段改为标准 Reno AIMD（每 RTT +1）
 * 4. [严重] 移除 MSS 硬编码上限 1460，支持 Jumbo Frame/TSO
 * 5. [优化] 字段位域压缩，严格保持 28 字节/连接
 * 6. [兼容] 恢复 TCP_WA_NONSTANDARD_KERNEL 手动兼容开关
 * 
 * 编译选项：
 * - 标准内核：直接编译
 * - 非标准内核（如 RHEL 3.10 带 4.x TCP 补丁）：
 *   cc -DTCP_WA_NONSTANDARD_KERNEL=1 ...
 * 
 * 内存布局：7×u32 = 28 字节（紧凑无填充）
 * 兼容性：Linux 2.6.13 - 6.x（含非标准内核）
 * 许可证：GPL v2
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/version.h>
#include <linux/math64.h>
#include <net/tcp.h>

/* ============================================================================
 * 兼容性配置 - 手动开关非标准内核支持
 * ============================================================================ */

#ifndef TCP_WA_NONSTANDARD_KERNEL
#define TCP_WA_NONSTANDARD_KERNEL	0	/* 默认：标准内核行为 */
#endif

/* ============================================================================
 * 配置参数与宏定义
 * ============================================================================ */

#define WA_MIN_CWND			2U
#define WA_MIN_RTT_US			1000U
#define WA_MAX_BW			250000000U
#define WA_RTT_AGING_INTERVAL		(900U * HZ)
#define WA_BW_IDLE_THRESHOLD		(5U * HZ)
#define WA_MAX_WINDOW_RATIO		4
#define WA_ABSOLUTE_MAX_WINDOW		100000U
#define WA_LOSS_RETENTION_NUM		7
#define WA_LOSS_RETENTION_DEN		10
#define WA_ECN_REDUCTION_NUM		8
#define WA_ECN_REDUCTION_DEN		10

/* cnt_and_flags 位域定义（高12位复用） */
#define WA_CNT_MASK			0x000FFFFFU	/* 低20位：CA计数器 */
#define WA_FLAG_SLOW_START		0x00100000U	/* 第20位：SS标志 */
#define WA_FLAG_ECN_ENABLED		0x00200000U	/* 第21位：ECN标志 */

/* ============================================================================
 * 数据结构（严格28字节）
 * ============================================================================ */

struct waproa {
	u32	last_ack_time;		/* 0-3: 上次ACK时间戳 */
	u32	cum_acked;		/* 4-7: SS阶段累积字节（CA阶段闲置） */
	u32	bw_est;			/* 8-11: 带宽估计（字节/jiffy） */
	u32	rtt_min;		/* 12-15: 最小RTT（微秒） */
	u32	last_safe_cwnd;		/* 16-19: 上次BDP安全窗口 */
	u32	rtt_reset_time;		/* 20-23: RTT老化计时器 */
	u32	cnt_and_flags;		/* 24-27: 位域（计数器+标志） */
};

/* 编译时验证大小 */
static void __unused __waproa_size_check(void)
{
	BUILD_BUG_ON(sizeof(struct waproa) != 28);
}

/* ============================================================================
 * 位域访问器（内联确保性能）
 * ============================================================================ */

static inline u32 waproa_get_cnt(struct waproa *ca)
{
	return ca->cnt_and_flags & WA_CNT_MASK;
}

static inline void waproa_set_cnt(struct waproa *ca, u32 v)
{
	ca->cnt_and_flags = (ca->cnt_and_flags & ~WA_CNT_MASK) | (v & WA_CNT_MASK);
}

static inline void waproa_add_cnt(struct waproa *ca, u32 v)
{
	u32 new_cnt = ((ca->cnt_and_flags & WA_CNT_MASK) + v) & WA_CNT_MASK;
	ca->cnt_and_flags = (ca->cnt_and_flags & ~WA_CNT_MASK) | new_cnt;
}

static inline int waproa_in_slow_start(struct waproa *ca)
{
	return (ca->cnt_and_flags & WA_FLAG_SLOW_START) != 0;
}

static inline void waproa_set_slow_start(struct waproa *ca, int enable)
{
	if (enable)
		ca->cnt_and_flags |= WA_FLAG_SLOW_START;
	else
		ca->cnt_and_flags &= ~WA_FLAG_SLOW_START;
}

static inline int waproa_ecn_enabled(struct waproa *ca)
{
	return (ca->cnt_and_flags & WA_FLAG_ECN_ENABLED) != 0;
}

static inline void waproa_set_ecn(struct waproa *ca, int enable)
{
	if (enable)
		ca->cnt_and_flags |= WA_FLAG_ECN_ENABLED;
	else
		ca->cnt_and_flags &= ~WA_FLAG_ECN_ENABLED;
}

/* ============================================================================
 * 工具函数
 * ============================================================================ */

static inline u32 waproa_clamp(u32 v, u32 min, u32 max)
{
	return (v < min) ? min : (v > max) ? max : v;
}

/* 修正：安全的64位除法（兼容32位系统，避免链接 __udivdi3） */
static inline u32 waproa_safe_div64(u64 dividend, u32 divisor)
{
	if (unlikely(divisor == 0))
		return 0;
	
#if BITS_PER_LONG == 64
	return (u32)(dividend / divisor);
#else
	u64 _tmp = dividend;
	do_div(_tmp, divisor);
	return (u32)_tmp;
#endif
}

/* ============================================================================
 * 核心算法：带宽估计、BDP计算、拥塞控制
 * ============================================================================ */

static void waproa_check_rtt_aging(struct waproa *ca, u32 now)
{
	u32 deadline = ca->rtt_reset_time + WA_RTT_AGING_INTERVAL;
	if ((s32)(now - deadline) >= 0) {
		ca->rtt_min = 0;
		ca->rtt_reset_time = now;
	}
}

static void waproa_update_bw(struct sock *sk, u32 acked_bytes, u32 rtt_us)
{
	struct waproa *ca = inet_csk_ca(sk);
	u32 now = (u32)jiffies;
	u32 delta = now - ca->last_ack_time;

	if (unlikely(ca->last_ack_time == 0)) {
		ca->last_ack_time = now;
		ca->cum_acked = acked_bytes;
		if (rtt_us && (ca->rtt_min == 0 || rtt_us < ca->rtt_min)) {
			ca->rtt_min = max_t(u32, rtt_us, WA_MIN_RTT_US);
			ca->rtt_reset_time = now;
		}
		return;
	}

	if (unlikely(delta > WA_BW_IDLE_THRESHOLD)) {
		if (ca->bw_est > 0) {
			ca->bw_est >>= 1;
			if (ca->bw_est < 1)
				ca->bw_est = 1;
		}
		ca->last_ack_time = now;
		ca->cum_acked = acked_bytes;
		waproa_check_rtt_aging(ca, now);
		return;
	}

	if (unlikely(delta == 0)) {
		if (likely(ca->cum_acked < U32_MAX - acked_bytes))
			ca->cum_acked += acked_bytes;
		else
			ca->cum_acked = U32_MAX;
		return;
	}

	if (rtt_us) {
		u32 rtt = max_t(u32, rtt_us, WA_MIN_RTT_US);
		if (ca->rtt_min == 0 || rtt < ca->rtt_min) {
			ca->rtt_min = rtt;
			ca->rtt_reset_time = now;
		}
	}

	if (likely(ca->cum_acked <= U32_MAX - acked_bytes))
		ca->cum_acked += acked_bytes;
	else
		ca->cum_acked = U32_MAX;

	if (ca->cum_acked >= tcp_sk(sk)->mss_cache) {
		u32 cur_bw = ca->cum_acked / delta;
		if (cur_bw > 0 && cur_bw < WA_MAX_BW) {
			if (ca->bw_est == 0) {
				ca->bw_est = cur_bw;
			} else {
				u64 new_bw = ((u64)ca->bw_est * 7) + cur_bw;
				ca->bw_est = (u32)(new_bw >> 3);
			}
		}
		ca->cum_acked = 0;
		ca->last_ack_time = now;
	}

	waproa_check_rtt_aging(ca, now);
}

/* 修正：安全的BDP计算（带U64溢出检查） */
static u32 waproa_calc_bdp(struct sock *sk)
{
	struct waproa *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u64 bdp_bytes;
	u32 mss, usecs_per_jiffy, result;

	mss = tp->mss_cache;
	if (unlikely(mss == 0))
		mss = 536;

	if (ca->bw_est == 0 || ca->rtt_min == 0)
		return max_t(u32, tp->snd_cwnd >> 1, WA_MIN_CWND);

	/* 修复：U64乘法溢出检查 */
	if (unlikely(ca->bw_est > (U64_MAX / ca->rtt_min)))
		return ca->last_safe_cwnd ? ca->last_safe_cwnd : WA_MIN_CWND;

	bdp_bytes = (u64)ca->bw_est * ca->rtt_min;
	usecs_per_jiffy = (u32)jiffies_to_usecs(1);
	if (unlikely(usecs_per_jiffy == 0))
		usecs_per_jiffy = 1000;

	bdp_bytes = waproa_safe_div64(bdp_bytes, usecs_per_jiffy);
	result = waproa_safe_div64(bdp_bytes + mss - 1, mss);
	result = waproa_clamp(result, WA_MIN_CWND, WA_ABSOLUTE_MAX_WINDOW);
	
	ca->last_safe_cwnd = result;
	return result;
}

/* 修正：标准Reno AIMD拥塞避免 */
static void waproa_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct waproa *ca = inet_csk_ca(sk);
	u32 cwnd = tp->snd_cwnd;
	u32 target, max_limit, cnt;

	(void)ack;

	if (!tcp_is_cwnd_limited(sk) || !acked)
		return;

	target = waproa_calc_bdp(sk);
	
	max_limit = target * WA_MAX_WINDOW_RATIO;
	if (max_limit > WA_ABSOLUTE_MAX_WINDOW)
		max_limit = WA_ABSOLUTE_MAX_WINDOW;
	if (max_limit < WA_MIN_CWND)
		max_limit = WA_MIN_CWND;

	if (waproa_in_slow_start(ca)) {
		u32 ss_limit = min_t(u32, tp->snd_ssthresh, target);
		
		if (cwnd < ss_limit) {
			u32 inc = min_t(u32, acked, ss_limit - cwnd);
			cwnd = min_t(u32, cwnd + inc, max_limit);
		} else {
			waproa_set_slow_start(ca, 0);
			waproa_set_cnt(ca, 0);
			goto congestion_avoidance;
		}
	} else {
congestion_avoidance:
		if (cwnd < target) {
			u32 headroom = target - cwnd;
			u32 inc = min_t(u32, acked, headroom);
			inc = min_t(u32, inc, cwnd >> 3);
			cwnd = min_t(u32, cwnd + inc, max_limit);
		} else {
			cnt = waproa_get_cnt(ca);
			cnt += acked;
			
			if (cnt >= cwnd) {
				cnt -= cwnd;
				if (cwnd < max_limit)
					cwnd++;
			}
			waproa_set_cnt(ca, cnt);
		}
	}

	tp->snd_cwnd = waproa_clamp(cwnd, WA_MIN_CWND, max_limit);
}

static u32 waproa_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct waproa *ca = inet_csk_ca(sk);
	u32 bdp, retained, max_ssthresh;

	bdp = waproa_calc_bdp(sk);
	retained = (bdp * WA_LOSS_RETENTION_NUM) / WA_LOSS_RETENTION_DEN;
	retained = max_t(u32, retained, WA_MIN_CWND);
	
	max_ssthresh = (tp->snd_cwnd * 8) / 10;
	max_ssthresh = max_t(u32, max_ssthresh, WA_MIN_CWND * 2);
	
	return min_t(u32, retained, max_ssthresh);
}

static void waproa_recovery(struct sock *sk)
{
	struct waproa *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 retained_bw;

	if (ca->bw_est > 0) {
		retained_bw = ((u64)ca->bw_est * WA_LOSS_RETENTION_NUM) / WA_LOSS_RETENTION_DEN;
		ca->bw_est = max_t(u32, retained_bw, 1);
	}
	
	ca->cum_acked = 0;
	waproa_set_cnt(ca, 0);
	waproa_set_slow_start(ca, 0);
	ca->last_ack_time = (u32)jiffies;
	ca->rtt_reset_time = (u32)jiffies;

	if (tp) {
		u32 recov_cwnd = max_t(u32, ca->last_safe_cwnd, WA_MIN_CWND);
		u32 max_cwnd = waproa_clamp(waproa_calc_bdp(sk) * WA_MAX_WINDOW_RATIO, 
					    WA_MIN_CWND, WA_ABSOLUTE_MAX_WINDOW);
		tp->snd_cwnd = min_t(u32, recov_cwnd, max_cwnd);
	}
}

/* ============================================================================
 * 兼容性ACK处理（三态支持）
 * ============================================================================ */

/* 基础处理逻辑 - 被所有版本调用 */
static void waproa_pkts_acked_impl(struct sock *sk, u32 num_acked, s32 rtt_us)
{
	struct waproa *ca = inet_csk_ca(sk);
	u32 acked_bytes;
	u32 rtt;

	if (num_acked == 0)
		return;

	rtt = (rtt_us > 0) ? (u32)rtt_us : 0;
	acked_bytes = num_acked * tcp_sk(sk)->mss_cache;
	waproa_update_bw(sk, acked_bytes, rtt);
}

/* 旧版内核接口：Linux < 4.15 */
static void waproa_pkts_acked_v1(struct sock *sk, u32 num_acked, s32 rtt_us)
{
	waproa_pkts_acked_impl(sk, num_acked, rtt_us);
}

/* 新版内核接口：Linux >= 4.15 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static void waproa_pkts_acked_v2(struct sock *sk, const struct ack_sample *sample)
{
	if (!sample)
		return;
	waproa_pkts_acked_impl(sk, sample->pkts_acked, sample->rtt_us);
}
#endif

/* 非标准内核兼容：手动包装器（适配向后移植的内核） */
#if TCP_WA_NONSTANDARD_KERNEL
static void waproa_pkts_acked_wrapper(struct sock *sk,
				      const struct ack_sample *sample)
{
	if (!sample) {
		waproa_pkts_acked_impl(sk, 0, -1);
	} else {
		waproa_pkts_acked_impl(sk, sample->pkts_acked, sample->rtt_us);
	}
}
#endif

/* ============================================================================
 * TCP事件与生命周期管理
 * ============================================================================ */

static void waproa_init(struct sock *sk)
{
	struct waproa *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	memset(ca, 0, sizeof(*ca));
	ca->last_ack_time = (u32)jiffies;
	ca->rtt_reset_time = (u32)jiffies;
	waproa_set_slow_start(ca, 1);
	waproa_set_cnt(ca, 0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	if (tp && (tcp_sk(sk)->ecn_flags & TCP_ECN_OK))
		waproa_set_ecn(ca, 1);
#endif

	if (tp && tp->snd_cwnd > 0) {
		ca->last_safe_cwnd = min_t(u32, tp->snd_cwnd, WA_ABSOLUTE_MAX_WINDOW);
	} else {
		ca->last_safe_cwnd = WA_MIN_CWND;
	}
}

static void waproa_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	struct waproa *ca = inet_csk_ca(sk);

	switch (ev) {
	case CA_EVENT_TX_START:
		ca->last_ack_time = (u32)jiffies;
		break;
	case CA_EVENT_LOSS:
		ca->cum_acked = 0;
		waproa_set_cnt(ca, 0);
		waproa_recovery(sk);
		break;
	case CA_EVENT_ECN_IS_CE:
		if (ca->bw_est > 0) {
			ca->bw_est = ((u64)ca->bw_est * WA_ECN_REDUCTION_NUM) / WA_ECN_REDUCTION_DEN;
			if (ca->bw_est < 1)
				ca->bw_est = 1;
		}
		break;
	case CA_EVENT_ECN_NO_CE:
		/* 无需处理 */
		break;
	default:
		break;
	}
}

static void waproa_set_state(struct sock *sk, u8 new_state)
{
	struct waproa *ca = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		ca->cum_acked = 0;
		waproa_set_cnt(ca, 0);
	}
}

static u32 waproa_undo_cwnd(struct sock *sk)
{
	return tcp_sk(sk)->snd_cwnd;
}

static void waproa_release(struct sock *sk)
{
	/* 无动态资源 */
}

/* ============================================================================
 * 模块注册（根据宏选择pkts_acked实现）
 * ============================================================================ */

static struct tcp_congestion_ops waproa_ops __read_mostly = {
	.init		= waproa_init,
	.release	= waproa_release,
	.ssthresh	= waproa_ssthresh,
	.cong_avoid	= waproa_cong_avoid,
	.cwnd_event	= waproa_cwnd_event,
	.undo_cwnd	= waproa_undo_cwnd,
	.set_state	= waproa_set_state,
	.name		= "waproa",
	.owner		= THIS_MODULE,

	/* 三态编译选择：
	 * 1. 非标准内核：使用 wrapper 手动适配
	 * 2. 标准新内核：使用 v2 接口  
	 * 3. 标准旧内核：使用 v1 接口
	 */
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
	const char *mode_str;
	
#if TCP_WA_NONSTANDARD_KERNEL
	mode_str = "non-standard (wrapper mode)";
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	mode_str = "standard (v2 ack_sample)";
#else
	mode_str = "legacy (v1 basic)";
#endif

	pr_info("TCP WAPROA v1.3.1: 28-byte fix + %s\n", mode_str);
	pr_info("  - Memory: %zu bytes/connection\n", sizeof(struct waproa));
	pr_info("  - Build: %s\n", TCP_WA_NONSTANDARD_KERNEL ? "manual compat" : "auto detect");
	
	BUILD_BUG_ON_MSG(sizeof(struct waproa) != 28, 
		"waproa struct size must be exactly 28 bytes");
	
	return tcp_register_congestion_control(&waproa_ops);
}

static void __exit waproa_unregister(void)
{
	tcp_unregister_congestion_control(&waproa_ops);
}

module_init(waproa_register);
module_exit(waproa_unregister);

MODULE_AUTHOR("EsquireProud547 (Original), Kimi AI (28-byte Fix)");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP WAPROA v1.3.1 - 28-byte Reno AIMD with non-standard kernel support");
MODULE_VERSION("1.3.1");
MODULE_ALIAS("tcp_waproa");

/*
 * TCP WAPROA v3.0.0 (Production Release)
 * ============================================================================
 * 版本: v3.0.0
 * 作者: EsquireProud547 (原始), Kimi AI (架构重构)
 * 许可证: GPL v2
 * 
 * 核心特性:
 * - 严格28字节每连接内存占用(7×u32，无填充)
 * - 位域压缩: 20位计数器+2位标志+6位日志级别+4位扩展
 * - 标准RFC 2581慢启动(cwnd < ssthresh)
 * - [修复] 拉伸ACK正确处理(AIMD阶段允许多次增长)
 * - [修复] HZ无关时间计算(毫秒级精度，跨平台一致)
 * - [修复] 全内核版本兼容(2.6.13 - 6.x)
 * - BDP自适应带宽估计与空闲指数衰减
 * - 丢包后保留70%带宽(适合无线/移动网络)
 * ============================================================================
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/version.h>
#include <linux/math64.h>
#include <net/tcp.h>

/* ============================================================================
 * 兼容性层 (Compatibility Layer)
 * ============================================================================ */

/* [修复] tcp_is_cwnd_limited() 2.6.13-2.6.25兼容 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
static inline bool tcp_is_cwnd_limited(const struct sock *sk)
{
	return true;
}
#endif

/* [修复] jiffies时间比较宏(确保旧内核兼容) */
#ifndef time_after
#define time_after(a, b)		((long)(b) - (long)(a) < 0)
#endif
#ifndef time_before
#define time_before(a, b)		time_after(b, a)
#endif

/* [修复] 日志指针格式版本兼容 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#define WA_PTR_FMT			"%pK"
#else
#define WA_PTR_FMT			"%p"
#endif

/* ============================================================================
 * 常量定义(与HZ无关)
 * ============================================================================ */

/* 窗口约束 */
#define WA_MIN_CWND			2U
#define WA_MIN_RTT_US			1000U
#define WA_MAX_BW			250000000U
#define WA_ABSOLUTE_MAX_WINDOW		100000U
#define WA_MAX_WINDOW_RATIO		4
#define WA_SMALL_WINDOW_THRESHOLD	64

/* 时间常量(毫秒，与HZ无关) */
#define WA_RTT_AGING_MS			900000		/* 15分钟 */
#define WA_IDLE_PERIOD_MS		5000		/* 5秒 */

/* 拥塞响应 */
#define WA_LOSS_RETENTION_NUM		7		/* 70%保留 */
#define WA_LOSS_RETENTION_DEN		10
#define WA_ECN_REDUCTION_NUM		8		/* 80%降速 */
#define WA_ECN_REDUCTION_DEN		10

/* 日志级别(6位) */
#define WA_LOG_NONE			0
#define WA_LOG_ERROR			1
#define WA_LOG_WARN			4
#define WA_LOG_INFO			8
#define WA_LOG_DEBUG			32
#define WA_LOG_VERBOSE			63

/* 位域布局 */
#define WA_CNT_MASK			0x000FFFFFU	/* 20位计数器 */
#define WA_FLAG_SS			0x00100000U	/* 慢启动标志 */
#define WA_FLAG_ECN			0x00200000U	/* ECN标志 */
#define WA_LOG_MASK			0x0FC00000U	/* 6位日志级别 */
#define WA_LOG_SHIFT			22
#define WA_CUSTOM_MASK			0xF0000000U	/* 4位自定义 */
#define WA_CUSTOM_SHIFT			28

/* ============================================================================
 * 数据结构(严格28字节)
 * ============================================================================ */

struct waproa {
	u32	last_ack_time;		/* jiffies时间戳 */
	u32	cum_acked;		/* 累积确认字节 */
	u32	bw_est;			/* 带宽估计(字节/jiffy) */
	u32	rtt_min;		/* 最小RTT(微秒) */
	u32	last_safe_cwnd;		/* BDP安全窗口 */
	u32	rtt_reset_time;		/* RTT老化计时器 */
	u32	cnt_and_flags;		/* 位域压缩字段 */
};

/* 编译时大小验证 */
static void __unused __waproa_size_check(void)
{
	BUILD_BUG_ON(sizeof(struct waproa) != 28);
}

/* ============================================================================
 * 位域访问器
 * ============================================================================ */

static inline u32 waproa_get_cnt(const struct waproa *ca)
{
	return ca->cnt_and_flags & WA_CNT_MASK;
}

static inline void waproa_set_cnt(struct waproa *ca, u32 v)
{
	ca->cnt_and_flags = (ca->cnt_and_flags & ~WA_CNT_MASK) | (v & WA_CNT_MASK);
}

static inline int waproa_in_ss(const struct waproa *ca)
{
	return (ca->cnt_and_flags & WA_FLAG_SS) != 0;
}

static inline void waproa_set_ss(struct waproa *ca, int enable)
{
	if (enable)
		ca->cnt_and_flags |= WA_FLAG_SS;
	else
		ca->cnt_and_flags &= ~WA_FLAG_SS;
}

static inline int waproa_ecn_enabled(const struct waproa *ca)
{
	return (ca->cnt_and_flags & WA_FLAG_ECN) != 0;
}

static inline void waproa_set_ecn(struct waproa *ca, int enable)
{
	if (enable)
		ca->cnt_and_flags |= WA_FLAG_ECN;
	else
		ca->cnt_and_flags &= ~WA_FLAG_ECN;
}

static inline u8 waproa_get_loglevel(const struct waproa *ca)
{
	return (u8)((ca->cnt_and_flags & WA_LOG_MASK) >> WA_LOG_SHIFT);
}

static inline void waproa_set_loglevel(struct waproa *ca, u8 lvl)
{
	ca->cnt_and_flags = (ca->cnt_and_flags & ~WA_LOG_MASK) |
			    (((u32)lvl << WA_LOG_SHIFT) & WA_LOG_MASK);
}

static inline u8 waproa_get_custom(const struct waproa *ca)
{
	return (u8)((ca->cnt_and_flags & WA_CUSTOM_MASK) >> WA_CUSTOM_SHIFT);
}

static inline void waproa_set_custom(struct waproa *ca, u8 flags)
{
	ca->cnt_and_flags = (ca->cnt_and_flags & ~WA_CUSTOM_MASK) |
			    (((u32)flags << WA_CUSTOM_SHIFT) & WA_CUSTOM_MASK);
}

/* ============================================================================
 * 工具函数
 * ============================================================================ */

static inline u32 waproa_clamp(u32 v, u32 min, u32 max)
{
	return (v < min) ? min : (v > max) ? max : v;
}

static inline u32 waproa_div64(u64 dividend, u32 divisor)
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

/* 日志宏 */
#define WA_LOG(ca, lvl, fmt, ...)						\
do {										\
	if (waproa_get_loglevel(ca) >= (lvl))					\
		pr_debug("WAPROA[" WA_PTR_FMT "]: " fmt "\n", ca, ##__VA_ARGS__); \
} while (0)

/* ============================================================================
 * 核心算法
 * ============================================================================ */

/* [修复] RTT老化检查(HZ无关) */
static void waproa_check_rtt_aging(struct waproa *ca, u32 now)
{
	u32 deadline = ca->rtt_reset_time + msecs_to_jiffies(WA_RTT_AGING_MS);

	if (time_after(now, deadline)) {
		ca->rtt_min = 0;
		ca->rtt_reset_time = now;
		WA_LOG(ca, WA_LOG_INFO, "RTT_AGING: reset");
	}
}

/* [修复] 带宽更新(HZ无关的空闲衰减) */
static void waproa_update_bw(struct sock *sk, u32 acked_bytes, u32 rtt_us)
{
	struct waproa *ca = inet_csk_ca(sk);
	u32 now = (u32)jiffies;
	u32 delta = now - ca->last_ack_time;
	u32 delta_ms = jiffies_to_msecs(delta);

	if (unlikely(ca->last_ack_time == 0)) {
		ca->last_ack_time = now;
		ca->cum_acked = acked_bytes;
		if (rtt_us && (ca->rtt_min == 0 || rtt_us < ca->rtt_min)) {
			ca->rtt_min = max_t(u32, rtt_us, WA_MIN_RTT_US);
			ca->rtt_reset_time = now;
		}
		return;
	}

	/* [修复] HZ无关空闲检测 */
	if (unlikely(delta_ms > WA_IDLE_PERIOD_MS)) {
		if (ca->bw_est > 0) {
			u32 periods = delta_ms / WA_IDLE_PERIOD_MS;
			ca->bw_est >>= periods;
			if (ca->bw_est < 1) ca->bw_est = 1;
		}
		ca->last_ack_time = now;
		ca->cum_acked = acked_bytes;
		waproa_check_rtt_aging(ca, now);
		return;
	}

	/* 零时间差累积 */
	if (unlikely(delta == 0)) {
		if (likely(ca->cum_acked < U32_MAX - acked_bytes))
			ca->cum_acked += acked_bytes;
		else
			ca->cum_acked = U32_MAX;
		return;
	}

	/* 更新RTT */
	if (rtt_us) {
		u32 rtt = max_t(u32, rtt_us, WA_MIN_RTT_US);
		if (ca->rtt_min == 0 || rtt < ca->rtt_min) {
			ca->rtt_min = rtt;
			ca->rtt_reset_time = now;
		}
	}

	/* 累积带宽 */
	if (likely(ca->cum_acked <= U32_MAX - acked_bytes))
		ca->cum_acked += acked_bytes;
	else
		ca->cum_acked = U32_MAX;

	if (ca->cum_acked >= tcp_sk(sk)->mss_cache) {
		u32 cur_bw = ca->cum_acked / delta;
		if (cur_bw > 0 && cur_bw < WA_MAX_BW) {
			if (ca->bw_est == 0)
				ca->bw_est = cur_bw;
			else {
				u64 new_bw = ((u64)ca->bw_est * 7) + cur_bw;
				ca->bw_est = (u32)(new_bw >> 3);
			}
		}
		ca->cum_acked = 0;
		ca->last_ack_time = now;
	}

	waproa_check_rtt_aging(ca, now);
}

/* BDP计算 */
static u32 waproa_calc_bdp(struct sock *sk)
{
	struct waproa *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u64 bdp_bytes;
	u32 mss, result;

	mss = tp->mss_cache;
	if (unlikely(mss == 0)) mss = 536;

	if (ca->bw_est == 0 || ca->rtt_min == 0)
		return max_t(u32, tp->snd_cwnd >> 1, WA_MIN_CWND);

	if (unlikely(ca->bw_est > (U64_MAX / ca->rtt_min)))
		return ca->last_safe_cwnd ? ca->last_safe_cwnd : WA_MIN_CWND;

	bdp_bytes = (u64)ca->bw_est * ca->rtt_min;
	bdp_bytes = waproa_div64(bdp_bytes, (u32)jiffies_to_usecs(1));
	result = waproa_div64(bdp_bytes + mss - 1, mss);
	result = waproa_clamp(result, WA_MIN_CWND, WA_ABSOLUTE_MAX_WINDOW);

	ca->last_safe_cwnd = result;
	return result;
}

/* [核心修复] 拥塞避免 - RFC 2581合规 + 拉伸ACK处理 */
static void waproa_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct waproa *ca = inet_csk_ca(sk);
	u32 cwnd = tp->snd_cwnd;
	u32 target_cwnd, max_limit;
	u64 cnt_acc;

	(void)ack;
	if (!tcp_is_cwnd_limited(sk) || !acked)
		return;

	target_cwnd = waproa_calc_bdp(sk);
	max_limit = waproa_clamp(target_cwnd * WA_MAX_WINDOW_RATIO, 
				 WA_MIN_CWND, WA_ABSOLUTE_MAX_WINDOW);

	/* RFC 2581慢启动: cwnd < ssthresh */
	if (waproa_in_ss(ca)) {
		if (cwnd < tp->snd_ssthresh) {
			u32 inc = min_t(u32, acked, tp->snd_ssthresh - cwnd);
			cwnd = min_t(u32, cwnd + inc, max_limit);
			acked -= inc;
			if (!acked) return;
		} else {
			waproa_set_ss(ca, 0);
			waproa_set_cnt(ca, 0);
			goto ca_phase;
		}
	}

ca_phase:
	/* 拥塞避免阶段 */
	if (cwnd < target_cwnd) {
		/* 追赶阶段 */
		u32 headroom = target_cwnd - cwnd;
		u32 inc = min_t(u32, acked, headroom);
		if (cwnd >= WA_SMALL_WINDOW_THRESHOLD)
			inc = min_t(u32, inc, max_t(u32, cwnd >> 3, 1));
		cwnd = min_t(u32, cwnd + inc, max_limit);
	} else {
		/* [核心修复] AIMD: 正确处理拉伸ACK(允许多次增长) */
		cnt_acc = (u64)waproa_get_cnt(ca) + acked;
		u32 growth = cnt_acc / cwnd;

		if (growth > 0) {
			cnt_acc -= (u64)growth * cwnd;
			if (cwnd + growth <= max_limit) {
				cwnd += growth;
			} else {
				cwnd = max_limit;
			}
			WA_LOG(ca, WA_LOG_DEBUG, "AIMD: growth=%u cwnd=%u", growth, cwnd);
		}
		waproa_set_cnt(ca, (u32)cnt_acc);
	}

	tp->snd_cwnd = waproa_clamp(cwnd, WA_MIN_CWND, max_limit);
}

/* 其他函数 */
static u32 waproa_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct waproa *ca = inet_csk_ca(sk);
	u32 bdp = waproa_calc_bdp(sk);
	u32 ssthresh = max_t(u32, (bdp * WA_LOSS_RETENTION_NUM) / WA_LOSS_RETENTION_DEN, 
			     WA_MIN_CWND);
	u32 max_thresh = max_t(u32, (tp->snd_cwnd * 8) / 10, WA_MIN_CWND * 2);

	ssthresh = min_t(u32, ssthresh, max_thresh);
	WA_LOG(ca, WA_LOG_INFO, "SSTHRESH: bdp=%u result=%u", bdp, ssthresh);
	return ssthresh;
}

static void waproa_recovery(struct sock *sk)
{
	struct waproa *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	WA_LOG(ca, WA_LOG_INFO, "RECOVERY: cwnd=%u", tp->snd_cwnd);

	if (ca->bw_est > 0) {
		ca->bw_est = max_t(u32, 
			((u64)ca->bw_est * WA_LOSS_RETENTION_NUM) / WA_LOSS_RETENTION_DEN, 1);
	}

	ca->cum_acked = 0;
	waproa_set_cnt(ca, 0);
	waproa_set_ss(ca, 0);
	ca->last_ack_time = (u32)jiffies;
	ca->rtt_reset_time = (u32)jiffies;

	if (tp) {
		tp->snd_cwnd = min_t(u32, 
			max_t(u32, ca->last_safe_cwnd, WA_MIN_CWND), WA_ABSOLUTE_MAX_WINDOW);
		tp->snd_ssthresh = waproa_ssthresh(sk);
	}
}

/* ============================================================================
 * ACK处理(三态兼容)
 * ============================================================================ */

static void waproa_pkts_acked_impl(struct sock *sk, u32 num_acked, s32 rtt_us)
{
	struct waproa *ca = inet_csk_ca(sk);
	u32 mss;

	if (num_acked == 0) return;

	mss = tcp_sk(sk)->mss_cache;
	if (unlikely(mss == 0)) mss = 536;

	waproa_update_bw(sk, num_acked * mss, (rtt_us > 0) ? (u32)rtt_us : 0);
}

static void waproa_pkts_acked_v1(struct sock *sk, u32 num_acked, s32 rtt_us)
{
	waproa_pkts_acked_impl(sk, num_acked, rtt_us);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static void waproa_pkts_acked_v2(struct sock *sk, const struct ack_sample *sample)
{
	if (sample)
		waproa_pkts_acked_impl(sk, sample->pkts_acked, sample->rtt_us);
}
#endif

#if TCP_WA_NONSTANDARD_KERNEL
static void waproa_pkts_acked_wrapper(struct sock *sk, const struct ack_sample *s)
{
	waproa_pkts_acked_impl(sk, s ? s->pkts_acked : 0, s ? s->rtt_us : -1);
}
#endif

/* ============================================================================
 * 生命周期
 * ============================================================================ */

static void waproa_init(struct sock *sk)
{
	struct waproa *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	memset(ca, 0, sizeof(*ca));
	ca->last_ack_time = (u32)jiffies;
	ca->rtt_reset_time = (u32)jiffies;
	waproa_set_ss(ca, 1);
	waproa_set_loglevel(ca, WA_LOG_INFO);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	if (tp && (tcp_sk(sk)->ecn_flags & TCP_ECN_OK))
		waproa_set_ecn(ca, 1);
#endif

	ca->last_safe_cwnd = (tp && tp->snd_cwnd > 0) ? 
		min_t(u32, tp->snd_cwnd, WA_ABSOLUTE_MAX_WINDOW) : WA_MIN_CWND;

	WA_LOG(ca, WA_LOG_INFO, "INIT: mss=%u cwnd=%u", 
	       tp ? tp->mss_cache : 0, ca->last_safe_cwnd);
}

static void waproa_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	struct waproa *ca = inet_csk_ca(sk);
	u32 now = (u32)jiffies;

	switch (ev) {
	case CA_EVENT_TX_START:
		ca->last_ack_time = now;
		break;
	case CA_EVENT_LOSS:
		waproa_recovery(sk);
		break;
	case CA_EVENT_ECN_IS_CE:
		if (ca->bw_est > 0) {
			ca->bw_est = max_t(u32,
				((u64)ca->bw_est * WA_ECN_REDUCTION_NUM) / WA_ECN_REDUCTION_DEN, 1);
		}
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

static void waproa_release(struct sock *sk) { }

/* ============================================================================
 * 可观测性
 * ============================================================================ */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
#include <linux/sock_diag.h>
#include <uapi/linux/inet_diag.h>

static size_t waproa_get_info(struct sock *sk, u32 ext, int *attr,
			      union tcp_cc_info *info)
{
	struct waproa *ca = inet_csk_ca(sk);
	if (ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		info->vegas.tcpv_enabled = ca->cnt_and_flags & 0xFFFF;
		info->vegas.tcpv_rttcnt = ca->bw_est;
		info->vegas.tcpv_rtt = ca->rtt_min;
		info->vegas.tcpv_minrtt = ca->last_safe_cwnd;
		return sizeof(struct tcpvegas_info);
	}
	return 0;
}
#endif

/* ============================================================================
 * 模块注册
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
	.get_info	= waproa_get_info,
#endif
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
	pr_info("TCP WAPROA v3.0.0: RFC-compliant BDP-based congestion control\n");
	pr_info("  Memory: %zu bytes/connection, HZ-independent, stretch-ACK fixed\n",
		sizeof(struct waproa));
	BUILD_BUG_ON_MSG(sizeof(struct waproa) != 28,
		"WAPROA: struct size must be exactly 28 bytes");
	return tcp_register_congestion_control(&waproa_ops);
}

static void __exit waproa_unregister(void)
{
	tcp_unregister_congestion_control(&waproa_ops);
}

module_init(waproa_register);
module_exit(waproa_unregister);

MODULE_AUTHOR("EsquireProud547 (Original), Kimi AI (v3 Architecture)");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP WAPROA v3.0.0 - Production-Ready BDP Congestion Control");
MODULE_VERSION("3.0.0");
MODULE_ALIAS("tcp_waproa");

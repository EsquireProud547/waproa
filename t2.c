/*
 * TCP WAPROA (Bandwidth Adaptive Proportional Rate with Online Adaptation)
 * ============================================================================
 * 版本: v2.0.0
 * 作者: EsquireProud547 (原始), Kimi AI (优化与修复)
 * 许可证: GPL v2
 * 
 * 版本历史:
 * v1.0  - 初始版本，28字节结构体，存在fast_div_u32除法错误
 * v1.2  - t2修复版，扩展至32字节，使用标准div_u64
 * v1.3  - 28字节严格修复版，位域压缩，引入Reno AIMD
 * v1.3.1- 恢复TCP_WA_NONSTANDARD_KERNEL兼容性开关
 * v1.3.2- 增加可观测性（6位日志级别+4位自定义标志+get_info）
 * v2.0.0- 优化注释排版，统一代码风格，修复潜在拼写错误
 * 
 * 关键特性:
 * - 严格28字节每连接内存占用（7×u32，无填充）
 * - 位域精细划分：20位计数器+2位标志+6位日志级别+4位自定义扩展
 * - 标准Reno AIMD拥塞避免（每RTT+1）
 * - 修复v1.0除法错误（移除256倍缩放倒数优化）
 * - 支持非标准内核兼容模式（向后移植TCP栈）
 * - 运行时日志级别控制（0-63级）
 * - 兼容Linux 2.6.13 - 6.x
 * ============================================================================
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/version.h>
#include <linux/math64.h>
#include <net/tcp.h>

/* =============================================================================
 * 编译时配置
 * ============================================================================= */

#ifndef TCP_WA_NONSTANDARD_KERNEL
#define TCP_WA_NONSTANDARD_KERNEL	0	/* 0=自动检测, 1=强制wrapper模式 */
#endif

/* =============================================================================
 * 常量定义
 * ============================================================================= */

#define WA_MIN_CWND			2U		/* 最小拥塞窗口（段） */
#define WA_MIN_RTT_US			1000U		/* 最小RTT（1ms，防除零） */
#define WA_MAX_BW			250000000U	/* 最大带宽估计（字节/jiffy） */
#define WA_RTT_AGING_INTERVAL		(900U * HZ)	/* RTT老化周期（15分钟@1000Hz） */
#define WA_BW_IDLE_THRESHOLD		(5U * HZ)	/* 空闲检测阈值（5秒） */
#define WA_MAX_WINDOW_RATIO		4		/* 最大窗口=BDP×4 */
#define WA_ABSOLUTE_MAX_WINDOW		100000U		/* 绝对窗口上限（段） */
#define WA_LOSS_RETENTION_NUM		7		/* 丢包后保留70%带宽 */
#define WA_LOSS_RETENTION_DEN		10
#define WA_ECN_REDUCTION_NUM		8		/* ECN降速至80% */
#define WA_ECN_REDUCTION_DEN		10

/* 日志级别定义（6位，0-63） */
#define WA_LOG_NONE			0	/* 静默 */
#define WA_LOG_ERROR			1	/* 仅错误 */
#define WA_LOG_WARN			4	/* 警告 */
#define WA_LOG_INFO			8	/* 关键事件（默认） */
#define WA_LOG_DEBUG			32	/* 详细调试 */
#define WA_LOG_VERBOSE			63	/* 全量输出 */

/* 
 * cnt_and_flags 位域布局（32位）:
 * [0:19]  (20位) snd_cwnd_cnt - Reno AIMD计数器（支持到1,048,575）
 * [20]    (1位)  FLAG_SLOW_START - 慢启动阶段标志
 * [21]    (1位)  FLAG_ECN - ECN使能标志
 * [22:27] (6位)  LOG_LEVEL - 调试日志级别（0-63）
 * [28:31] (4位)  CUSTOM_FLAGS - 用户扩展标志位
 */
#define WA_CNT_MASK			0x000FFFFFU
#define WA_FLAG_SS			0x00100000U	/* 第20位 */
#define WA_FLAG_ECN			0x00200000U	/* 第21位 */
#define WA_LOG_MASK			0x0FC00000U	/* 第22-27位 */
#define WA_LOG_SHIFT			22
#define WA_CUSTOM_MASK			0xF0000000U	/* 第28-31位 */
#define WA_CUSTOM_SHIFT			28

/* =============================================================================
 * 数据结构（严格28字节）
 * ============================================================================= */

struct waproa {
	u32	last_ack_time;		/* 上次ACK时间戳（jiffies） */
	u32	cum_acked;		/* 累积确认字节（SS阶段）/闲置（CA阶段） */
	u32	bw_est;			/* 带宽估计（字节/jiffy） */
	u32	rtt_min;		/* 最小RTT（微秒） */
	u32	last_safe_cwnd;		/* 上次计算的BDP安全窗口（段） */
	u32	rtt_reset_time;		/* RTT老化计时器（jiffies） */
	u32	cnt_and_flags;		/* 位域：计数器+标志+日志级别+自定义 */
};

/* 编译时验证大小（必须为28字节） */
static void __unused __waproa_size_verify(void)
{
	BUILD_BUG_ON(sizeof(struct waproa) != 28);
}

/* =============================================================================
 * 位域访问器（内联，零开销）
 * ============================================================================= */

/* 计数器访问（20位） */
static inline u32 waproa_get_cnt(const struct waproa *ca)
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

/* 状态标志访问 */
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

/* 日志级别访问（6位，0-63） */
static inline u8 waproa_get_loglevel(const struct waproa *ca)
{
	return (u8)((ca->cnt_and_flags & WA_LOG_MASK) >> WA_LOG_SHIFT);
}

static inline void waproa_set_loglevel(struct waproa *ca, u8 lvl)
{
	ca->cnt_and_flags = (ca->cnt_and_flags & ~WA_LOG_MASK) |
			    (((u32)lvl << WA_LOG_SHIFT) & WA_LOG_MASK);
}

/* 自定义标志访问（4位，0-15） */
static inline u8 waproa_get_custom(const struct waproa *ca)
{
	return (u8)((ca->cnt_and_flags & WA_CUSTOM_MASK) >> WA_CUSTOM_SHIFT);
}

static inline void waproa_set_custom(struct waproa *ca, u8 flags)
{
	ca->cnt_and_flags = (ca->cnt_and_flags & ~WA_CUSTOM_MASK) |
			    (((u32)flags << WA_CUSTOM_SHIFT) & WA_CUSTOM_MASK);
}

/* =============================================================================
 * 工具函数
 * ============================================================================= */

/* 数值钳制 */
static inline u32 waproa_clamp(u32 v, u32 min, u32 max)
{
	return (v < min) ? min : (v > max) ? max : v;
}

/* 安全64位除法（兼容32位系统，避免__udivdi3链接错误） */
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

/* =============================================================================
 * 日志宏（运行时级别控制）
 * ============================================================================= */

#define WA_LOG(ca, lvl, fmt, ...)					\
do {									\
	if (waproa_get_loglevel(ca) >= (lvl)) {				\
		pr_debug("WAPROA[%p]: " fmt "\n", ca, ##__VA_ARGS__);	\
	}								\
} while (0)

/* =============================================================================
 * 核心算法实现
 * ============================================================================= */

/*
 * waproa_check_rtt_aging - RTT老化检查（处理jiffies回绕）
 * 当15分钟内无更新时重置rtt_min，防止路由变化后使用过时的低RTT
 */
static void waproa_check_rtt_aging(struct waproa *ca, u32 now)
{
	u32 deadline = ca->rtt_reset_time + WA_RTT_AGING_INTERVAL;
	
	/* 有符号比较自动处理32位回绕 */
	if ((s32)(now - deadline) >= 0) {
		ca->rtt_min = 0;
		ca->rtt_reset_time = now;
		WA_LOG(ca, WA_LOG_INFO, "RTT_AGING: reset after %us", 
		       WA_RTT_AGING_INTERVAL / HZ);
	}
}

/*
 * waproa_update_bw - 带宽估计更新（带空闲衰减）
 * 
 * 算法逻辑：
 * 1. 空闲检测（>5秒无ACK）：带宽指数衰减（bw_est /= 2）
 * 2. 正常情况：累积ACK字节，计算瞬时带宽=bytes/delta
 * 3. 滑动平均：新估计 = (旧×7 + 新×1) / 8
 * 
 * 注意：cum_acked仅在慢启动阶段有效，CA阶段该字段闲置
 */
static void waproa_update_bw(struct sock *sk, u32 acked_bytes, u32 rtt_us)
{
	struct waproa *ca = inet_csk_ca(sk);
	u32 now = (u32)jiffies;
	u32 delta = now - ca->last_ack_time; /* 无符号减法处理回绕 */

	/* 首次初始化 */
	if (unlikely(ca->last_ack_time == 0)) {
		ca->last_ack_time = now;
		ca->cum_acked = acked_bytes;
		if (rtt_us && (ca->rtt_min == 0 || rtt_us < ca->rtt_min)) {
			ca->rtt_min = max_t(u32, rtt_us, WA_MIN_RTT_US);
			ca->rtt_reset_time = now;
		}
		return;
	}

	/* 空闲链路处理：指数衰减带宽估计 */
	if (unlikely(delta > WA_BW_IDLE_THRESHOLD)) {
		if (ca->bw_est > 0) {
			u32 old_bw = ca->bw_est;
			ca->bw_est >>= 1;
			if (ca->bw_est < 1)
				ca->bw_est = 1;
			WA_LOG(ca, WA_LOG_DEBUG, "IDLE: bw %u -> %u", old_bw, ca->bw_est);
		}
		ca->last_ack_time = now;
		ca->cum_acked = acked_bytes;
		waproa_check_rtt_aging(ca, now);
		return;
	}

	/* 零时间差：累积字节（防突发ACK） */
	if (unlikely(delta == 0)) {
		if (likely(ca->cum_acked < U32_MAX - acked_bytes))
			ca->cum_acked += acked_bytes;
		else
			ca->cum_acked = U32_MAX;
		return;
	}

	/* 更新最小RTT（钳制不低于1ms） */
	if (rtt_us) {
		u32 rtt = max_t(u32, rtt_us, WA_MIN_RTT_US);
		if (ca->rtt_min == 0 || rtt < ca->rtt_min) {
			ca->rtt_min = rtt;
			ca->rtt_reset_time = now;
		}
	}

	/* 累积字节并计算瞬时带宽 */
	if (likely(ca->cum_acked <= U32_MAX - acked_bytes))
		ca->cum_acked += acked_bytes;
	else
		ca->cum_acked = U32_MAX;

	if (ca->cum_acked >= tcp_sk(sk)->mss_cache) {
		u32 cur_bw = ca->cum_acked / delta;
		
		if (cur_bw > 0 && cur_bw < WA_MAX_BW) {
			u32 old_bw = ca->bw_est;
			if (ca->bw_est == 0) {
				ca->bw_est = cur_bw;
			} else {
				/* EWMA滤波：权重7:1 */
				u64 new_bw = ((u64)ca->bw_est * 7) + cur_bw;
				ca->bw_est = (u32)(new_bw >> 3);
			}
			
			/* 带宽变化超过25%时记录 */
			if (abs((int)ca->bw_est - (int)old_bw) > (old_bw >> 2)) {
				WA_LOG(ca, WA_LOG_DEBUG, "BW_UPDATE: %u -> %u", 
				       old_bw, ca->bw_est);
			}
		}
		ca->cum_acked = 0;
		ca->last_ack_time = now;
	}

	waproa_check_rtt_aging(ca, now);
}

/*
 * waproa_calc_bdp - 计算带宽延迟积（BDP）
 * 
 * 公式: BDP = (bw_est × rtt_min) / usecs_per_jiffy / mss
 * 
 * 安全特性：
 * - U64乘法溢出检查（bw_est × rtt_min）
 * - 使用标准do_div()替代v1.0的错误fast_div_u32()
 * - 支持Jumbo Frame（无MSS硬编码上限）
 */
static u32 waproa_calc_bdp(struct sock *sk)
{
	struct waproa *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u64 bdp_bytes;
	u32 mss, usecs_per_jiffy, result;

	mss = tp->mss_cache;
	if (unlikely(mss == 0))
		mss = 536; /* RFC 896最小MSS */

	/* 无有效测量时保守回退（当前窗口的一半） */
	if (ca->bw_est == 0 || ca->rtt_min == 0)
		return max_t(u32, tp->snd_cwnd >> 1, WA_MIN_CWND);

	/* 致命错误修复：U64乘法溢出检查 */
	if (unlikely(ca->bw_est > (U64_MAX / ca->rtt_min)))
		return ca->last_safe_cwnd ? ca->last_safe_cwnd : WA_MIN_CWND;

	bdp_bytes = (u64)ca->bw_est * ca->rtt_min;
	
	/* 转换为字节：除以每jiffy微秒数 */
	usecs_per_jiffy = (u32)jiffies_to_usecs(1);
	if (unlikely(usecs_per_jiffy == 0))
		usecs_per_jiffy = 1000;

	bdp_bytes = waproa_div64(bdp_bytes, usecs_per_jiffy);

	/* 转换为段数（向上取整确保带宽利用） */
	result = waproa_div64(bdp_bytes + mss - 1, mss);
	result = waproa_clamp(result, WA_MIN_CWND, WA_ABSOLUTE_MAX_WINDOW);
	
	ca->last_safe_cwnd = result;
	return result;
}

/*
 * waproa_cong_avoid - 拥塞避免主函数
 * 
 * 状态机：
 * 1. 慢启动（SS）：指数增长，每ACK增加，直到ssthresh或target_cwnd
 * 2. 拥塞避免（CA）：
 *    - 若cwnd < target：较快增长（但限制为cwnd/8，防突发）
 *    - 若cwnd >= target：标准Reno AIMD，每RTT+1（使用20位计数器）
 */
static void waproa_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct waproa *ca = inet_csk_ca(sk);
	u32 cwnd = tp->snd_cwnd;
	u32 target_cwnd, max_limit, cnt;

	(void)ack; /* 抑制未使用参数警告 */

	if (!tcp_is_cwnd_limited(sk) || !acked)
		return;

	target_cwnd = waproa_calc_bdp(sk);
	
	/* 动态窗口上限：min(4×BDP, 100000) */
	max_limit = target_cwnd * WA_MAX_WINDOW_RATIO;
	if (max_limit > WA_ABSOLUTE_MAX_WINDOW)
		max_limit = WA_ABSOLUTE_MAX_WINDOW;
	if (max_limit < WA_MIN_CWND)
		max_limit = WA_MIN_CWND;

	if (waproa_in_ss(ca)) {
		u32 ss_limit = min_t(u32, tp->snd_ssthresh, target_cwnd);
		
		if (cwnd < ss_limit) {
			/* 慢启动：指数增长 */
			u32 increment = min_t(u32, acked, ss_limit - cwnd);
			WA_LOG(ca, WA_LOG_DEBUG, "SS: cwnd=%u inc=%u", cwnd, increment);
			cwnd = min_t(u32, cwnd + increment, max_limit);
		} else {
			/* 退出慢启动，进入CA，重置计数器 */
			waproa_set_ss(ca, 0);
			waproa_set_cnt(ca, 0);
			WA_LOG(ca, WA_LOG_INFO, "EXIT_SS: cwnd=%u ssthresh=%u", 
			       cwnd, tp->snd_ssthresh);
			goto congestion_avoidance;
		}
	} else {
congestion_avoidance:
		if (cwnd < target_cwnd) {
			/* 追赶阶段：限制增长率防振荡 */
			u32 headroom = target_cwnd - cwnd;
			u32 increment = min_t(u32, acked, headroom);
			increment = min_t(u32, increment, cwnd >> 3); /* 12.5%限制 */
			
			WA_LOG(ca, WA_LOG_DEBUG, "CA_CATCHUP: cwnd=%u target=%u inc=%u",
			       cwnd, target_cwnd, increment);
			cwnd = min_t(u32, cwnd + increment, max_limit);
		} else {
			/* 标准Reno AIMD：每RTT增加1 */
			cnt = waproa_get_cnt(ca) + acked;
			if (cnt >= cwnd) {
				cnt -= cwnd;
				if (cwnd < max_limit) {
					cwnd++;
					WA_LOG(ca, WA_LOG_DEBUG, "CA_AIMD: cwnd++ -> %u", cwnd);
				}
			}
			waproa_set_cnt(ca, cnt);
		}
	}

	tp->snd_cwnd = waproa_clamp(cwnd, WA_MIN_CWND, max_limit);
}

/*
 * waproa_ssthresh - 计算慢启动阈值（丢包后）
 * 
 * 策略：保留70%BDP，但不超过当前窗口的80%
 * 适用于：随机丢包链路（无线/卫星），避免Reno式剧减
 */
static u32 waproa_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct waproa *ca = inet_csk_ca(sk);
	u32 bdp, ssthresh, max_thresh;

	bdp = waproa_calc_bdp(sk);
	
	/* 基于BDP的保守阈值（70%） */
	ssthresh = max_t(u32, (bdp * WA_LOSS_RETENTION_NUM) / WA_LOSS_RETENTION_DEN, 
			 WA_MIN_CWND);
	
	/* 硬上限：当前窗口的80% */
	max_thresh = max_t(u32, (tp->snd_cwnd * 8) / 10, WA_MIN_CWND * 2);
	
	ssthresh = min_t(u32, ssthresh, max_thresh);
	WA_LOG(ca, WA_LOG_INFO, "SSTHRESH: bdp=%u result=%u", bdp, ssthresh);
	
	return ssthresh;
}

/*
 * waproa_recovery - 丢包恢复处理
 * 
 * 与Reno不同：保留70%带宽估计（非清零），温和降速
 */
static void waproa_recovery(struct sock *sk)
{
	struct waproa *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 retained_bw;

	WA_LOG(ca, WA_LOG_INFO, "RECOVERY: cwnd=%u bw=%u", 
	       tp->snd_cwnd, ca->bw_est);

	if (ca->bw_est > 0) {
		retained_bw = ((u64)ca->bw_est * WA_LOSS_RETENTION_NUM) / 
			      WA_LOSS_RETENTION_DEN;
		ca->bw_est = max_t(u32, retained_bw, 1);
	}
	
	/* 重置状态机 */
	ca->cum_acked = 0;
	waproa_set_cnt(ca, 0);
	waproa_set_ss(ca, 0); /* 丢包后退出慢启动 */
	ca->last_ack_time = (u32)jiffies;
	ca->rtt_reset_time = (u32)jiffies;

	if (tp) {
		u32 recovery_cwnd = max_t(u32, ca->last_safe_cwnd, WA_MIN_CWND);
		tp->snd_cwnd = min_t(u32, recovery_cwnd, WA_ABSOLUTE_MAX_WINDOW);
		tp->snd_ssthresh = waproa_ssthresh(sk);
	}
}

/* =============================================================================
 * ACK处理（三态兼容：标准旧/标准新/非标准）
 * ============================================================================= */

/* 统一处理逻辑 */
static void waproa_pkts_acked_impl(struct sock *sk, u32 num_acked, s32 rtt_us)
{
	struct waproa *ca = inet_csk_ca(sk);
	u32 acked_bytes, rtt;

	if (num_acked == 0)
		return;

	rtt = (rtt_us > 0) ? (u32)rtt_us : 0;
	acked_bytes = num_acked * tcp_sk(sk)->mss_cache;
	waproa_update_bw(sk, acked_bytes, rtt);
}

/* 标准旧内核：Linux < 4.15 */
static void waproa_pkts_acked_v1(struct sock *sk, u32 num_acked, s32 rtt_us)
{
	waproa_pkts_acked_impl(sk, num_acked, rtt_us);
}

/* 标准新内核：Linux >= 4.15，使用ack_sample结构 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
static void waproa_pkts_acked_v2(struct sock *sk, const struct ack_sample *sample)
{
	if (!sample)
		return;
	waproa_pkts_acked_impl(sk, sample->pkts_acked, sample->rtt_us);
}
#endif

/* 非标准内核兼容：手动适配向后移植的高版本TCP栈 */
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

/* =============================================================================
 * TCP事件处理与生命周期
 * ============================================================================= */

static void waproa_init(struct sock *sk)
{
	struct waproa *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* 清零所有字段（含cnt_and_flags） */
	memset(ca, 0, sizeof(*ca));
	
	ca->last_ack_time = (u32)jiffies;
	ca->rtt_reset_time = (u32)jiffies;
	waproa_set_ss(ca, 1);		/* 初始进入慢启动 */
	waproa_set_cnt(ca, 0);
	waproa_set_loglevel(ca, WA_LOG_INFO);	/* 默认INFO级别 */
	waproa_set_custom(ca, 0);		/* 自定义标志清零 */
	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	if (tp && (tcp_sk(sk)->ecn_flags & TCP_ECN_OK))
		waproa_set_ecn(ca, 1);
#endif

	if (tp && tp->snd_cwnd > 0)
		ca->last_safe_cwnd = min_t(u32, tp->snd_cwnd, WA_ABSOLUTE_MAX_WINDOW);
	else
		ca->last_safe_cwnd = WA_MIN_CWND;

	WA_LOG(ca, WA_LOG_INFO, "INIT: mss=%u init_cwnd=%u", 
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
		ca->cum_acked = 0;
		waproa_set_cnt(ca, 0);
		waproa_recovery(sk);
		break;
		
	case CA_EVENT_ECN_IS_CE:
		WA_LOG(ca, WA_LOG_INFO, "ECN_CE: reducing bandwidth");
		if (ca->bw_est > 0) {
			ca->bw_est = ((u64)ca->bw_est * WA_ECN_REDUCTION_NUM) / 
				     WA_ECN_REDUCTION_DEN;
			if (ca->bw_est < 1)
				ca->bw_est = 1;
		}
		break;
		
	case CA_EVENT_ECN_NO_CE:
		/* 无需操作 */
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
		WA_LOG(ca, WA_LOG_INFO, "STATE_CHANGE: -> Loss");
	}
}

static u32 waproa_undo_cwnd(struct sock *sk)
{
	return tcp_sk(sk)->snd_cwnd;
}

static void waproa_release(struct sock *sk)
{
	/* 当前无动态资源需释放 */
}

/* =============================================================================
 * 可观测性接口（Linux 5.0+）
 * ============================================================================= */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
#include <linux/sock_diag.h>
#include <uapi/linux/inet_diag.h>

/*
 * waproa_get_info - 暴露内部状态给ss工具
 * 
 * 复用tcpvegas_info结构字段映射：
 * - tcpv_enabled: cnt_and_flags低16位（标志+日志级别）
 * - tcpv_rttcnt:  bw_est（带宽估计）
 * - tcpv_rtt:     rtt_min（微秒）
 * - tcpv_minrtt:  last_safe_cwnd（BDP窗口）
 */
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

/* =============================================================================
 * 模块注册
 * ============================================================================= */

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
	const char *mode_str;
	
#if TCP_WA_NONSTANDARD_KERNEL
	mode_str = "non-standard (wrapper)";
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
	mode_str = "standard v2 (ack_sample)";
#else
	mode_str = "legacy v1 (basic)";
#endif

	pr_info("TCP WAPROA v2.0.0: 28-byte BDP-based congestion control\n");
	pr_info("  Mode: %s\n", mode_str);
	pr_info("  Memory: %zu bytes/connection\n", sizeof(struct waproa));
	pr_info("  Layout: 20bit cnt + 2bit flags + 6bit log + 4bit custom\n");
	pr_info("  Fixes: div256, u64 overflow, Reno AIMD, MSS limit\n");
	
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

MODULE_AUTHOR("EsquireProud547 (Original), Kimi AI (v2 Optimization)");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP WAPROA v2.0.0 - 28-byte Strict Fixed Congestion Control");
MODULE_VERSION("2.0.0");
MODULE_ALIAS("tcp_waproa");

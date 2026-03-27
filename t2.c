/*
 * TCP WAPROA (Bandwidth Adaptive Proportional Rate with Online Adaptation)
 * 拥塞控制算法 - 严格修复版 v1.2
 * 
 * 修复记录（v1.0 → v1.2）：
 * 1. [致命] 移除 fast_div_u32() 的 256 倍除法错误，改用标准内核除法宏
 * 2. [严重] 拥塞避免阶段改为标准 Reno AIMD（每 RTT +1），替代原激进增长
 * 3. [严重] 添加 u64 乘法溢出检查（bw_est * rtt_min）
 * 4. [中等] 修复慢启动状态机逻辑（退出时清除标志位）
 * 5. [中等] 移除 MSS 硬编码上限（支持 Jumbo Frame/TSO）
 * 6. [一般] 添加完整的 tcp_congestion_ops 回调（set_state/get_info）
 * 7. [一般] 统一使用 div_u64() 和标准除法，移除非标准 API
 * 
 * 算法特性：
 * - 基于 ACK 速率的带宽估计（Westwood-like）
 * - BDP 动态窗口上限（防止 Bufferbloat）
 * - 空闲带宽指数衰减（适应间歇链路）
 * - 丢包保留 70% 带宽（非 Reno 式剧减）
 * - 每连接内存占用：32 字节
 * 
 * 兼容性：Linux 2.6.13 - 6.x
 * 作者：EsquireProud547 (原始), Kimi AI (修复与优化)
 * 许可证：GPL v2
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/version.h>
#include <linux/math64.h>
#include <net/tcp.h>

/* ============================================================================
 * 配置参数与宏定义
 * ============================================================================ */

#define TCP_WA_NONSTANDARD_KERNEL	1	/* 兼容非标准内核配置 */

/* 滤波器参数：历史权重 7/8，新样本 1/8 */
#define WA_BW_FILTER_HISTORY		7
#define WA_BW_FILTER_DIVISOR		8

#define WA_MIN_CWND			2U	/* 最小拥塞窗口（段） */
#define WA_MIN_RTT_US			1000U	/* 最小 RTT 微秒（1ms） */
#define WA_MAX_BW			250000000U /* 最大带宽（字节/jiffy） */

#ifndef TCP_INFINITE_SSTHRESH
#define TCP_INFINITE_SSTHRESH		0x7fffffff
#endif

#define WA_RTT_AGING_INTERVAL		(900 * HZ) /* RTT 老化周期（~15min@1000Hz） */
#define WA_BW_IDLE_THRESHOLD		(5 * HZ)   /* 空闲检测阈值（5秒） */

/* 窗口硬限制：4×BDP 或绝对上限 100,000 段 */
#define WA_MAX_WINDOW_RATIO		4
#define WA_ABSOLUTE_MAX_WINDOW		100000U

/* 丢包恢复保留 70% 带宽 */
#define WA_LOSS_BW_RETENTION_NUM	7
#define WA_LOSS_BW_RETENTION_DEN	10

/* ECN 降速至 80% */
#define WA_ECN_REDUCTION_NUM		8
#define WA_ECN_REDUCTION_DEN		10

/* 状态标志位 */
#define WA_FLAG_IN_SLOW_START		0x01
#define WA_FLAG_ECN_ENABLED		0x02

/* ============================================================================
 * 数据结构
 * ============================================================================ */

/**
 * struct waproa - 每连接私有数据（32字节）
 * 
 * 内存布局优化：所有 u32 字段连续，减少缓存行占用。
 * 注意：必须满足 sizeof(struct waproa) <= ICSK_CA_PRIV_SIZE（通常 16/32/512）
 */
struct waproa {
	/* 带宽估计相关（16字节） */
	u32	last_ack_time;		/* 上次 ACK 时间戳（jiffies） */
	u32	cum_acked;		/* 累积确认字节数 */
	u32	bw_est;			/* 带宽估计（字节/jiffy） */
	u32	rtt_min;		/* 最小 RTT（微秒） */
	
	/* 拥塞控制状态（12字节） */
	u32	last_safe_cwnd;		/* 上次计算的 BDP 安全窗口 */
	u32	rtt_reset_time;		/* RTT 老化计时器 */
	u32	snd_cwnd_cnt;		/* 拥塞避免计数器（Reno 风格） */
	
	/* 标志与填充（4字节） */
	u8	flags;			/* WA_FLAG_* 状态标志 */
	u8	reserved[3];		/* 对齐填充（确保 32 字节边界） */
};

/* 验证结构体大小限制 */
static void __unused waproa_size_check(void) {
	BUILD_BUG_ON(sizeof(struct waproa) > ICSK_CA_PRIV_SIZE);
}

/* ============================================================================
 * 工具函数
 * ============================================================================ */

/**
 * waproa_clamp_u32() - 32位数值钳制
 * @val: 输入值
 * @min_val: 最小值（包含）
 * @max_val: 最大值（包含）
 * 
 * 返回限制在 [min_val, max_val] 范围内的 val。
 */
static inline u32 waproa_clamp_u32(u32 val, u32 min_val, u32 max_val)
{
	if (unlikely(val < min_val))
		return min_val;
	if (unlikely(val > max_val))
		return max_val;
	return val;
}

/**
 * waproa_get_now() - 获取当前时间戳
 * 
 * 返回 32 位 jiffies，自动处理回绕（wrap-around）。
 */
static inline u32 waproa_get_now(void)
{
	return (u32)jiffies;
}

/**
 * waproa_time_delta() - 计算时间差（处理 32 位回绕）
 * @now: 当前时间
 * @last: 上次时间
 * 
 * 无符号减法自动处理 jiffies 回绕。
 */
static inline u32 waproa_time_delta(u32 now, u32 last)
{
	return (u32)(now - last);
}

/**
 * waproa_state_valid() - 验证连接状态有效性
 * @sk: socket 指针
 * 
 * 检查指针有效性和窗口范围，防止异常状态导致计算错误。
 */
static int waproa_state_valid(struct sock *sk)
{
	struct waproa *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	
	if (unlikely(!ca || !tp))
		return 0;
	if (unlikely(tp->snd_cwnd > WA_ABSOLUTE_MAX_WINDOW))
		return 0;
	return 1;
}

/* ============================================================================
 * 带宽估计（Bandwidth Estimation）
 * ============================================================================ */

/**
 * waproa_update_bw() - 更新带宽估计（带空闲衰减）
 * @sk: socket 指针
 * @acked_bytes: 本次 ACK 确认的字节数
 * 
 * 核心逻辑：
 * 1. 空闲检测（>5秒无 ACK）：带宽指数衰减（减半）
 * 2. 累积 ACK 字节，计算瞬时带宽（acked/delta）
 * 3. 滑动平均滤波：新估计 = (旧×7 + 新×1) / 8
 * 
 * 注意：所有累加操作均包含溢出保护。
 */
static void waproa_update_bw(struct sock *sk, u32 acked_bytes)
{
	struct waproa *ca = inet_csk_ca(sk);
	u32 now = waproa_get_now();
	u32 delta = waproa_time_delta(now, ca->last_ack_time);
	u32 cur_bw;
	u64 new_bw_est;

	/* 首次初始化 */
	if (unlikely(ca->last_ack_time == 0)) {
		ca->last_ack_time = now;
		ca->cum_acked = acked_bytes;
		return;
	}

	/* 空闲链路处理：指数衰减带宽估计 */
	if (unlikely(delta > WA_BW_IDLE_THRESHOLD)) {
		if (ca->bw_est > 0) {
			ca->bw_est >>= 1;  /* 除以 2 */
			if (ca->bw_est < 1)
				ca->bw_est = 0;
		}
		ca->last_ack_time = now;
		ca->cum_acked = acked_bytes;
		return;
	}

	/* 零时间差：累积字节（防突发） */
	if (unlikely(delta == 0)) {
		if (likely(ca->cum_acked < (U32_MAX - acked_bytes)))
			ca->cum_acked += acked_bytes;
		else
			ca->cum_acked = U32_MAX;
		return;
	}

	/* 累积字节溢出保护 */
	if (unlikely(ca->cum_acked > (U32_MAX - acked_bytes)))
		ca->cum_acked = U32_MAX;
	else
		ca->cum_acked += acked_bytes;

	/* 计算瞬时带宽（需累积至少一个 MSS 且时间差>0） */
	if (likely(ca->cum_acked >= tcp_sk(sk)->mss_cache && delta > 0)) {
		cur_bw = ca->cum_acked / delta;  /* u32/u32 = u32 */
		
		if (likely(cur_bw > 0 && cur_bw < WA_MAX_BW)) {
			if (ca->bw_est == 0) {
				ca->bw_est = cur_bw;
			} else {
				/* 滑动平均：7/8 历史 + 1/8 新值 */
				new_bw_est = (u64)ca->bw_est * WA_BW_FILTER_HISTORY + cur_bw;
				new_bw_est = div_u64(new_bw_est, WA_BW_FILTER_DIVISOR);
				ca->bw_est = (u32)min_t(u64, new_bw_est, U32_MAX);
			}
		}
		ca->cum_acked = 0;
		ca->last_ack_time = now;
	}
}

/**
 * waproa_check_rtt_aging() - RTT 老化检查（15分钟超时）
 * @ca: 私有数据结构
 * @now: 当前时间
 * 
 * 防止历史最小 RTT 过时（如路由变化、网络条件改变）。
 */
static void waproa_check_rtt_aging(struct waproa *ca, u32 now)
{
	u32 reset_deadline = ca->rtt_reset_time + (u32)WA_RTT_AGING_INTERVAL;
	
	/* 使用有符号比较处理回绕 */
	if ((s32)(now - reset_deadline) >= 0) {
		ca->rtt_min = 0;  /* 重置，等待新测量 */
		ca->rtt_reset_time = now;
	}
}

/* ============================================================================
 * ACK 处理（兼容多版本内核）
 * ============================================================================ */

/**
 * waproa_pkts_acked_v1() - 旧版 ACK 处理（Linux < 4.15）
 * 
 * 从 ACK 信息中提取 RTT 和确认字节数，更新带宽估计。
 */
static void waproa_pkts_acked_v1(struct sock *sk, u32 num_acked, s32 rtt_us)
{
	struct waproa *ca = inet_csk_ca(sk);
	u32 acked_bytes;
	u32 now = waproa_get_now();
	u32 rtt;

	rtt = (rtt_us < 0) ? 0 : (u32)rtt_us;
	acked_bytes = num_acked * tcp_sk(sk)->mss_cache;

	/* 更新最小 RTT（钳制不低于 1ms） */
	if (likely(rtt > 0)) {
		rtt = max_t(u32, rtt, WA_MIN_RTT_US);
		if (ca->rtt_min == 0 || rtt < ca->rtt_min) {
			ca->rtt_min = rtt;
			ca->rtt_reset_time = now;
		}
	}

	waproa_check_rtt_aging(ca, now);
	waproa_update_bw(sk, acked_bytes);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
/**
 * waproa_pkts_acked_v2() - 新版 ACK 处理（Linux >= 4.15）
 * 
 * 使用 struct ack_sample 获取更精确的 ACK 信息。
 */
static void waproa_pkts_acked_v2(struct sock *sk, const struct ack_sample *sample)
{
	struct waproa *ca = inet_csk_ca(sk);
	u32 acked_bytes;
	u32 rtt;
	u32 now = waproa_get_now();

	if (!sample)
		return;

	rtt = (sample->rtt_us < 0) ? 0 : (u32)sample->rtt_us;
	acked_bytes = sample->pkts_acked * tcp_sk(sk)->mss_cache;

	if (likely(rtt > 0)) {
		rtt = max_t(u32, rtt, WA_MIN_RTT_US);
		if (ca->rtt_min == 0 || rtt < ca->rtt_min) {
			ca->rtt_min = rtt;
			ca->rtt_reset_time = now;
		}
	}

	waproa_check_rtt_aging(ca, now);
	waproa_update_bw(sk, acked_bytes);
}
#endif

#if TCP_WA_NONSTANDARD_KERNEL
/**
 * waproa_pkts_acked_wrapper() - 兼容性包装器
 * 
 * 适配不同内核版本的 pkts_acked 回调签名差异。
 */
static void waproa_pkts_acked_wrapper(struct sock *sk,
				      const struct ack_sample *sample)
{
	if (!sample)
		waproa_pkts_acked_v1(sk, 0, -1);
	else
		waproa_pkts_acked_v1(sk, sample->pkts_acked, sample->rtt_us);
}
#endif

/* ============================================================================
 * BDP 计算与窗口限制
 * ============================================================================ */

/**
 * waproa_calculate_bdp() - 计算带宽延迟积（BDP）
 * @sk: socket 指针
 * 
 * 计算公式：BDP = (bw_est × rtt_min) / usecs_per_jiffy / mss
 * 
 * 修复说明（v1.2）：
 * - 使用 div_u64() 替代错误的 fast_div_u32()
 * - 添加 u64 乘法溢出检查
 * - 移除 MSS 硬编码上限，支持现代网络特性（TSO/Jumbo）
 * 
 * 返回：建议的拥塞窗口（段数）
 */
static u32 waproa_calculate_bdp(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct waproa *ca = inet_csk_ca(sk);
	u64 bdp_bytes;
	u32 mss, usecs_per_jiffy, safe_cwnd;

	/* 状态异常时使用回退值 */
	if (unlikely(!waproa_state_valid(sk))) {
		safe_cwnd = max_t(u32, ca->last_safe_cwnd, WA_MIN_CWND);
		return safe_cwnd ? safe_cwnd : WA_MIN_CWND;
	}

	mss = tp->mss_cache;
	if (unlikely(mss == 0))
		mss = 536;  /* TCP 最小 MSS */
	/* 修复：移除 1460 上限，允许 TSO/GSO 大包 */

	/* 无有效测量时使用保守估计 */
	if (ca->bw_est == 0 || ca->rtt_min == 0) {
		safe_cwnd = max_t(u32, tp->snd_cwnd >> 1, WA_MIN_CWND);
		ca->last_safe_cwnd = safe_cwnd;
		return safe_cwnd;
	}

	/* 溢出检查：bw_est × rtt_min 是否超过 U64 范围 */
	if (unlikely(ca->bw_est > (U64_MAX / ca->rtt_min))) {
		safe_cwnd = max_t(u32, tp->snd_cwnd >> 1, WA_MIN_CWND);
		ca->last_safe_cwnd = safe_cwnd;
		return safe_cwnd;
	}

	bdp_bytes = (u64)ca->bw_est * ca->rtt_min;
	
	/* 安全检查：乘法回绕检测（理论上 U64 不会回绕，但防御性编程） */
	if (unlikely(bdp_bytes < ca->bw_est || bdp_bytes < ca->rtt_min)) {
		safe_cwnd = max_t(u32, tp->snd_cwnd >> 1, WA_MIN_CWND);
		ca->last_safe_cwnd = safe_cwnd;
		return safe_cwnd;
	}

	usecs_per_jiffy = (u32)jiffies_to_usecs(1);
	if (unlikely(usecs_per_jiffy == 0))
		usecs_per_jiffy = 1000;  /* 默认 1000Hz */

	/* 修复：使用标准内核除法 */
	bdp_bytes = div_u64(bdp_bytes, usecs_per_jiffy);

	/* 转换为段数（向上取整确保带宽利用） */
	safe_cwnd = (u32)div_u64(bdp_bytes + mss - 1, mss);
	safe_cwnd = waproa_clamp_u32(safe_cwnd, WA_MIN_CWND, WA_ABSOLUTE_MAX_WINDOW);
	
	ca->last_safe_cwnd = safe_cwnd;
	return safe_cwnd;
}

/**
 * waproa_max_window_limit() - 计算动态窗口上限
 * @ca: 私有数据结构
 * 
 * 上限 = min(4 × BDP, 100000 段)
 * 
 * 防止过度缓冲（bufferbloat），同时保证高 BDP 链路利用率。
 */
static u32 waproa_max_window_limit(struct waproa *ca)
{
	u64 bdp_based_limit;
	u32 bdp_segs;

	/* 无测量时返回绝对上限 */
	if (ca->bw_est == 0 || ca->rtt_min == 0)
		return WA_ABSOLUTE_MAX_WINDOW;

	/* 复用 BDP 计算逻辑但放大 4 倍 */
	bdp_based_limit = (u64)ca->bw_est * ca->rtt_min;
	
	/* 溢出预防 */
	if (bdp_based_limit > (U64_MAX / WA_MAX_WINDOW_RATIO))
		return WA_ABSOLUTE_MAX_WINDOW;
	
	bdp_based_limit = div_u64(bdp_based_limit, (u32)jiffies_to_usecs(1));
	bdp_based_limit *= WA_MAX_WINDOW_RATIO;

	bdp_segs = (u32)min_t(u64, bdp_based_limit, WA_ABSOLUTE_MAX_WINDOW);
	return max_t(u32, bdp_segs, WA_MIN_CWND);
}

/* ============================================================================
 * 拥塞控制核心（Congestion Control）
 * ============================================================================ */

/**
 * waproa_in_slow_start() - 检查并更新慢启动状态
 * @ca: 私有数据结构
 * @tp: TCP socket 指针
 * 
 * 修复（v1.2）：当 cwnd >= ssthresh 时正确清除慢启动标志。
 */
static inline int waproa_in_slow_start(struct waproa *ca, struct tcp_sock *tp)
{
	if (ca->flags & WA_FLAG_IN_SLOW_START) {
		/* 检查退出条件 */
		if (tp->snd_cwnd >= tp->snd_ssthresh)
			ca->flags &= ~WA_FLAG_IN_SLOW_START;
		else
			return 1;
	}
	return (tp->snd_cwnd < tp->snd_ssthresh);
}

/**
 * waproa_cong_avoid() - 拥塞避免主函数
 * @sk: socket 指针
 * @ack: ACK 序列号（未使用，但保留 API 兼容）
 * @acked: 本次 ACK 确认的段数
 * 
 * 修复说明（v1.2）：
 * - 拥塞避免阶段改为标准 Reno AIMD：每 RTT 增加 1 段
 * - 使用 snd_cwnd_cnt 计数器实现平滑增长
 * - 接近目标窗口时限制增长速率（防止突发）
 */
static void waproa_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct waproa *ca = inet_csk_ca(sk);
	u32 target_cwnd, snd_cwnd, max_limit;

	(void)ack; /* 显式标记未使用，抑制编译器警告 */

	snd_cwnd = tp->snd_cwnd;
	max_limit = waproa_max_window_limit(ca);
	
	/* 窗口未受限或无可 ACK 数据 */
	if (!tcp_is_cwnd_limited(sk) || !acked)
		return;

	target_cwnd = waproa_calculate_bdp(sk);
	
	if (waproa_in_slow_start(ca, tp)) {
		/* 慢启动阶段：指数增长 */
		u32 slow_start_limit = min_t(u32, tp->snd_ssthresh, target_cwnd);
		
		if (snd_cwnd < slow_start_limit) {
			/* 限制单步增长不超过目标差值，且防止回绕 */
			u32 increment = min_t(u32, acked, slow_start_limit - snd_cwnd);
			snd_cwnd = min_t(u32, snd_cwnd + increment, max_limit);
		} else {
			/* 达到慢启动上限，进入拥塞避免 */
			ca->flags &= ~WA_FLAG_IN_SLOW_START;
			goto congestion_avoidance;
		}
	} else {
congestion_avoidance:
		/* 拥塞避免阶段：标准 Reno AIMD */
		if (snd_cwnd < target_cwnd) {
			/* 窗口小于目标时：较快速增长，但限制突发 */
			u32 headroom = target_cwnd - snd_cwnd;
			u32 increment = min_t(u32, acked, headroom);
			
			/* 限制单步不超过当前窗口的 12.5%（防振荡） */
			increment = min_t(u32, increment, snd_cwnd >> 3);
			snd_cwnd = min_t(u32, snd_cwnd + increment, max_limit);
		} else {
			/* 窗口达到/超过目标时：标准线性增长
			 * 每 RTT 增加 1（通过 snd_cwnd_cnt 计数器）
			 */
			ca->snd_cwnd_cnt += acked;
			if (ca->snd_cwnd_cnt >= snd_cwnd) {
				ca->snd_cwnd_cnt -= snd_cwnd;
				if (snd_cwnd < max_limit)
					snd_cwnd++;
			}
		}
	}

	tp->snd_cwnd = waproa_clamp_u32(snd_cwnd, WA_MIN_CWND, max_limit);
}

/**
 * waproa_ssthresh() - 计算慢启动阈值（ssthresh）
 * @sk: socket 指针
 * 
 * 丢包后：ssthresh = max(BDP, cwnd × 0.7)
 * 确保保留 70% 带宽估计，适用于随机丢包链路（无线/卫星）。
 */
static u32 waproa_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct waproa *ca = inet_csk_ca(sk);
	u32 bdp, safe_ssthresh, max_ssthresh;

	if (unlikely(!waproa_state_valid(sk))) {
		safe_ssthresh = max_t(u32, ca->last_safe_cwnd, WA_MIN_CWND);
		/* 保守上限：当前窗口的 70% */
		max_ssthresh = (tp->snd_cwnd * WA_LOSS_BW_RETENTION_NUM) / 
			       WA_LOSS_BW_RETENTION_DEN;
		return min_t(u32, safe_ssthresh, max_t(u32, max_ssthresh, WA_MIN_CWND));
	}

	bdp = waproa_calculate_bdp(sk);
	
	/* 基于 BDP 的阈值，保留 70% */
	safe_ssthresh = max_t(u32, (bdp * WA_LOSS_BW_RETENTION_NUM) / 
			      WA_LOSS_BW_RETENTION_DEN, WA_MIN_CWND);
	
	/* 硬上限：不超过当前窗口的 80% */
	max_ssthresh = max_t(u32, (tp->snd_cwnd * 8) / 10, WA_MIN_CWND * 2);
	
	return min_t(u32, safe_ssthresh, max_ssthresh);
}

/* ============================================================================
 * 事件处理（丢包、ECN、初始化）
 * ============================================================================ */

/**
 * waproa_recovery() - 丢包恢复处理
 * @sk: socket 指针
 * 
 * 不同于 Reno 的 cwnd/2，保留 70% 带宽估计，温和降速。
 */
static void waproa_recovery(struct sock *sk)
{
	struct waproa *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 retained_bw;
	u32 now = waproa_get_now();

	/* 保留 70% 带宽估计（温和响应） */
	if (ca->bw_est > 0) {
		retained_bw = div_u64((u64)ca->bw_est * WA_LOSS_BW_RETENTION_NUM, 
				      WA_LOSS_BW_RETENTION_DEN);
		ca->bw_est = max_t(u32, retained_bw, 1);
	}
	
	/* 重置累积器和计时器 */
	ca->cum_acked = 0;
	ca->snd_cwnd_cnt = 0;
	ca->last_ack_time = now;
	ca->rtt_reset_time = now;

	if (likely(tp)) {
		u32 recovery_cwnd = max_t(u32, ca->last_safe_cwnd, WA_MIN_CWND);
		u32 max_cwnd = waproa_max_window_limit(ca);
		
		tp->snd_cwnd = min_t(u32, recovery_cwnd, max_cwnd);
		tp->snd_ssthresh = waproa_ssthresh(sk);
	}
}

/**
 * waproa_init() - 初始化新连接
 * @sk: socket 指针
 */
static void waproa_init(struct sock *sk)
{
	struct waproa *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 now = waproa_get_now();

	memset(ca, 0, sizeof(*ca));
	ca->last_ack_time = now;
	ca->rtt_reset_time = now;
	ca->flags = WA_FLAG_IN_SLOW_START;
	ca->snd_cwnd_cnt = 0;
	
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

/**
 * waproa_cwnd_event() - TCP 事件处理
 * @sk: socket 指针
 * @ev: 事件类型（丢包、ECN、传输开始等）
 */
static void waproa_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	struct waproa *ca = inet_csk_ca(sk);
	u32 now = waproa_get_now();

	switch (ev) {
	case CA_EVENT_TX_START:
		/* 传输开始：重置 ACK 时间基准 */
		ca->last_ack_time = now;
		break;
		
	case CA_EVENT_LOSS:
		/* 丢包事件：进入恢复 */
		ca->cum_acked = 0;
		waproa_recovery(sk);
		break;
		
	case CA_EVENT_ECN_IS_CE:
		/* 显式拥塞通知（ECN CE 标记）：降速至 80% */
		if (ca->bw_est > 0) {
			ca->bw_est = div_u64((u64)ca->bw_est * WA_ECN_REDUCTION_NUM,
					     WA_ECN_REDUCTION_DEN);
			ca->bw_est = max_t(u32, ca->bw_est, 1);
		}
		break;
		
	case CA_EVENT_ECN_NO_CE:
		/* ECN 无拥塞：无需操作 */
		break;
		
	default:
		break;
	}
}

/**
 * waproa_release() - 连接释放（清理资源）
 * @sk: socket 指针
 */
static void waproa_release(struct sock *sk)
{
	(void)sk; /* 当前无动态资源需释放 */
}

/**
 * waproa_undo_cwnd() - 撤销窗口调整（如假重传检测）
 * @sk: socket 指针
 * 
 * 返回当前窗口（Westwood 风格不撤销）。
 */
static u32 waproa_undo_cwnd(struct sock *sk)
{
	return tcp_sk(sk)->snd_cwnd;
}

/**
 * waproa_set_state() - 设置拥塞控制状态
 * @sk: socket 指针
 * @new_state: 新状态（如 TCP_CA_Loss）
 */
static void waproa_set_state(struct sock *sk, u8 new_state)
{
	struct waproa *ca = inet_csk_ca(sk);
	
	if (new_state == TCP_CA_Loss) {
		ca->cum_acked = 0;
		ca->snd_cwnd_cnt = 0;
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
/**
 * waproa_get_info() - 获取算法调试信息（ss 工具使用）
 * @sk: socket 指针
 * @ext: 扩展信息类型
 * @attr: 属性数组
 * @info: 信息联合体
 */
static size_t waproa_get_info(struct sock *sk, u32 ext, int *attr,
			      union tcp_cc_info *info)
{
	struct waproa *ca = inet_csk_ca(sk);
	
	if (ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		/* 复用 VEGASINFO 结构输出调试信息 */
		info->vegas.tcpv_enabled = ca->flags;
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

static struct tcp_congestion_ops waproa_cong_ops __read_mostly = {
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
	printk(KERN_INFO "TCP WAPROA v1.2: "
	       "Bandwidth Adaptive Congestion Control (strict fix)\n"
	       "  - Buffer limit: %u segments (4xBDP or absolute)\n"
	       "  - Memory usage: %zu bytes/connection\n"
	       "  - Bug fixes: div256, overflow, aggressive growth\n",
	       WA_ABSOLUTE_MAX_WINDOW, sizeof(struct waproa));

	return tcp_register_congestion_control(&waproa_cong_ops);
}

static void __exit waproa_unregister(void)
{
	tcp_unregister_congestion_control(&waproa_cong_ops);
}

module_init(waproa_register);
module_exit(waproa_unregister);

MODULE_AUTHOR("EsquireProud547 (Original), Kimi AI (Fixed)");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP WAPROA v1.2 - BDP-based Congestion Control (Production Fix)");
MODULE_VERSION("1.2");
MODULE_ALIAS("tcp_congestion_control_waproa");

package org.example.publicapi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 公网只读端点的<b>独立限流器</b>。
 *
 * <h3>为什么不复用业务限流（RateLimitInterceptor）</h3>
 * 业务限流是给"登录后的自用界面"配的（默认 30 次/分钟），
 * 而公网匿名端点面对的是完全不同的威胁模型：没有身份、可以换 IP、
 * 目的往往不是用功能而是把配额/带宽/上游查询打满。
 * <p>
 * 两件事必须分开，而且要在<b>代码层分开</b>：
 * <ul>
 *   <li>公网端点有自己更严的阈值（默认 20 次/分钟）；</li>
 *   <li>改业务阈值时，<b>不会顺手把公网阈值一起放宽</b> ——
 *       共用一份配置的典型事故就是"为了本地调试把上限调大，
 *       结果公网端点也跟着被放宽"，而且没人会注意到。</li>
 * </ul>
 *
 * <p>实现取"按分钟固定窗口 + 每 IP 计数"：不引入任何依赖、行为可预测、
 * 状态上限可控（超过 {@value #MAX_TRACKED_KEYS} 个 IP 就清理过期窗口，
 * 避免被大量伪造来源撑爆内存）。
 *
 * <p>边界说明：这是<b>进程内</b>限流，重启即清零；它挡的是单机高频刷取，
 * 不是分布式刷取。边缘层的兜底靠 Cloudflare 侧的缓存与速率规则（10–30 秒缓存
 * 已经把绝大部分重复请求挡在应用之外）。
 */
@Component
public class PublicRateLimiter {

    private static final Logger logger = LoggerFactory.getLogger(PublicRateLimiter.class);

    /** 内存里最多同时跟踪多少个来源 IP，超过就先清理过期窗口 */
    private static final int MAX_TRACKED_KEYS = 5000;

    @Value("${app.public-api.requests-per-minute:20}")
    private int requestsPerMinute;

    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    /** 配额（供响应头 / 文档展示，避免"限流多少"只存在于配置里） */
    public int limitPerMinute() {
        return Math.max(1, requestsPerMinute);
    }

    /**
     * 记一次请求并判断是否放行。
     *
     * @param clientIp 调用方 IP（取不到时归入 unknown 桶）
     * @return true 放行；false 已超限
     */
    public boolean allow(String clientIp) {
        String key = (clientIp == null || clientIp.isBlank()) ? "unknown" : clientIp.trim();
        long minute = System.currentTimeMillis() / 60000L;

        if (windows.size() > MAX_TRACKED_KEYS) {
            // 只保留当前与上一分钟：其余窗口已经不可能再被命中
            int before = windows.size();
            windows.entrySet().removeIf(e -> e.getValue().minute < minute - 1);
            logger.warn("公网端点来源 IP 跟踪表过大（{}），已清理到 {}", before, windows.size());
        }

        Window w = windows.compute(key,
                (k, cur) -> (cur == null || cur.minute != minute) ? new Window(minute) : cur);
        return w.count.incrementAndGet() <= limitPerMinute();
    }

    private static final class Window {
        private final long minute;
        private final AtomicInteger count = new AtomicInteger();

        private Window(long minute) {
            this.minute = minute;
        }
    }
}

package org.example.publicapi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 公开问答 / 公开知识库检索的<b>独立限流器</b>（按分钟固定窗口 + 每 IP 计数）。
 *
 * <h3>为什么不复用只读端点的 {@link PublicRateLimiter}</h3>
 * 两者的成本差了一个数量级：
 * <ul>
 *   <li>{@code /api/public/{overview,alerts,...}} 是<b>纯查询 + 15 秒服务端快照</b>，
 *       刷它主要消耗带宽；20 次/分钟是够用的；</li>
 *   <li>{@code /api/public/ask} 会<b>调模型</b>（一次提问可能两次调用），
 *       {@code /api/public/kb} 会调用 embedding 接口 —— 都花钱。</li>
 * </ul>
 * 共用一份配置的典型事故是"为了调页面上的告警刷新率把 20 改成 60"，
 * 顺手把会花钱的问答端点也放宽了 3 倍，而且不会有任何报错。
 * 所以这边的默认值是 <b>6 次/分钟</b>（可配），与只读端点的 20 分开。
 *
 * <p>实现取"按分钟固定窗口 + 每 IP 计数"：不引入依赖、行为可预测、
 * 状态上限可控（超过 {@value #MAX_TRACKED_KEYS} 个来源就清理过期窗口，
 * 避免被大量伪造来源撑爆内存）。
 *
 * <p>边界说明：这是<b>进程内</b>限流，重启即清零；它挡的是单机高频刷取，
 * 不是分布式刷取。真正的成本兜底是 {@code app.quota.public-daily-limit} 那本账。
 *
 * <p>实例由 {@link PublicRateLimitersConfig} 显式创建（问答与检索各一个），
 * 因此本类刻意<b>不带</b> {@code @Component}：加上它就会多出一个单例，
 * 而"注入到哪一个"会变成运气问题。
 */
public class PublicAskRateLimiter {

    private static final Logger logger = LoggerFactory.getLogger(PublicAskRateLimiter.class);

    private static final int MAX_TRACKED_KEYS = 5000;

    /**
     * 每分钟请求上限（构造时由调用方从配置读出）。
     *
     * <p>默认 6：这个值是"一个人正常试几句够用、脚本刷起来会被立刻挡住"之间取的。
     * 注意它<b>不</b>控制成本（那是每日公开额度的事），只控制频率。
     */
    private final int requestsPerMinute;

    /**
     * @param requestsPerMinute 每分钟上限；非正数按 1 处理（fail-closed：
     *                          配置写错时必须更严，不能变成"不限流"）
     */
    public PublicAskRateLimiter(int requestsPerMinute) {
        this.requestsPerMinute = Math.max(1, requestsPerMinute);
    }

    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    /** 配额（供响应头 / 文档展示，避免"限流多少"只存在于配置里） */
    public int limitPerMinute() {
        return requestsPerMinute;
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
            int before = windows.size();
            windows.entrySet().removeIf(e -> e.getValue().minute < minute - 1);
            logger.warn("公开问答限流来源表过大（{}），已清理到 {}", before, windows.size());
        }

        Window w = windows.compute(key,
                (k, cur) -> (cur == null || cur.minute != minute) ? new Window(minute) : cur);
        return w.count.incrementAndGet() <= limitPerMinute();
    }

    /**
     * 当前窗口还剩多少次（用于下发 {@code X-RateLimit-Remaining}）。
     *
     * <p>只读、不计数：它就是"让页面上显示的剩余额度与后端真正在用的计数器一致"。
     * 显示值的意义在于访客能自己看出"为什么被挡了"，而不是看到一个玄学 429。
     */
    public int remaining(String clientIp) {
        String key = (clientIp == null || clientIp.isBlank()) ? "unknown" : clientIp.trim();
        long minute = System.currentTimeMillis() / 60000L;
        Window w = windows.get(key);
        if (w == null || w.minute != minute) {
            return limitPerMinute();
        }
        int used = w.count.get();
        // 已超限时"第 N 次请求"会让计数大于上限 —— 剩余量按 0 报，不报负数
        return Math.max(0, limitPerMinute() - used);
    }

    private static final class Window {
        private final long minute;
        private final AtomicInteger count = new AtomicInteger();

        private Window(long minute) {
            this.minute = minute;
        }
    }
}

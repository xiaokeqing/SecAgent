package org.example.llm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * 出站调用的统一守卫：<b>有界等待 + 熔断冷却 + 半开自愈</b>。
 *
 * <h3>为什么需要它（实测教训，不是设计洁癖）</h3>
 * 连续两个外部调用会无限/超长等待：
 * <ul>
 *   <li>DashScope chat：底层 readTimeout 180 秒 → 断网时 /api/chat 挂满 3 分钟、客户端收不到任何响应；</li>
 *   <li>DashScope embedding：<b>完全没有超时</b> → 断网时研判请求挂死，线程被一直占着。</li>
 * </ul>
 * 共性根因是"出站调用没有统一规范"。所以这里把三件事做成一处：
 * <ol>
 *   <li><b>有界等待</b>：不管底层 SDK 自己等多久，调用方最多等 timeoutMs；</li>
 *   <li><b>熔断冷却</b>：一次超时后该依赖进入冷却期，期间<b>立即失败</b>，
 *       避免一次请求里每个调用点各等一遍超时（实测过：15s+15s+15s 叠加）；</li>
 *   <li><b>半开自愈</b>：冷却结束后放一个探测通过，成功即闭合 —— 防"网络抖一下永久不可用"。</li>
 * </ol>
 *
 * <p>线程池为守护线程且容量有界：上游再有界，也不能让卡住的调用把线程堆满
 * （2C2G 小机上线程耗尽会导致连健康检查都不响应）。
 */
@Component
public class OutboundGuard {

    private static final Logger logger = LoggerFactory.getLogger(OutboundGuard.class);

    /** 默认冷却时长（毫秒）；可按依赖覆盖 */
    @Value("${app.outbound.default-cooldown-ms:60000}")
    private long defaultCooldownMs;

    private final Map<String, Long> cooldownUntil = new ConcurrentHashMap<>();

    /** 有界线程池：卡住的调用不会无限滋生线程 */
    private static final ExecutorService POOL = Executors.newFixedThreadPool(8, r -> {
        Thread t = new Thread(r, "outbound-call");
        t.setDaemon(true);
        return t;
    });

    /** 每个依赖的在飞上限：防止卡住的调用无限堆积（小机雪崩路径） */
    @Value("${app.outbound.max-inflight-per-dependency:2}")
    private int maxInflightPerDependency;

    private final Map<String, java.util.concurrent.Semaphore> bulkheads = new ConcurrentHashMap<>();

    private java.util.concurrent.Semaphore bulkhead(String key) {
        return bulkheads.computeIfAbsent(key, k -> new java.util.concurrent.Semaphore(maxInflightPerDependency));
    }

    /** 该依赖当前占用名额（用于自检日志与页面提示） */
    public int inFlight(String key) {
        java.util.concurrent.Semaphore s = bulkheads.get(key);
        return s == null ? 0 : maxInflightPerDependency - s.availablePermits();
    }

    /** 该依赖是否处于冷却期（熔断 open） */
    public boolean coolingDown(String key) {
        Long until = cooldownUntil.get(key);
        return until != null && System.currentTimeMillis() < until;
    }

    /** 剩余冷却毫秒数（0 表示未冷却），用于日志与页面提示 */
    public long cooldownRemainingMs(String key) {
        Long until = cooldownUntil.get(key);
        long now = System.currentTimeMillis();
        return (until == null || until <= now) ? 0 : until - now;
    }

    /** 手动清除冷却（自愈探测成功后调用） */
    public void clearCooldown(String key) {
        cooldownUntil.remove(key);
    }

    /**
     * 有界调用。
     *
     * @param key       依赖标识（如 {@code dashscope-embedding}），冷却按它隔离
     * @param timeoutMs 本次最多等多久
     * @param call      真正的调用
     * @throws Exception 超时抛 {@code IllegalStateException}（信息里带"超时"），
     *                   冷却期抛 {@code IllegalStateException}（信息里带"冷却"）；两种都属"依赖不可用"
     */
    public <T> T call(String key, long timeoutMs, Callable<T> call) throws Exception {
        long remain = cooldownRemainingMs(key);
        if (remain > 0) {
            throw new IllegalStateException("依赖 " + key + " 处于冷却期（剩余 " + remain + " ms），直接 fail-closed");
        }
        Future<T> future = POOL.submit(call);
        java.util.concurrent.Semaphore sem = bulkhead(key);
        if (!sem.tryAcquire()) {
            // 该依赖在飞已满：直接失败，不再排队堆积（队列堆积 = 雪崩前兆）
            future.cancel(true);
            throw new IllegalStateException("依赖 " + key + " 并发已满（上限 " + maxInflightPerDependency + "），直接 fail-closed");
        }
        try {
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            openCircuit(key, defaultCooldownMs);
            logger.warn("出站调用超时（依赖={}，{} ms），按 fail-closed 终止；进入 {} ms 冷却",
                    key, timeoutMs, defaultCooldownMs);
            throw new IllegalStateException("依赖 " + key + " 调用超时（" + timeoutMs + " ms）：已终止");
        } catch (java.util.concurrent.ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception ex) {
                throw ex;
            }
            throw new IllegalStateException("依赖 " + key + " 调用失败: " + cause);
        } finally {
            sem.release();
        }
    }

    /** 打开熔断（可指定冷却时长） */
    public void openCircuit(String key, long cooldownMs) {
        cooldownUntil.put(key, System.currentTimeMillis() + cooldownMs);
    }

    /** 依赖不可用的统一判定（超时与冷却期都算） */
    public static boolean isUnavailable(Throwable e) {
        if (e == null) {
            return false;
        }
        String m = String.valueOf(e.getMessage());
        return e instanceof IllegalStateException
                || m.contains("超时") || m.contains("冷却") || m.contains("不可用");
    }
}

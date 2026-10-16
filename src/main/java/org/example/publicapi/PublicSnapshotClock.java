package org.example.publicapi;

/**
 * 公网数据「快照时刻」的**请求内**记录点（包内可见，不是对外契约的一部分）。
 *
 * <h3>它解决什么</h3>
 * 缓存别名路径（{@code /api/public/<name>.js}）必须在响应体里如实告诉页面
 * <b>"这份数据的真实生成时刻"</b> —— 否则一旦被 Cloudflare / 浏览器缓存住，
 * 页面上的"刚刚同步"就会假装更新（违反站主红线 D4：不许造假、上限/截断/时间都要如实）。
 *
 * <p>而"这份数据是什么时候生成的"只有两处知道：
 * <ul>
 *   <li>走 {@link PublicApiController.Snapshot} 的端点 ⇒ 快照实际加载的那一刻；</li>
 *   <li>不走快照的端点（如 {@code /kb}：它体内有秒级的 {@code generatedAt}）⇒ 本次请求处理的那一刻。</li>
 * </ul>
 * 两者都在<b>同一个请求线程</b>上发生，所以用一个 {@link ThreadLocal} 记录、由
 * {@link PublicApiController#ok(Map, jakarta.servlet.http.HttpServletResponse)} 读取即可，
 * 不需要改任何端点的签名。
 *
 * <h3>时序（谁清、谁写、谁读）</h3>
 * <ol>
 *   <li>{@link PublicCorsInterceptor#preHandle} 在进入控制器前 <b>clear + mark(now)</b>
 *       —— 既清掉上一个请求在线程池里留下的值，又给"不走快照"的端点一个诚实的默认值；</li>
 *   <li>{@code Snapshot.get(...)} 命中或刷新时 <b>覆盖</b> 成快照的真实加载时刻；</li>
 *   <li>{@code ok(...)} 只在<b>别名路径</b>上读取（读完即 clear）。</li>
 * </ol>
 * 全链路只在 {@code /api/public/**} 上使用；旧路径既不读也不写响应体，行为逐字节不变。
 */
final class PublicSnapshotClock {

    private PublicSnapshotClock() {
    }

    private static final ThreadLocal<Long> AT_EPOCH_MILLIS = new ThreadLocal<>();

    /** 记录"这份数据的生成时刻"（毫秒纪元） */
    static void mark(long epochMillis) {
        AT_EPOCH_MILLIS.set(epochMillis);
    }

    /** 读取当前请求已记录的时刻；没有记录返回 {@code null}（调用方按"就是现在"处理） */
    static Long peek() {
        return AT_EPOCH_MILLIS.get();
    }

    /** 清空（请求开始与读取之后各一次，避免线程池复用导致串味） */
    static void clear() {
        AT_EPOCH_MILLIS.remove();
    }
}

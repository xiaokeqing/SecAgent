package org.example.config;

/**
 * 出站客户端的<b>统一超时生效值</b>（单一事实来源）。
 *
 * <h3>为什么要有这个类（而不是各客户端各写一套 @Value）</h3>
 * 实测事故：DashScope chat 的 read timeout 是 180 秒、embedding 完全没有超时，
 * 断网时请求挂满 3 分钟、线程被一直占住；而 Wazuh 管理 API / indexer / SSH
 * 这几条出站链路当时连"有没有超时"都说不清 —— 因为它们各自读不同的配置项，
 * 事后想核对"实际生效的是几秒"只能逐个翻代码。
 *
 * <p>所以这里把 connect / read / call 三项收成一处：
 * <ul>
 *   <li>{@code connect} 必须短（3s）—— 实测阻断出网时卡住的是 TCP 建连，
 *       而建连对线程中断无反应，长超时会让线程长时间占住；</li>
 *   <li>{@code read} 适中（12s）—— 等对端响应的时间；</li>
 *   <li>{@code call} 封顶（15s）—— 兜住"读超时之上还有重试/重定向"，
 *       且必须小于入口预算（/api/chat 25s、公开问答 20s），否则入口先被拖死。</li>
 * </ul>
 *
 * <p>值是<b>不可变的</b>：客户端拿到后行为就不会中途变化，自检打印的也就是运行期真正生效的值。
 */
public final class OutboundTimeouts {

    /** 建连超时默认值（毫秒）：必须短，详见类注释 */
    public static final long DEFAULT_CONNECT_MS = 3000L;

    /** 读/写超时默认值（毫秒） */
    public static final long DEFAULT_READ_MS = 12000L;

    /** 单次调用总预算默认值（毫秒）：不得超过入口预算 */
    public static final long DEFAULT_CALL_MS = 15000L;

    private final long connectTimeoutMs;
    private final long readTimeoutMs;
    private final long callTimeoutMs;

    public OutboundTimeouts(long connectTimeoutMs, long readTimeoutMs, long callTimeoutMs) {
        // 兜底：配置写错（0 或负数）时不能变成"永不超时" —— 那正是本项要修的问题本身
        this.connectTimeoutMs = connectTimeoutMs > 0 ? connectTimeoutMs : DEFAULT_CONNECT_MS;
        this.readTimeoutMs = readTimeoutMs > 0 ? readTimeoutMs : DEFAULT_READ_MS;
        this.callTimeoutMs = callTimeoutMs > 0 ? callTimeoutMs : DEFAULT_CALL_MS;
    }

    /** 默认值组合（3s / 12s / 15s），供单测与无 Spring 环境的降级使用 */
    public static OutboundTimeouts defaults() {
        return new OutboundTimeouts(DEFAULT_CONNECT_MS, DEFAULT_READ_MS, DEFAULT_CALL_MS);
    }

    public long getConnectTimeoutMs() {
        return connectTimeoutMs;
    }

    public long getReadTimeoutMs() {
        return readTimeoutMs;
    }

    public long getCallTimeoutMs() {
        return callTimeoutMs;
    }

    /** 便于日志与自检：{@code connect=3000ms read=12000ms call=15000ms} */
    public String describe() {
        return "connect=" + connectTimeoutMs + "ms read=" + readTimeoutMs + "ms call=" + callTimeoutMs + "ms";
    }

    @Override
    public String toString() {
        return describe();
    }
}

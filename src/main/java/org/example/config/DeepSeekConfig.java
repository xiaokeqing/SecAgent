package org.example.config;

/**
 * DeepSeek（OpenAI 兼容）对话模型的出站配置 —— <b>不可变值对象</b>。
 *
 * <h3>为什么它不是 {@code @Configuration}（这里是曾经真的起不来的一处）</h3>
 * 本类同时被两件事用：① 作为"真正生效的超时"被 provider 注入；② 作为<b>值对象</b>
 * 被单测直接 {@code new DeepSeekConfig(1000, 500, 1500)} 构造。
 * 如果把它自己也标成 {@code @Configuration} 并在里面用 {@code @Bean} 产出同类型，
 * Spring 会拿到的 Bean 定义名与类型都撞车，实测启动即失败：
 * <pre>
 * BeanDefinitionStoreException: Invalid bean definition with name 'deepSeekConfig'
 * defined in org.example.config.DeepSeekConfig:
 * &#64;Bean definition illegally overridden by existing bean definition
 * </pre>
 * 它在<b>编译期与全部单测里都是绿的</b>（本仓库没有全量 {@code @SpringBootTest}，
 * 而 {@code SpringBeanConstructorTest} 只扫 {@code @Component/@Service/...}、不扫
 * {@code @Configuration}），只有容器启动才暴露 —— 所以装配点被挪到
 * {@link DeepSeekOutboundConfig}：<b>装配的是别的类，就不会和自己撞车</b>。
 * 形状与 {@link OutboundConfig} → {@link OutboundTimeouts} 一致。
 *
 * <h3>为什么单独一个类，而不是在 provider 里散落 {@code @Value}</h3>
 * 与 {@link DashScopeConfig} 同一个理由：启动自检要打印的值必须来自
 * <b>真正被用来构造客户端</b>的那个对象。散落 {@code @Value} 时，
 * "配置改了但客户端没拿到"会打印出骗人的值 —— 这正是本项目踩过的坑。
 *
 * <h3>为什么要做「不可放大」的上限钳制</h3>
 * 出站超时矩阵是有预算的：connect 3s / read 12s / call 15s，而 call 必须小于
 * 入口预算（/api/chat 25s、公开问答 20s）。如果有人把 DeepSeek 的超时配成 60s，
 * 结果不是"更宽容"，而是<b>入口先被拖死</b>（客户端早就超时了，线程还占着）。
 * 所以这里只允许<b>收紧</b>：配置值大于默认值就夹回默认值，并在自检里如实打印。
 *
 * <h3>为什么能复用 DashScope 的那组配置项</h3>
 * 没有任何理由让两家供应商的短预算不一样；默认直接引 {@code app.outbound.*}
 * （与 Wazuh / SSH 共用同一组数），需要更短时再用 {@code app.llm.deepseek.*} 覆盖。
 */
public class DeepSeekConfig {

    /**
     * 已生效的建连超时（毫秒）。
     *
     * <p>上游 {@code app.llm.deepseek.connect-timeout-ms} 默认回落
     * {@code app.outbound.connect-timeout-ms}（3s），且被 {@link #MAX_CONNECT_MS} 钳住。
     */
    private final long connectTimeoutMs;

    /** 已生效的读超时（毫秒）；见类注释的"可收紧不可放大" */
    private final long readTimeoutMs;

    /** 已生效的单次调用总预算（毫秒） */
    private final long callTimeoutMs;

    /** 上限（= 统一超时矩阵的默认值）：超过它一律夹回，见类注释 */
    public static final long MAX_CONNECT_MS = OutboundTimeouts.DEFAULT_CONNECT_MS;

    /** 上限：读超时 */
    public static final long MAX_READ_MS = OutboundTimeouts.DEFAULT_READ_MS;

    /** 上限：单次调用总预算（必须小于入口预算） */
    public static final long MAX_CALL_MS = OutboundTimeouts.DEFAULT_CALL_MS;

    public DeepSeekConfig(long connectTimeoutMs, long readTimeoutMs, long callTimeoutMs) {
        // 三级钳制：① 非法值（0/负数）→ 默认值；② 超过上限 → 上限；③ 否则用配置值。
        // 第二条是"只许收紧不许放大"的落点：它不能靠约定，必须靠代码。
        this.connectTimeoutMs = clamp(connectTimeoutMs, MAX_CONNECT_MS);
        this.readTimeoutMs = clamp(readTimeoutMs, MAX_READ_MS);
        this.callTimeoutMs = clamp(callTimeoutMs, MAX_CALL_MS);
    }

    private static long clamp(long configured, long max) {
        if (configured <= 0) {
            return max;
        }
        return Math.min(configured, max);
    }

    /** 全部取默认值（3s / 12s / 15s），供单测与无 Spring 环境使用 */
    public static DeepSeekConfig defaults() {
        return new DeepSeekConfig(MAX_CONNECT_MS, MAX_READ_MS, MAX_CALL_MS);
    }

    public long getEffectiveConnectTimeoutMs() {
        return connectTimeoutMs;
    }

    public long getEffectiveReadTimeoutMs() {
        return readTimeoutMs;
    }

    public long getEffectiveCallTimeoutMs() {
        return callTimeoutMs;
    }

    /** 供启动自检与统一守卫使用：与 {@code OutboundTimeouts} 同一形状 */
    public OutboundTimeouts toOutboundTimeouts() {
        return new OutboundTimeouts(connectTimeoutMs, readTimeoutMs, callTimeoutMs);
    }
}

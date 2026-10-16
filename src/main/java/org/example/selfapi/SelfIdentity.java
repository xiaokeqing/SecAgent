package org.example.selfapi;

/**
 * 自用身份（{@code X-User-Token}）的请求上下文标注。
 *
 * <h3>为什么不能复用 {@code EvalIdentity} 的标注位</h3>
 * {@code EvalIdentity} 里已经有「评测 / 公开演示」两个互斥标注，配额分派与 RESPONDER 分叉都读它。
 * 自用池是<b>第四个</b>身份，它的语义与前两个都不同（额度软上限、允许完整链路），
 * 硬塞进现有两个 boolean 会让"两个都置上时听谁的"变成没有答案的问题 ——
 * 而这类歧义不会报错，只会静默记错账。
 *
 * <h3>为什么必须是 InheritableThreadLocal</h3>
 * 编排跑在 {@code OrchestrationService.ORCHESTRATOR_POOL} 上，模型出口也在那个线程里，
 * 那里拿不到 {@code HttpServletRequest}。普通 {@code ThreadLocal} 传不过去，
 * 表现是"自用请求被当成普通用户"（不报错、只是记错账）。
 *
 * <p>与 {@code EvalIdentity} 同一形状：父线程与子线程共享<b>同一个可变载体</b>，
 * 池任务入口显式重设、{@code finally} 里显式清理，两层都清。
 * 调用方（拦截器与控制器）必须在 {@code finally} 里调 {@link #end()}。
 */
public final class SelfIdentity {

    private SelfIdentity() {
    }

    /** 审计/会话里的固定 actor 名（与 eval-runner 同一口径：便于打标与隔离） */
    public static final String USERNAME = "self-owner";

    private static final ThreadLocal<Marker> MARKER = new InheritableThreadLocal<>() {
        @Override
        protected Marker initialValue() {
            return new Marker();
        }
    };

    /**
     * 可变标注载体。
     *
     * <p>线程池复用线程时，{@code InheritableThreadLocal} 只在<b>线程创建</b>那一刻继承。
     * 用可变载体（而不是 {@code ThreadLocal<Boolean>}）能让父线程的清理解除子线程看到的残留，
     * 见 {@code EvalIdentity.Marker} 的同类说明。
     */
    private static final class Marker {
        volatile Boolean selfRequest;

        void clear() {
            this.selfRequest = null;
        }
    }

    private static Marker marker() {
        return MARKER.get();
    }

    /** 当前线程是否在处理自用请求（{@code X-User-Token} 命中）。 */
    public static boolean isSelfRequest() {
        return Boolean.TRUE.equals(marker().selfRequest);
    }

    /** 标注"当前线程正在处理一个自用请求"。必须配 {@link #end()}。 */
    public static void markSelfRequest() {
        marker().selfRequest = Boolean.TRUE;
    }

    /** 显式标注"不是自用请求"（不留 null 的歧义） */
    public static void markNonSelfRequest() {
        marker().selfRequest = Boolean.FALSE;
    }

    /** 清除自用标注（成功与失败路径都要调） */
    public static void end() {
        marker().clear();
    }
}

package org.example.security;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

/**
 * 评测身份（EVAL）的识别与请求上下文。
 *
 * <h3>它解决的真问题</h3>
 * 改造前评测脚本用<b>管理员账号密码登录</b>跑卷：一次两卷约 50 次模型调用，
 * 而用户日额度就是 50 —— 跑完评测当天所有真实用户都被"额度已用完"挡住。
 * 想给评测放宽额度，就只能放宽所有人的额度。
 *
 * <p>现在评测走<b>独立凭据</b> {@code app.eval.token}（环境变量 {@code APP_EVAL_TOKEN}）：
 * <ul>
 *   <li>识别为 {@link Role#EVAL}，<b>只允许 POST /api/chat</b>（评测所需），
 *       任何处置/审批/策略/数据写入端点一律 403；</li>
 *   <li>模型调用走<b>独立计数器</b>与独立持久化文件，和用户额度互不挤占；</li>
 *   <li>该身份下的 RESPONDER 一律走"模拟"路径，<b>绝不真下发</b>工具动作；</li>
 *   <li>请求可带 {@code evalRunId}（评测脚本的 runId），写入会话/评测审计，
 *       使评测流量可打标、可隔离、可追溯。</li>
 * </ul>
 *
 * <h3>为什么用 ThreadLocal 传"当前是不是评测请求"</h3>
 * 配额检查发生在模型出口 {@code DashScopeLlmProvider.generate()}，它在
 * 编排线程池里被调用 —— 那里拿不到 {@code HttpServletRequest}，
 * 而"配额按调用来源分派"必须精确到<b>这一次调用</b>（用全局开关会导致
 * 评测把用户额度刷掉，或者反过来）。因此用显式的作用域上下文：
 * {@code ChatController} 在编排前 {@link #beginEvalRequest}，
 * 编排任务在 {@code finally} 里 {@link #endEvalRequest}，绝不跨请求残留。
 *
 * <p><b>必须是 InheritableThreadLocal（实测踩过）</b>：{@code /api/chat} 的编排跑在
 * {@code ChatController.ORCHESTRATOR_POOL} 这类线程池上，模型出口也在那个线程里。
 * 用普通 {@link ThreadLocal} 时子线程看不到父线程的标注 ——
 * 表现是"评测请求被识别了、却没走模拟路径、还记到了用户额度上"，
 * 而且不会报任何错。继承式 ThreadLocal 让子线程创建时拿到父线程的值，
 * 再加上任务入口的显式 set，两层保证。
 */
@Component
public class EvalIdentity {

    private static final Logger logger = LoggerFactory.getLogger(EvalIdentity.class);

    /** 评测身份的固定用户名（写入会话/审计 actor，便于打标与隔离） */
    public static final String USERNAME = "eval-runner";

    /** 审计记录里标记评测流量的前缀 —— 公开端点据此过滤 */
    public static final String ACTOR_PREFIX = "eval-";

    /** 评测身份唯一允许调用的端点（精确匹配，不做任何前缀推断） */
    public static final String ALLOWED_PATH = "/api/chat";

    /** token 最小长度：比 CredentialGuard.MIN_LENGTH 略宽，避免误伤已有随机 token */
    static final int MIN_TOKEN_LENGTH = 12;

    /**
     * 评测凭据。<b>刻意不设默认值</b>：默认空 → 评测身份关闭。
     * 写死一个默认 token 等于把"评测身份"变成公开的后门。
     */
    @Value("${app.eval.token:}")
    private String token;

    /** 显式开关；false 时即使配了 token 也不启用（便于临时吊销） */
    @Value("${app.eval.enabled:true}")
    private boolean enabled;

    /**
     * 当前请求是否为评测身份。三个值：
     * <ul>
     *   <li>{@code null} —— 未显式标注（非 /api/chat 路径，按普通用户处理）；</li>
     *   <li>{@code Boolean.FALSE} —— 显式标注为普通请求；</li>
     *   <li>{@code Boolean.TRUE} —— 评测请求（走评测额度与模拟处置）。</li>
     * </ul>
     * 用"是否显式标注"区分，而不是默认 false：将来若出现别的编排入口，
     * 没有标注的请求不会被误判成评测流量（宁可算在用户头上，也不能让评测偷偷免费）。
     *
     * <p>继承式：编排/模型调用跑在线程池里，普通 ThreadLocal 传不过去。
     */
    private static final ThreadLocal<Marker> MARKER = new InheritableThreadLocal<Marker>() {
        @Override
        protected Marker initialValue() {
            return new Marker();
        }
    };

    /**
     * 可变的标注载体。
     *
     * <h3>为什么不是一个 <code>ThreadLocal&lt;Boolean&gt;</code></h3>
     * 线程池会复用线程，而<b>继承只发生在线程创建的那一刻</b>：
     * <pre>
     *   请求 A（评测）在某池线程上跑完 → 该线程的 ThreadLocal 里留着 true
     *   请求 B（普通）复用该线程 → 读到残留的 true → 被当成评测请求
     * </pre>
     * 反之，请求 A 清空后，请求 B 在<b>新建</b>的池线程上仍可能从父线程继承到一个
     * 过期的值。两种残留都不会报错，只会让配额记错账、或让评测动作真的下发。
     * <p>
     * 所以这里用"父线程与子线程共享同一个可变载体"：
     * 子线程创建时继承到<b>同一个实例</b>，父线程清除时子线程立刻看到 null，
     * 池任务再在自己的 {@code finally} 里显式清一次 —— 两层都清，才谈得上干净。
     */
    private static final class Marker {
        volatile Boolean evalRequest;
        volatile String runId;

        void clear() {
            this.evalRequest = null;
            this.runId = null;
        }
    }

    /** 当前线程的标注（首次访问时创建，子线程继承父线程的实例） */
    private static Marker marker() {
        return MARKER.get();
    }

    @PostConstruct
    public void init() {
        if (!enabled) {
            logger.info("评测身份：未启用（app.eval.enabled=false），/api/chat 只认登录会话与系统级 API Token");
            return;
        }
        if (token == null || token.isBlank()) {
            logger.info("评测身份：未配置 app.eval.token（APP_EVAL_TOKEN）→ 功能关闭，行为与改造前一致");
            return;
        }
        if (token.trim().length() < MIN_TOKEN_LENGTH) {
            // fail-closed：宁可关闭评测身份，也不接受一个可被猜到的凭据
            logger.warn("评测身份：app.eval.token 长度不足 {} 位 —— 已拒绝启用（评测功能关闭）", MIN_TOKEN_LENGTH);
            return;
        }
        logger.info("评测身份：已启用（独立额度 + 流量打标 + RESPONDER 模拟路径），仅允许 {}", ALLOWED_PATH);
    }

    /** 评测身份是否启用（未配 token / 显式关闭 / token 过短 → false） */
    public boolean enabled() {
        return enabled && token != null && !token.isBlank() && token.trim().length() >= MIN_TOKEN_LENGTH;
    }

    /**
     * 请求是否为<b>评测请求</b>。
     *
     * <p>用于两件事：① 模型配额分派（评测走独立计数器）；
     * ② RESPONDER 是否走模拟路径（评测绝不真封禁）。
     */
    public static boolean isEvalRequest() {
        return Boolean.TRUE.equals(marker().evalRequest);
    }

    /** 当前请求的评测 runId；非评测请求返回 null */
    public static String currentRunId() {
        return marker().runId;
    }

    /**
     * 标注"当前线程正在处理一个评测请求"。必须在 {@code finally} 里配 {@link #endEvalRequest()}，
     * 否则线程池复用会把上一次的评测身份带给下一个用户请求（那等于给普通用户免费额度、
     * 还可能让评测身份的动作真的下发）。
     */
    public static void beginEvalRequest(String runId) {
        Marker m = marker();
        m.evalRequest = Boolean.TRUE;
        m.runId = (runId != null && !runId.isBlank()) ? runId.trim() : null;
    }

    /** 标注"当前线程处理的是普通请求"（显式，不留 null 的歧义） */
    public static void beginUserRequest() {
        Marker m = marker();
        m.evalRequest = Boolean.FALSE;
        m.runId = null;
    }

    /** 清除线程上的评测标注 */
    public static void endEvalRequest() {
        marker().clear();
    }

    /**
     * 请求是否携带<b>有效的</b>评测凭据。
     *
     * <p>比较用定长比较（{@link #constantTimeEquals}），与系统级 API Token 同一口径，
     * 避免"逐字节比较提前返回"泄露 token 前缀。
     */
    public boolean matches(HttpServletRequest request) {
        if (!enabled()) {
            return false;
        }
        String presented = bearerToken(request);
        if (presented == null) {
            return false;
        }
        return constantTimeEquals(presented, token.trim());
    }

    /** 从 {@code Authorization: Bearer <token>} 取 token；没有则 null */
    public static String bearerToken(HttpServletRequest request) {
        String header = request == null ? null : request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            return null;
        }
        String value = header.substring(7).trim();
        return value.isEmpty() ? null : value;
    }

    /** 评测身份是否允许调用该路径 —— 只有 {@link #ALLOWED_PATH}，精确匹配 */
    public static boolean pathAllowed(String path) {
        return ALLOWED_PATH.equals(path);
    }

    /** 从请求体反序列化得到的 runId 里挑出"像 runId"的那个（其余一律丢弃） */
    public static String normalizeRunId(String raw) {
        if (raw == null) {
            return null;
        }
        String v = raw.trim();
        if (v.isEmpty() || v.length() > 64) {
            return null;
        }
        // 只接受 EVAL- 开头 + 字母数字短横：避免评测脚本把任意文本塞进审计字段
        if (!v.regionMatches(true, 0, "EVAL-", 0, 5)) {
            return null;
        }
        for (int i = 5; i < v.length(); i++) {
            char c = v.charAt(i);
            boolean ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-';
            if (!ok) {
                return null;
            }
        }
        return v;
    }

    static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        byte[] x = a.getBytes(StandardCharsets.UTF_8);
        byte[] y = b.getBytes(StandardCharsets.UTF_8);
        if (x.length != y.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < x.length; i++) {
            diff |= x[i] ^ y[i];
        }
        return diff == 0;
    }
}

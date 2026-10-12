package org.example.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 评测身份（{@code app.eval.token}）的识别与范围收敛测试。
 *
 * <h3>防的是什么</h3>
 * 方案的安全边界写得很明确：<b>评测 token 只能调 /api/chat</b>，
 * 不能处置/审批/策略/数据写入。这条边界如果只写在文档里，日后有人加一个
 * "评测顺便也能调"的端点，不会有任何报错 —— 所以把它做成会失败的测试。
 * <p>
 * 另外还验证"未配置 token 时功能完全关闭"：这是本次改造是否会影响现有行为的开关，
 * 必须由测试而不是由约定保证。
 */
class EvalIdentityTest {

    private static final String TOKEN = "eval-token-for-unit-test-0123456789";

    private EvalIdentity identity;

    @BeforeEach
    void setUp() {
        identity = newIdentity(TOKEN, true);
    }

    private static EvalIdentity newIdentity(String token, boolean enabled) {
        EvalIdentity id = new EvalIdentity();
        ReflectionTestUtils.setField(id, "token", token);
        ReflectionTestUtils.setField(id, "enabled", enabled);
        id.init();
        return id;
    }

    private static MockHttpServletRequest bearer(String path, String token) {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", path);
        if (token != null) {
            req.addHeader("Authorization", "Bearer " + token);
        }
        return req;
    }

    @Test
    @DisplayName("携带评测 token 的请求被识别为 EVAL 身份")
    void evalTokenIsRecognized() {
        assertTrue(identity.enabled(), "配置了 token 时应启用");
        assertTrue(identity.matches(bearer("/api/chat", TOKEN)), "正确 token 应命中评测身份");
    }

    @Test
    @DisplayName("token 不对 / 没有 Authorization 头 / 不是 Bearer 形态 → 都不是评测身份")
    void wrongOrMissingTokenIsNotEval() {
        assertFalse(identity.matches(bearer("/api/chat", TOKEN + "x")), "token 多一个字符不该命中");
        assertFalse(identity.matches(bearer("/api/chat", TOKEN.substring(0, TOKEN.length() - 1))),
                "token 少一个字符不该命中");
        assertFalse(identity.matches(bearer("/api/chat", null)), "没有 Authorization 头不该命中");
        assertFalse(identity.matches(new MockHttpServletRequest("POST", "/api/chat")),
                "完全没有凭据不该命中");

        MockHttpServletRequest basic = new MockHttpServletRequest("POST", "/api/chat");
        basic.addHeader("Authorization", "Basic " + TOKEN);
        assertFalse(identity.matches(basic), "非 Bearer 形态不该命中");
    }

    @Test
    @DisplayName("【核心】评测身份只允许 /api/chat，其余路径一律拒绝")
    void onlyChatPathIsAllowed() {
        assertTrue(EvalIdentity.pathAllowed("/api/chat"), "/api/chat 是评测唯一允许的端点");

        // 处置 / 审批 / 策略 / 数据写入 —— 全部必须拒绝
        assertFalse(EvalIdentity.pathAllowed("/api/response/block"), "处置端点必须拒绝");
        assertFalse(EvalIdentity.pathAllowed("/api/response/audit"), "审计读取也不放开");
        assertFalse(EvalIdentity.pathAllowed("/api/response/approve"), "审批端点必须拒绝");
        assertFalse(EvalIdentity.pathAllowed("/api/kb/approve"), "知识库审核必须拒绝");
        assertFalse(EvalIdentity.pathAllowed("/api/auth/users"), "用户管理必须拒绝");
        assertFalse(EvalIdentity.pathAllowed("/api/eval/run"), "评测运行接口本身也不放开");
        assertFalse(EvalIdentity.pathAllowed("/api/chat/clear"), "写会话的端点也算数据写入");
        // 前缀形态不得被当成同一个端点
        assertFalse(EvalIdentity.pathAllowed("/api/chat/"), "带斜杠的路径不等价于 /api/chat");
        assertFalse(EvalIdentity.pathAllowed("/api/chat-stream"), "同前缀不同路径必须拒绝");
    }

    @Test
    @DisplayName("未配置 token（或显式关闭 / token 过短）→ 评测身份完全关闭，不影响现有行为")
    void featureIsOffWithoutToken() {
        EvalIdentity noToken = newIdentity("", true);
        assertFalse(noToken.enabled(), "空 token 时功能关闭");
        assertFalse(noToken.matches(bearer("/api/chat", "anything")), "关闭后不认任何 token");

        EvalIdentity disabled = newIdentity(TOKEN, false);
        assertFalse(disabled.enabled(), "显式关闭时功能关闭");
        assertFalse(disabled.matches(bearer("/api/chat", TOKEN)), "关闭后即使 token 正确也不认");

        EvalIdentity tooShort = newIdentity("short", true);
        assertFalse(tooShort.enabled(), "token 过短时拒绝启用（fail-closed）");
        assertFalse(tooShort.matches(bearer("/api/chat", "short")), "过短 token 不生效");
    }

    @Test
    @DisplayName("评测请求上下文不跨请求残留（线程池复用会白送额度）")
    void requestContextDoesNotLeak() {
        assertFalse(EvalIdentity.isEvalRequest(), "默认不是评测请求");
        assertNull(EvalIdentity.currentRunId());

        EvalIdentity.beginEvalRequest("EVAL-abc123");
        assertTrue(EvalIdentity.isEvalRequest());
        assertEquals("EVAL-abc123", EvalIdentity.currentRunId());

        EvalIdentity.endEvalRequest();
        assertFalse(EvalIdentity.isEvalRequest(), "结束后必须回到普通请求");
        assertNull(EvalIdentity.currentRunId(), "runId 也必须清掉");
    }

    @Test
    @DisplayName("显式标注为普通请求时，不会被当成评测（宁可算用户账，也不让评测偷额度）")
    void explicitUserRequestIsNotEval() {
        EvalIdentity.beginEvalRequest("EVAL-abc123");
        EvalIdentity.beginUserRequest();
        assertFalse(EvalIdentity.isEvalRequest());
        assertNull(EvalIdentity.currentRunId());
        EvalIdentity.endEvalRequest();
    }

    @Test
    @DisplayName("【实测踩过】标注必须能穿过编排线程池（普通 ThreadLocal 会静默失效）")
    void evalFlagCrossesThreadPool() throws Exception {
        // /api/chat 的编排与模型出口跑在 ChatController.ORCHESTRATOR_POOL 里。
        // 如果标注传不过去，表现是：评测请求被识别为 EVAL，配额却记到用户头上、
        // RESPONDER 还会真的执行动作 —— 而且不报任何错。
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(2);
        try {
            EvalIdentity.beginEvalRequest("EVAL-pool01");
            try {
                java.util.concurrent.Future<Boolean> seen = pool.submit(EvalIdentity::isEvalRequest);
                assertTrue(seen.get(5, java.util.concurrent.TimeUnit.SECONDS),
                        "子线程（线程池）必须看得到评测标注");

                java.util.concurrent.Future<String> runId =
                        pool.submit(EvalIdentity::currentRunId);
                assertEquals("EVAL-pool01", runId.get(5, java.util.concurrent.TimeUnit.SECONDS),
                        "runId 也必须一起传下去（评测留痕要用）");
            } finally {
                EvalIdentity.endEvalRequest();
            }

            // 反过来：清掉之后子线程不能残留（线程池复用会把上一次的标注带给下一个请求）
            java.util.concurrent.Future<Boolean> afterEnd = pool.submit(EvalIdentity::isEvalRequest);
            assertFalse(afterEnd.get(5, java.util.concurrent.TimeUnit.SECONDS),
                    "清理后新建的子线程不得再看到评测标注");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("runId 只接受 EVAL- 开头的短标记，其余一律丢弃（防止任意文本进审计字段）")
    void runIdIsNormalized() {
        assertEquals("EVAL-abc123", EvalIdentity.normalizeRunId(" EVAL-abc123 "));
        assertEquals("EVAL-1A2B", EvalIdentity.normalizeRunId("EVAL-1A2B"));
        assertNull(EvalIdentity.normalizeRunId(null));
        assertNull(EvalIdentity.normalizeRunId(""));
        assertNull(EvalIdentity.normalizeRunId("not-an-eval-id"));
        assertNull(EvalIdentity.normalizeRunId("EVAL-bad space"));
        assertNull(EvalIdentity.normalizeRunId("EVAL-" + "x".repeat(200)), "过长必须丢弃");
    }

    // ==================== 拦截器层：真实拒绝行为 ====================

    private ApiTokenInterceptor interceptorWithEval() {
        ApiTokenInterceptor interceptor = new ApiTokenInterceptor();
        ReflectionTestUtils.setField(interceptor, "enabled", true);
        ReflectionTestUtils.setField(interceptor, "expectedToken", "system-level-token-not-eval");
        ReflectionTestUtils.setField(interceptor, "whiteList", "/api/health,/api/public/**");
        ReflectionTestUtils.setField(interceptor, "authService", new AuthService());
        ReflectionTestUtils.setField(interceptor, "evalIdentity", identity);
        return interceptor;
    }

    @Test
    @DisplayName("【核心】评测 token 调处置端点 → 403，且响应体说明原因")
    void evalTokenCannotCallResponseEndpoint() throws Exception {
        ApiTokenInterceptor interceptor = interceptorWithEval();
        MockHttpServletRequest req = bearer("/api/response/block", TOKEN);
        MockHttpServletResponse res = new MockHttpServletResponse();

        assertFalse(interceptor.preHandle(req, res, new Object()), "评测身份访问处置端点必须被拒");
        assertEquals(403, res.getStatus(), "必须是 403（不是 401，也不是默默放行）");

        Map<?, ?> body = new ObjectMapper().readValue(res.getContentAsByteArray(), Map.class);
        assertEquals(403, body.get("code"));
        assertTrue(String.valueOf(body.get("message")).contains("/api/chat"),
                "错误信息应说明评测身份只允许 /api/chat，实际：" + body.get("message"));
    }

    @Test
    @DisplayName("评测 token 调 /api/chat → 放行，且写入 role=EVAL、user=eval-runner")
    void evalTokenCanCallChat() throws Exception {
        ApiTokenInterceptor interceptor = interceptorWithEval();
        MockHttpServletRequest req = bearer("/api/chat", TOKEN);
        MockHttpServletResponse res = new MockHttpServletResponse();

        assertTrue(interceptor.preHandle(req, res, new Object()), "评测身份调 /api/chat 必须放行");
        assertEquals(Role.EVAL, req.getAttribute("secagent.role"), "角色必须是 EVAL");
        assertEquals(EvalIdentity.USERNAME, req.getAttribute("secagent.user"), "身份应标记为评测");
    }

    @Test
    @DisplayName("错误的评测 token 不会被当成评测身份放行（退化成普通未授权）")
    void wrongEvalTokenIsRejectedAsUnauthorized() throws Exception {
        ApiTokenInterceptor interceptor = interceptorWithEval();
        MockHttpServletRequest req = bearer("/api/chat", TOKEN + "-wrong");
        MockHttpServletResponse res = new MockHttpServletResponse();

        assertFalse(interceptor.preHandle(req, res, new Object()), "错误 token 不该放行");
        assertEquals(401, res.getStatus(), "错误 token 是未授权（401），不是评测身份");
    }

    @Test
    @DisplayName("RBAC 第二道锁：EVAL 角色访问管理员端点同样 403")
    void evalRoleIsDeniedByRbac() throws Exception {
        RbacInterceptor rbac = new RbacInterceptor();
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/response/audit");
        req.setAttribute("secagent.role", Role.EVAL);
        req.setAttribute("secagent.user", EvalIdentity.USERNAME);
        MockHttpServletResponse res = new MockHttpServletResponse();

        assertFalse(rbac.preHandle(req, res, new Object()), "EVAL 角色不得通过管理员端点");
        assertEquals(403, res.getStatus());
        assertNotEquals(Role.ADMIN, Role.EVAL);
    }
}

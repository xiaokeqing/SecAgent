package org.example.selfapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 自用控制器的<b>防御纵深</b>测试：拦截器被绕过时，控制器仍必须 fail-closed。
 *
 * <h3>为什么值得单独测</h3>
 * 自用面的鉴权实际发生在 {@link SelfTokenInterceptor}（未通过时请求根本进不到控制器），
 * 所以控制器里的兜底判断平时<b>不会被走到</b> —— 而恰恰是它挡着
 * 「哪天有人把 {@code /api/user/**} 从拦截器路径里删掉」这一类改动。
 *
 * <p>两条判据方向完全相反，必须钉死：
 * <ul>
 *   <li>有<b>通过标记</b>、无失败标记 ⇒ 放行（返回 null，继续走正常逻辑）；</li>
 *   <li>没有通过标记（不管有没有失败标记）⇒ 一律拒绝。</li>
 * </ul>
 * 写成"没有失败标记就放行"的话，删掉拦截器注册会让自用面变成<b>匿名可访问</b>，
 * 而且不会有任何报错 —— 这正是要防的失败模式。
 */
class SelfApiControllerGuardTest {

    private final SelfApiController controller = new SelfApiController();

    private static MockHttpServletRequest request() {
        return new MockHttpServletRequest("GET", "/api/user/status");
    }

    private static MockHttpServletRequest failedRequest(int status, String reason, String message, int retryAfter) {
        MockHttpServletRequest req = request();
        req.setAttribute(SelfApiController.ATTR_FAIL_STATUS, status);
        req.setAttribute(SelfApiController.ATTR_FAIL_REASON, reason);
        req.setAttribute(SelfApiController.ATTR_FAIL_MESSAGE, message);
        req.setAttribute(SelfApiController.ATTR_FAIL_RETRY_AFTER, retryAfter);
        return req;
    }

    private ResponseEntity<Map<String, Object>> guard(MockHttpServletRequest req, MockHttpServletResponse res) {
        try {
            java.lang.reflect.Method m = SelfApiController.class.getDeclaredMethod(
                    "authFailure", jakarta.servlet.http.HttpServletRequest.class,
                    jakarta.servlet.http.HttpServletResponse.class);
            m.setAccessible(true);
            @SuppressWarnings("unchecked")
            ResponseEntity<Map<String, Object>> result =
                    (ResponseEntity<Map<String, Object>>) m.invoke(controller, req, res);
            return result;
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("兜底方法签名变了，本测试需要同步更新：" + e.getMessage(), e);
        }
    }

    @Test
    @DisplayName("拦截器已判失败时，状态端点仍按 401 拒绝（兜底分支必须真的生效）")
    void statusIsRejectedWhenInterceptorMarkedFailure() {
        MockHttpServletRequest req = failedRequest(401, "TOKEN_INVALID", "令牌无效或已轮换", 0);
        MockHttpServletResponse res = new MockHttpServletResponse();

        ResponseEntity<Map<String, Object>> entity = controller.status(req, res);

        assertNotNull(entity);
        assertEquals(HttpStatus.UNAUTHORIZED, entity.getStatusCode());
        Map<String, Object> body = entity.getBody();
        assertNotNull(body);
        assertEquals(401, body.get("code"));
        assertEquals("TOKEN_INVALID", body.get("reason"));
        assertTrue(String.valueOf(res.getHeader("Cache-Control")).contains("no-store"),
                "鉴权失败响应必须不被缓存");
        assertNull(body.get("data"), "失败响应里不得附带自用面数据");
    }

    @Test
    @DisplayName("429 兜底：限速/封禁必须下发 Retry-After（页面才能如实提示多少秒后再试）")
    void rateLimitedFailureCarriesRetryAfter() {
        MockHttpServletRequest req = failedRequest(429, "IP_TEMPORARILY_BANNED", "尝试过于频繁", 600);
        MockHttpServletResponse res = new MockHttpServletResponse();

        ResponseEntity<Map<String, Object>> entity = controller.status(req, res);

        assertNotNull(entity);
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, entity.getStatusCode());
        assertEquals("600", res.getHeader("Retry-After"));
        assertEquals(429, entity.getBody().get("code"));
    }

    @Test
    @DisplayName("【核心】没有通过标记一律拒绝（拦截器被绕过 => fail-closed，不得变成匿名可访问）")
    void missingPassMarkerIsRejected() {
        // 完全没有通过标记、也没有失败标记：这正是"拦截器没生效"的样子
        ResponseEntity<Map<String, Object>> entity = guard(request(), new MockHttpServletResponse());

        assertNotNull(entity, "没有通过标记时必须拒绝，绝不能放行");
        assertEquals(HttpStatus.UNAUTHORIZED, entity.getStatusCode());
        assertEquals("UNAUTHORIZED", entity.getBody().get("reason"));
        assertTrue(String.valueOf(entity.getBody().get("message")).contains("鉴权"),
                "文案要指向'没经过鉴权'，而不是编一个令牌错误（否则排障方向会被带偏）");
    }

    @Test
    @DisplayName("有通过标记且无失败标记 => 放行（兜底不能把正常请求误拒）")
    void passMarkerWithoutFailureMeansAllowed() {
        MockHttpServletRequest req = request();
        req.setAttribute(SelfTokenInterceptor.ATTR_SELF_OK, Boolean.TRUE);

        ResponseEntity<Map<String, Object>> entity = guard(req, new MockHttpServletResponse());

        assertNull(entity, "通过标记存在且没有失败标记时必须放行（返回 null）");
    }

    @Test
    @DisplayName("通过标记与失败标记同时存在时按失败处理（不允许'部分通过'）")
    void failureWinsOverPassMarker() {
        MockHttpServletRequest req = failedRequest(429, "LOGIN_RATE_LIMITED", "请求过于频繁", 60);
        req.setAttribute(SelfTokenInterceptor.ATTR_SELF_OK, Boolean.TRUE);

        ResponseEntity<Map<String, Object>> entity = guard(req, new MockHttpServletResponse());

        assertNotNull(entity, "有失败标记就必须拒绝（两个标记并存时不得乐观放行）");
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, entity.getStatusCode());
    }
}

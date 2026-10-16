package org.example.selfapi;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 自用面<b>失败响应</b>的契约测试（真跑拦截器 {@link SelfTokenInterceptor} 那条路径）。
 *
 * <h3>为什么单独测这个</h3>
 * 未通过鉴权的请求根本进不到控制器 —— 前端拿到的 401/429 全部由本拦截器直接写出来。
 * 所以"跨域下前端能不能如实提示多少秒后再试"这件事，只能在<b>这一层</b>验证。
 *
 * <p>钉住三件事：
 * <ol>
 *   <li>429 必须同时给 {@code Retry-After} 头与响应体 {@code retryAfter}，且两处<b>数值一致</b>
 *       （跨域下浏览器读头需要 {@code Access-Control-Expose-Headers}，见
 *       {@code WebMvcConfig.EXPOSED_HEADERS}；体字段是前端的三层兜底之一）；</li>
 *   <li>401 <b>不得</b>带 retryAfter（否则前端会把"令牌不对"显示成"被限流"）；</li>
 *   <li>失败响应体里搜不到令牌明文（红线）。</li>
 * </ol>
 *
 * <p>不需要 Spring 上下文：注入一个真跑的 {@link UserTokenService}（限速阈值调成 1 次/分钟）
 * 就能在两条请求内把真实 429 打出来。它防的是"只改了一个地方"——
 * 例如只加了头忘了体，或只加了体忘了头。
 */
class SelfTokenInterceptorRejectTest {

    /** 测试专用令牌（≥32 字符）；只存在于测试里，不是任何环境的真实凭据 */
    private static final String TOKEN = "test-only-token-0123456789abcdefghijklmnopqrstuvwxyz";

    @TempDir
    Path tmp;

    @AfterEach
    void tearDown() {
        SelfIdentity.end();
    }

    private UserTokenService service(int loginPerMinute, String auditName) {
        UserTokenService s = new UserTokenService();
        ReflectionTestUtils.setField(s, "tokenSha256", UserTokenService.sha256Hex(TOKEN));
        ReflectionTestUtils.setField(s, "loginPerMinute", loginPerMinute);
        ReflectionTestUtils.setField(s, "failThreshold", 10);
        ReflectionTestUtils.setField(s, "failWindowSeconds", 600);
        ReflectionTestUtils.setField(s, "banSeconds", 600);
        ReflectionTestUtils.setField(s, "auditFile", tmp.resolve(auditName).toString());
        s.init();
        return s;
    }

    private SelfTokenInterceptor interceptor(UserTokenService service) {
        SelfTokenInterceptor i = new SelfTokenInterceptor();
        ReflectionTestUtils.setField(i, "userTokenService", service);
        ReflectionTestUtils.setField(i, "enabled", true);
        return i;
    }

    private static MockHttpServletRequest statusRequest() {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/user/status");
        req.setRemoteAddr("203.0.113.9");
        return req;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> json(MockHttpServletResponse res) throws Exception {
        return new ObjectMapper().readValue(res.getContentAsString(), Map.class);
    }

    @Test
    @DisplayName("【核心】429：Retry-After 头与响应体 retryAfter 都在，且两处数值一致")
    void rateLimitedFailureCarriesRetryAfterInHeaderAndBody() throws Exception {
        SelfTokenInterceptor interceptor = interceptor(service(1, "audit-429.jsonl"));

        MockHttpServletRequest first = statusRequest();
        first.addHeader(SelfTokenInterceptor.TOKEN_HEADER, TOKEN);
        assertTrue(interceptor.preHandle(first, new MockHttpServletResponse(), new Object()),
                "第 1 次（配额内）必须放行");

        MockHttpServletRequest second = statusRequest();
        second.addHeader(SelfTokenInterceptor.TOKEN_HEADER, TOKEN);
        MockHttpServletResponse res = new MockHttpServletResponse();
        assertFalse(interceptor.preHandle(second, res, new Object()), "第 2 次必须被限速");

        assertEquals(429, res.getStatus());
        String header = res.getHeader("Retry-After");
        assertNotNull(header, "429 必须带 Retry-After 头（HTTP 层客户端依赖它）");

        Map<String, Object> body = json(res);
        assertEquals(429, body.get("code"));
        assertEquals("LOGIN_RATE_LIMITED", body.get("reason"));
        assertNotNull(body.get("retryAfter"),
                "429 响应体必须带 retryAfter（跨域下浏览器读不到头时靠它兜底）");
        assertEquals(Integer.parseInt(header), ((Number) body.get("retryAfter")).intValue(),
                "头与体的秒数必须一致 —— 不一致会让前端两个提示互相打架");
        assertTrue(Integer.parseInt(header) > 0, "秒数必须为正，前端才能倒数");
    }

    @Test
    @DisplayName("401 不得带 retryAfter（否则前端会把『令牌不对』显示成『被限流』）")
    void plainUnauthorizedHasNoRetryAfter() throws Exception {
        SelfTokenInterceptor interceptor = interceptor(service(1000, "audit-401.jsonl"));

        MockHttpServletRequest req = statusRequest();
        req.addHeader(SelfTokenInterceptor.TOKEN_HEADER, TOKEN + "-wrong");
        MockHttpServletResponse res = new MockHttpServletResponse();

        assertFalse(interceptor.preHandle(req, res, new Object()));
        assertEquals(401, res.getStatus());
        assertNull(res.getHeader("Retry-After"), "401 不该有限流秒数");
        Map<String, Object> body = json(res);
        assertEquals("TOKEN_INVALID", body.get("reason"));
        assertNull(body.get("retryAfter"), "401 的响应体里不该出现 retryAfter");
    }

    @Test
    @DisplayName("【红线】失败响应体里搜不到令牌明文（失败文案可安全展示给站主）")
    void failureBodyNeverEchoesToken() throws Exception {
        SelfTokenInterceptor interceptor = interceptor(service(1, "audit-leak.jsonl"));

        MockHttpServletRequest req = statusRequest();
        req.addHeader(SelfTokenInterceptor.TOKEN_HEADER, TOKEN);
        interceptor.preHandle(req, new MockHttpServletResponse(), new Object());   // 用掉额度

        MockHttpServletRequest second = statusRequest();
        second.addHeader(SelfTokenInterceptor.TOKEN_HEADER, TOKEN);
        MockHttpServletResponse res = new MockHttpServletResponse();
        interceptor.preHandle(second, res, new Object());

        String raw = res.getContentAsString();
        assertFalse(raw.contains(TOKEN), "响应体里绝不能出现令牌原文");
        assertFalse(raw.contains(UserTokenService.sha256Hex(TOKEN)), "响应体里也不能出现令牌哈希");
    }

    @Test
    @DisplayName("OPTIONS 预检不鉴权、不进限速（否则浏览器预检会被 401 挡掉）")
    void optionsPreflightPassesThrough() throws Exception {
        SelfTokenInterceptor interceptor = interceptor(service(1, "audit-options.jsonl"));

        MockHttpServletRequest preflight = new MockHttpServletRequest("OPTIONS", "/api/user/status");
        assertTrue(interceptor.preHandle(preflight, new MockHttpServletResponse(), new Object()),
                "预检必须放行（CORS 预检不带 X-User-Token）");
    }
}

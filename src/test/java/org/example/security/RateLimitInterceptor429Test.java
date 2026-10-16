package org.example.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 全局限流器 429 的<b>可读性契约</b>测试。
 *
 * <h3>为什么这一层也要管</h3>
 * {@code /api/user/**} 前面先跑的是本限流器（见 {@code WebMvcConfig} 的拦截器顺序），
 * 所以浏览器可能收到的 429 <b>不是</b>自用面那条（{@code LOGIN_RATE_LIMITED}），
 * 而是这条全局的 {@code RATE_LIMITED}。两条都必须给出真实秒数 —— 只修一条的话，
 * 前端另一条路径仍然会回落到"永远显示 60 秒"。
 *
 * <p>与 {@code SelfTokenInterceptorRejectTest} 同一口径：
 * {@code Retry-After} 头 + 响应体 {@code retryAfter} 两处都给、且数值一致。
 */
class RateLimitInterceptor429Test {

    private RateLimitInterceptor interceptor(int limit) {
        RateLimitInterceptor i = new RateLimitInterceptor();
        ReflectionTestUtils.setField(i, "enabled", true);
        ReflectionTestUtils.setField(i, "limit", limit);
        ReflectionTestUtils.setField(i, "loginLimit", limit);
        return i;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> json(MockHttpServletResponse res) throws Exception {
        return new ObjectMapper().readValue(res.getContentAsString(), Map.class);
    }

    @Test
    @DisplayName("【核心】超限 429：Retry-After 头 + 响应体 retryAfter，且秒数在 1~60 之间")
    void overLimitCarriesRetryAfterInHeaderAndBody() throws Exception {
        RateLimitInterceptor interceptor = interceptor(1);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/status");
        req.setRemoteAddr("203.0.113.9");
        assertTrue(interceptor.preHandle(req, new MockHttpServletResponse(), new Object()), "第 1 次放行");

        MockHttpServletResponse res = new MockHttpServletResponse();
        assertFalse(interceptor.preHandle(req, res, new Object()), "第 2 次必须 429");

        assertEquals(429, res.getStatus());
        String header = res.getHeader("Retry-After");
        assertNotNull(header, "429 必须带 Retry-After 头");
        int seconds = Integer.parseInt(header);
        assertTrue(seconds >= 1 && seconds <= 60,
                "固定窗口是 60 秒，剩余秒数应落在 [1,60]，实际=" + seconds);

        Map<String, Object> body = json(res);
        assertEquals(429, body.get("code"));
        assertEquals("RATE_LIMITED", body.get("reason"), "必须给稳定的原因码，前端才能分档提示");
        assertEquals(seconds, ((Number) body.get("retryAfter")).intValue(), "头与体的秒数必须一致");
        assertTrue(String.valueOf(res.getHeader("Cache-Control")).contains("no-store"),
                "限流响应不得被缓存（否则边缘会把 429 发给下一个人）");
    }

    @Test
    @DisplayName("额度内的请求照常放行（加了头与字段不得改变放行语义）")
    void withinLimitStillPasses() throws Exception {
        RateLimitInterceptor interceptor = interceptor(3);
        for (int i = 0; i < 3; i++) {
            MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/status");
            req.setRemoteAddr("203.0.113.10");
            assertTrue(interceptor.preHandle(req, new MockHttpServletResponse(), new Object()),
                    "第 " + (i + 1) + " 次在额度内，必须放行");
        }
    }
}

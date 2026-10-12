package org.example.publicapi;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 公网端点 CORS 白名单测试。
 *
 * <h3>防的是什么</h3>
 * 改造前线上是"回显任意 Origin"：任何网站都能借访客浏览器读取安全大屏的数据，
 * 而且因为响应带 {@code Access-Control-Allow-Origin: *}（回显），
 * 数据可以被任意第三方页面读取并展示。
 * <p>
 * 这里断言的重点不是"白名单里的来源能过"，而是 <b>"非白名单来源一个 CORS 头都拿不到"</b> ——
 * 后者才是收紧；前者只是没把它改坏。
 */
class PublicCorsInterceptorTest {

    /** 与 application.yml 默认值一致 */
    private static final String DEFAULT_ORIGINS =
            "https://xiaokeqing.cn,https://www.xiaokeqing.cn,http://localhost:1313,http://127.0.0.1:1313";

    private PublicCorsInterceptor interceptor;

    @BeforeEach
    void setUp() {
        interceptor = newInterceptor(DEFAULT_ORIGINS);
    }

    private static PublicCorsInterceptor newInterceptor(String origins) {
        PublicCorsInterceptor i = new PublicCorsInterceptor();
        ReflectionTestUtils.setField(i, "allowedOriginsConfig", origins);
        return i;
    }

    private static MockHttpServletResponse handle(PublicCorsInterceptor i, String method, String path, String origin)
            throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest(method, path);
        if (origin != null) {
            req.addHeader("Origin", origin);
        }
        MockHttpServletResponse res = new MockHttpServletResponse();
        i.preHandle(req, res, new Object());
        return res;
    }

    @Test
    @DisplayName("【核心】白名单来源拿到 Access-Control-Allow-Origin（精确回显该来源）")
    void allowedOriginsGetCorsHeader() throws Exception {
        for (String origin : List.of("https://xiaokeqing.cn", "https://www.xiaokeqing.cn",
                "http://localhost:1313", "http://127.0.0.1:1313")) {
            MockHttpServletResponse res = handle(interceptor, "GET", "/api/public/overview", origin);
            assertEquals(origin, res.getHeader("Access-Control-Allow-Origin"),
                    origin + " 应收到 ACAO");
            assertEquals("Origin", res.getHeader("Vary"),
                    "带 Origin 判定的响应必须带 Vary: Origin，否则 CDN 会把 A 的响应喂给 B");
        }
    }

    @Test
    @DisplayName("【核心】非白名单来源一个 Access-Control-* 头都不回（不是回 *，也不是回显）")
    void disallowedOriginsGetNoCorsHeader() throws Exception {
        for (String origin : List.of("https://evil.example", "https://xiaokeqing.cn.evil.com",
                "http://localhost:1314", "null", "https://XIAOKEQING.CN")) {
            MockHttpServletResponse res = handle(interceptor, "GET", "/api/public/overview", origin);
            assertNull(res.getHeader("Access-Control-Allow-Origin"),
                    origin + " 不该收到 ACAO（大小写不同也算不同来源）");
            assertNull(res.getHeader("Access-Control-Allow-Credentials"),
                    origin + " 不该收到其他 CORS 头");
        }
    }

    @Test
    @DisplayName("没有 Origin 头（curl / 服务端调用）不受影响，照常放行")
    void requestsWithoutOriginPass() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/public/overview");
        MockHttpServletResponse res = new MockHttpServletResponse();
        assertTrue(interceptor.preHandle(req, res, new Object()), "无 Origin 的请求必须继续走");
        assertNull(res.getHeader("Access-Control-Allow-Origin"), "无 Origin 不回 CORS 头");
    }

    @Test
    @DisplayName("白名单来源的预检：204 + 允许方法/头，且不进控制器")
    void preflightFromAllowedOriginIsAnswered() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("OPTIONS", "/api/public/overview");
        req.addHeader("Origin", "https://xiaokeqing.cn");
        req.addHeader("Access-Control-Request-Method", "GET");
        MockHttpServletResponse res = new MockHttpServletResponse();

        assertFalse(interceptor.preHandle(req, res, new Object()), "预检必须在这里结束（不进控制器）");
        assertEquals(204, res.getStatus());
        assertEquals("https://xiaokeqing.cn", res.getHeader("Access-Control-Allow-Origin"));
        assertNotNull(res.getHeader("Access-Control-Allow-Methods"));
        assertNotNull(res.getHeader("Access-Control-Allow-Headers"));
        assertNotNull(res.getHeader("Access-Control-Max-Age"));
    }

    @Test
    @DisplayName("非白名单来源的预检：403 且没有 CORS 头（浏览器据此判定失败）")
    void preflightFromDisallowedOriginIsForbidden() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("OPTIONS", "/api/public/overview");
        req.addHeader("Origin", "https://evil.example");
        MockHttpServletResponse res = new MockHttpServletResponse();

        assertFalse(interceptor.preHandle(req, res, new Object()));
        assertEquals(403, res.getStatus());
        assertNull(res.getHeader("Access-Control-Allow-Origin"));
    }

    @Test
    @DisplayName("白名单解析：去空白、丢空项、不做前后缀匹配")
    void whitelistParsingIsExact() {
        PublicCorsInterceptor messy = newInterceptor(" https://a.example ,, http://b.example ");
        assertEquals(2, messy.allowedOrigins().size(), "空白与空项应被丢弃");
        assertTrue(messy.isAllowed("https://a.example"));
        assertTrue(messy.isAllowed("http://b.example"));
        assertFalse(messy.isAllowed("https://a.example.evil"), "子串/前缀匹配必须不成立");
        assertFalse(messy.isAllowed("https://sub.a.example"), "子域默认不放行");
        assertFalse(messy.isAllowed(null));
        assertFalse(messy.isAllowed("  "));

        PublicCorsInterceptor empty = newInterceptor("");
        assertTrue(empty.allowedOrigins().isEmpty(), "空白名单解析结果为空");
        assertFalse(empty.isAllowed("https://a.example"), "空白名单不放行任何来源");
    }

    @Test
    @DisplayName("公网路径判定必须带边界（/api/publicfoo 不算公网端点）")
    void publicPathBoundary() {
        assertTrue(PublicApiCorsProcessor.isPublicPath("/api/public"));
        assertTrue(PublicApiCorsProcessor.isPublicPath("/api/public/overview"));
        assertTrue(PublicApiCorsProcessor.isPublicPath("/api/public/alerts/agg-1"));
        assertFalse(PublicApiCorsProcessor.isPublicPath("/api/publicfoo"));
        assertFalse(PublicApiCorsProcessor.isPublicPath("/api/response/block"));
        assertFalse(PublicApiCorsProcessor.isPublicPath(null));
    }

    @Test
    @DisplayName("公网端点在 Spring 这一层没有 CORS 配置（交给自写拦截器独占，避免两套规则取并集）")
    void springCorsIsHandedOffForPublicPaths() {
        CorsConfiguration business = new CorsConfiguration();
        business.setAllowedOrigins(List.of("http://localhost:9900"));
        CorsConfigurationSource delegated = request -> business;
        PublicApiCorsProcessor processor = new PublicApiCorsProcessor(delegated);

        MockHttpServletRequest pub = new MockHttpServletRequest("GET", "/api/public/overview");
        assertNull(processor.configurationFor(pub), "公网端点必须由拦截器独占（Spring 返回 null 配置）");

        MockHttpServletRequest biz = new MockHttpServletRequest("GET", "/api/alerts/list");
        assertEquals(business, processor.configurationFor(biz), "业务端点必须原样走原配置");
    }

    @Test
    @DisplayName("公网路径由 Spring 处理器放行（不加 CORS 头），业务路径原样走默认处理器")
    void processorDelegatesCorrectly() throws Exception {
        PublicApiCorsProcessor processor = new PublicApiCorsProcessor(request -> null);

        MockHttpServletResponse pubRes = new MockHttpServletResponse();
        MockHttpServletRequest pubReq = new MockHttpServletRequest("GET", "/api/public/overview");
        assertTrue(processor.processRequest(null, pubReq, pubRes), "公网路径：Spring 不参与，照常放行");
        assertNull(pubRes.getHeader("Access-Control-Allow-Origin"), "Spring 不得给公网端点加 CORS 头");

        // 业务路径且无配置：Spring 默认处理器对【非预检】跨域请求放行但不回 ACAO
        // （浏览器据此拦截读取），这就是原有行为 —— 本改造不该改变它
        MockHttpServletRequest bizReq = new MockHttpServletRequest("GET", "/api/alerts/list");
        bizReq.addHeader("Origin", "https://evil.example");
        MockHttpServletResponse bizRes = new MockHttpServletResponse();
        assertTrue(processor.processRequest(null, bizReq, bizRes),
                "业务端点的非预检跨域请求仍按原有行为放行到控制器");
        assertNull(bizRes.getHeader("Access-Control-Allow-Origin"),
                "无配置时默认处理器不回 ACAO（浏览器会拦下读取）");

        // 业务路径的【预检】无配置 → 默认处理器 403（原有行为）
        MockHttpServletRequest bizPreflight = new MockHttpServletRequest("OPTIONS", "/api/alerts/list");
        bizPreflight.addHeader("Origin", "https://evil.example");
        bizPreflight.addHeader("Access-Control-Request-Method", "GET");
        MockHttpServletResponse preflightRes = new MockHttpServletResponse();
        assertFalse(processor.processRequest(null, bizPreflight, preflightRes),
                "业务端点的无配置预检仍应被默认处理器拒绝");
        assertEquals(403, preflightRes.getStatus());
    }
}

package org.example.publicapi;

import org.example.aggregation.AlertAggregationService;
import org.example.core.model.AlertSeverity;
import org.example.core.model.AlertSource;
import org.example.core.model.AlertType;
import org.example.core.model.SecurityAlert;
import org.example.integration.WazuhGateway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.lang.reflect.Proxy;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * B3：缓存别名路径（{@code /api/public/<name>.js}）的契约测试。
 *
 * <p>它钉住这一批的<b>四条不可退让的边界</b>：
 * <ol>
 *   <li><b>别名是纯增量路由</b>：同一控制器方法、同一 payload；旧路径（无 {@code .js}）
 *       的 CORS 口径与响应体<b>一个字都不变</b>（回显白名单来源 + {@code Vary: Origin}）；</li>
 *   <li><b>别名可缓存</b>：{@code Access-Control-Allow-Origin: *} 且<b>没有</b>
 *       {@code Vary: Origin}（否则边缘缓存命中率打折，等于白做）；</li>
 *   <li><b>别名必须防"扩展名被当脚本"</b>：{@code X-Content-Type-Options: nosniff}，
 *       且 {@code Access-Control-Expose-Headers} 放行 {@code Age}（真实年龄要用它）；</li>
 *   <li><b>不许假装更新（站主红线 D4）</b>：别名响应体必须带 {@code snapshotAt} /
 *       {@code cacheAgeSeconds} / {@code snapshotTtlSeconds}，页面按 {@code snapshotAt} 显示同步时间。</li>
 * </ol>
 */
class PublicApiCacheAliasTest {

    private PublicApiController controller;
    private PublicCorsInterceptor cors;

    @BeforeEach
    void setUp() {
        controller = new PublicApiController();
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 20);
        ReflectionTestUtils.setField(controller, "rateLimiter", limiter);
        ReflectionTestUtils.setField(controller, "cacheSeconds", 15);
        ReflectionTestUtils.setField(controller, "exposeBuildSha", false);
        ReflectionTestUtils.setField(controller, "buildSha", "test");

        WazuhGateway gateway = (WazuhGateway) Proxy.newProxyInstance(
                WazuhGateway.class.getClassLoader(),
                new Class<?>[]{WazuhGateway.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "mode" -> "REAL";
                    case "isAvailable" -> true;
                    case "recentAlerts" -> List.of(alert("a1", "45.83.91.12"));
                    case "toString" -> "StubGateway";
                    default -> null;
                });
        PublicAlertSource source = new PublicAlertSource();
        ReflectionTestUtils.setField(source, "wazuhGateway", gateway);
        ReflectionTestUtils.setField(source, "aggregator", new AlertAggregationService());
        ReflectionTestUtils.setField(controller, "source", source);

        cors = new PublicCorsInterceptor();
        ReflectionTestUtils.setField(cors, "allowedOriginsConfig",
                "https://xiaokeqing.cn,https://www.xiaokeqing.cn");
    }

    private static SecurityAlert alert(String id, String ip) {
        SecurityAlert a = new SecurityAlert(id, "内部标题不该出现在响应里", AlertSeverity.HIGH,
                AlertType.SCAN, AlertSource.SURICATA);
        a.setSrcIp(ip);
        a.setOccurredAt("2026-10-13 10:00:00");
        return a;
    }

    private MockMvc mvc() {
        return MockMvcBuilders.standaloneSetup(controller).addInterceptors(cors).build();
    }

    @Test
    @DisplayName("别名路径：可缓存（ACAO=* 且无 Vary）+ nosniff + 放行 Age + 带 snapshotAt 三件套")
    void aliasPathIsCacheableAndCarriesFreshness() throws Exception {
        String body = mvc().perform(get("/api/public/latest.js")
                        .header("Origin", "https://example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(200))
                .andExpect(jsonPath("$.data.available").value(true))
                .andExpect(jsonPath("$.snapshotAt").exists())
                .andExpect(jsonPath("$.cacheAgeSeconds").exists())
                .andExpect(jsonPath("$.snapshotTtlSeconds").value(15))
                // TTL 45s（> 站点 40s 轮询间隔）+ stale-while-revalidate（边缘先发旧值再后台验证）
                .andExpect(header().string("Cache-Control",
                        "public, max-age=45, stale-while-revalidate=90"))
                .andExpect(header().string("Access-Control-Allow-Origin", "*"))
                .andExpect(header().doesNotExist("Vary"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                // 硬条件：别名是为了"可缓存"才用 .js 后缀，内容类型**必须**仍是 JSON ——
                // 否则一旦 payload 里有攻击者可控字符串，就是一条 XSS 面。
                .andExpect(header().string("Content-Type",
                        org.hamcrest.Matchers.startsWith("application/json")))
                .andExpect(header().string("Access-Control-Expose-Headers",
                        org.hamcrest.Matchers.containsString("Age")))
                .andReturn().getResponse().getContentAsString();

        assertFalse(body.contains("45.83.91.12"), "完整来源 IP 不得出现（别名同样走同一套脱敏）：" + body);
    }

    @Test
    @DisplayName("别名 ETag 按【数据内容】算：同一快照窗口内两次请求必须同一个 ETag（否则 CF 再验证永远拿不到 304）")
    void aliasEtagIsStableWithinSnapshotWindow() throws Exception {
        // 两次请求之间隔 1.2 秒 ⇒ cacheAgeSeconds 很可能已经不同（这正是线上 ETag 每秒都变的根因）；
        // 但 ETag 只应对"数据内容"敏感，所以两次必须一致。
        String etag1 = mvc().perform(get("/api/public/latest.js")).andReturn().getResponse().getHeader("ETag");
        Thread.sleep(1200);
        String etag2 = mvc().perform(get("/api/public/latest.js")).andReturn().getResponse().getHeader("ETag");

        assertNotNull(etag1, "别名必须下发 ETag（否则只能按完整体哈希算、每秒都变）");
        assertEquals(etag1, etag2,
                "同一快照窗口内 ETag 必须稳定：volatile 字段（cacheAgeSeconds/snapshotAt）不得参与计算");
    }

    @Test
    @DisplayName("旧路径行为不变：回显白名单来源 + Vary: Origin，且体内没有别名专属字段")
    void legacyPathKeepsWhitelistBehaviourAndBody() throws Exception {
        String body = mvc().perform(get("/api/public/latest")
                        .header("Origin", "https://xiaokeqing.cn"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(200))
                .andExpect(jsonPath("$.data.available").value(true))
                .andExpect(jsonPath("$.snapshotAt").doesNotExist())
                .andExpect(jsonPath("$.cacheAgeSeconds").doesNotExist())
                .andExpect(header().string("Cache-Control", "public, max-age=15"))
                .andExpect(header().string("Access-Control-Allow-Origin", "https://xiaokeqing.cn"))
                .andExpect(header().string("Vary", "Origin"))
                .andExpect(header().doesNotExist("X-Content-Type-Options"))
                .andReturn().getResponse().getContentAsString();

        assertFalse(body.contains("snapshotTtlSeconds"), "旧路径不得出现别名专属字段：" + body);
    }

    @Test
    @DisplayName("非白名单来源走旧路径：照旧不下发 CORS 头（白名单没有被别名改动放松）")
    void legacyPathStillRefusesUnknownOrigin() throws Exception {
        mvc().perform(get("/api/public/latest").header("Origin", "https://example.com"))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"))
                .andExpect(header().doesNotExist("Vary"));
    }

    @Test
    @DisplayName("别名预检：204 + ACAO=* + 不回 Vary（浏览器拿得到可缓存的判定）")
    void aliasPreflight() throws Exception {
        // 直接驱动拦截器：standalone MockMvc 的 OPTIONS 会走 Spring 自己的 PreFlightHandler，
        // 那条路与本类要钉的"别名口径"无关（且在 standalone 环境里没有对应 HandlerAdapter）。
        org.springframework.mock.web.MockHttpServletRequest req =
                new org.springframework.mock.web.MockHttpServletRequest("OPTIONS", "/api/public/latest.js");
        req.addHeader("Origin", "https://example.com");
        req.addHeader("Access-Control-Request-Method", "GET");
        org.springframework.mock.web.MockHttpServletResponse res =
                new org.springframework.mock.web.MockHttpServletResponse();

        boolean proceed = cors.preHandle(req, res, new Object());

        assertFalse(proceed, "预检必须在拦截器内结束，不进控制器（不做一次无意义的上游取数）");
        assertEquals(204, res.getStatus());
        assertEquals("*", res.getHeader("Access-Control-Allow-Origin"));
        assertNull(res.getHeader("Vary"), "别名不得下发 Vary（否则边缘命中率打折）");
        assertEquals("nosniff", res.getHeader("X-Content-Type-Options"));
    }
}

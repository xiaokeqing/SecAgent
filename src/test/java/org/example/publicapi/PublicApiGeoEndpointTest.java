package org.example.publicapi;

import org.example.aggregation.AlertAggregationService;
import org.example.geoip.GeoAggregator;
import org.example.geoip.GeoIpService;
import org.example.geoip.GeoTestFixtures;
import org.example.geoip.GeoWindow;
import org.example.integration.WazuhGateway;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code GET /api/public/geo} 的端点契约测试（真跑一遍 MVC 路由 + 信封 + 各个降级分支）。
 *
 * <p>它钉的是四件事：
 * <ol>
 *   <li>路由真的存在、真的按既有信封（{@code code/message/data}）回话；</li>
 *   <li>库缺失 / 库损坏 / 数据源不可用 / 窗口为空 —— 四种降级各回<b>自己的 reason</b>，
 *       而不是统统变成"空分布"（那会被页面渲染成"24 小时风平浪静"）；</li>
 *   <li>正常分支的载荷<b>一个 IP 都没有</b>（对整段响应体做正则断言）；</li>
 *   <li>DB-IP 的 CC BY 4.0 署名真的在响应体里（许可要求署名，不是"文档里写一句"）。</li>
 * </ol>
 */
class PublicApiGeoEndpointTest {

    @TempDir
    Path tmp;

    private PublicApiController controller;

    private void baseController() {
        controller = new PublicApiController();
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 20);
        ReflectionTestUtils.setField(controller, "rateLimiter", limiter);
        ReflectionTestUtils.setField(controller, "cacheSeconds", 15);
        ReflectionTestUtils.setField(controller, "exposeBuildSha", false);
        ReflectionTestUtils.setField(controller, "buildSha", "test");
        ReflectionTestUtils.setField(controller, "geoMinCount", 3);
        ReflectionTestUtils.setField(controller, "geoMinSharePercent", 1.0d);
        ReflectionTestUtils.setField(controller, "geoTopIps", 1000);
        ReflectionTestUtils.setField(controller, "geoTopCountries", 20);
        ReflectionTestUtils.setField(controller, "geoTopProvinces", 10);
        ReflectionTestUtils.setField(controller, "geoTopAsns", 10);
        ReflectionTestUtils.setField(controller, "geoSelfIps", "");
    }

    /** 夹具库：1.0.0.0/24=AU、1.0.1.0/24=CN浙江、1.0.2.0/24=CN福建、1.0.3.0/24=US */
    private GeoIpService fixtureGeo() throws Exception {
        Path city = GeoTestFixtures.writeGz(tmp, "dbip-city-lite-2026-10.csv.gz", GeoTestFixtures.CITY_4);
        Path asn = GeoTestFixtures.writeGz(tmp, "dbip-asn-lite-2026-10.csv.gz", GeoTestFixtures.ASN_ALL);
        GeoIpService geo = new GeoIpService();
        ReflectionTestUtils.setField(geo, "cityDb", city.toString());
        ReflectionTestUtils.setField(geo, "asnDb", asn.toString());
        ReflectionTestUtils.setField(geo, "enabled", true);
        ReflectionTestUtils.setField(geo, "ipv6Enabled", true);
        geo.init();
        geo.loadBlocking();
        assertTrue(geo.ready(), geo.summary());
        return geo;
    }

    /** 用动态代理造网关替身：只回答 mode 与 geoWindow24h（与项目既有测试同一套做法） */
    private void wireSource(String mode, GeoWindow window) {
        WazuhGateway gateway = (WazuhGateway) Proxy.newProxyInstance(
                WazuhGateway.class.getClassLoader(),
                new Class<?>[]{WazuhGateway.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "mode" -> mode;
                    case "isAvailable" -> "REAL".equalsIgnoreCase(mode);
                    case "recentAlerts" -> List.of();
                    case "geoWindow24h" -> window;
                    case "toString" -> "StubGateway(" + mode + ")";
                    default -> null;
                });
        PublicAlertSource source = new PublicAlertSource();
        ReflectionTestUtils.setField(source, "wazuhGateway", gateway);
        ReflectionTestUtils.setField(source, "aggregator", new AlertAggregationService());
        ReflectionTestUtils.setField(controller, "source", source);
    }

    private static GeoWindow window(long total, GeoAggregator.IpCount... counts) {
        long withIp = 0;
        for (GeoAggregator.IpCount c : counts) {
            withIp += c.count();
        }
        return new GeoWindow(true, "OK", null, total, withIp, false, List.of(counts),
                List.of(new GeoAggregator.TrendPoint("2026-10-13T20:00", 12)));
    }

    private MockMvc mvc() {
        return MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    @DisplayName("正常：200 + 既有信封 + 国家/省份/ASN/趋势 + 分母披露 + 限流与缓存头")
    void returnsAggregatesWhenEverythingIsUp() throws Exception {
        baseController();
        ReflectionTestUtils.setField(controller, "geoIpService", fixtureGeo());
        wireSource("REAL", window(1000,
                new GeoAggregator.IpCount("1.0.1.1", 100),
                new GeoAggregator.IpCount("1.0.1.2", 60),
                new GeoAggregator.IpCount("1.0.2.1", 40),
                new GeoAggregator.IpCount("1.0.3.1", 30),
                new GeoAggregator.IpCount("10.0.0.1", 25),
                new GeoAggregator.IpCount("203.0.113.9", 5)));

        String body = mvc().perform(get("/api/public/geo"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(200))
                .andExpect(jsonPath("$.message").value("success"))
                .andExpect(jsonPath("$.data.available").value(true))
                .andExpect(jsonPath("$.data.reason").value("OK"))
                .andExpect(jsonPath("$.data.window").value("24h"))
                .andExpect(jsonPath("$.data.geoSource").value("DB-IP Lite City 2026-10 + DB-IP Lite ASN 2026-10"))
                .andExpect(jsonPath("$.data.byCountry[0].country").value("CN"))
                .andExpect(jsonPath("$.data.byCountry[0].countryName").value("中国"))
                .andExpect(jsonPath("$.data.byCountry[0].count").value(200))
                .andExpect(jsonPath("$.data.byCountry[0].uniqueIps").value(3))
                .andExpect(jsonPath("$.data.byProvinceCN[0].province").value("Zhejiang"))
                .andExpect(jsonPath("$.data.byProvinceCN[0].count").value(160))
                .andExpect(jsonPath("$.data.byAsnTop[0].asn").value(4134))
                .andExpect(jsonPath("$.data.byAsnTop[0].org").value("CHINANET-BACKBONE"))
                .andExpect(jsonPath("$.data.trend[0].count").value(12))
                .andExpect(jsonPath("$.data.coverage.totalAlerts").value(1000))
                .andExpect(jsonPath("$.data.coverage.geocoded").value(230))
                .andExpect(jsonPath("$.data.coverage.excludedInternal").value(25))
                .andExpect(jsonPath("$.data.coverage.excludedReserved").value(5))
                .andExpect(jsonPath("$.data.thresholds.minCount").value(3))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .header().string("Cache-Control", "public, max-age=15"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .header().string("X-RateLimit-Limit", "20"))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        assertNoIpLeak(body);
        assertFalse(body.contains("10.0.0.1"), "内网 IP 不得出现：" + body);
        assertTrue(body.contains(GeoIpService.ATTRIBUTION), "CC BY 4.0 署名必须在响应里：" + body);
        assertTrue(body.contains("\"geoAttribution\""), body);
    }

    @Test
    @DisplayName("库缺失（没有 Bean）：available=false + GEO_DB_MISSING，不返回空分布冒充'没有攻击'")
    void missingDatabaseIsReported() throws Exception {
        baseController();
        wireSource("REAL", window(1000, new GeoAggregator.IpCount("1.0.1.1", 100)));

        mvc().perform(get("/api/public/geo"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(false))
                .andExpect(jsonPath("$.data.reason").value("GEO_DB_MISSING"))
                .andExpect(jsonPath("$.data.geoSource").value(org.hamcrest.Matchers.nullValue()))
                .andExpect(jsonPath("$.data.byCountry").isEmpty())
                .andExpect(jsonPath("$.data.note").exists());
    }

    @Test
    @DisplayName("库损坏：available=false + GEO_DB_UNUSABLE（与 MISSING 区分开，运维知道该修哪一段）")
    void unusableDatabaseIsReported() throws Exception {
        baseController();
        Path fake = tmp.resolve("dbip-city-lite-2026-10.csv.gz");
        Files.writeString(fake, "不是 gzip\n", StandardCharsets.UTF_8);
        GeoIpService geo = new GeoIpService();
        ReflectionTestUtils.setField(geo, "cityDb", fake.toString());
        ReflectionTestUtils.setField(geo, "asnDb", "");
        ReflectionTestUtils.setField(geo, "enabled", true);
        ReflectionTestUtils.setField(geo, "ipv6Enabled", true);
        geo.init();
        geo.loadBlocking();
        ReflectionTestUtils.setField(controller, "geoIpService", geo);
        wireSource("REAL", window(10, new GeoAggregator.IpCount("1.0.1.1", 10)));

        mvc().perform(get("/api/public/geo"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(false))
                .andExpect(jsonPath("$.data.reason").value("GEO_DB_UNUSABLE"));
    }

    @Test
    @DisplayName("数据源不可用（MOCK）：available=false + DATA_SOURCE_UNAVAILABLE")
    void dataSourceUnavailableIsReported() throws Exception {
        baseController();
        ReflectionTestUtils.setField(controller, "geoIpService", fixtureGeo());
        wireSource("MOCK", GeoWindow.unavailable("DATA_SOURCE_UNAVAILABLE"));

        mvc().perform(get("/api/public/geo"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(false))
                .andExpect(jsonPath("$.data.reason").value("DATA_SOURCE_UNAVAILABLE"));
    }

    @Test
    @DisplayName("数据源可用但窗口内没有带来源 IP 的告警：available=true + NO_DATA_IN_WINDOW（不是故障）")
    void emptyWindowIsNotAnError() throws Exception {
        baseController();
        ReflectionTestUtils.setField(controller, "geoIpService", fixtureGeo());
        wireSource("REAL", GeoWindow.empty(111031));

        mvc().perform(get("/api/public/geo"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(true))
                .andExpect(jsonPath("$.data.reason").value("NO_DATA_IN_WINDOW"))
                .andExpect(jsonPath("$.data.coverage.totalAlerts").value(111031))
                .andExpect(jsonPath("$.data.byCountry").isEmpty());
    }

    @Test
    @DisplayName("小时 × 国家：有 per-IP 小时桶 → 24 点真实交叉；拿不到 → available:false 且不摊分")
    void byCountryHourIsRealCrossOrHonestlyUnavailable() throws Exception {
        baseController();
        ReflectionTestUtils.setField(controller, "geoIpService", fixtureGeo());

        // 25 个整点标签（与真实响应同形：extended_bounds 给出首尾两个边界桶，末尾那个是"当前小时"）
        List<GeoAggregator.TrendPoint> trend = new java.util.ArrayList<>();
        for (int i = 0; i <= 24; i++) {
            trend.add(new GeoAggregator.TrendPoint(String.format("2026-10-13T%02d:00", i), 10));
        }

        // 有交叉数据：CN 的 12 条落在 00/01 点，US 的 4 条落在 02 点
        wireSource("REAL", new GeoWindow(true, "OK", null, 1000, 16, false,
                List.of(new GeoAggregator.IpCount("1.0.1.1", 12,
                                java.util.Map.of("2026-10-13T00:00", 5L, "2026-10-13T01:00", 7L)),
                        new GeoAggregator.IpCount("1.0.3.1", 4,
                                java.util.Map.of("2026-10-13T02:00", 4L))),
                trend));

        mvc().perform(get("/api/public/geo"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.byCountryHour.available").value(true))
                .andExpect(jsonPath("$.data.byCountryHour.hours", hasSize(24)))
                .andExpect(jsonPath("$.data.byCountryHour.hours[0]").value("2026-10-13T00:00"))
                .andExpect(jsonPath("$.data.byCountryHour.hours[23]").value("2026-10-13T23:00"))
                .andExpect(jsonPath("$.data.byCountryHour.series[0].country").value("CN"))
                .andExpect(jsonPath("$.data.byCountryHour.series[0].counts", hasSize(24)))
                .andExpect(jsonPath("$.data.byCountryHour.series[0].counts[0]").value(5))
                .andExpect(jsonPath("$.data.byCountryHour.series[0].counts[1]").value(7))
                .andExpect(jsonPath("$.data.byCountryHour.series[0].counts[2]").value(0))
                .andExpect(jsonPath("$.data.byCountryHour.series[1].country").value("US"))
                .andExpect(jsonPath("$.data.byCountryHour.series[1].counts[2]").value(4));

        // 拿不到交叉数据（旧解析/子聚合缺失）：整块 available:false，且**不拿合计摊到小时**
        baseController();
        ReflectionTestUtils.setField(controller, "geoIpService", fixtureGeo());
        wireSource("REAL", new GeoWindow(true, "OK", null, 1000, 16, false,
                List.of(new GeoAggregator.IpCount("1.0.1.1", 12),
                        new GeoAggregator.IpCount("1.0.3.1", 4)),
                trend));

        mvc().perform(get("/api/public/geo"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.byCountryHour.available").value(false))
                .andExpect(jsonPath("$.data.byCountryHour.reason").value("HOUR_CROSS_MISSING"))
                .andExpect(jsonPath("$.data.byCountryHour.hours", hasSize(0)))
                .andExpect(jsonPath("$.data.byCountryHour.series", hasSize(0)))
                // 24h 合计照常给（不因为小时交叉缺失就丢掉既有能力）
                .andExpect(jsonPath("$.data.byCountry[0].country").value("CN"))
                .andExpect(jsonPath("$.data.byCountry[0].count").value(12));
    }

    @Test
    @DisplayName("限流：与其余公开端点同一个桶（20 次/分钟），超了就是 429 + Retry-After")
    void rateLimited() throws Exception {
        baseController();
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 1);
        ReflectionTestUtils.setField(controller, "rateLimiter", limiter);
        ReflectionTestUtils.setField(controller, "geoIpService", fixtureGeo());
        wireSource("REAL", window(10, new GeoAggregator.IpCount("1.0.1.1", 10)));

        mvc().perform(get("/api/public/geo")).andExpect(status().isOk());
        mvc().perform(get("/api/public/geo"))
                .andExpect(status().isTooManyRequests())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .header().string("Retry-After", "60"));
    }

    @Test
    @DisplayName("我方 IP 配置生效：配置里的自用 IP 不进任何榜")
    void selfIpsFromConfigAreExcluded() throws Exception {
        baseController();
        ReflectionTestUtils.setField(controller, "geoIpService", fixtureGeo());
        ReflectionTestUtils.setField(controller, "geoSelfIps", "1.0.1.1 , 1.0.1.2");
        wireSource("REAL", window(100,
                new GeoAggregator.IpCount("1.0.1.1", 90),
                new GeoAggregator.IpCount("1.0.3.1", 10)));

        mvc().perform(get("/api/public/geo"))
                .andExpect(jsonPath("$.data.coverage.excludedSelf").value(90))
                .andExpect(jsonPath("$.data.byCountry[0].country").value("US"));
    }

    @Test
    @DisplayName("配置兜底：门槛被设成 0 时按 1 兜底（不能因为没注入就变成'什么都上榜'）")
    void toleratesUnsetConfig() throws Exception {
        baseController();
        ReflectionTestUtils.setField(controller, "geoMinCount", 0);
        ReflectionTestUtils.setField(controller, "geoTopCountries", 0);
        ReflectionTestUtils.setField(controller, "geoIpService", fixtureGeo());
        wireSource("REAL", window(10, new GeoAggregator.IpCount("1.0.1.1", 10)));

        mvc().perform(get("/api/public/geo"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.thresholds.minCount").value(1));
    }

    @Test
    @DisplayName("公开面只增字段：既有的 /api/public/latest 仍走同一个信封与缓存头（没有被新端点影响）")
    void existingEndpointsUnaffected() throws Exception {
        baseController();
        ReflectionTestUtils.setField(controller, "geoIpService", fixtureGeo());
        wireSource("REAL", window(10, new GeoAggregator.IpCount("1.0.1.1", 10)));
        PublicAuditReader reader = new PublicAuditReader();
        ReflectionTestUtils.setField(reader, "dataDir", tmp.toString());
        ReflectionTestUtils.setField(controller, "auditReader", reader);

        mvc().perform(get("/api/public/geo")).andExpect(status().isOk());
        mvc().perform(get("/api/public/latest")).andExpect(status().isOk())
                .andExpect(jsonPath("$.data.reason").value("NO_DATA_IN_WINDOW"));
    }

    @Test
    @DisplayName("默认没有配置自用 IP：集合为空而不是 null（空集合不该被当成'排除一切'）")
    void defaultSelfIpsIsEmptySet() {
        assertEquals(Set.of(), PublicApiController.parseSelfIps(""));
        assertEquals(Set.of(), PublicApiController.parseSelfIps(null));
        assertEquals(Set.of("1.1.1.1"), PublicApiController.parseSelfIps(" 1.1.1.1 , "));
    }

    /** 公开面出参不允许出现任何 IP 形态字符串（IPv4 与 IPv6 各一条正则） */
    private static void assertNoIpLeak(String body) {
        assertFalse(Pattern.compile("(?<![\\d.])\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(?![\\d.])")
                .matcher(body).find(), "响应体里出现 IPv4：" + body);
        assertFalse(Pattern.compile("(?<![0-9A-Fa-f:])((?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4})(?![0-9A-Fa-f:])")
                .matcher(body).find(), "响应体里出现 IPv6：" + body);
    }
}

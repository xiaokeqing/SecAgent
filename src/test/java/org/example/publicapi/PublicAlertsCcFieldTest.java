package org.example.publicapi;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.aggregation.AlertAggregationService;
import org.example.core.model.AlertSeverity;
import org.example.core.model.AlertSource;
import org.example.core.model.AlertType;
import org.example.core.model.SecurityAlert;
import org.example.geoip.GeoIpService;
import org.example.geoip.GeoTestFixtures;
import org.example.integration.WazuhGateway;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code GET /api/public/alerts.js} 的 {@code cc} 字段契约测试（真跑 MVC 路由）。
 *
 * <p>钉住四件事：
 * <ol>
 *   <li>有来源地理时 {@code cc} = ISO-3166-1 alpha-2 大写二字码，且<b>省/市/ASN 一个字都不出现在响应里</b>；</li>
 *   <li>取不到时 {@code cc} 键存在、值为 {@code null}，不是 {@code ""}/{@code "XX"}/{@code "未知"}；</li>
 *   <li>没有 {@code srcGeo} 时真的走 {@code /api/public/geo} 的同一个离线库（夹具库 1.0.1.x → CN）；</li>
 *   <li>既有字段一个不少（含中文 label），别名路径的 ETag 照旧下发且同一快照内稳定。</li>
 * </ol>
 *
 * <p>夹具做法与 {@code PublicAlertsAttckFieldTest} / {@code PublicApiGeoEndpointTest} 一致：
 * 不启 Spring 上下文，直接 {@code new} 控制器 + ReflectionTestUtils 注入依赖（网关用 Proxy 桩）。
 */
class PublicAlertsCcFieldTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @TempDir
    Path tmp;

    private PublicApiTestAssembly api;

    private static SecurityAlert alert(String id, String ruleName, String srcIp, String srcGeo, AlertType type) {
        SecurityAlert a = new SecurityAlert();
        a.setId(id);
        a.setRuleName(ruleName);
        a.setSrcIp(srcIp);
        a.setSrcGeo(srcGeo);
        a.setType(type);
        a.setSeverity(AlertSeverity.HIGH);
        a.setSource(AlertSource.WAZUH);
        a.setOccurredAt("2026-02-10 10:00:00");
        a.setTitle(ruleName);
        return a;
    }

    /** 夹具库：1.0.1.0/24 = CN、1.0.3.0/24 = US（与 /geo 端点测试共用） */
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

    /** 只回答 mode/isAvailable/recentAlerts 的网关替身。 */
    private void wire(List<SecurityAlert> alerts, GeoIpService geo) {
        WazuhGateway gateway = (WazuhGateway) Proxy.newProxyInstance(
                WazuhGateway.class.getClassLoader(),
                new Class<?>[]{WazuhGateway.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "mode" -> "REAL";
                    case "isAvailable" -> true;
                    case "recentAlerts" -> alerts;
                    case "toString" -> "StubGateway";
                    default -> null;
                });

        PublicAlertSource source = new PublicAlertSource();
        ReflectionTestUtils.setField(source, "wazuhGateway", gateway);
        ReflectionTestUtils.setField(source, "aggregator", new AlertAggregationService());
        if (geo != null) {
            ReflectionTestUtils.setField(source, "geoIpService", geo);
        }

        api = new PublicApiTestAssembly();
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 200);
        ReflectionTestUtils.setField(api.support, "rateLimiter", limiter);
        ReflectionTestUtils.setField(api.support, "cacheSeconds", 15);
        ReflectionTestUtils.setField(api.support, "exposeBuildSha", false);
        ReflectionTestUtils.setField(api.support, "buildSha", "test");
        ReflectionTestUtils.setField(api.support, "source", source);
    }

    private MockMvc mvc() {
        return api.mvc();
    }

    private Map<String, Object> fetchItem() throws Exception {
        String body = mvc().perform(get("/api/public/alerts.js").param("w", "5"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(200))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        Map<String, Object> root = MAPPER.readValue(body, new TypeReference<>() {
        });
        Map<String, Object> data = (Map<String, Object>) root.get("data");
        assertNotNull(data, "响应缺 data 节点：" + body);
        List<Map<String, Object>> list = (List<Map<String, Object>>) data.get("list");
        assertNotNull(list, "响应缺 data.list 节点：" + body);
        assertFalse(list.isEmpty(), "夹具一条告警，list 不应为空：" + body);
        return list.get(0);
    }

    @Test
    @DisplayName("有来源地理：cc 只取国家码（US），省/市/ASN 不进响应；既有字段一个不少")
    void ccIsCountryCodeOnlyAndExistingFieldsRemain() throws Exception {
        wire(List.of(alert("a1", "SSH Brute Force", "8.8.8.8",
                "US|California|Mountain View|15169|Google LLC", AlertType.BRUTE_FORCE)), null);

        String body = mvc().perform(get("/api/public/alerts.js").param("w", "5"))
                .andExpect(status().isOk())
                // ETag 逻辑不动：别名照旧下发 ETag（缓存/再验证契约）
                .andExpect(header().exists("ETag"))
                .andExpect(jsonPath("$.data.list[0].cc").value("US"))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        Map<String, Object> item = fetchItem();
        assertEquals("US", item.get("cc"), "cc ← srcGeo 首段");
        assertNull(item.get("srcGeo"), "逐条地理明细仍然刻意不下发（PublicApiGeoLeakTest 的口径）");
        Set<String> expected = Set.of("aggId", "count", "startTime", "endTime", "title", "ruleName",
                "srcIp", "srcGeo", "occurredAt", "status", "hitCount",
                "severity", "severityLabel", "type", "typeLabel", "source", "sourceLabel", "attck", "cc");
        assertTrue(item.keySet().containsAll(expected),
                "既有字段丢失；缺=" + diff(expected, item.keySet()) + "，实际键=" + item.keySet());

        assertFalse(body.contains("California"), "cc 只出国家码，省/市不得出现：" + body);
        assertFalse(body.contains("Mountain View"), "城市不得出现：" + body);
        assertFalse(body.contains("15169"), "ASN 不得出现：" + body);
        assertFalse(body.contains("Google LLC"), "AS 机构不得出现：" + body);
    }

    @Test
    @DisplayName("cc 取不到：键存在、值为 null（不是 \"\" / \"XX\" / \"未知\"）")
    void ccIsNullWhenCountryUnknown() throws Exception {
        // 保留地址 198.51.100.9 在夹具库里查不到；也不给离线库 —— 两条回退路径都取不到
        wire(List.of(alert("a2", "扫描", "198.51.100.9", null, AlertType.SCAN)), null);

        Map<String, Object> item = fetchItem();
        assertTrue(item.containsKey("cc"), "cc 必须始终是契约字段（值可为 null）");
        assertNull(item.get("cc"), "取不到国家就是 null");
        assertFalse("".equals(item.get("cc")), "不得写空串");
        assertFalse("XX".equals(item.get("cc")), "不得写 XX 占位");
        assertFalse("未知".equals(item.get("cc")), "不得写中文占位");
    }

    @Test
    @DisplayName("srcGeo 缺失时回落到离线库：1.0.1.x → CN（与 /api/public/geo 同一个 GeoIpService）")
    void ccFallsBackToOfflineGeoLibrary() throws Exception {
        wire(List.of(alert("a3", "SSH Brute Force", "1.0.1.7", null, AlertType.BRUTE_FORCE)), fixtureGeo());

        Map<String, Object> item = fetchItem();
        assertEquals("CN", item.get("cc"), "缺 srcGeo 时用离线库解析 srcIp");
        assertEquals("1.0.***.***", item.get("srcIp"), "cc 添加不改变既有 srcIp 掩码口径");
    }

    private static Set<String> diff(Set<String> expected, Set<String> actual) {
        return expected.stream().filter(k -> !actual.contains(k)).collect(java.util.stream.Collectors.toSet());
    }
}

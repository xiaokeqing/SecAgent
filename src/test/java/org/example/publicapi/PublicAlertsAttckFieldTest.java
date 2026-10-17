package org.example.publicapi;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.aggregation.AlertAggregationService;
import org.example.core.model.AlertSeverity;
import org.example.core.model.AlertSource;
import org.example.core.model.AlertType;
import org.example.core.model.SecurityAlert;
import org.example.integration.WazuhGateway;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code GET /api/public/alerts} 的 ATT&amp;CK 字段契约测试。
 *
 * <p>与 {@link AttackTechniqueMapperTest} 的分工：那个测"映射表本身对不对"，这个测
 * "公开响应里到底出现了什么"。三件事必须同时成立：
 * <ol>
 *   <li>聚合项新增 {@code attck} = {id,name,label}；</li>
 *   <li>映射不到的规则该字段为 JSON {@code null}（键存在、值为 null），不是被删掉、
 *       也不是塞一个兜底技术；</li>
 *   <li>既有字段（ruleName/typeLabel/severityLabel/count…）一个都没少、没被改名 ——
 *       前端和历史调用方不感知这次改动。</li>
 * </ol>
 *
 * <p>夹具沿用 {@code PublicAlertsCredentialLeakTest} 的做法：直接 {@code new} 控制器 +
 * ReflectionTestUtils 注入依赖（WazuhGateway 用 Proxy 桩），不启动 Spring 上下文，
 * 因此不受 Redis/网络影响。
 */
class PublicAlertsAttckFieldTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static SecurityAlert alert(String id, String ruleName, String srcIp, AlertType type) {
        SecurityAlert a = new SecurityAlert();
        a.setId(id);
        a.setRuleName(ruleName);
        a.setSrcIp(srcIp);
        a.setType(type);
        a.setSeverity(AlertSeverity.HIGH);
        a.setSource(AlertSource.WAZUH);
        a.setOccurredAt("2026-02-10 10:00:00");
        a.setTitle(ruleName);
        return a;
    }

    private static Map<String, Object> fetchAlerts() throws Exception {
        // 三条告警用不同 srcIp，保证聚合不会被并桶（分桶键是 srcIp+"|"+type）
        List<SecurityAlert> alerts = List.of(
                alert("a1", "SSH Brute Force", "106.37.205.248", AlertType.BRUTE_FORCE),
                alert("a2", "Suricata: Alert - ET SCAN SUSPICIOUS inbound to MSSQL",
                        "45.83.12.9", AlertType.SQL_INJECTION),
                alert("a3", "自定义规则：主机磁盘使用率超过 90%", "91.240.118.5", AlertType.OTHER));

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

        PublicApiController controller = new PublicApiController();
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 200);
        ReflectionTestUtils.setField(controller, "rateLimiter", limiter);
        ReflectionTestUtils.setField(controller, "cacheSeconds", 15);
        ReflectionTestUtils.setField(controller, "exposeBuildSha", false);
        ReflectionTestUtils.setField(controller, "buildSha", "test");
        ReflectionTestUtils.setField(controller, "source", source);

        MockMvc mvc = MockMvcBuilders.standaloneSetup(controller).build();
        String body = mvc.perform(get("/api/public/alerts"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        Map<String, Object> root = MAPPER.readValue(body, new TypeReference<>() {
        });
        Map<String, Object> data = (Map<String, Object>) root.get("data");
        assertNotNull(data, "响应缺 data 节点：" + body);
        return data;
    }

    private static Map<String, Object> itemWithRuleName(Map<String, Object> data, String ruleName) {
        List<Map<String, Object>> list = (List<Map<String, Object>>) data.get("list");
        assertNotNull(list, "响应缺 data.list 节点");
        return list.stream()
                .filter(it -> ruleName.equals(it.get("ruleName")))
                .findFirst()
                .orElseThrow(() -> new AssertionError("data.list 里找不到 ruleName=" + ruleName + "，实际="
                        + list.stream().map(it -> String.valueOf(it.get("ruleName"))).toList()));
    }

    @Test
    @DisplayName("聚合项带 attck={id,name,label}：T1110 / T1190 各自落到对应技术")
    void aggregateItemsCarryAttck() throws Exception {
        Map<String, Object> data = fetchAlerts();

        Map<String, Object> attck = (Map<String, Object>) itemWithRuleName(data, "SSH Brute Force").get("attck");
        assertNotNull(attck, "SSH Brute Force 应有 attck");
        assertEquals("T1110", attck.get("id"));
        assertEquals("暴力破解", attck.get("name"));
        assertEquals("Brute Force", attck.get("label"));

        Map<String, Object> sqli = (Map<String, Object>) itemWithRuleName(
                data, "Suricata: Alert - ET SCAN SUSPICIOUS inbound to MSSQL").get("attck");
        assertNotNull(sqli, "ET SCAN SUSPICIOUS 应有 attck");
        assertEquals("T1190", sqli.get("id"));
        assertEquals("利用面向公众的应用", sqli.get("name"));
        assertEquals("Exploit Public-Facing Application", sqli.get("label"));
    }

    @Test
    @DisplayName("映射不到的规则：attck 键存在且为 null（不是删字段、不是兜底技术）")
    void unknownRuleMapsToNull() throws Exception {
        Map<String, Object> data = fetchAlerts();
        Map<String, Object> item = itemWithRuleName(data, "自定义规则：主机磁盘使用率超过 90%");
        assertTrue(item.containsKey("attck"), "attck 键必须存在（值可以是 null）");
        assertNull(item.get("attck"), "未知规则不许猜，attck 应为 null");
        // 原规则名必须原样保留，前端仍能显示
        assertEquals("自定义规则：主机磁盘使用率超过 90%", item.get("ruleName"));
    }

    @Test
    @DisplayName("向后兼容：既有聚合字段一个不少（含中文 label 与计数字段）")
    void existingAggregateFieldsRemain() throws Exception {
        Map<String, Object> data = fetchAlerts();
        Map<String, Object> item = itemWithRuleName(data, "SSH Brute Force");
        for (String key : List.of("aggId", "count", "startTime", "endTime", "title", "ruleName",
                "srcIp", "srcGeo", "occurredAt", "status", "hitCount",
                "severity", "severityLabel", "type", "typeLabel", "source", "sourceLabel", "attck")) {
            assertTrue(item.containsKey(key), "既有字段丢失：" + key + "，实际键=" + item.keySet());
        }
        assertNotNull(item.get("typeLabel"), "typeLabel 不应为空");
        assertTrue(item.get("typeLabel") instanceof String, "typeLabel 应为中文标签字符串");
    }
}

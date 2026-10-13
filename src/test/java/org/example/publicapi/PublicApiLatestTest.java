package org.example.publicapi;

import org.example.core.model.AlertSeverity;
import org.example.core.model.AlertSource;
import org.example.core.model.AlertType;
import org.example.core.model.SecurityAlert;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code GET /api/public/latest} 的载荷口径测试。
 *
 * <h3>这个端点为什么要有一组专门的测试</h3>
 * 它是"悬空端点"的收口：前端曾经探测它、拿到 404，于是页面上出现了
 * "latest 未就绪 / 用 audit 替代"这类技术免责文字。收口有两条路（实现 / 删除），
 * 选了实现之后，就多出一个<b>匿名可访问</b>的响应体 —— 它的字段白名单与
 * "无数据时如实降级"必须被钉死，否则今天为了页面方便加的字段，
 * 明天就是一个没人评审过的公开数据面。
 */
class PublicApiLatestTest {

    private static SecurityAlert alert(String id, AlertSeverity sev, String ip, String at) {
        SecurityAlert a = new SecurityAlert(id, "标题不该出现在公网出参里", sev, AlertType.SCAN, AlertSource.WAZUH);
        a.setRuleName("规则名也不该出现");
        a.setSrcIp(ip);
        a.setDstIp("10.0.10.21");        // 内网目的地址：绝不允许出现在公网出参
        a.setDstAsset("web-01");         // 资产名：同上
        a.setOccurredAt(at);
        a.setRawLog("原始日志：绝不允许出现");
        return a;
    }

    @Test
    @DisplayName("有数据：available=true，等级/来源分布按窗口聚合，最近一条取时间最大者")
    void availablePayloadAggregatesWindow() {
        List<SecurityAlert> alerts = new ArrayList<>();
        alerts.add(alert("a1", AlertSeverity.HIGH, "45.83.91.12", "2026-10-13 10:00:00"));
        alerts.add(alert("a2", AlertSeverity.HIGH, "45.83.91.12", "2026-10-13 10:05:00"));
        alerts.add(alert("a3", AlertSeverity.CRITICAL, "203.0.113.9", "2026-10-13 12:30:00"));
        alerts.add(alert("a4", AlertSeverity.MEDIUM, "198.51.100.7", "2026-10-13 09:00:00"));

        Map<String, Object> out = PublicApiController.buildLatest(
                alerts, true, "REAL", 200, 15, "2026-10-13 13:00:00", List.of());

        assertEquals(true, out.get("available"));
        assertEquals("OK", out.get("reason"));
        assertEquals("REAL", out.get("wazuhMode"));
        assertEquals(200, out.get("windowSize"));
        assertEquals(4, out.get("windowAlertCount"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> sev = (List<Map<String, Object>>) out.get("severityCounts");
        assertEquals(AlertSeverity.values().length, sev.size(), "等级分布固定输出全部档位，前端不必兜底");
        assertEquals(1L, countOf(sev, "CRITICAL"));
        assertEquals(2L, countOf(sev, "HIGH"));
        assertEquals(1L, countOf(sev, "MEDIUM"));
        assertEquals(0L, countOf(sev, "LOW"));

        @SuppressWarnings("unchecked")
        Map<String, Object> ev = (Map<String, Object>) out.get("latestEvent");
        assertNotNull(ev);
        assertEquals("2026-10-13 12:30:00", ev.get("occurredAt"));
        assertEquals("CRITICAL", ev.get("severity"));
        assertEquals("严重", ev.get("severityLabel"));
        assertEquals("203.0.***.***", ev.get("srcIp"), "来源 IP 必须掩码到网段（保留前两段）");

        assertNull(out.get("latestBlock"), "没有封禁记录时如实为 null，不编一条出来");
    }

    @Test
    @DisplayName("公网出参不含标题/规则名/内网目的地址/资产名/原始日志（字段白名单）")
    void payloadNeverLeaksInternalFields() {
        List<SecurityAlert> alerts = List.of(
                alert("a1", AlertSeverity.CRITICAL, "45.83.91.12", "2026-10-13 12:30:00"));
        Map<String, Object> out = PublicApiController.buildLatest(
                alerts, true, "REAL", 200, 15, "2026-10-13 13:00:00", List.of());

        assertFalse(flat(out).contains("标题不该出现在公网出参里"), flat(out));
        assertFalse(flat(out).contains("规则名也不该出现"), flat(out));
        assertFalse(flat(out).contains("10.0.10.21"), "内网目的地址不得出现：" + flat(out));
        assertFalse(flat(out).contains("web-01"), "资产名不得出现：" + flat(out));
        assertFalse(flat(out).contains("原始日志"), "原始日志不得出现：" + flat(out));
        // 聚合 id / 成员 id 也不在出参里（那是内部簇标识）
        assertFalse(flat(out).contains("memberIds"), flat(out));
    }

    @Test
    @DisplayName("数据源不可用：available=false + DATA_SOURCE_UNAVAILABLE，且绝不用 0 冒充太平")
    void unavailableIsHonest() {
        Map<String, Object> out = PublicApiController.buildLatest(
                List.of(), false, "MOCK", 200, 15, "2026-10-13 13:00:00", List.of());

        assertEquals(false, out.get("available"));
        assertEquals("DATA_SOURCE_UNAVAILABLE", out.get("reason"));
        assertEquals("MOCK", out.get("wazuhMode"));
        assertEquals(0, out.get("windowAlertCount"));
        assertNull(out.get("latestEvent"));
        assertTrue(String.valueOf(out.get("note")).contains("不展示任何告警数字"), String.valueOf(out.get("note")));
        assertFalse(out.containsKey("severityCounts"),
                "不可用时不该给出一张全 0 的分布图 —— 那会被前端画成「一切正常」");
    }

    @Test
    @DisplayName("数据源可用但窗口内确实没有告警：区分成 NO_DATA_IN_WINDOW（不是故障）")
    void emptyButHealthyIsDifferentFromUnavailable() {
        Map<String, Object> out = PublicApiController.buildLatest(
                List.of(), false, "REAL", 200, 15, "2026-10-13 13:00:00", List.of());

        assertEquals(false, out.get("available"));
        assertEquals("NO_DATA_IN_WINDOW", out.get("reason"));
        assertTrue(String.valueOf(out.get("note")).contains("没有任何真实告警"), String.valueOf(out.get("note")));
    }

    @Test
    @DisplayName("时间解析不出来的告警不冒充「最近一条」")
    void unparseableTimeNeverBecomesLatest() {
        List<SecurityAlert> alerts = new ArrayList<>();
        alerts.add(alert("bad", AlertSeverity.CRITICAL, "45.83.91.12", "不是时间"));
        alerts.add(alert("good", AlertSeverity.HIGH, "45.83.91.12", "2026-10-13 11:00:00"));

        Map<String, Object> out = PublicApiController.buildLatest(
                alerts, true, "REAL", 200, 15, "2026-10-13 13:00:00", List.of());

        @SuppressWarnings("unchecked")
        Map<String, Object> ev = (Map<String, Object>) out.get("latestEvent");
        assertEquals("2026-10-13 11:00:00", ev.get("occurredAt"),
                "解析不了时间的要先跳过，不能让 null 时间排到最前");
    }

    @Test
    @DisplayName("带最近一次封禁时原样复用已掩码的封禁记录（不新增字段）")
    void latestBlockIsReusedVerbatim() {
        Map<String, Object> block = new LinkedHashMap<>();
        block.put("id", "BLK-1");
        block.put("ip", "45.83.***.***");
        block.put("source", "智能体");

        Map<String, Object> out = PublicApiController.buildLatest(
                List.of(alert("a1", AlertSeverity.HIGH, "45.83.91.12", "2026-10-13 11:00:00")),
                true, "REAL", 200, 15, "2026-10-13 13:00:00", List.of(block));

        @SuppressWarnings("unchecked")
        Map<String, Object> got = (Map<String, Object>) out.get("latestBlock");
        assertEquals("45.83.***.***", got.get("ip"));
        assertEquals("BLK-1", got.get("id"));
    }

    private static long countOf(List<Map<String, Object>> buckets, String key) {
        for (Map<String, Object> b : buckets) {
            if (key.equals(b.get("key"))) {
                return ((Number) b.get("count")).longValue();
            }
        }
        throw new AssertionError("分布里缺少档位 " + key + "：" + buckets);
    }

    /** 把嵌套结构拍平成一段文本，用于"某些字段绝对不许出现"的断言 */
    private static String flat(Object o) {
        StringBuilder sb = new StringBuilder();
        flatten(o, sb);
        return sb.toString();
    }

    private static void flatten(Object o, StringBuilder sb) {
        if (o instanceof Map<?, ?> m) {
            m.forEach((k, v) -> {
                sb.append(k).append('=');
                flatten(v, sb);
                sb.append(';');
            });
        } else if (o instanceof List<?> l) {
            l.forEach(v -> flatten(v, sb));
        } else {
            sb.append(String.valueOf(o));
        }
    }
}

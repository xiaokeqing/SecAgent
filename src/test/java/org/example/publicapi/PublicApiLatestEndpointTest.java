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
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code GET /api/public/latest} 的<b>端点契约</b>测试（真跑一遍 MVC 路由 + 信封）。
 *
 * <p>{@link PublicApiLatestTest} 钉的是"载荷字段口径"，这里钉的是
 * "这个 URL 真的存在、真的返回 200、真的按既有信封（code/message/data）回话" ——
 * 这次收口的起因正是"前端探测这个 URL 拿到 404"，所以"路由存在"本身就是验收项。
 *
 * <h3>为什么不用 Mockito，而用动态代理造替身</h3>
 * 一是本仓库既有测试就是这么做替身的（见 {@code PublicAlertSourceFailClosedTest}），
 * 保持一致比换工具重要；二是这里要验证的是<b>数据源到响应体这一整条真实链路</b>
 * （含 fail-closed 剔除与 IP 掩码），mock 掉 {@code PublicAlertSource} 反而把
 * 最该被验证的那段逻辑替换掉了。
 */
class PublicApiLatestEndpointTest {

    private PublicApiController controller;

    @TempDir
    Path dataDir;

    @BeforeEach
    void setUp() throws Exception {
        controller = new PublicApiController();
        PublicRateLimiter limiter = new PublicRateLimiter();
        // 无 Spring 上下文时 @Value 不生效，字段是 0 → limitPerMinute() 兜底成 1。
        // 显式设成与 application.yml 一致的 20，才能断言"响应头里的限流值与线上一致"。
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 20);
        ReflectionTestUtils.setField(controller, "rateLimiter", limiter);
        ReflectionTestUtils.setField(controller, "cacheSeconds", 15);
        ReflectionTestUtils.setField(controller, "exposeBuildSha", false);
        ReflectionTestUtils.setField(controller, "buildSha", "test");

        // 用真实的 PublicAuditReader，喂一个临时数据目录：
        // 于是"封禁记录怎么被掩码、怎么被挑字段"也是真跑出来的，而不是我手写的期望值
        PublicAuditReader reader = new PublicAuditReader();
        ReflectionTestUtils.setField(reader, "dataDir", dataDir.toString());
        Files.writeString(dataDir.resolve("blocked-ips.json"),
                "[{\"id\":\"BLK-1\",\"ip\":\"45.83.91.12\",\"durationMinutes\":60,"
                        + "\"source\":\"智能体\",\"actor\":\"admin\",\"auditId\":\"AUD-1\","
                        + "\"createdAt\":\"2026-10-13 12:00:00\",\"expiresAt\":\"2026-10-13 13:00:00\","
                        + "\"unblocked\":false}]", StandardCharsets.UTF_8);
        ReflectionTestUtils.setField(controller, "auditReader", reader);
    }

    private MockMvc mvc() {
        return MockMvcBuilders.standaloneSetup(controller).build();
    }

    private void wireSource(String mode, List<SecurityAlert> alerts) {
        WazuhGateway gateway = (WazuhGateway) Proxy.newProxyInstance(
                WazuhGateway.class.getClassLoader(),
                new Class<?>[]{WazuhGateway.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "mode" -> mode;
                    case "isAvailable" -> "REAL".equalsIgnoreCase(mode);
                    case "recentAlerts" -> alerts;
                    case "toString" -> "StubGateway(" + mode + ")";
                    default -> null;
                });
        PublicAlertSource source = new PublicAlertSource();
        ReflectionTestUtils.setField(source, "wazuhGateway", gateway);
        ReflectionTestUtils.setField(source, "aggregator", new AlertAggregationService());
        ReflectionTestUtils.setField(controller, "source", source);
    }

    private static SecurityAlert alert(String id, AlertSeverity sev, String ip, String at) {
        SecurityAlert a = new SecurityAlert(id, "内部标题不该出现在响应里", sev, AlertType.SCAN, AlertSource.SURICATA);
        a.setSrcIp(ip);
        a.setDstIp("10.0.10.21");
        a.setDstAsset("web-01");
        a.setOccurredAt(at);
        return a;
    }

    @Test
    @DisplayName("有真实数据：200 + 既有信封 + 可用性字段 + 掩码来源 + 内网地址不出现")
    void returnsAggregatedSummaryWhenDataAvailable() throws Exception {
        wireSource("REAL", List.of(
                alert("a1", AlertSeverity.HIGH, "45.83.91.12", "2026-10-13 10:00:00"),
                alert("a2", AlertSeverity.CRITICAL, "203.0.113.9", "2026-10-13 12:00:00")));

        String body = mvc().perform(get("/api/public/latest"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(200))
                .andExpect(jsonPath("$.message").value("success"))
                .andExpect(jsonPath("$.data.available").value(true))
                .andExpect(jsonPath("$.data.reason").value("OK"))
                .andExpect(jsonPath("$.data.wazuhMode").value("REAL"))
                .andExpect(jsonPath("$.data.windowAlertCount").value(2))
                .andExpect(jsonPath("$.data.latestEvent.severity").value("CRITICAL"))
                .andExpect(jsonPath("$.data.latestEvent.typeLabel").exists())
                .andExpect(jsonPath("$.data.latestBlock.ip").value("45.83.***.***"))
                .andReturn().getResponse().getContentAsString();

        assertFalse(body.contains("10.0.10.21"), "内网目的地址不得出现在公网响应里：" + body);
        assertFalse(body.contains("45.83.91.12"), "完整来源 IP 不得出现（必须掩码）：" + body);
        assertFalse(body.contains("内部标题"), "内部标题不得出现：" + body);
        assertFalse(body.contains("web-01"), "资产名不得出现：" + body);
    }

    @Test
    @DisplayName("数据源不可用：仍然 200，但 available=false + 原因（不是 500、不是空 body）")
    void returnsHonestDegradedPayloadWhenUnavailable() throws Exception {
        wireSource("MOCK", List.of(alert("a1", AlertSeverity.HIGH, "45.83.91.12", "2026-10-13 10:00:00")));

        mvc().perform(get("/api/public/latest"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(false))
                .andExpect(jsonPath("$.data.reason").value("DATA_SOURCE_UNAVAILABLE"))
                .andExpect(jsonPath("$.data.wazuhMode").value("MOCK"))
                .andExpect(jsonPath("$.data.note").exists())
                .andExpect(jsonPath("$.data.latestEvent").doesNotExist());
    }

    @Test
    @DisplayName("端点真实存在（不再落到全局 404 兜底）：REAL 但窗口内无告警 → NO_DATA_IN_WINDOW")
    void endpointIsMappedNot404() throws Exception {
        wireSource("REAL", List.of());

        mvc().perform(get("/api/public/latest"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.reason").value("NO_DATA_IN_WINDOW"));
    }

    @Test
    @DisplayName("Rate-Limit / Cache-Control 与其余公开端点同一套（限流头与缓存头都在）")
    void usesSameHeadersAsOtherPublicEndpoints() throws Exception {
        wireSource("REAL", List.of(alert("a1", AlertSeverity.HIGH, "45.83.91.12", "2026-10-13 10:00:00")));

        mvc().perform(get("/api/public/latest"))
                .andExpect(status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .header().string("X-RateLimit-Limit", "20"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .header().string("Cache-Control", "public, max-age=15"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .header().exists("X-Data-Source"));
    }
}

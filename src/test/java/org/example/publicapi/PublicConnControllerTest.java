package org.example.publicapi;

import org.example.geoip.GeoIpInfo;
import org.example.geoip.GeoIpService;
import org.example.integration.SuricataGateway;
import org.example.integration.WazuhGateway;
import org.example.integration.suricata.FlowEvent;
import org.example.integration.suricata.Ja3Count;
import org.example.integration.suricata.PortCount;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;
import java.util.List;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 公开连接面板：未登录可读，但只给端口/国家/JA3 的聚合；
 * IP 固定遮蔽成 {@code 1.2.3.x}，内网地址直接拒绝。
 */
class PublicConnControllerTest {

    private static final Instant NOW = Instant.parse("2026-11-07T12:00:00Z");

    @Test
    void anonymousRequestGetsOnlyAggregates() throws Exception {
        MockMvc mvc = mvc(new PublicConnController(support(), gateway("REAL", List.of())));

        String body = mvc.perform(get("/api/public/conn.js"))   // 不带任何 Authorization
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", containsString("public")))
                .andExpect(jsonPath("$.data.mode").value("REAL"))
                .andExpect(jsonPath("$.data.view").value("all"))
                .andExpect(jsonPath("$.data.ports[0].port").value(22))
                .andExpect(jsonPath("$.data.ports[0].count").value(5))
                .andExpect(jsonPath("$.data.ports[1].port").value(443))
                .andExpect(jsonPath("$.data.ja3[0].ja3").value("abc123def456"))
                .andExpect(jsonPath("$.data.ja3[0].count").value(3))
                .andExpect(jsonPath("$.data.ipDisclosure.masked").value(true))
                .andExpect(jsonPath("$.data.ipDisclosure.notice").value(containsString("1.2.3.x")))
                .andReturn().getResponse().getContentAsString();

        // 公开投影里不能出现目的地址/内网地址
        Assertions.assertFalse(body.contains("10.0.0.10"), "公开响应不得包含内网目的地址");
    }

    @Test
    void ipIsMaskedAndInternalIpIsRefused() throws Exception {
        List<FlowEvent> flows = List.of(
                connection("45.205.1.230"), connection("45.205.1.230"), connection("45.205.1.230"));
        PublicConnController controller = new PublicConnController(support(), gateway("REAL", flows));
        ReflectionTestUtils.setField(controller, "geoIpService", geo());
        MockMvc mvc = mvc(controller);

        String body = mvc.perform(get("/api/public/conn.js")
                        .param("view", "by-ip")
                        .param("ip", "45.205.1.230")
                        .param("limit", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.ip").value("45.205.1.x"))
                .andExpect(jsonPath("$.data.countries[0].country").value("US"))
                .andExpect(jsonPath("$.data.countries[0].count").value(3))
                .andReturn().getResponse().getContentAsString();
        Assertions.assertFalse(body.contains("45.205.1.230"), "公开响应不得包含完整 IP");

        // 内网/保留地址：不查、不展示、不回显
        String internal = mvc.perform(get("/api/public/conn.js")
                        .param("view", "by-ip")
                        .param("ip", "10.0.0.5"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("INTERNAL_IP"))
                .andReturn().getResponse().getContentAsString();
        Assertions.assertFalse(internal.contains("10.0.0.5"), "拒绝信息不得回显内网地址");
    }

    private static MockMvc mvc(PublicConnController controller) {
        return MockMvcBuilders.standaloneSetup(controller)
                .addFilters(new PublicEtagFilter())
                .build();
    }

    private static FlowEvent connection(String srcIp) {
        return new FlowEvent("flow", NOW, srcIp, 41000, "10.0.0.10", 22, "TCP", "ssh",
                120L, 340L, 4L, 5L, NOW, NOW);
    }

    private static GeoIpService geo() {
        return new GeoIpService() {
            @Override
            public GeoIpInfo lookup(String ip) {
                return new GeoIpInfo("US", null, null, 0, null);
            }
        };
    }

    private static SuricataGateway gateway(String mode, List<FlowEvent> flows) {
        return (SuricataGateway) java.lang.reflect.Proxy.newProxyInstance(
                SuricataGateway.class.getClassLoader(),
                new Class<?>[]{SuricataGateway.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "mode" -> mode;
                    case "isAvailable" -> "REAL".equalsIgnoreCase(mode);
                    case "topDestPorts" -> List.of(new PortCount(22, 5), new PortCount(443, 2));
                    case "ja3Stats" -> List.of(new Ja3Count("abc123def456", 3));
                    case "connectionsByIp" -> flows;
                    case "topSni" -> List.of();
                    case "recentNetworkAlerts" -> List.of();
                    default -> null;
                });
    }

    private static PublicApiSupport support() {
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 20);

        PublicAlertSource source = new PublicAlertSource();
        ReflectionTestUtils.setField(source, "wazuhGateway", realGateway());

        PublicApiSupport support = new PublicApiSupport();
        ReflectionTestUtils.setField(support, "rateLimiter", limiter);
        ReflectionTestUtils.setField(support, "source", source);
        ReflectionTestUtils.setField(support, "cacheSeconds", 15);
        ReflectionTestUtils.setField(support, "ipPolicy", PublicIpPolicy.of(false));
        return support;
    }

    private static WazuhGateway realGateway() {
        return (WazuhGateway) java.lang.reflect.Proxy.newProxyInstance(
                WazuhGateway.class.getClassLoader(),
                new Class<?>[]{WazuhGateway.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "mode" -> "REAL";
                    case "isAvailable" -> true;
                    case "recentAlerts" -> List.of();
                    default -> null;
                });
    }
}

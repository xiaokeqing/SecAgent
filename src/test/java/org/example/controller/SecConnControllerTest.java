package org.example.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.example.core.model.SecurityAlert;
import org.example.integration.SuricataGateway;
import org.example.integration.suricata.FlowEvent;
import org.example.integration.suricata.Ja3Count;
import org.example.integration.suricata.PortCount;
import org.example.integration.suricata.SniCount;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@link SecConnController} 的响应契约测试（standalone MockMvc，不起 Spring 上下文）。
 *
 * <p>钉住三点：
 * ① 每条响应都带 {@code data.mode} —— 前端要靠它区分"真的没有这个 IP"和"根本没读到 eve.json"；
 * ② 字段名/嵌套结构是前端直接用的，改了会静默让页面变空；
 * ③ 非法参数（limit=0）收敛成下限而不是 400。
 */
class SecConnControllerTest {

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        // standalone 默认的 MappingJackson2HttpMessageConverter 只有裸 ObjectMapper，
        // 没有 JavaTimeModule 时 Instant 直接序列化失败 / 变成 epoch 数字 —— 那是测试脚手架的差异。
        // 生产里 Spring Boot 的 JacksonAutoConfiguration 会注册 JavaTimeModule 并关闭
        // WRITE_DATES_AS_TIMESTAMPS（否则时间会变成 1793930400.000000000 这种数字），
        // 所以这里按同样的口径建 converter，测到的才是前端真实拿到的 JSON。
        ObjectMapper bootLike = Jackson2ObjectMapperBuilder.json()
                .featuresToDisable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .build();
        mvc = MockMvcBuilders.standaloneSetup(new SecConnController(new StubGateway()))
                .setMessageConverters(new MappingJackson2HttpMessageConverter(bootLike))
                .build();
    }

    @Test
    @DisplayName("top-ports 返回 mode 与按次数降序的端口列表")
    void topPortsShape() throws Exception {
        mvc.perform(get("/api/sec/conn/top-ports").param("minutes", "15").param("limit", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(200))
                .andExpect(jsonPath("$.data.mode").value("REAL"))
                .andExpect(jsonPath("$.data.minutes").value(15))
                .andExpect(jsonPath("$.data.ports[0].port").value(443))
                .andExpect(jsonPath("$.data.ports[0].count").value(3))
                .andExpect(jsonPath("$.data.ports[1].port").value(3389));
    }

    @Test
    @DisplayName("by-ip 返回连接列表，空 IP 返回空数组而不是 500")
    void byIpShape() throws Exception {
        mvc.perform(get("/api/sec/conn/by-ip").param("ip", "10.0.0.5"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.mode").value("REAL"))
                .andExpect(jsonPath("$.data.connections[0].srcIp").value("10.0.0.5"))
                .andExpect(jsonPath("$.data.connections[0].destPort").value(443))
                // Instant 必须序列化成 ISO 字符串，否则前端按字符串解析会拿到时间戳数字
                .andExpect(jsonPath("$.data.connections[0].ts").value("2026-11-06T02:00:00Z"))
                .andExpect(jsonPath("$.data.total").value(1));

        mvc.perform(get("/api/sec/conn/by-ip").param("ip", " "))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.total").value(0));
    }

    @Test
    @DisplayName("tls-stats 同时返回 SNI 与 JA3 两个榜")
    void tlsStatsShape() throws Exception {
        mvc.perform(get("/api/sec/conn/tls-stats").param("minutes", "60"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.mode").value("REAL"))
                .andExpect(jsonPath("$.data.topSni[0].sni").value("a.example.com"))
                .andExpect(jsonPath("$.data.ja3[0].ja3").value("ja3-aaa"));
    }

    @Test
    @DisplayName("limit=0 收敛到 1，不报 400")
    void clampsBadParams() throws Exception {
        mvc.perform(get("/api/sec/conn/top-ports").param("limit", "0"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.ports.length()").value(1));
    }

    /** 固定返回值的网关桩：这里测的是 HTTP 层的形状，不测统计逻辑（统计在 SuricataEventQueryTest 里）。 */
    private static final class StubGateway implements SuricataGateway {
        @Override
        public boolean isAvailable() {
            return true;
        }

        @Override
        public String mode() {
            return "REAL";
        }

        @Override
        public List<SecurityAlert> recentNetworkAlerts(int limit) {
            return List.of();
        }

        @Override
        public List<FlowEvent> connectionsByIp(String ip, int limit) {
            return List.of(new FlowEvent("flow", Instant.parse("2026-11-06T02:00:00Z"),
                    "10.0.0.5", 50000, "10.0.0.9", 443, "TCP", "tls",
                    1200, 8000, 10, 12, Instant.parse("2026-11-06T01:59:59Z"),
                    Instant.parse("2026-11-06T02:00:00Z")));
        }

        @Override
        public List<PortCount> topDestPorts(int minutes, int limit) {
            return List.of(new PortCount(443, 3), new PortCount(3389, 2)).subList(0, Math.min(limit, 2));
        }

        @Override
        public List<SniCount> topSni(int minutes, int limit) {
            return List.of(new SniCount("a.example.com", 3)).subList(0, Math.min(limit, 1));
        }

        @Override
        public List<Ja3Count> ja3Stats(int minutes, int limit) {
            return List.of(new Ja3Count("ja3-aaa", 3)).subList(0, Math.min(limit, 1));
        }
    }
}

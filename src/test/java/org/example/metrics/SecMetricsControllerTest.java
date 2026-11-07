package org.example.metrics;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;

import static org.example.metrics.MetricsTestFixtures.NOW;
import static org.example.metrics.MetricsTestFixtures.unblockedBlock;
import static org.example.metrics.MetricsTestFixtures.wazuhAlert;
import static org.example.metrics.MetricsTestFixtures.service;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 端点层单测：只验证统一信封与参数收敛，统计口径由 {@link MetricsSummaryServiceTest} 覆盖。
 */
class SecMetricsControllerTest {

    private MockMvc mvc(List<org.example.core.model.SecurityAlert> alerts,
                        List<org.example.response.BlockRecord> blocks) {
        MetricsSummaryService svc = service("REAL", alerts, "REAL", List.of(), blocks);
        return MockMvcBuilders.standaloneSetup(new SecMetricsController(svc)).build();
    }

    @Test
    @DisplayName("GET /api/sec/metrics/summary：统一信封 {code,message,data}，mode 在 data 里")
    void wrapsDataInEnvelope() throws Exception {
        MockMvc mvc = mvc(
                List.of(wazuhAlert("a1", "198.51.100.1", NOW.minusMinutes(40)),
                        wazuhAlert("a2", "198.51.100.2", NOW.minusMinutes(30))),
                List.of(unblockedBlock("198.51.100.1", NOW.minusMinutes(20), NOW.minusMinutes(5),
                        NOW.minusMinutes(5), "自动")));

        mvc.perform(get("/api/sec/metrics/summary"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(200))
                .andExpect(jsonPath("$.message").value("success"))
                .andExpect(jsonPath("$.data.mode").value("REAL"))
                .andExpect(jsonPath("$.data.window.hours").value(24))
                .andExpect(jsonPath("$.data.mttd.available").value(false))
                .andExpect(jsonPath("$.data.mttd.reason").value("样本不足"))
                .andExpect(jsonPath("$.data.mttr.available").value(false))
                .andExpect(jsonPath("$.data.samples.alerts").value(2))
                .andExpect(jsonPath("$.data.samples.blocks").value(1))
                .andExpect(jsonPath("$.data.worst").isArray());
    }

    @Test
    @DisplayName("hours 参数：缺省 24，越界收敛到 1..168（不返回 400）")
    void hoursIsClampedToRange() throws Exception {
        MockMvc mvc = mvc(List.of(), List.of());

        mvc.perform(get("/api/sec/metrics/summary"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.window.hours").value(24));

        mvc.perform(get("/api/sec/metrics/summary").param("hours", "0"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.window.hours").value(1));

        mvc.perform(get("/api/sec/metrics/summary").param("hours", "999"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.window.hours").value(168));

        mvc.perform(get("/api/sec/metrics/summary").param("hours", "72"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.window.hours").value(72));
    }
}

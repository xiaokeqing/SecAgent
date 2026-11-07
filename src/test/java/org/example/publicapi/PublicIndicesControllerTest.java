package org.example.publicapi;

import org.example.integration.WazuhGateway;
import org.example.integration.wazuh.WazuhService;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 公开索引面板：REAL 时如实返回条目/占用，取不到时必须是 MOCK + 空数组，
 * 且 MOCK 结果不进 60 秒缓存（数据源恢复后第一次请求就能看到）。
 */
class PublicIndicesControllerTest {

    @Test
    void returnsRealIndexStatsAndCachesThem() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("available", true);
        raw.put("total", 1234L);
        List<Map<String, Object>> list = new ArrayList<>();
        list.add(entry("wazuh-alerts-4.x-2026.11.01", 1000L, 204800L, "2026-11-01"));
        list.add(entry("wazuh-alerts-4.x-2026.11.02", 234L, 40960L, "2026-11-02"));
        raw.put("indices", list);
        raw.put("note", "已读取 2 个日索引的 _cat/indices 统计（bytes=b）");

        WazuhService wazuh = new WazuhService() {
            @Override
            public String mode() {
                return "REAL";
            }

            @Override
            public Map<String, Object> alertIndices(int days) {
                calls.incrementAndGet();
                return raw;
            }
        };
        MockMvc mvc = mvc(new PublicIndicesController(support(), wazuh));

        mvc.perform(get("/api/public/indices.js"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", containsString("public")))
                .andExpect(jsonPath("$.data.mode").value("REAL"))
                .andExpect(jsonPath("$.data.retentionDays").value(7))
                .andExpect(jsonPath("$.data.total").value(1234))
                .andExpect(jsonPath("$.data.indices[0].name").value("wazuh-alerts-4.x-2026.11.01"))
                .andExpect(jsonPath("$.data.indices[0].docs").value(1000))
                .andExpect(jsonPath("$.data.indices[0].bytesEstimate").value(204800))
                .andExpect(jsonPath("$.data.indices[0].date").value("2026-11-01"))
                .andExpect(jsonPath("$.data.indices[1].name").value("wazuh-alerts-4.x-2026.11.02"))
                .andExpect(jsonPath("$.data.note").value(containsString("_cat/indices")));

        // 第二次请求命中 60 秒进程内缓存：不再打 indexer
        mvc.perform(get("/api/public/indices"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.total").value(1234));
        org.junit.jupiter.api.Assertions.assertEquals(1, calls.get(),
                "REAL 结果应命中 60 秒缓存，第二次请求不应再查询数据源");
    }

    @Test
    void unavailableSourceIsMockWithNoFabricatedNumbers() throws Exception {
        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("available", false);
        raw.put("reason", "QUERY_FAILED");
        raw.put("note", "索引统计查询失败（indexer 连接超时）");

        WazuhService wazuh = new WazuhService() {
            @Override
            public String mode() {
                return "MOCK";
            }

            @Override
            public Map<String, Object> alertIndices(int days) {
                return raw;
            }
        };
        MockMvc mvc = mvc(new PublicIndicesController(support(), wazuh));

        String body = mvc.perform(get("/api/public/indices.js"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.mode").value("MOCK"))
                .andExpect(jsonPath("$.data.retentionDays").value(7))
                .andExpect(jsonPath("$.data.total").value(0))
                .andExpect(jsonPath("$.data.indices").isEmpty())
                .andExpect(jsonPath("$.data.note").value(containsString("QUERY_FAILED")))
                .andExpect(jsonPath("$.data.note").value(containsString("indexer 连接超时")))
                .andReturn().getResponse().getContentAsString();

        // MOCK 时绝不能出现任何条目数字（0 只是"没有数据"，note 已说明原因）
        org.junit.jupiter.api.Assertions.assertFalse(body.contains("1000"),
                "MOCK 响应不得包含编造的条目数");
    }

    private static MockMvc mvc(PublicIndicesController controller) {
        return MockMvcBuilders.standaloneSetup(controller)
                .addFilters(new PublicEtagFilter())
                .build();
    }

    private static Map<String, Object> entry(String name, long docs, long bytes, String date) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", name);
        m.put("docs", docs);
        m.put("bytesEstimate", bytes);
        m.put("date", date);
        return m;
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

    /** 只回答 mode/isAvailable 的网关替身（PublicApiSupport.ok 读它定 X-Data-Source）。 */
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

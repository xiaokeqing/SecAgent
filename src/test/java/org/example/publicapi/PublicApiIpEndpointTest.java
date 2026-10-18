package org.example.publicapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code GET /api/public/ip?q=<ip>}（个人版 AbuseIPDB）的端点契约测试。
 *
 * <p>它钉的是四件事：
 * <ol>
 *   <li><b>正常 IP</b>：字段真的按口径出现在 {@code data} 里，{@code credStructure}
 *       只给结构（{@code 6 位} + {@code 弱口令}），<b>口令原文一个字符都不进响应体</b>；</li>
 *   <li><b>无数据的 IP</b>：仍然 <b>200</b>，各项写 null 而不是 0 —— "读不到"不能被读成
 *       "这个 IP 什么都没干"；{@code notes[]} 必须非空（说明为什么是 null）；</li>
 *   <li><b>非法 IP</b>：非 IPv4 字面量 / 内网保留地址 / 缺参数 → <b>400</b> + 机读 reason，
 *       且 {@code Cache-Control: no-store}；</li>
 *   <li>复用既有外壳：{@code Cache-Control: public, max-age=15} 的公共缓存口径。</li>
 * </ol>
 */
class PublicApiIpEndpointTest {

    @TempDir
    Path tmp;

    private final ObjectMapper mapper = new ObjectMapper();

    private static final String IP = "45.155.205.233";

    /** 允许出现的字段（形状冻结：多一个少一个都会有测试红） */
    private static final List<String> IP_FIELDS = List.of(
            "generatedAt", "cacheSeconds", "window", "windowHours", "available", "reason",
            "query", "ipVersion", "firstSeen", "lastSeen", "events", "byKind", "ports",
            "credStructure", "threat", "geo", "banned", "sources", "limits", "notes", "note");

    // ==================== 夹具 ====================

    /** 索引侧替身：直接给一份固定的 {@code ipActivity} 结果（不打真网关） */
    private static PublicAlertSource sourceStub(Map<String, Object> activity) {
        // 控制器 ok(...) 会读 source.available() 填 X-Data-Source，所以替身连 mode/available 一起给
        boolean ok = activity != null && Boolean.TRUE.equals(activity.get("available"));
        return new PublicAlertSource() {
            @Override
            public String mode() {
                return ok ? "REAL" : "MOCK";
            }

            @Override
            public boolean available() {
                return ok;
            }

            @Override
            public Map<String, Object> ipActivity(String srcIp, int windowHours) {
                return activity;
            }
        };
    }

    private PublicIpProfileService service(PublicAlertSource source) {
        PublicAuditReader reader = new PublicAuditReader();
        ReflectionTestUtils.setField(reader, "dataDir", tmp.toString());
        ReflectionTestUtils.setField(reader, "ipPolicy", PublicIpPolicy.of(false));

        PublicIpProfileService svc = new PublicIpProfileService();
        ReflectionTestUtils.setField(svc, "source", source);
        ReflectionTestUtils.setField(svc, "auditReader", reader);
        ReflectionTestUtils.setField(svc, "ipPolicy", PublicIpPolicy.of(false));
        ReflectionTestUtils.setField(svc, "cacheSeconds", 15);
        ReflectionTestUtils.setField(svc, "windowHours", 168);
        ReflectionTestUtils.setField(svc, "topKinds", 12);
        return svc;
    }

    private PublicApiController controller(PublicIpProfileService svc, PublicAlertSource source) {
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 20);

        PublicApiController c = new PublicApiController();
        ReflectionTestUtils.setField(c, "rateLimiter", limiter);
        ReflectionTestUtils.setField(c, "cacheSeconds", 15);
        ReflectionTestUtils.setField(c, "exposeBuildSha", false);
        ReflectionTestUtils.setField(c, "buildSha", "test");
        ReflectionTestUtils.setField(c, "ipPolicy", PublicIpPolicy.of(false));
        ReflectionTestUtils.setField(c, "source", source);
        ReflectionTestUtils.setField(c, "ipProfileService", svc);
        return c;
    }

    private MockMvc mvc(PublicApiController c) {
        return MockMvcBuilders.standaloneSetup(c).addFilters(new PublicEtagFilter()).build();
    }

    private JsonNode data(PublicApiController c, String url) throws Exception {
        String body = mvc(c).perform(get(url)).andExpect(status().isOk()).andReturn()
                .getResponse().getContentAsString(StandardCharsets.UTF_8);
        return mapper.readTree(body).path("data");
    }

    /** 有数据的一份 {@code ipActivity}（形状与 WazuhService 的实现一致） */
    private static Map<String, Object> activityWithData() {
        Map<String, Object> stages = new LinkedHashMap<>();
        stages.put("alerts", 5L);
        stages.put("decoyPorts", 4L);
        stages.put("honeypotLogins", 4L);
        stages.put("honeypotSuccess", 0L);
        stages.put("honeypotFailed", 4L);

        // 与 WazuhService 的输出同形：[{key,count}]（topN 的形状），不是 Map
        List<Map<String, Object>> byKind = List.of(
                Map.of("key", "扫描", "count", 5L),
                Map.of("key", "蜜罐登录失败", "count", 4L));

        Map<String, Object> a = new LinkedHashMap<>();
        a.put("available", true);
        a.put("windowHours", 168);
        a.put("total", 9L);
        a.put("firstSeen", "2026-10-14 00:10:00");
        a.put("lastSeen", "2026-10-17 23:59:00");
        a.put("stages", stages);
        a.put("byKind", byKind);
        a.put("ports", List.of(Map.of("key", "22", "count", 4L),
                Map.of("key", "6379", "count", 1L)));
        a.put("topCredentials", List.of(Map.of("key", "root / 123456", "count", 3L)));
        a.put("sampled", 9L);
        a.put("truncated", false);
        return a;
    }

    // ==================== 1) 正常 IP ====================

    @Test
    @DisplayName("正常 IP：字段齐全，口令只给结构（原文不出现）")
    void normalIp() throws Exception {
        // 一条「正在封着」的留痕：banned 分支要真有数
        Files.writeString(tmp.resolve("blocked-ips.json"), """
                [{"ip":"45.155.205.233","createdAt":"2026-10-17 10:00:00",
                  "expiresAt":"2099-01-01 00:00:00","unblocked":false,
                  "source":"MANUAL","actor":"human","auditId":"a1"}]
                """);

        PublicAlertSource src = sourceStub(activityWithData());
        PublicApiController c = controller(service(src), src);
        String body = mvc(c).perform(get("/api/public/ip").param("q", IP))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "public, max-age=15"))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        JsonNode data = mapper.readTree(body).path("data");
        // ok(...) 的 ship() 会在末尾补统一口径字段 ipDisclosure，所以期望集合 = 自有字段 + 它
        List<String> expected = new java.util.ArrayList<>(IP_FIELDS);
        expected.add(PublicIpPolicy.DISCLOSURE_FIELD);
        assertEquals(expected, fieldNames(data), "字段集合与口径一起冻结");

        assertTrue(data.path("available").asBoolean());
        assertEquals("OK", data.path("reason").asText());
        assertEquals(IP, data.path("query").asText());
        assertEquals("168h", data.path("window").asText());
        assertEquals("2026-10-14 00:10:00", data.path("firstSeen").asText());
        assertEquals("2026-10-17 23:59:00", data.path("lastSeen").asText());
        assertEquals(9, data.path("events").asInt());
        assertEquals(5, data.path("byKind").path("扫描").asInt());
        assertEquals(4, data.path("byKind").path("蜜罐登录失败").asInt());
        assertEquals(22, data.path("ports").get(0).path("port").asInt());
        assertEquals(6379, data.path("ports").get(1).path("port").asInt());

        // 口令：只给结构
        JsonNode cred = data.path("credStructure");
        assertEquals(1, cred.size());
        assertEquals("root", cred.get(0).path("username").asText());
        assertEquals(6, cred.get(0).path("passwordLength").asInt());
        assertTrue(cred.get(0).path("weakPassword").asBoolean());

        // 整个响应体：口令原文一个字符都不许有
        assertFalse(body.contains("123456"), "口令原文泄漏进响应体");
        // key 是「用户名 / 结构」而不是「用户名 / 口令」：结构里只有位数与字符类
        assertTrue(cred.get(0).path("key").asText().contains("位"),
                "key 必须已换成结构说明，而不是原口令");

        // 封禁留痕
        JsonNode banned = data.path("banned");
        assertNotNull(banned.get("count"));
        assertEquals(1, banned.path("count").asInt());
        assertEquals("2026-10-17 10:00:00", banned.path("lastBannedAt").asText());
        assertTrue(banned.path("active").asBoolean());

        // GeoIP 库没装配 → geo=null + notes 说明（不猜）
        assertTrue(data.path("geo").isNull());
        assertTrue(notesContain(data, "GeoIP"), "geo 为 null 必须在 notes[] 里说明");
        assertEquals("NOT_WIRED", data.path("sources").path("geoip").path("status").asText());
    }

    // ==================== 2) 无数据的 IP ====================

    @Test
    @DisplayName("无数据 IP：200 + 各项 null（不写 0），notes 说明原因")
    void noDataIp() throws Exception {
        Map<String, Object> none = new LinkedHashMap<>();
        none.put("available", false);
        none.put("reason", "DATA_SOURCE_UNAVAILABLE");
        none.put("note", "Wazuh 网关当前不是 REAL（mode=UNKNOWN）");

        PublicAlertSource src = sourceStub(none);
        PublicApiController c = controller(service(src), src);
        JsonNode data = data(c, "/api/public/ip?q=" + IP);

        assertFalse(data.path("available").asBoolean());
        assertEquals("DATA_SOURCE_UNAVAILABLE", data.path("reason").asText());
        for (String k : List.of("firstSeen", "lastSeen", "events", "byKind", "ports", "credStructure",
                "geo", "banned")) {
            assertTrue(data.path(k).isNull(), k + " 读不到时必须 null（不能写 0/空数组冒充没有）");
        }
        assertTrue(data.path("notes").size() > 0, "每一项 null 都要在 notes[] 里给原因");
        assertTrue(notesContain(data, "DATA_SOURCE_UNAVAILABLE"));
        // 留痕文件不存在 ⇒ banned 也不能写成 0 次
        assertEquals("UNREADABLE", data.path("sources").path("audit").path("status").asText());
        assertEquals(IP, data.path("query").asText(), "query 仍是唯一被查的那个 IP");
    }

    @Test
    @DisplayName("服务未装配：降级载荷 available=false 且全 null，不 500")
    void serviceMissing() throws Exception {
        PublicApiController c = controller(null, sourceStub(null));
        JsonNode data = data(c, "/api/public/ip?q=" + IP);
        assertFalse(data.path("available").asBoolean());
        assertEquals("IP_PROFILE_DISABLED", data.path("reason").asText());
        assertTrue(data.path("events").isNull());
        assertTrue(data.path("byKind").isNull());
        assertEquals("NOT_WIRED", data.path("sources").path("indexer").path("status").asText());
    }

    // ==================== 3) 非法 IP → 400 ====================

    @Test
    @DisplayName("非法 IP / 内网地址 / 缺参数 → 400，且 no-store")
    void invalidIp() throws Exception {
        PublicAlertSource src = sourceStub(activityWithData());
        PublicApiController c = controller(service(src), src);
        MockMvc mvc = mvc(c);

        for (String[] tc : new String[][]{
                {"abc", "INVALID_IP"},
                {"45.155.205", "INVALID_IP"},
                {"45.155.205.256", "INVALID_IP"},
                {"45.155.205.233:22", "INVALID_IP"},
                {"45.155.205.0/24", "INVALID_IP"},
                {"10.0.0.1", "NOT_PUBLIC_IP"},
                {"192.168.1.1", "NOT_PUBLIC_IP"},
                {"127.0.0.1", "NOT_PUBLIC_IP"},
                {"", "MISSING_Q"},
        }) {
            String body = mvc.perform(get("/api/public/ip").param("q", tc[0]))
                    .andExpect(status().isBadRequest())
                    .andExpect(header().string("Cache-Control", "no-store"))
                    .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
            JsonNode root = mapper.readTree(body);
            assertEquals(400, root.path("code").asInt(), tc[0]);
            assertEquals(tc[1], root.path("reason").asText(), "q=" + tc[0]);
        }

        // 完全没有 q 参数也算缺
        mvc.perform(get("/api/public/ip"))
                .andExpect(status().isBadRequest());
    }

    // ==================== 工具 ====================

    private static List<String> fieldNames(JsonNode n) {
        List<String> names = new java.util.ArrayList<>();
        n.fieldNames().forEachRemaining(names::add);
        return names;
    }

    private static boolean notesContain(JsonNode data, String needle) {
        for (JsonNode n : data.path("notes")) {
            if (n.asText().contains(needle)) {
                return true;
            }
        }
        return false;
    }
}

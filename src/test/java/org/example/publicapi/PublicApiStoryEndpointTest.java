package org.example.publicapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.aggregation.AlertAggregationService;
import org.example.integration.WazuhGateway;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code GET /api/public/story?src=} 的端点契约测试。
 *
 * <p>它钉的是：<b>关联正确性</b>（同一 src 的四段按时间合并成一条流）、
 * <b>coverage</b>（每段查到多少条 / 哪段未接入 / 为什么是 0）、
 * <b>边界</b>（不在候选池 → 404、非法地址 → 400、空窗口、缺参数）、
 * <b>限量</b>（每段独立上限 + truncated）、
 * <b>零敏感项</b>（口令/内部资产名/内网地址/原始日志/规则正则原文），
 * 以及掩码态的冻结串回归。
 */
class PublicApiStoryEndpointTest {

    @TempDir
    Path tmp;

    private final ObjectMapper mapper = new ObjectMapper();

    private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(?:\\.\\d{1,3}){3}");

    private static final List<String> STORY_FIELDS = List.of(
            "generatedAt", "cacheSeconds", "window", "windowHours", "available", "reason", "srcIp",
            "firstSeen", "lastSeen", "severityMax", "severityMaxLabel", "gaps", "stages", "events",
            "eventCount", "truncated", "coverage", "commandsAvailable", "commandsNote", "limits", "note");

    private PublicApiController controller(String mode, boolean honeypotWired, boolean maskIps,
                                           boolean withAudit, int maxEventsPerStage) throws Exception {
        if (withAudit) {
            AttackStoryFixtures.writeAudit(tmp, LocalDateTime.now());
        } else {
            AttackStoryFixtures.writeEmptyAudit(tmp);
        }
        PublicIpPolicy policy = PublicIpPolicy.of(maskIps);

        PublicAuditReader reader = new PublicAuditReader();
        ReflectionTestUtils.setField(reader, "dataDir", tmp.toString());
        ReflectionTestUtils.setField(reader, "ipPolicy", policy);

        WazuhGateway gateway = AttackStoryFixtures.gateway(mode, honeypotWired);
        PublicAlertSource source = new PublicAlertSource();
        ReflectionTestUtils.setField(source, "wazuhGateway", gateway);
        ReflectionTestUtils.setField(source, "aggregator", new AlertAggregationService());

        AttackStoryService svc = new AttackStoryService();
        ReflectionTestUtils.setField(svc, "source", source);
        ReflectionTestUtils.setField(svc, "auditReader", reader);
        ReflectionTestUtils.setField(svc, "ipPolicy", policy);
        ReflectionTestUtils.setField(svc, "cacheSeconds", 15);
        ReflectionTestUtils.setField(svc, "topSources", 50);
        ReflectionTestUtils.setField(svc, "maxEventsPerStage", maxEventsPerStage);
        ReflectionTestUtils.setField(svc, "maxLimit", 20);
        ReflectionTestUtils.setField(svc, "selfIps", AttackStoryFixtures.IP_SELF);

        PublicApiController c = new PublicApiController();
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 20);
        ReflectionTestUtils.setField(c, "rateLimiter", limiter);
        ReflectionTestUtils.setField(c, "cacheSeconds", 15);
        ReflectionTestUtils.setField(c, "exposeBuildSha", false);
        ReflectionTestUtils.setField(c, "buildSha", "test");
        ReflectionTestUtils.setField(c, "ipPolicy", policy);
        ReflectionTestUtils.setField(c, "source", source);
        ReflectionTestUtils.setField(c, "auditReader", reader);
        ReflectionTestUtils.setField(c, "attackStoryService", svc);
        return c;
    }

    private MockMvc mvc(PublicApiController c) {
        return MockMvcBuilders.standaloneSetup(c).addFilters(new PublicEtagFilter()).build();
    }

    private String body(PublicApiController c, String url) throws Exception {
        return mvc(c).perform(get(url)).andExpect(status().isOk()).andReturn()
                .getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    private String storyOf(String ip, String query) throws Exception {
        PublicApiController c = controller("REAL", true, false, true, 40);
        return body(c, "/api/public/story?src=" + ip + (query == null ? "" : query));
    }

    // ==================== 关联正确性 ====================

    @Test
    @DisplayName("【核心】同一来源的四段按时间合并成一条升序事件流（告警+诱饵端口+处置审计）")
    void mergesAllStagesInTimeOrder() throws Exception {
        String json = storyOf(AttackStoryFixtures.IP_DECOY, null);
        JsonNode data = mapper.readTree(json).get("data");

        assertTrue(data.get("available").asBoolean());
        assertEquals(AttackStoryFixtures.IP_DECOY, data.get("srcIp").asText());
        // 3 条告警 + 2 条诱饵端口 + 2 条处置审计
        assertEquals(7, data.get("eventCount").asInt(), "四段事件必须合并进同一条流：" + json);

        Set<String> stages = new LinkedHashSet<>();
        String lastTs = "";
        for (JsonNode e : data.get("events")) {
            stages.add(e.get("stage").asText());
            String ts = e.get("ts").asText();
            assertTrue(ts.compareTo(lastTs) >= 0, "事件必须按时间升序：" + json);
            lastTs = ts;
            assertTrue(e.has("kind") && e.has("summary") && e.has("severity"),
                    "每条事件要给 ts/stage/kind/summary/severity 或 outcome：" + e);
        }
        assertEquals(Set.of("alerts", "decoyPorts", "auditActions"), stages);

        // 同一来源的阶段计数与 /stories 完全一致（两个端点不会各算一套）
        assertEquals(21, data.get("stages").get("alerts").asLong());
        assertEquals(54, data.get("stages").get("decoyPorts").asLong());
        assertEquals(0, data.get("stages").get("honeypotLogins").asLong());
        assertEquals(2, data.get("stages").get("auditActions").asLong());
        assertEquals(List.of("honeypotLogins"), toList(data.get("gaps")));
        assertTrue(data.get("truncated").asBoolean(), "两段都被限量过，顶部必须标 truncated");

        // 字段白名单
        Set<String> actual = new LinkedHashSet<>();
        data.fieldNames().forEachRemaining(actual::add);
        Set<String> expected = new LinkedHashSet<>(STORY_FIELDS);
        expected.add("ipDisclosure");
        assertEquals(expected, actual, "字段白名单：只许新增、不许改名/删除");
    }

    @Test
    @DisplayName("固定时间的来源：事件顺序逐条可预期（时间轴绘制的确定性前提）")
    void eventOrderIsDeterministicForFixedTimes() throws Exception {
        String json = storyOf(AttackStoryFixtures.IP_HONEYPOT, null);
        JsonNode events = mapper.readTree(json).get("data").get("events");

        assertEquals(3, events.size());
        assertEquals("2026-10-13 23:05:00", events.get(0).get("ts").asText());
        assertEquals("alerts", events.get(0).get("stage").asText());
        assertEquals("2026-10-13 23:30:00", events.get(1).get("ts").asText());
        assertEquals("honeypotLogins", events.get(1).get("stage").asText());
        assertEquals("SUCCESS", events.get(1).get("outcome").asText());
        assertEquals("高危", events.get(1).get("severityLabel").asText(),
                "Wazuh level=10 按本站四档口径是「高危」（不是「严重」——12–15 才是严重）");
        assertEquals("FAILED", events.get(2).get("outcome").asText());
    }

    @Test
    @DisplayName("只在处置审计里有记录的来源：三段为 0、事件流仍只有那一条审计（不拿别的顶替）")
    void auditOnlySourceHasAuditEventsOnly() throws Exception {
        String json = storyOf(AttackStoryFixtures.IP_AUDIT_ONLY, null);
        JsonNode data = mapper.readTree(json).get("data");

        assertEquals(1, data.get("eventCount").asInt());
        assertEquals("auditActions", data.get("events").get(0).get("stage").asText());
        assertEquals("封禁 IP", data.get("events").get(0).get("kind").asText());
        assertTrue(data.get("events").get(0).get("summary").asText().contains("结果=成功"),
                "审计事件只给结论（操作者/模式/结果）：" + json);
        assertEquals(3, data.get("gaps").size(), "另外三段必须进 gaps：" + json);
        assertFalse(json.contains("夹具处置原因"), "审计 reason 正文不进故事线：" + json);
    }

    // ==================== coverage ====================

    @Test
    @DisplayName("coverage：每段给'查到多少条'（不是取回多少条）与 truncated；未接入的段给 NOT_WIRED + 原因")
    void coverageReportsQueriedAndWiring() throws Exception {
        String json = storyOf(AttackStoryFixtures.IP_DECOY, null);
        JsonNode cov = mapper.readTree(json).get("data").get("coverage");

        assertEquals("OK", cov.get("alerts").get("status").asText());
        assertEquals(21, cov.get("alerts").get("queried").asLong(), "queried 是【查到了多少条】");
        assertEquals(3, cov.get("alerts").get("returned").asLong());
        assertEquals(true, cov.get("alerts").get("truncated").asBoolean());
        assertEquals(54, cov.get("decoyPorts").get("queried").asLong());
        assertEquals(0, cov.get("honeypotLogins").get("queried").asLong());
        assertEquals("OK", cov.get("auditActions").get("status").asText());
        assertEquals(2, cov.get("auditActions").get("queried").asLong());
        assertEquals(40, cov.get("maxEventsPerStage").asInt());

        // 未接入的段：状态必须与"接入但这段没有数据"区分开
        PublicApiController c = controller("REAL", false, false, true, 40);
        JsonNode cov2 = mapper.readTree(body(c, "/api/public/story?src=" + AttackStoryFixtures.IP_DECOY))
                .get("data").get("coverage");
        assertEquals("NOT_WIRED", cov2.get("honeypotLogins").get("status").asText());
        assertEquals("STAGE_NOT_WIRED", cov2.get("honeypotLogins").get("reason").asText());
        assertTrue(cov2.get("honeypotLogins").get("note").asText().contains("没有接入数据源"),
                "未接入要给出原因：" + cov2);
        assertEquals("OK", cov2.get("decoyPorts").get("status").asText(),
                "只有真正没数据源的段才是 NOT_WIRED");
    }

    @Test
    @DisplayName("蜜罐命令时间线没有数据源：commandsAvailable=false + 一句说明（不编命令序列）")
    void commandsTimelineIsHonestlyUnavailable() throws Exception {
        String json = storyOf(AttackStoryFixtures.IP_HONEYPOT, null);
        JsonNode data = mapper.readTree(json).get("data");

        assertFalse(data.get("commandsAvailable").asBoolean());
        assertTrue(data.get("commandsNote").asText().contains("命令"),
                "必须说清'命令时间线未接入'：" + json);
        assertTrue(data.get("commandsNote").asText().contains("不编造"), json);
    }

    // ==================== 边界 ====================

    @Test
    @DisplayName("不在候选池 / 非法地址 / 缺参数：三种边界各有自己的 code 与 reason")
    void boundaryCases() throws Exception {
        PublicApiController c = controller("REAL", true, false, true, 40);

        // 不在池里：404（刻意不服务池外来源，避免这个端点变成"某 IP 有没有打过我们"的查询器）
        mvc(c).perform(get("/api/public/story?src=" + AttackStoryFixtures.IP_OUTSIDE_POOL))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.reason").value("SOURCE_NOT_IN_WINDOW"));

        // 内网地址：形状就不合法 → 400（连查都不查）
        mvc(c).perform(get("/api/public/story?src=" + AttackStoryFixtures.IP_INTERNAL))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("INVALID_SRC"));

        // 我方 IP 是合法公网地址（形状没问题），只是不进候选池 → 404
        mvc(c).perform(get("/api/public/story?src=" + AttackStoryFixtures.IP_SELF))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.reason").value("SOURCE_NOT_IN_WINDOW"));

        mvc(c).perform(get("/api/public/story"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("MISSING_SRC"));

        mvc(c).perform(get("/api/public/story?src=" + AttackStoryFixtures.IP_DECOY + "&window=3h"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("WINDOW_NOT_SUPPORTED"));
    }

    @Test
    @DisplayName("数据源不是 REAL：available=false + DATA_SOURCE_UNAVAILABLE（不返回空事件流冒充'没干过'）")
    void failClosedWhenSourceIsDown() throws Exception {
        PublicApiController c = controller("MOCK", true, false, true, 40);

        String json = body(c, "/api/public/story?src=" + AttackStoryFixtures.IP_DECOY);
        JsonNode data = mapper.readTree(json).get("data");

        assertFalse(data.get("available").asBoolean());
        assertEquals("DATA_SOURCE_UNAVAILABLE", data.get("reason").asText());
        assertTrue(data.get("events").isEmpty());
        assertEquals(0, data.get("eventCount").asInt());
        assertTrue(data.get("coverage").has("alerts"), "降级载荷也要保留字段形状：" + json);
    }

    @Test
    @DisplayName("服务未装配：available=false + STORY_DISABLED")
    void missingServiceIsReported() throws Exception {
        PublicApiController c = controller("REAL", true, false, true, 40);
        ReflectionTestUtils.setField(c, "attackStoryService", null);

        mvc(c).perform(get("/api/public/story?src=" + AttackStoryFixtures.IP_DECOY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(false))
                .andExpect(jsonPath("$.data.reason").value("STORY_DISABLED"))
                .andExpect(jsonPath("$.data.events").isEmpty());
    }

    @Test
    @DisplayName("单来源事件上限：每段各自限量 → truncated=true，事件明显少于该段总量")
    void perStageCapIsEnforced() throws Exception {
        PublicApiController c = controller("REAL", true, false, true, 1);

        String json = body(c, "/api/public/story?src=" + AttackStoryFixtures.IP_HONEYPOT);
        JsonNode data = mapper.readTree(json).get("data");

        assertEquals(1, data.get("coverage").get("maxEventsPerStage").asInt());
        assertEquals(2, data.get("eventCount").asInt(), "每段最多 1 条（告警 1 + 登录 1）");
        assertTrue(data.get("truncated").asBoolean());
        assertTrue(data.get("coverage").get("honeypotLogins").get("queried").asLong() > 1,
                "queried 仍然是查到多少条，而不是取回多少条：" + json);
    }

    // ==================== 复用既有外壳 ====================

    @Test
    @DisplayName("限流 + ETag：同一个桶、同一份快照内第二次 304")
    void rateLimitAndEtag() throws Exception {
        PublicApiController c = controller("REAL", true, false, true, 40);
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 1);
        ReflectionTestUtils.setField(c, "rateLimiter", limiter);

        var first = mvc(c).perform(get("/api/public/story?src=" + AttackStoryFixtures.IP_DECOY))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "public, max-age=15"))
                .andReturn();
        String etag = first.getResponse().getHeader("ETag");
        assertTrue(etag != null && etag.startsWith("\""), "必须下发强 ETag：" + etag);
        String body1 = first.getResponse().getContentAsString(StandardCharsets.UTF_8);

        // 第二次被限流挡下（限流在 ETag 之前计数，304 也计入）
        mvc(c).perform(get("/api/public/story?src=" + AttackStoryFixtures.IP_DECOY)
                        .header("If-None-Match", etag))
                .andExpect(status().isTooManyRequests());

        // 换一个"更宽"的限流桶，验证 304 本身
        PublicRateLimiter wide = new PublicRateLimiter();
        ReflectionTestUtils.setField(wide, "requestsPerMinute", 20);
        ReflectionTestUtils.setField(c, "rateLimiter", wide);
        var second = mvc(c).perform(get("/api/public/story?src=" + AttackStoryFixtures.IP_DECOY)
                        .header("If-None-Match", etag))
                .andExpect(status().isNotModified()).andReturn();
        assertEquals(0, second.getResponse().getContentAsByteArray().length, "304 不许带 body");

        assertEquals(body1, body(c, "/api/public/story?src=" + AttackStoryFixtures.IP_DECOY),
                "同一份快照内两次组装必须逐字节相同");
    }

    // ==================== 敏感项扫描 ====================

    @Test
    @DisplayName("【核心】事件流里零敏感项：口令只给结构、内部资产名被替换、内网地址成「内网/未知」")
    void timelineHasZeroSensitiveItems() throws Exception {
        String json = storyOf(AttackStoryFixtures.IP_HONEYPOT, null);

        assertFalse(json.contains(AttackStoryFixtures.PASSWORD), "口令原文不得出现：" + json);
        assertTrue(json.contains("口令=[口令已隐藏]"), "口令要整段被隐藏而不是删掉：" + json);
        assertTrue(json.contains("用户=root"), "用户名可以给（与 /honeypot 口径一致）：" + json);
        assertFalse(json.contains(AttackStoryFixtures.ASSET_NAME), "内部资产名必须被替换：" + json);
        assertTrue(json.contains(PublicAssetFilter.PLACEHOLDER) || !json.contains("web-0"),
                "内部资产名要么被替换成占位符、要么根本不出现：" + json);

        String decoy = storyOf(AttackStoryFixtures.IP_DECOY, null);
        assertFalse(decoy.contains(AttackStoryFixtures.INTERNAL_ADDR),
                "内网目的地址不得出现（真实态写成「内网/未知」）：" + decoy);
        assertTrue(decoy.contains("内网/未知"), "内网地址要如实标注而不是丢掉整句：" + decoy);
        assertFalse(decoy.contains(AttackStoryFixtures.RAW_LOG_SENTINEL), "原始日志不该被取回：" + decoy);
        assertFalse(decoy.contains(AttackStoryFixtures.RULE_REGEX_SENTINEL), "规则正则原文不该被取回：" + decoy);
        assertNoUnexpectedIp(decoy, Set.of(AttackStoryFixtures.IP_DECOY));
        assertNoUnexpectedIp(json, Set.of(AttackStoryFixtures.IP_HONEYPOT));
    }

    @Test
    @DisplayName("超长规则描述被截断（只给摘要，不把整段原文搬到公网）")
    void summaryIsTruncated() throws Exception {
        PublicApiController c = controller("REAL", true, false, false, 40);
        AttackStoryFixtures.writeAudit(tmp, LocalDateTime.now());
        String json = body(c, "/api/public/story?src=" + AttackStoryFixtures.IP_ALERTS_ONLY);

        for (JsonNode e : mapper.readTree(json).get("data").get("events")) {
            assertTrue(e.get("summary").asText().length() <= AttackStoryService.SUMMARY_MAX_CHARS + 1,
                    "summary 必须截断：" + e);
            assertTrue(e.get("summary").asText().endsWith("…"), "截断要有可见标记：" + e);
        }
    }

    // ==================== 掩码回归 ====================

    @Test
    @DisplayName("掩码回归：事件流里的来源地址（含文本里的）全部掩码到网段，且冻结串一致")
    void maskedTimelineMatchesGolden() throws Exception {
        PublicApiController c = controller("REAL", true, true, false, 40);
        String json = body(c, "/api/public/story?src=" + AttackStoryFixtures.IP_DECOY);

        assertFalse(json.contains(AttackStoryFixtures.IP_DECOY), "掩码态不得出现完整地址：" + json);
        assertTrue(json.contains("77.90.***.***"), "文本里的来源地址同样必须掩码：" + json);
        assertFalse(json.contains(AttackStoryFixtures.INTERNAL_ADDR), "内网地址写成「内部地址」：" + json);
        assertTrue(json.contains("内部地址"), json);

        String normalized = json.replaceAll("\"generatedAt\":\"[^\"]*\"", "\"generatedAt\":\"<TS>\"");
        String golden = new String(PublicApiStoryEndpointTest.class
                .getResourceAsStream("/publicapi/masked-golden-story.json").readAllBytes(),
                StandardCharsets.UTF_8).strip();
        assertEquals(golden, normalized);
    }

    // ==================== 工具 ====================

    private static List<String> toList(JsonNode arr) {
        List<String> out = new ArrayList<>();
        arr.forEach(n -> out.add(n.asText()));
        return out;
    }

    private static void assertNoUnexpectedIp(String body, Set<String> allowedIps) {
        Matcher m = IPV4.matcher(body);
        List<String> unexpected = new ArrayList<>();
        while (m.find()) {
            if (!allowedIps.contains(m.group())) {
                unexpected.add(m.group());
            }
        }
        assertTrue(unexpected.isEmpty(), "响应里出现了不该出现的 IPv4：" + unexpected + "；body=" + body);
    }
}

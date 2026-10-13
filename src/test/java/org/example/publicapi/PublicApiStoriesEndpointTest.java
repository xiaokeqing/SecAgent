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
import org.springframework.test.web.servlet.MvcResult;
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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code GET /api/public/stories} 的端点契约测试（真跑 MVC 路由 + 信封 + 降级分支）。
 *
 * <p>它钉的是七件事：
 * <ol>
 *   <li>排序真的按"剧本完整度 → 最高等级 → 条数"（面试官看的就是这个列表的前几条）；</li>
 *   <li>{@code stages} 四段计数与 <b>{@code gaps[]}</b> 正确：没有数据的段必须被列出来；</li>
 *   <li>某一段"<b>未接入</b>"与"<b>这段没有数据</b>"能分开读（{@code coverage.stageStatus}）；</li>
 *   <li>内网/保留地址与我方 IP <b>不进榜</b>，排除数如实披露；</li>
 *   <li>整段响应体除了"该有的来源 IP"之外，<b>零敏感项</b>（正则扫描：口令/内部资产名/
 *       内网地址/原始日志/规则正则原文）；</li>
 *   <li>fail-closed：数据源不是 REAL / 服务未装配 → {@code available=false} + 各自的 reason；</li>
 *   <li>复用既有外壳：限流、ETag（304）、缓存头、{@code ipDisclosure}。</li>
 * </ol>
 */
class PublicApiStoriesEndpointTest {

    @TempDir
    Path tmp;

    private final ObjectMapper mapper = new ObjectMapper();

    /** 只有"公网字面量"形态的 IP 才允许出现在这个端点的响应里 */
    private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(?:\\.\\d{1,3}){3}");

    private static final List<String> STORIES_FIELDS = List.of(
            "generatedAt", "cacheSeconds", "window", "windowHours", "available", "reason",
            "limit", "candidates", "sourceCount", "stageLabels", "sources", "coverage", "limits", "note");

    private PublicApiController controller(String mode, boolean honeypotWired, boolean maskIps,
                                           boolean withAudit) throws Exception {
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
        ReflectionTestUtils.setField(svc, "maxEventsPerStage", 40);
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

    // ==================== 正常分支 ====================

    @Test
    @DisplayName("正常：按剧本完整度排序 + 四段计数 + gaps + coverage + 排除内网与我方 IP")
    void recommendsSourcesByCompleteness() throws Exception {
        PublicApiController c = controller("REAL", true, false, true);

        MvcResult result = mvc(c).perform(get("/api/public/stories"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(200))
                .andExpect(jsonPath("$.message").value("success"))
                .andExpect(jsonPath("$.data.available").value(true))
                .andExpect(jsonPath("$.data.reason").value("OK"))
                .andExpect(jsonPath("$.data.window").value("24h"))
                .andExpect(jsonPath("$.data.windowHours").value(24))
                .andExpect(jsonPath("$.data.limit").value(10))
                // 候选 4 个：诱饵+告警、告警+蜜罐、只有告警、只在处置审计里
                .andExpect(jsonPath("$.data.candidates").value(4))
                .andExpect(jsonPath("$.data.sourceCount").value(4))
                // ① 剧本最完整（3/4 段）的排第一
                .andExpect(jsonPath("$.data.sources[0].srcIp").value(AttackStoryFixtures.IP_DECOY))
                .andExpect(jsonPath("$.data.sources[0].stages.alerts").value(21))
                .andExpect(jsonPath("$.data.sources[0].stages.decoyPorts").value(54))
                .andExpect(jsonPath("$.data.sources[0].stages.honeypotLogins").value(0))
                .andExpect(jsonPath("$.data.sources[0].stages.auditActions").value(2))
                .andExpect(jsonPath("$.data.sources[0].stagesWithData").value(3))
                .andExpect(jsonPath("$.data.sources[0].stageCount").value(4))
                .andExpect(jsonPath("$.data.sources[0].severityMax").value("CRITICAL"))
                .andExpect(jsonPath("$.data.sources[0].severityMaxLabel").value("严重"))
                .andExpect(jsonPath("$.data.sources[0].gaps[0]").value("honeypotLogins"))
                .andExpect(jsonPath("$.data.sources[0].gapLabels[0]").value("蜜罐登录"))
                .andExpect(jsonPath("$.data.sources[0].firstSeen").value("2026-10-14 00:10:00"))
                // lastSeen 是"四段里的最晚一条"：窗口内有处置审计记录时它会晚于纯 indexer 的时间
                .andExpect(jsonPath("$.data.sources[0].lastSeen")
                        .value(org.hamcrest.Matchers.greaterThanOrEqualTo("2026-10-14 01:00:00")))
                // ② 两段的按最高等级排（10=高危 在 12=严重 之后）
                .andExpect(jsonPath("$.data.sources[1].srcIp").value(AttackStoryFixtures.IP_HONEYPOT))
                .andExpect(jsonPath("$.data.sources[1].gaps.length()").value(2))
                // ③ 一段的按等级排：处置审计（HIGH）在只有告警（LOW）之前
                .andExpect(jsonPath("$.data.sources[2].srcIp").value(AttackStoryFixtures.IP_AUDIT_ONLY))
                .andExpect(jsonPath("$.data.sources[2].stages.auditActions").value(1))
                .andExpect(jsonPath("$.data.sources[3].srcIp").value(AttackStoryFixtures.IP_ALERTS_ONLY))
                .andExpect(jsonPath("$.data.sources[3].stagesWithData").value(1))
                // ④ 排除项如实披露
                .andExpect(jsonPath("$.data.coverage.excludedSelf").value(1))
                .andExpect(jsonPath("$.data.coverage.excludedInternal").value(1))
                .andExpect(jsonPath("$.data.coverage.withSourceIp").value(106976))
                .andExpect(jsonPath("$.data.coverage.indexerTotalAlerts").value(112693))
                .andExpect(jsonPath("$.data.coverage.stageStatus.alerts").value("OK"))
                .andExpect(jsonPath("$.data.coverage.stageStatus.decoyPorts").value("OK"))
                .andExpect(jsonPath("$.data.coverage.stageStatus.honeypotLogins").value("OK"))
                .andExpect(jsonPath("$.data.coverage.stageStatus.auditActions").value("OK"))
                .andExpect(jsonPath("$.data.coverage.audit.actionRecords").value(4))
                .andExpect(jsonPath("$.data.coverage.audit.evalFiltered").value(1))
                .andExpect(jsonPath("$.data.limits.maxEventsPerStage").value(40))
                .andExpect(jsonPath("$.data.limits.maxLimit").value(20))
                .andExpect(header().string("Cache-Control", "public, max-age=15"))
                .andExpect(header().string("X-RateLimit-Limit", "20"))
                .andExpect(header().string("X-Data-Source", "WAZUH_REAL"))
                .andReturn();

        String json = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertNoIpLeak(json, Set.of(AttackStoryFixtures.IP_DECOY, AttackStoryFixtures.IP_HONEYPOT,
                AttackStoryFixtures.IP_AUDIT_ONLY, AttackStoryFixtures.IP_ALERTS_ONLY));
        assertTrue(json.contains("\"ipDisclosure\""), "公开端点必须带统一口径字段：" + json);

        // 字段白名单（多一个字段就说明有人顺手加了字段）
        JsonNode data = mapper.readTree(json).get("data");
        Set<String> actual = new LinkedHashSet<>();
        data.fieldNames().forEachRemaining(actual::add);
        Set<String> expected = new LinkedHashSet<>(STORIES_FIELDS);
        expected.add("ipDisclosure");
        assertEquals(expected, actual, "字段白名单：只许新增、不许改名/删除");
    }

    @Test
    @DisplayName("缺阶段：该段数据源未接入时，gaps 与 coverage.stageStatus 都要如实说'未接入'")
    void notWiredStageIsReportedAsNotWired() throws Exception {
        PublicApiController c = controller("REAL", false, false, false);

        String json = body(c, "/api/public/stories");

        assertEquals("NOT_WIRED", mapper.readTree(json).get("data").get("coverage")
                .get("stageStatus").get("honeypotLogins").asText());
        assertTrue(mapper.readTree(json).get("data").get("coverage")
                        .get("stageNotes").get("honeypotLogins").asText().toLowerCase().contains("cowrie"),
                "未接入的段要说清数据源是谁：" + json);
        // 每一个来源的 gaps 都必须【恰好】等于"计数为 0 的那几个阶段"（多一个少一个都是编）
        JsonNode sources = mapper.readTree(json).get("data").get("sources");
        for (JsonNode s : sources) {
            Set<String> expectGaps = new LinkedHashSet<>();
            for (String stage : AttackStoryService.STAGE_ORDER) {
                if (s.get("stages").get(stage).asLong() == 0) {
                    expectGaps.add(stage);
                }
            }
            Set<String> actualGaps = new LinkedHashSet<>();
            s.get("gaps").forEach(g -> actualGaps.add(g.asText()));
            assertEquals(expectGaps, actualGaps, "gaps 必须恰好是'没有数据的阶段'：" + s);
            assertEquals(4 - expectGaps.size(), s.get("stagesWithData").asInt(),
                    "stagesWithData 要与 gaps 对得上：" + s);
        }
        // 判定查询失败时给 UNKNOWN 而不是 NOT_WIRED（不猜"未接入"）—— 这条由 WazuhStoryQueryTest 钉住
        assertTrue(json.contains("\"honeypotLogins\""), json);
    }

    @Test
    @DisplayName("空窗口：数据源可用但没有候选来源 → available=true + NO_DATA_IN_WINDOW（不是故障）")
    void emptyWindowIsNotAnError() throws Exception {
        PublicApiController c = controller("REAL", true, false, false);
        WazuhGateway empty = (WazuhGateway) java.lang.reflect.Proxy.newProxyInstance(
                WazuhGateway.class.getClassLoader(), new Class<?>[]{WazuhGateway.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "mode" -> "REAL";
                    case "isAvailable" -> true;
                    case "storySources" -> {
                        java.util.Map<String, Object> m = new java.util.LinkedHashMap<>();
                        m.put("available", true);
                        m.put("reason", "NO_DATA_IN_WINDOW");
                        m.put("indexerTotal", 0L);
                        m.put("withSourceIp", 0L);
                        m.put("sources", List.of());
                        m.put("stageWiring", java.util.Map.of("alerts", "NOT_WIRED",
                                "decoyPorts", "NOT_WIRED", "honeypotLogins", "NOT_WIRED"));
                        yield m;
                    }
                    default -> null;
                });
        PublicAlertSource source = new PublicAlertSource();
        ReflectionTestUtils.setField(source, "wazuhGateway", empty);
        ReflectionTestUtils.setField(source, "aggregator", new AlertAggregationService());
        ReflectionTestUtils.setField(c, "source", source);
        ReflectionTestUtils.setField(ReflectionTestUtils.getField(c, "attackStoryService"), "source", source);

        mvc(c).perform(get("/api/public/stories"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(true))
                .andExpect(jsonPath("$.data.reason").value("NO_DATA_IN_WINDOW"))
                .andExpect(jsonPath("$.data.candidates").value(0))
                .andExpect(jsonPath("$.data.sources").isEmpty())
                .andExpect(jsonPath("$.data.note").value(org.hamcrest.Matchers.containsString("不是故障")));
    }

    // ==================== 边界与降级 ====================

    @Test
    @DisplayName("fail-closed：数据源不是 REAL → available=false + DATA_SOURCE_UNAVAILABLE（绝不给内置样本）")
    void mockModeIsFailClosed() throws Exception {
        PublicApiController c = controller("MOCK", true, false, true);

        String json = body(c, "/api/public/stories");
        JsonNode data = mapper.readTree(json).get("data");

        assertFalse(data.get("available").asBoolean());
        assertEquals("DATA_SOURCE_UNAVAILABLE", data.get("reason").asText());
        assertTrue(data.get("sources").isEmpty(), "数据源不可用时不许返回任何来源：" + json);
        assertTrue(data.get("coverage").has("stageStatus"), "降级载荷也要保留字段形状：" + json);
    }

    @Test
    @DisplayName("服务未装配（裁剪部署/单测）：available=false + STORY_DISABLED，不返回任何来源")
    void missingServiceIsReported() throws Exception {
        PublicApiController c = controller("REAL", true, false, true);
        ReflectionTestUtils.setField(c, "attackStoryService", null);

        mvc(c).perform(get("/api/public/stories"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(false))
                .andExpect(jsonPath("$.data.reason").value("STORY_DISABLED"))
                .andExpect(jsonPath("$.data.sources").isEmpty())
                .andExpect(jsonPath("$.data.ipDisclosure.masked").value(false));
    }

    @Test
    @DisplayName("不支持的 window：400 + WINDOW_NOT_SUPPORTED（不悄悄按 24h 处理）")
    void unsupportedWindowIsRejected() throws Exception {
        PublicApiController c = controller("REAL", true, false, false);

        mvc(c).perform(get("/api/public/stories").param("window", "2h"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("WINDOW_NOT_SUPPORTED"));

        mvc(c).perform(get("/api/public/stories").param("window", "7d"))
                .andExpect(status().isBadRequest())
                .andExpect(header().string("Cache-Control", "no-store"));
    }

    @Test
    @DisplayName("分页/上限：limit 截断候选、candidates 不变；limit 非法或超大一律夹回 [1, maxLimit]")
    void limitIsClampedAndReported() throws Exception {
        PublicApiController c = controller("REAL", true, false, true);

        String one = body(c, "/api/public/stories?limit=1");
        assertEquals(1, mapper.readTree(one).get("data").get("sourceCount").asInt());
        assertEquals(4, mapper.readTree(one).get("data").get("candidates").asInt(),
                "candidates 是窗口内的候选总数，不受 limit 影响");

        String zero = body(c, "/api/public/stories?limit=0");
        assertEquals(1, mapper.readTree(zero).get("data").get("limit").asInt());

        String huge = body(c, "/api/public/stories?limit=100000");
        assertEquals(20, mapper.readTree(huge).get("data").get("limit").asInt());

        String garbage = body(c, "/api/public/stories?limit=abc");
        assertEquals(10, mapper.readTree(garbage).get("data").get("limit").asInt());
    }

    @Test
    @DisplayName("窗口参数：1h/6h/24h/72h 都接受，且回显规范化的 window")
    void supportedWindowsAreAccepted() throws Exception {
        PublicApiController c = controller("REAL", true, false, true);

        for (String w : new String[]{"1h", "6h", "24h", "72h"}) {
            String json = body(c, "/api/public/stories?window=" + w);
            assertEquals(w, mapper.readTree(json).get("data").get("window").asText());
            assertEquals(Integer.parseInt(w.substring(0, w.length() - 1)),
                    mapper.readTree(json).get("data").get("windowHours").asInt());
        }
    }

    // ==================== 复用既有外壳 ====================

    @Test
    @DisplayName("限流：与其余公开端点同一个桶（20 次/分钟），超了就是 429 + Retry-After")
    void rateLimited() throws Exception {
        PublicApiController c = controller("REAL", true, false, true);
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 1);
        ReflectionTestUtils.setField(c, "rateLimiter", limiter);

        mvc(c).perform(get("/api/public/stories")).andExpect(status().isOk());
        mvc(c).perform(get("/api/public/stories"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "60"));
    }

    @Test
    @DisplayName("ETag：同一份快照内两次请求逐字节相同，带 If-None-Match 的第二次是 304")
    void etagIsStableWithinSnapshot() throws Exception {
        PublicApiController c = controller("REAL", true, false, true);

        MvcResult first = mvc(c).perform(get("/api/public/stories")).andExpect(status().isOk()).andReturn();
        String body1 = first.getResponse().getContentAsString(StandardCharsets.UTF_8);
        String etag = first.getResponse().getHeader("ETag");
        assertTrue(etag != null && etag.startsWith("\""), "必须下发强 ETag：" + etag);

        MvcResult second = mvc(c).perform(get("/api/public/stories")
                        .header("If-None-Match", etag))
                .andExpect(status().isNotModified()).andReturn();
        assertEquals(0, second.getResponse().getContentAsByteArray().length, "304 不许带 body");

        String body2 = mvc(c).perform(get("/api/public/stories")).andReturn()
                .getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertEquals(body1, body2, "同一份 15 秒快照内两次组装的载荷必须逐字节相同（否则 304 永远不命中）");
    }

    @Test
    @DisplayName("掩码回归：开关为 true 时两个端点都回到掩码口径，且载荷逐字节等于冻结串")
    void maskedPayloadMatchesGolden() throws Exception {
        PublicApiController c = controller("REAL", true, true, false);

        String stories = normalize(body(c, "/api/public/stories"));
        assertEquals(golden("masked-golden-stories.json"), stories);

        String story = normalize(body(c, "/api/public/story?src=" + AttackStoryFixtures.IP_DECOY));
        assertEquals(golden("masked-golden-story.json"), story);
    }

    @Test
    @DisplayName("两种口径只差 IP 相关字段：字段集合完全一致，真实态给真实地址、掩码态给网段")
    void realAndMaskedDifferOnlyInIpFields() throws Exception {
        PublicApiController real = controller("REAL", true, false, false);
        String realJson = body(real, "/api/public/stories");

        PublicApiController masked = controller("REAL", true, true, false);
        String maskedJson = body(masked, "/api/public/stories");

        assertTrue(realJson.contains(AttackStoryFixtures.IP_DECOY), "真实态必须显示观测到的真实来源地址");
        assertFalse(maskedJson.contains(AttackStoryFixtures.IP_DECOY), "掩码态不得出现完整地址：" + maskedJson);
        assertTrue(maskedJson.contains("77.90.***.***"), "掩码态保留网段级：" + maskedJson);

        JsonNode r = mapper.readTree(realJson).get("data");
        JsonNode m = mapper.readTree(maskedJson).get("data");
        Set<String> rk = new LinkedHashSet<>();
        r.fieldNames().forEachRemaining(rk::add);
        Set<String> mk = new LinkedHashSet<>();
        m.fieldNames().forEachRemaining(mk::add);
        assertEquals(rk, mk, "两种口径的字段集合必须一致（只换值，不换结构）");
        assertEquals(r.get("candidates").asInt(), m.get("candidates").asInt());
        assertNotEquals(r.get("ipDisclosure").get("masked").asBoolean(),
                m.get("ipDisclosure").get("masked").asBoolean());
    }

    // ==================== 敏感项扫描 ====================

    @Test
    @DisplayName("【核心】响应体里除了'该有的来源 IP'，零敏感项（口令/内部资产名/内网地址/原始日志/规则正则）")
    void responseHasZeroSensitiveItems() throws Exception {
        // 蜜罐那一段必须接上，才会把带口令的规则描述带进管线
        PublicApiController c = controller("REAL", true, false, true);
        String json = body(c, "/api/public/stories");

        assertNoIpLeak(json, Set.of(AttackStoryFixtures.IP_DECOY, AttackStoryFixtures.IP_HONEYPOT,
                AttackStoryFixtures.IP_AUDIT_ONLY, AttackStoryFixtures.IP_ALERTS_ONLY));
        assertNoSensitiveText(json);
    }

    /** 响应体里出现的每一个 IPv4 都必须是"授权公开的来源地址" */
    private static void assertNoIpLeak(String body, Set<String> allowedIps) {
        Matcher m = IPV4.matcher(body);
        List<String> unexpected = new ArrayList<>();
        while (m.find()) {
            if (!allowedIps.contains(m.group())) {
                unexpected.add(m.group());
            }
        }
        assertTrue(unexpected.isEmpty(), "响应里出现了不该出现的 IPv4：" + unexpected + "；body=" + body);
        assertFalse(body.contains(AttackStoryFixtures.IP_INTERNAL), "内网来源不得进榜：" + body);
        assertFalse(body.contains(AttackStoryFixtures.IP_SELF), "我方 IP 不得进榜：" + body);
        assertFalse(body.contains(AttackStoryFixtures.INTERNAL_ADDR), "内网/隧道地址不得出现：" + body);
    }

    /** 口令 / 内部资产名 / 原始日志 / 规则正则原文：一个都不许出现 */
    private static void assertNoSensitiveText(String body) {
        assertFalse(body.contains(AttackStoryFixtures.PASSWORD), "口令原文出现在公开响应里：" + body);
        assertFalse(Pattern.compile("(口令|密码|password|passwd|pwd)\\s*[:=：]\\s*(?!\\[口令已隐藏\\])",
                        Pattern.CASE_INSENSITIVE).matcher(body).find(),
                "出现了未经处理的口令字段（必须是 口令=[口令已隐藏]）：" + body);
        assertFalse(body.contains(AttackStoryFixtures.ASSET_NAME), "内部资产名必须被替换：" + body);
        assertFalse(body.contains(AttackStoryFixtures.RAW_LOG_SENTINEL), "原始日志不该被取回：" + body);
        assertFalse(body.contains(AttackStoryFixtures.RULE_REGEX_SENTINEL), "规则正则原文不该被取回：" + body);
    }

    // ==================== 纯函数口径 ====================

    @Test
    @DisplayName("参数解析是纯函数：window 只认 1h/6h/24h/72h，limit 一律夹进 [1,max]")
    void parameterParsingIsPure() {
        assertEquals(24, AttackStoryService.parseWindowHours(null));
        assertEquals(24, AttackStoryService.parseWindowHours("24h"));
        assertEquals(24, AttackStoryService.parseWindowHours(" 24H "));
        assertEquals(1, AttackStoryService.parseWindowHours("1"));
        assertEquals(null, AttackStoryService.parseWindowHours("2h"));
        assertEquals(null, AttackStoryService.parseWindowHours("7d"));
        assertEquals(null, AttackStoryService.parseWindowHours("abc"));

        assertEquals(10, AttackStoryService.parseLimit(null, 20));
        assertEquals(10, AttackStoryService.parseLimit("abc", 20));
        assertEquals(1, AttackStoryService.parseLimit("-5", 20));
        assertEquals(1, AttackStoryService.parseLimit("0", 20));
        assertEquals(20, AttackStoryService.parseLimit("999", 20));
        assertEquals(1, AttackStoryService.parseLimit("5", 0));
    }

    @Test
    @DisplayName("IP 判定：只有认得出来的公网字面量才进候选池（内网/保留/带端口/乱值都不进）")
    void publicIpJudgement() {
        assertTrue(AttackStoryService.isPublicIp("77.90.185.30"));
        assertTrue(AttackStoryService.isPublicIp("2001:db8::1"));
        assertFalse(AttackStoryService.isPublicIp("10.0.0.10"));
        assertFalse(AttackStoryService.isPublicIp("172.19.0.1"));
        assertFalse(AttackStoryService.isPublicIp("192.168.1.1"));
        assertFalse(AttackStoryService.isPublicIp("127.0.0.1"));
        assertFalse(AttackStoryService.isPublicIp("::1"));
        assertFalse(AttackStoryService.isPublicIp(""));
        assertFalse(AttackStoryService.isPublicIp("not-an-ip"));
    }

    // ==================== 工具 ====================

    private static String normalize(String body) {
        return body.replaceAll("\"generatedAt\":\"[^\"]*\"", "\"generatedAt\":\"<TS>\"");
    }

    private static String golden(String name) throws Exception {
        try (var in = PublicApiStoriesEndpointTest.class.getResourceAsStream("/publicapi/" + name)) {
            if (in == null) {
                throw new IllegalStateException("找不到冻结串资源：/publicapi/" + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8).strip();
        }
    }
}

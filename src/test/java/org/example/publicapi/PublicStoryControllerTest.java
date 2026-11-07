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
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code GET /api/public/story?id=} 时间线变体的契约测试。
 *
 * <p>与 {@code PublicApiStoryEndpointTest}（{@code ?src=} 老契约）共用同一批
 * {@link AttackStoryFixtures}，钉的是新投影的四条底线：
 * <b>正常</b>（available:true + 时间正序 + 字段名）、
 * <b>非法 IP 400</b>、<b>数据源不可用 → available:false 而非 0 假数据</b>、
 * <b>匿名可访问</b>；另外回归"老 {@code ?src=} 契约没被抢走"与 ETag/缓存头。
 */
class PublicStoryControllerTest {

    private static final String IP = AttackStoryFixtures.IP_DECOY;

    private static final Pattern TS = Pattern.compile("\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}");

    private static final List<String> SEVERITIES = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW");

    private final ObjectMapper mapper = new ObjectMapper();

    @TempDir
    Path tmp;

    private PublicApiController controller(boolean withStoryService, String mode) throws Exception {
        AttackStoryFixtures.writeAudit(tmp, LocalDateTime.now());
        PublicIpPolicy policy = PublicIpPolicy.of(false);

        PublicAuditReader reader = new PublicAuditReader();
        ReflectionTestUtils.setField(reader, "dataDir", tmp.toString());
        ReflectionTestUtils.setField(reader, "ipPolicy", policy);

        PublicAlertSource source = new PublicAlertSource();
        ReflectionTestUtils.setField(source, "wazuhGateway", AttackStoryFixtures.gateway(mode, true));
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
        ReflectionTestUtils.setField(c, "attackStoryService", withStoryService ? svc : null);
        return c;
    }

    private MockMvc mvc(PublicApiController c) {
        return MockMvcBuilders.standaloneSetup(c).addFilters(new PublicEtagFilter()).build();
    }

    private JsonNode performOK(PublicApiController c, String url) throws Exception {
        MvcResult result = mvc(c).perform(get(url))
                .andExpect(status().isOk())
                .andReturn();
        return mapper.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    // ==================== 1. 正常：时间正序 + 约定字段 ====================

    @Test
    @DisplayName("【正常】available:true、事件按时间正序、字段名与四档严重度齐全")
    void normalTimelineIsSortedAndShaped() throws Exception {
        JsonNode body = performOK(controller(true, "REAL"), "/api/public/story?id=" + IP);
        assertEquals(200, body.get("code").asInt());
        JsonNode data = body.get("data");

        assertTrue(data.get("available").asBoolean(), "REAL 数据源应可用：" + body);
        assertEquals(IP, data.get("id").asText());
        assertTrue(data.get("reason").isNull(), "可用时 reason 必须是 null，不是空串或 OK 之外的废话");
        assertTrue(data.get("total").asInt() >= 7, "3 条告警 + 2 条诱饵端口 + 2 条审计，至少 7 条：" + body);

        JsonNode window = data.get("window");
        assertEquals(24, window.get("hours").asInt(), "默认窗口 24h");
        assertTrue(TS.matcher(window.get("start").asText()).matches(), "start 用 yyyy-MM-dd HH:mm:ss：" + body);
        assertTrue(TS.matcher(window.get("end").asText()).matches(), "end 用 yyyy-MM-dd HH:mm:ss：" + body);
        assertTrue(window.get("start").asText().compareTo(window.get("end").asText()) < 0);

        assertTrue(TS.matcher(data.get("firstSeen").asText()).matches());
        assertTrue(TS.matcher(data.get("lastSeen").asText()).matches());

        JsonNode events = data.get("events");
        assertEquals(data.get("total").asInt(), events.size(), "本次数据未超 200，total 应等于 events 条数");
        assertEquals(24, data.get("window").get("hours").asInt());

        String previous = "";
        for (JsonNode e : events) {
            assertEquals(IP, e.get("src").asText(), "src 与 id 同一显示口径");
            assertTrue(TS.matcher(e.get("time").asText()).matches(), "time 必须格式化：" + e);
            assertFalse(e.get("kind").asText().isEmpty(), "kind 不能为空：" + e);
            assertFalse(e.get("rule").asText().isEmpty(), "rule 不能为空：" + e);
            assertTrue(SEVERITIES.contains(e.get("sev").asText()), "sev 只允许四档：" + e);
            assertEquals(1, e.get("count").asInt());
            assertTrue(e.get("detail").isTextual(), "detail 是字符串（已脱敏摘要）：" + e);
            assertTrue(e.get("time").asText().compareTo(previous) >= 0, "事件必须按时间正序：" + body);
            previous = e.get("time").asText();
        }

        JsonNode severity = data.get("severity");
        assertEquals(SEVERITIES.size(), severity.size());
        int sum = 0;
        for (String sev : SEVERITIES) {
            assertTrue(severity.has(sev), "severity 缺 " + sev);
            sum += severity.get(sev).asInt();
        }
        assertEquals(events.size(), sum, "四档计数应覆盖返回的每条事件：" + body);
        assertFalse(body.toString().contains(AttackStoryFixtures.PASSWORD), "口令不得出现在公开响应：" + body);
    }

    // ==================== 2. IP 非法 400 ====================

    @Test
    @DisplayName("【400】缺 id / 形状非法 / 内网地址都不进数据通路")
    void invalidIpIsRejected() throws Exception {
        PublicApiController c = controller(true, "REAL");
        MockMvc mvc = mvc(c);

        mvc.perform(get("/api/public/story?id="))
                .andExpect(status().isBadRequest())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.code").value(400))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.reason").value("MISSING_ID"));

        mvc.perform(get("/api/public/story?id=not-an-ip"))
                .andExpect(status().isBadRequest())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.reason").value("INVALID_IP"));

        mvc.perform(get("/api/public/story?id=" + AttackStoryFixtures.IP_INTERNAL))
                .andExpect(status().isBadRequest())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.reason").value("INVALID_IP"));
    }

    // ==================== 3. 数据不足：available:false，绝不返回假 0 ====================

    @Test
    @DisplayName("【降级】数据源非 REAL → available:false + reason:数据源不可用，events 为空且计数全 0")
    void unavailableSourceDegradesHonestly() throws Exception {
        JsonNode body = performOK(controller(true, "MOCK"), "/api/public/story?id=" + IP);
        JsonNode data = body.get("data");

        assertFalse(data.get("available").asBoolean(), "MOCK 数据源必须 available:false：" + body);
        assertEquals("数据源不可用", data.get("reason").asText());
        assertEquals(0, data.get("total").asInt());
        assertEquals(0, data.get("events").size());
        assertTrue(data.get("firstSeen").isNull());
        assertTrue(data.get("lastSeen").isNull());
        for (String sev : SEVERITIES) {
            assertEquals(0, data.get("severity").get(sev).asInt(), "没有数据时四档计数必须是 0：" + sev);
        }
        assertEquals(IP, data.get("id").asText(), "降级载荷仍要有 id，页面才知道查的是谁");
        assertEquals(24, data.get("window").get("hours").asInt());
        assertFalse(body.toString().contains("\"stage\""), "不得把内部事件结构透出");
    }

    @Test
    @DisplayName("【降级】故事线服务未装配 → 同样 available:false（裁剪部署不炸）")
    void missingServiceDegradesHonestly() throws Exception {
        JsonNode data = performOK(controller(false, "REAL"), "/api/public/story?id=" + IP).get("data");
        assertFalse(data.get("available").asBoolean());
        assertEquals("数据源不可用", data.get("reason").asText());
        assertEquals(0, data.get("events").size());
    }

    // ==================== 4. 未登录可访问 ====================

    @Test
    @DisplayName("【公开】不带任何 Token/Authorization 也可 200，并带缓存与数据源头")
    void anonymousRequestIsServed() throws Exception {
        MvcResult result = mvc(controller(true, "REAL"))
                .perform(get("/api/public/story?id=" + IP))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Data-Source", "WAZUH_REAL"))
                .andExpect(header().string("X-RateLimit-Limit", "20"))
                .andExpect(header().string("Cache-Control", "public, max-age=15"))
                .andReturn();
        JsonNode body = mapper.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
        assertEquals(200, body.get("code").asInt());
        assertTrue(result.getResponse().getHeader("ETag") != null, "PublicEtagFilter 应给新路径发 ETag");
    }

    // ==================== 5. 与老契约共存 & 条件请求 ====================

    @Test
    @DisplayName("【回归】不带 id 时仍走老 ?src= 契约（srcIp/stage 字段），新变体没有抢走它")
    void legacySrcContractStillWinsWithoutId() throws Exception {
        JsonNode body = performOK(controller(true, "REAL"), "/api/public/story?src=" + IP);
        JsonNode data = body.get("data");
        assertTrue(data.has("srcIp"), "老契约字段 srcIp 必须还在：" + body);
        assertTrue(data.get("events").get(0).has("stage"), "老契约事件字段是 stage：" + body);
        assertFalse(data.has("id"), "老契约不应出现新变体的 id：" + body);
    }

    @Test
    @DisplayName("【前端契约】hours= 是 window= 的别名（前端时间线卡用 ?id=&hours=24）")
    void hoursParamIsAcceptedAsWindowAlias() throws Exception {
        JsonNode data = performOK(controller(true, "REAL"),
                "/api/public/story?id=" + IP + "&hours=6").get("data");
        assertTrue(data.get("available").asBoolean());
        assertEquals(6, data.get("window").get("hours").asInt(), "hours=6 必须真的只查 6h 窗口");

        // window= 仍优先；非法别名（hours=7）与非法 window 一样 400，不静默退回 24h
        mvc(controller(true, "REAL")).perform(get("/api/public/story?id=" + IP + "&hours=7"))
                .andExpect(status().isBadRequest())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.reason").value("WINDOW_NOT_SUPPORTED"));
    }

    @Test
    @DisplayName("【缓存】带 If-None-Match 的第二次请求返回 304")
    void etagSupportsConditionalGet() throws Exception {
        PublicApiController c = controller(true, "REAL");
        String etag = mvc(c).perform(get("/api/public/story?id=" + IP))
                .andExpect(status().isOk())
                .andReturn().getResponse().getHeader("ETag");
        assertTrue(etag != null && etag.startsWith("\""), "ETag 必须存在且带引号：" + etag);

        mvc(c).perform(get("/api/public/story?id=" + IP).header("If-None-Match", etag))
                .andExpect(status().isNotModified());
    }
}

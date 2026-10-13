package org.example.publicapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.accesslog.WebStatsAggregator;
import org.example.accesslog.WebStatsFixtures;
import org.example.accesslog.WebStatsService;
import org.example.aggregation.AlertAggregationService;
import org.example.integration.WazuhGateway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.OffsetDateTime;
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
 * {@code GET /api/public/webstats} 的端点契约测试（真跑一遍 MVC 路由 + 信封 + 各个降级分支）。
 *
 * <h3>它钉的是七件事</h3>
 * <ol>
 *   <li>路由存在、走既有信封（{@code code/message/data}）、带 {@code ipDisclosure} 与缓存/限流头；</li>
 *   <li><b>整段响应体零 IP</b>：连"UA 里塞 IP"这条最脏的路也一起扫（正则断言）；</li>
 *   <li><b>零原始路径</b>：攻击者可控的 path（含查询串/脚本标签）一个字符都不许出现在公网响应里；</li>
 *   <li>六种不可用状态各回<b>自己的 reason</b>（不许退化成"空分布"）；</li>
 *   <li>字段白名单：多一个字段就是不合格；</li>
 *   <li>确定性排序（ETag/304 的前提）；</li>
 *   <li>既有端点未受影响（同一个信封、同一套缓存头）。</li>
 * </ol>
 */
class PublicApiWebstatsEndpointTest {

    @TempDir
    Path tmp;

    private final ObjectMapper mapper = new ObjectMapper();
    private final List<WebStatsService> startedServices = new ArrayList<>();

    private PublicApiController controller;

    /** IPv4 形态（点分四段） */
    private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(?:\\.\\d{1,3}){3}");

    @AfterEach
    void tearDown() {
        for (WebStatsService s : startedServices) {
            s.stop();
        }
        startedServices.clear();
    }

    private void baseController() {
        controller = new PublicApiController();
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 20);
        ReflectionTestUtils.setField(controller, "rateLimiter", limiter);
        ReflectionTestUtils.setField(controller, "cacheSeconds", 15);
        ReflectionTestUtils.setField(controller, "exposeBuildSha", false);
        ReflectionTestUtils.setField(controller, "buildSha", "test");
        ReflectionTestUtils.setField(controller, "webStatsMinCount", 5);
        ReflectionTestUtils.setField(controller, "webStatsTopCategories", 10);
        ReflectionTestUtils.setField(controller, "webStatsTopUas", 5);
        wireSource();
    }

    /**
     * 造一个 {@link WebStatsService} 替身：真实现 + 真回填（只把文件探测间隔调大，
     * 免得"等 10 秒才知道状态"让测试变脆）。
     */
    private WebStatsService serviceFor(Path dir, boolean accessLogEnabled) throws Exception {
        WebStatsService s = new WebStatsService();
        ReflectionTestUtils.setField(s, "enabled", true);
        ReflectionTestUtils.setField(s, "accessLogEnabled", accessLogEnabled);
        ReflectionTestUtils.setField(s, "uaMaxChars", 60);
        ReflectionTestUtils.setField(s, "backfillMaxMb", 64);
        ReflectionTestUtils.setField(s, "fileProbeSeconds", 3600);
        if (accessLogEnabled) {
            s.beginBackfill(dir);
            s.awaitBackfill(5_000);
        } else {
            s.beginBackfill(dir);
        }
        startedServices.add(s);
        ReflectionTestUtils.setField(controller, "webStatsService", s);
        return s;
    }

    /** 只回答 mode/isAvailable/recentAlerts（与 /api/public/geo 的端点测试同一套做法） */
    private void wireSource() {
        WazuhGateway gateway = (WazuhGateway) Proxy.newProxyInstance(
                WazuhGateway.class.getClassLoader(),
                new Class<?>[]{WazuhGateway.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "mode" -> "MOCK";
                    case "isAvailable" -> false;
                    case "recentAlerts" -> List.of();
                    case "toString" -> "StubGateway(MOCK)";
                    default -> null;
                });
        PublicAlertSource source = new PublicAlertSource();
        ReflectionTestUtils.setField(source, "wazuhGateway", gateway);
        ReflectionTestUtils.setField(source, "aggregator", new AlertAggregationService());
        ReflectionTestUtils.setField(controller, "source", source);
    }

    private MockMvc mvc() {
        return MockMvcBuilders.standaloneSetup(controller).build();
    }

    /** 造一份真实形态的访问日志：含扫描路径、脚本标签、查询串哨兵、以及"UA 里塞 IP" */
    private Path fixtureLog() throws Exception {
        OffsetDateTime now = OffsetDateTime.now();
        List<String> lines = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            lines.add(WebStatsFixtures.accessLine(now, "GET", "/wp-login.php", 404, "curl/8.0.1"));
        }
        for (int i = 0; i < 5; i++) {
            lines.add(WebStatsFixtures.accessLine(now, "GET", "/.env", 404, "curl/8.0.1"));
        }
        for (int i = 0; i < 5; i++) {
            lines.add(WebStatsFixtures.accessLine(now, "GET",
                    "/%3Cscript%3Ealert(1)%3C/script%3E?token=SECRET-SENTINEL&file=SECRET-SENTINEL",
                    404, "1.2.3.4-scanner (2001:db8::1)"));
        }
        lines.add(WebStatsFixtures.accessLine(now, "GET", "/api/public/geo", 200, "Mozilla/5.0 (X11)"));
        Path dir = Files.createDirectory(tmp.resolve("log"));
        Files.write(dir.resolve("access.jsonl"), lines, StandardCharsets.UTF_8);
        return dir;
    }

    private void assertNoIpShape(String body) {
        Matcher m = IPV4.matcher(body);
        assertFalse(m.find(), "响应体里出现了 IPv4 形态（站主口径①：连掩码 IP 都不给）");
        assertFalse(body.contains("::"), "响应体里出现了 IPv6 压缩形态");
        assertFalse(body.contains("203.0.113.9"), "响应体里出现了日志里的 clientIp（聚合端点不许给 IP）");
    }

    // ==================== 正常分支 ====================

    @Test
    @DisplayName("正常：200 + 既有信封 + 状态码类别 + 类别榜 + UA 榜 + 7 天/热力 + 口径头，且整段响应零 IP")
    void returnsAggregatesWithoutAnyIp() throws Exception {
        baseController();
        serviceFor(fixtureLog(), true);

        MvcResult result = mvc().perform(get("/api/public/webstats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(200))
                .andExpect(jsonPath("$.message").value("success"))
                .andExpect(jsonPath("$.data.available").value(true))
                .andExpect(jsonPath("$.data.reason").value("OK"))
                .andExpect(jsonPath("$.data.window").value("24h"))
                .andExpect(jsonPath("$.data.cacheSeconds").value(15))
                .andExpect(jsonPath("$.data.totals.requests").value(16))
                .andExpect(jsonPath("$.data.totals.statusClass['2xx']").value(1))
                .andExpect(jsonPath("$.data.totals.statusClass['4xx']").value(15))
                .andExpect(jsonPath("$.data.totals.statusClass['5xx']").value(0))
                // 计数相同（各 5）→ 按类别名升序：dotenv < other-404 < wp-login
                .andExpect(jsonPath("$.data.topCategories[0].category").value("dotenv"))
                .andExpect(jsonPath("$.data.topCategories[1].category").value("other-404"))
                .andExpect(jsonPath("$.data.topCategories[2].category").value("wp-login"))
                .andExpect(jsonPath("$.data.topCategories[0].count").value(5))
                // 门槛 ≥5：Mozilla/5.0 (X11) 只有 1 次 → 不上榜
                .andExpect(jsonPath("$.data.topUas.length()").value(2))
                .andExpect(jsonPath("$.data.thresholds.minCount").value(5))
                .andExpect(jsonPath("$.data.coverage.bucketCount").value(288))
                .andExpect(jsonPath("$.data.coverage.hourCells").value(168))
                .andExpect(jsonPath("$.data.coverage.backfillDone").value(true))
                .andExpect(jsonPath("$.data.ipDisclosure.notice").exists())
                .andExpect(header().string("Cache-Control", "public, max-age=15"))
                .andExpect(header().string("X-RateLimit-Limit", "20"))
                .andReturn();

        String body = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
        // ① 零 IP：连"UA 里塞 IPv4/IPv6"这条最脏的路也扫掉
        assertNoIpShape(body);
        // ② 零原始路径/查询串：公网页面上永远不出现攻击者可控字符串
        assertFalse(body.contains("/wp-login.php"), "原始 path 不许出现（只许出现类别名 wp-login）");
        assertFalse(body.contains(".env"), "原始 path 不许出现（只许出现类别名 dotenv）");
        assertFalse(body.contains("SECRET-SENTINEL"), "查询串原文/值一个字符都不许出现");
        assertFalse(body.contains("<script>"), "攻击者输入不许出现在响应里");
        assertFalse(body.contains("%3Cscript"), "URL 编码后的攻击者输入同样不许出现");
        // ③ 被换掉的 IP 形态要看得出来（否则"零 IP"可能只是因为整行被丢了）
        assertTrue(body.contains("[ip]-scanner"), "UA 里的 IP 必须替换成 [ip] 而不是丢掉整行：" + body);

        JsonNode data = mapper.readTree(body).get("data");
        assertEquals(new LinkedHashSet<>(List.of("generatedAt", "cacheSeconds", "window", "available", "reason",
                        "totals", "topCategories", "topUas", "byDay", "heatmap", "thresholds", "coverage",
                        "note", "ipDisclosure")),
                new LinkedHashSet<>(iterable(data.fieldNames())),
                "字段白名单：多一个字段就说明有人顺手加了字段（公开契约不许无声扩大）");
        assertEquals(16L, data.get("byDay").get(0).get("requests").asLong());
        long heatSum = 0L;
        for (JsonNode h : data.get("heatmap")) {
            heatSum += h.get("count").asLong();
        }
        assertEquals(16L, heatSum, "热力图只列非零格，但总和必须等于窗口内请求数");
        assertTrue(data.get("byDay").size() >= 1, "今天必须有数据");
        assertTrue(data.get("note").asText().contains("不含任何 IP"));
    }

    private static List<String> iterable(java.util.Iterator<String> it) {
        List<String> out = new ArrayList<>();
        it.forEachRemaining(out::add);
        return out;
    }

    // ==================== 六种不可用状态 ====================

    @Test
    @DisplayName("没有装配数据面：available=false + WEBSTATS_DISABLED（不是'空分布'）")
    void disabledWhenNoService() throws Exception {
        baseController();
        ReflectionTestUtils.setField(controller, "webStatsService", null);

        mvc().perform(get("/api/public/webstats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(false))
                .andExpect(jsonPath("$.data.reason").value("WEBSTATS_DISABLED"))
                .andExpect(jsonPath("$.data.totals.requests").value(0))
                .andExpect(jsonPath("$.data.topCategories").isEmpty())
                .andExpect(jsonPath("$.data.byDay").isEmpty());
    }

    @Test
    @DisplayName("访问日志关掉：LOG_DISABLED（数据源压根没开，与'没有请求'是两件事）")
    void logDisabledReason() throws Exception {
        baseController();
        Path dir = Files.createDirectory(tmp.resolve("log"));
        serviceFor(dir, false);

        mvc().perform(get("/api/public/webstats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(false))
                .andExpect(jsonPath("$.data.reason").value("LOG_DISABLED"));
    }

    @Test
    @DisplayName("访问日志文件不存在：LOG_FILE_MISSING")
    void logFileMissingReason() throws Exception {
        baseController();
        serviceFor(Files.createDirectory(tmp.resolve("log")), true);

        mvc().perform(get("/api/public/webstats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(false))
                .andExpect(jsonPath("$.data.reason").value("LOG_FILE_MISSING"));
    }

    @Test
    @DisplayName("访问日志读不出来：LOG_UNREADABLE（读失败不许被当成'0 请求'）")
    void logUnreadableReason() throws Exception {
        baseController();
        Path dir = Files.createDirectory(tmp.resolve("log"));
        Files.createDirectory(dir.resolve("access.jsonl"));
        serviceFor(dir, true);

        mvc().perform(get("/api/public/webstats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(false))
                .andExpect(jsonPath("$.data.reason").value("LOG_UNREADABLE"));
    }

    @Test
    @DisplayName("日志可读但 24h 内真的没有请求：WINDOW_EMPTY（不是故障，也不是被隐藏）")
    void windowEmptyReason() throws Exception {
        baseController();
        Path dir = Files.createDirectory(tmp.resolve("log"));
        Files.write(dir.resolve("access.jsonl"), List.of(), StandardCharsets.UTF_8);
        serviceFor(dir, true);

        mvc().perform(get("/api/public/webstats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(false))
                .andExpect(jsonPath("$.data.reason").value("WINDOW_EMPTY"));
    }

    @Test
    @DisplayName("启动回填还没读完：BACKFILL_RUNNING（不许把'还没读到'画成'没有请求'）")
    void backfillRunningReason() throws Exception {
        baseController();
        Path dir = Files.createDirectory(tmp.resolve("log"));
        Files.write(dir.resolve("access.jsonl"), List.of(), StandardCharsets.UTF_8);
        WebStatsService svc = serviceFor(dir, true);
        ReflectionTestUtils.setField(svc, "backfillDone", false);

        mvc().perform(get("/api/public/webstats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(false))
                .andExpect(jsonPath("$.data.reason").value("BACKFILL_RUNNING"));
    }

    // ==================== 复用既有外壳 ====================

    @Test
    @DisplayName("限流：与其余公开端点同一个桶（20 次/分钟），超了就是 429 + Retry-After")
    void rateLimited() throws Exception {
        baseController();
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 1);
        ReflectionTestUtils.setField(controller, "rateLimiter", limiter);
        serviceFor(Files.createDirectory(tmp.resolve("log")), true);

        mvc().perform(get("/api/public/webstats")).andExpect(status().isOk());
        mvc().perform(get("/api/public/webstats"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "60"));
    }

    @Test
    @DisplayName("既有端点未受影响：打完 /webstats 之后 /latest 仍是同一个信封与缓存头")
    void existingEndpointsUnaffected() throws Exception {
        baseController();
        serviceFor(fixtureLog(), true);
        PublicAuditReader reader = new PublicAuditReader();
        ReflectionTestUtils.setField(reader, "dataDir", tmp.toString());
        ReflectionTestUtils.setField(controller, "auditReader", reader);

        mvc().perform(get("/api/public/webstats")).andExpect(status().isOk());
        mvc().perform(get("/api/public/latest"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(200))
                .andExpect(jsonPath("$.data.reason").value("DATA_SOURCE_UNAVAILABLE"))
                .andExpect(jsonPath("$.data.ipDisclosure.notice").exists())
                .andExpect(header().string("Cache-Control", "public, max-age=15"));
    }

    // ==================== 纯函数分支（ETag 前提 + 门槛兜底） ====================

    @Test
    @DisplayName("确定性：同样输入两次组装 → 逐字节相同（ETag/304 的前提）")
    void payloadIsDeterministic() throws Exception {
        OffsetDateTime now = OffsetDateTime.now();
        WebStatsAggregator agg = new WebStatsAggregator();
        for (int i = 0; i < 5; i++) {
            agg.record(now, 404, "/wp-login.php", "curl/8.0.1");
            agg.record(now, 404, "/.env", "curl/8.0.1");
        }
        WebStatsAggregator.Snapshot snap = agg.snapshot(now, WebStatsAggregator.Thresholds.defaults());
        WebStatsService svc = new WebStatsService();
        ReflectionTestUtils.setField(svc, "enabled", true);
        ReflectionTestUtils.setField(svc, "accessLogEnabled", true);
        WebStatsService.Status st = svc.status();
        WebStatsAggregator.Thresholds th = WebStatsAggregator.Thresholds.defaults();

        String a = mapper.writeValueAsString(PublicApiController.buildWebStatsAvailable(snap, st, 15, "2026-10-14 12:00:00", th));
        String b = mapper.writeValueAsString(PublicApiController.buildWebStatsAvailable(snap, st, 15, "2026-10-14 12:00:00", th));
        assertEquals(a, b);
    }

    @Test
    @DisplayName("门槛兜底：配置被写成 0 也不能变成'什么都上榜'（按 1 兜底）")
    void thresholdsFallBackToOne() {
        WebStatsAggregator.Thresholds t = new WebStatsAggregator.Thresholds(0, 0, -1).normalized();
        assertEquals(1, t.minCount());
        assertEquals(1, t.topCategories());
        assertEquals(0, t.topUas());
        assertEquals(33.33d, PublicApiController.webStatsSharePercent(1, 3), 0.001d);
        assertEquals(0d, PublicApiController.webStatsSharePercent(1, 0));
    }

    @Test
    @DisplayName("共享集合：不可用载荷的字段集必须与可用载荷一致（前端只判 available 一个开关）")
    void unavailablePayloadHasSameFields() {
        Set<String> expected = new LinkedHashSet<>(List.of("generatedAt", "cacheSeconds", "window", "available",
                "reason", "totals", "topCategories", "topUas", "byDay", "heatmap", "thresholds", "coverage", "note"));
        assertEquals(expected, new LinkedHashSet<>(
                PublicApiController.buildWebStatsUnavailable("X", "note", 15, "now").keySet()));
        assertEquals(expected, new LinkedHashSet<>(PublicApiController.buildWebStatsAvailable(
                WebStatsAggregator.Snapshot.empty(), null, 15, "now",
                WebStatsAggregator.Thresholds.defaults()).keySet()));
    }
}

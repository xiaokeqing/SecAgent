package org.example.publicapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.aggregation.AlertAggregationService;
import org.example.core.model.AlertSeverity;
import org.example.core.model.AlertSource;
import org.example.core.model.AlertType;
import org.example.core.model.SecurityAlert;
import org.example.integration.WazuhGateway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * ① 聚合端点（{@code /api/public/home.js}）+ ①b 两个面板端点（{@code /deploy.js} / {@code /eval.js}）的契约测试。
 *
 * <p>它钉住这一批的<b>五条不可退让的边界</b>：
 * <ol>
 *   <li><b>逐字段一致</b>：{@code home.data.alerts} 与 {@code alerts.data} 必须<b>深度相等</b>
 *       （geo / honeypot 同理）—— 聚合端点不许"顺手改一个字段名"或漏一个字段；
 *       漏字段不会报错，只会让前端某个字段永远读不到，所以这条只能用断言钉住；</li>
 *   <li><b>一次请求拿三块</b>：一个 HTTP 请求返回三块 + 各自可用性；</li>
 *   <li><b>别名缓存口径不变</b>：{@code max-age=45, stale-while-revalidate=90} + 稳定 ETag +
 *       {@code nosniff} + {@code ACAO:*}（无 {@code Vary}）+ {@code snapshotAt} 三件套；</li>
 *   <li><b>取不到就如实说</b>：{@code deploy.release.available=false}（未配置发布文件）与
 *       {@code eval.available=false}（未配置评测报告）各有 reason，绝不用 0/启动时刻冒充；</li>
 *   <li><b>配好了就透传白名单字段</b>：文件在的时候必须 available=true 且带上真值。</li>
 * </ol>
 */
class PublicApiHomeEndpointTest {

    private static final ObjectMapper M = new ObjectMapper();

    private PublicApiController controller;
    private PublicCorsInterceptor cors;

    @BeforeEach
    void setUp() {
        controller = new PublicApiController();
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 20);
        ReflectionTestUtils.setField(controller, "rateLimiter", limiter);
        ReflectionTestUtils.setField(controller, "cacheSeconds", 45);
        ReflectionTestUtils.setField(controller, "exposeBuildSha", false);
        ReflectionTestUtils.setField(controller, "buildSha", "testsha");
        ReflectionTestUtils.setField(controller, "buildSourceSha", "sourcesha");
        ReflectionTestUtils.setField(controller, "buildArtifactMd5", "md5md5");
        ReflectionTestUtils.setField(controller, "buildTime", "2026-10-16T20:00:00Z");

        WazuhGateway gateway = (WazuhGateway) Proxy.newProxyInstance(
                WazuhGateway.class.getClassLoader(),
                new Class<?>[]{WazuhGateway.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "mode" -> "REAL";
                    case "isAvailable" -> true;
                    case "recentAlerts" -> List.of(alert("a1", "45.83.91.12"));
                    case "toString" -> "StubGateway";
                    default -> null;
                });
        PublicAlertSource source = new PublicAlertSource();
        ReflectionTestUtils.setField(source, "wazuhGateway", gateway);
        ReflectionTestUtils.setField(source, "aggregator", new AlertAggregationService());
        ReflectionTestUtils.setField(controller, "source", source);

        cors = new PublicCorsInterceptor();
        ReflectionTestUtils.setField(cors, "allowedOriginsConfig",
                "https://xiaokeqing.cn,https://www.xiaokeqing.cn");
    }

    private static SecurityAlert alert(String id, String ip) {
        SecurityAlert a = new SecurityAlert(id, "内部标题不该出现在响应里", AlertSeverity.HIGH,
                AlertType.SCAN, AlertSource.SURICATA);
        a.setSrcIp(ip);
        a.setOccurredAt("2026-10-13 10:00:00");
        return a;
    }

    private MockMvc mvc() {
        return MockMvcBuilders.standaloneSetup(controller).addInterceptors(cors).build();
    }

    private JsonNode data(String path) throws Exception {
        String body = mvc().perform(get(path)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return M.readTree(body).get("data");
    }

    @Test
    @DisplayName("① 逐字段一致：home.data.{alerts,geo,honeypot} 与三个单端点的 data 深度相等")
    void aggregateBlocksAreFieldForFieldIdentical() throws Exception {
        // 先分别打三个单端点（各自独立快照），再打聚合端点
        JsonNode alerts = data("/api/public/alerts");
        JsonNode geo = data("/api/public/geo");
        JsonNode honeypot = data("/api/public/honeypot");
        JsonNode home = data("/api/public/home");

        assertTrue(alerts.size() > 0, "单端点 alerts 不该是空对象（否则这条断言没有意义）");
        assertEquals(alerts, home.get("alerts"),
                "home.data.alerts 必须与 alerts.data 逐字段相同（含 ipDisclosure）；差异="
                        + diff(alerts, home.get("alerts")));
        assertEquals(geo, home.get("geo"),
                "home.data.geo 必须与 geo.data 逐字段相同；差异=" + diff(geo, home.get("geo")));
        assertEquals(honeypot, home.get("honeypot"),
                "home.data.honeypot 必须与 honeypot.data 逐字段相同；差异="
                        + diff(honeypot, home.get("honeypot")));
    }

    /** 逐字段差异定位（断言失败时要能一眼看出是哪个字段，不然只看到"两个大 JSON 不相等"） */
    private static String diff(JsonNode a, JsonNode b) {
        if (b == null) {
            return "聚合里缺少这个子块";
        }
        StringBuilder sb = new StringBuilder();
        a.fieldNames().forEachRemaining(f -> {
            if (!b.has(f)) {
                sb.append("缺少字段 ").append(f).append("; ");
            } else if (!a.get(f).equals(b.get(f))) {
                sb.append("字段不同 ").append(f).append(": ").append(a.get(f)).append(" != ").append(b.get(f)).append("; ");
            }
        });
        b.fieldNames().forEachRemaining(f -> {
            if (!a.has(f)) {
                sb.append("多出字段 ").append(f).append("; ");
            }
        });
        return sb.length() == 0 ? "(无差异)" : sb.toString();
    }

    @Test
    @DisplayName("① 一次请求拿三块：三块齐全且各有 available 语义")
    void oneRequestReturnsAllThreeBlocks() throws Exception {
        String body = mvc().perform(get("/api/public/home.js"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(200))
                .andExpect(jsonPath("$.data.alerts").exists())
                .andExpect(jsonPath("$.data.geo").exists())
                .andExpect(jsonPath("$.data.honeypot").exists())
                .andExpect(jsonPath("$.data.alerts.ipDisclosure").exists())
                .andExpect(jsonPath("$.data.geo.ipDisclosure").exists())
                .andExpect(jsonPath("$.data.honeypot.ipDisclosure").exists())
                .andReturn().getResponse().getContentAsString();
        // 三块都必须在同一个响应体里（这就是"只付一次路程"的物证）
        assertTrue(body.contains("\"alerts\"") && body.contains("\"geo\"") && body.contains("\"honeypot\""),
                "聚合响应体必须同时含三块");
    }

    @Test
    @DisplayName("① 别名口径与单端点一致：max-age=45 + SWR=90 + 稳定 ETag + nosniff + snapshotAt 三件套")
    void aggregateAliasKeepsCacheContract() throws Exception {
        String etag1 = mvc().perform(get("/api/public/home.js"))
                .andExpect(header().string("Cache-Control", "public, max-age=45, stale-while-revalidate=90"))
                .andExpect(header().string("Access-Control-Allow-Origin", "*"))
                .andExpect(header().doesNotExist("Vary"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Content-Type",
                        org.hamcrest.Matchers.startsWith("application/json")))
                .andExpect(jsonPath("$.snapshotAt").exists())
                .andExpect(jsonPath("$.cacheAgeSeconds").exists())
                .andExpect(jsonPath("$.snapshotTtlSeconds").value(45))
                .andReturn().getResponse().getHeader("ETag");
        Thread.sleep(1200);
        String etag2 = mvc().perform(get("/api/public/home.js")).andReturn().getResponse().getHeader("ETag");
        assertEquals(etag1, etag2,
                "聚合端点的 ETag 也必须按数据内容算（含 nested 三块）：同一快照窗口内必须稳定，"
                        + "否则 CF 再验证永远拿不到 304，三合一的收益会被回源吃掉");
    }

    @Test
    @DisplayName("① 一次请求只消耗一份限流额度：打满上限前，home 能连打 20 次而 429 只出现在第 21 次")
    void aggregateConsumesOneTokenPerRequest() throws Exception {
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 20);
        ReflectionTestUtils.setField(controller, "rateLimiter", limiter);
        for (int i = 0; i < 20; i++) {
            mvc().perform(get("/api/public/home")).andExpect(status().isOk());
        }
        // 第 21 次：与其它端点同一套 429 信封（Retry-After + 可读 message）
        mvc().perform(get("/api/public/home"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "60"))
                .andExpect(jsonPath("$.code").value(429));
    }

    @Test
    @DisplayName("①b 未配置时如实说取不到：deploy.release.available=false / eval.available=false，且带 reason")
    void panelEndpointsFailClosedWhenUnconfigured() throws Exception {
        mvc().perform(get("/api/public/deploy.js"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(true))
                .andExpect(jsonPath("$.data.build.sha").value("testsha"))
                .andExpect(jsonPath("$.data.build.selfReported").value(true))
                .andExpect(jsonPath("$.data.runtime.uptimeSeconds").exists())
                .andExpect(jsonPath("$.data.release.available").value(false))
                .andExpect(jsonPath("$.data.release.reason").value("RELEASE_INFO_NOT_CONFIGURED"));

        mvc().perform(get("/api/public/eval.js"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(false))
                .andExpect(jsonPath("$.data.reason").value("EVAL_REPORT_NOT_CONFIGURED"));
    }

    @Test
    @DisplayName("①b 配好了就透传白名单：发布信息 + 评测真值（其余键不透传）")
    void panelEndpointsPassThroughWhitelistedKeys() throws Exception {
        Path deployFile = Files.createTempFile("xk-deploy", ".json");
        Files.writeString(deployFile, "{\"release\":\"site-20261016-221614\",\"fileCount\":2302,"
                + "\"totalBytes\":159526083,\"switchedAt\":\"2026-10-16T22:16:14+08:00\","
                + "\"secretInternalField\":\"不该出现\"}", StandardCharsets.UTF_8);
        Path evalFile = Files.createTempFile("xk-eval", ".json");
        Files.writeString(evalFile, "{\"generatedAt\":\"2026-10-16T21:00:00+08:00\",\"sampleSize\":96,"
                + "\"keyPointHitRate\":0.698,\"refusalRate\":0.947,\"strictRate\":0.725,"
                + "\"citationRate\":1.0,\"personaCatchphraseRate\":0.0,\"tabooRate\":0.475,"
                + "\"internalNote\":\"不该出现\"}", StandardCharsets.UTF_8);
        ReflectionTestUtils.setField(controller, "deployFile", deployFile.toString());
        ReflectionTestUtils.setField(controller, "evalReportFile", evalFile.toString());

        String deploy = mvc().perform(get("/api/public/deploy"))
                .andExpect(jsonPath("$.data.release.available").value(true))
                .andExpect(jsonPath("$.data.release.release").value("site-20261016-221614"))
                .andExpect(jsonPath("$.data.release.fileCount").value(2302))
                .andReturn().getResponse().getContentAsString();
        assertFalse(deploy.contains("secretInternalField"), "运维文件里的非白名单键不得透传到公网：" + deploy);

        String eval = mvc().perform(get("/api/public/eval"))
                .andExpect(jsonPath("$.data.available").value(true))
                .andExpect(jsonPath("$.data.sampleSize").value(96))
                .andExpect(jsonPath("$.data.keyPointHitRate").value(0.698))
                .andExpect(jsonPath("$.data.personaCatchphraseRate").value(0.0))
                .andReturn().getResponse().getContentAsString();
        assertFalse(eval.contains("internalNote"), "评测报告里的非白名单键不得透传：" + eval);

        // 坏路径 / 文件不存在，且**冷缓存** ⇒ 如实说读不到（不是 500，也不是空 200）
        ReflectionTestUtils.setField(controller, "evalCache", new PublicApiController.Snapshot());
        ReflectionTestUtils.setField(controller, "evalReportFile", deployFile + ".does-not-exist");
        mvc().perform(get("/api/public/eval"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(false))
                .andExpect(jsonPath("$.data.reason").value("EVAL_REPORT_UNREADABLE"));
    }

    @Test
    @DisplayName("①b 刷新失败保留旧值（stale-on-error）：文件消失后快照仍给上一次成功值 + 如实年龄，不是 500 也不是空")
    void staleOnErrorKeepsLastGoodValue() throws Exception {
        Path evalFile = Files.createTempFile("xk-eval-stale", ".json");
        Files.writeString(evalFile, "{\"sampleSize\":96,\"keyPointHitRate\":0.698}", StandardCharsets.UTF_8);
        ReflectionTestUtils.setField(controller, "evalReportFile", evalFile.toString());

        // ① 冷缓存 + 文件在 ⇒ 真值
        mvc().perform(get("/api/public/eval"))
                .andExpect(jsonPath("$.data.available").value(true))
                .andExpect(jsonPath("$.data.sampleSize").value(96));

        // ② 文件被删掉、快照还没过期 ⇒ 仍给上一次成功值（这正是 Snapshot 的"刷新失败保留旧值"），
        //    并且**别名路径**（.js）必须带 snapshotAt/cacheAgeSeconds 让页面如实标注"这份数据有多旧"
        //    （新鲜度三件套只下发在别名路径上：旧路径响应体逐字节不变，见 ok(...) 的注释）。
        assertTrue(evalFile.toFile().delete(), "测试前提：删掉评测报告文件");
        mvc().perform(get("/api/public/eval.js"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(true))
                .andExpect(jsonPath("$.data.sampleSize").value(96))
                .andExpect(jsonPath("$.cacheAgeSeconds").exists())
                .andExpect(jsonPath("$.snapshotAt").exists());

        // ③ 冷缓存再打（模拟 TTL 过期后重启的进程）⇒ 立刻如实说读不到
        ReflectionTestUtils.setField(controller, "evalCache", new PublicApiController.Snapshot());
        mvc().perform(get("/api/public/eval"))
                .andExpect(jsonPath("$.data.available").value(false))
                .andExpect(jsonPath("$.data.reason").value("EVAL_REPORT_UNREADABLE"));
    }
}

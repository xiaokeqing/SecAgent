package org.example.publicapi;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.aggregation.AlertAggregationService;
import org.example.core.model.AlertSeverity;
import org.example.core.model.AlertSource;
import org.example.core.model.AlertType;
import org.example.core.model.SecurityAlert;
import org.example.integration.WazuhGateway;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 公开面 IP 口径的<b>端到端契约测试</b>：真跑 MVC 路由，把两种开关状态下的响应逐条比。
 *
 * <h3>为什么必须端到端（不能只测工具类）</h3>
 * 这次改造的风险不是"掩码函数写错了"，而是"<b>某个端点忘了读开关</b>" ——
 * 那种错误在单测里永远看不见（工具类是好的），只有把 HTTP 响应打出来才发现
 * 同一个攻击源在一个端点是真的、在另一个端点还是掩码。所以这里对四个公开端点
 * （{@code /latest}、{@code /alerts}、{@code /honeypot}、{@code /audit}）各跑一遍两种状态。
 *
 * <h3>同时钉住"永不公开"两条（与开关无关）</h3>
 * <ul>
 *   <li>蜜罐完整口令：{@code topCredentials} 只出结构、{@code timeline.detail} 里的
 *       {@code 口令=123456} 被替换 —— 两种状态下响应里都不许出现口令原文；</li>
 *   <li>内部资产名：告警标题 / 时间线 detail 里的 {@code web-01}、{@code auth.log}、
 *       {@code /api/order/detail} 一律替换为占位符；</li>
 *   <li>内网/链路地址在任何口径下都不作为来源地址出现。</li>
 * </ul>
 */
class PublicIpDisclosureE2ETest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 攻击源（公网，RFC5737 之外的测试值不重要；这里用实测见过的形状） */
    private static final String ATTACKER = "106.37.205.248";
    /** 链路地址：绝不允许作为来源地址公开 */
    private static final String LINK_LOCAL = "172.18.0.1";
    /** 明文口令哨兵：出现在任何一个公开响应里都算失败 */
    private static final String PLAINTEXT = "P@ssw0rd-Str0ng";

    @TempDir
    Path dataDir;

    // ==================== 夹具 ====================

    private static SecurityAlert alert(String id, String srcIp, String title) {
        SecurityAlert a = new SecurityAlert(id, title, AlertSeverity.HIGH, AlertType.SCAN, AlertSource.SURICATA);
        a.setRuleName("规则：" + title);
        a.setSrcIp(srcIp);
        a.setDstIp("10.0.10.21");
        a.setDstAsset("web-01");
        a.setOccurredAt("2026-10-13 12:00:00");
        return a;
    }

    /** 蜜罐原始载荷（<b>未脱敏</b>，形状与 WazuhService 一致：口令原文就在里面） */
    private static Map<String, Object> honeypotRaw() {
        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("available", true);
        raw.put("commandsAvailable", false);
        raw.put("total", 9352);
        raw.put("connections", 3127);
        raw.put("logins", 3113);
        raw.put("loginFails", 5);
        raw.put("sampled", 800);
        raw.put("topCredentials", List.of(
                Map.of("key", "root / " + PLAINTEXT, "count", 3113),
                Map.of("key", "admin / 123456", "count", 88)));
        raw.put("topSources", List.of(
                Map.of("key", ATTACKER, "count", 120),
                Map.of("key", LINK_LOCAL, "count", 40)));
        raw.put("topClients", List.of(Map.of("key", "SSH-2.0-Go", "count", 10)));
        raw.put("timeline", List.of(
                Map.of("time", "2026-10-13 12:00:00", "kind", "登录成功",
                        "srcIp", ATTACKER,
                        "detail", "蜜罐: 攻击者\"登录成功\" 用户=root 口令=" + PLAINTEXT + " 来源=" + ATTACKER),
                Map.of("time", "2026-10-13 12:01:00", "kind", "新连接",
                        "srcIp", LINK_LOCAL,
                        "detail", "蜜罐: 新的 SSH 连接来自 " + LINK_LOCAL + "，目标主机 web-01，日志 auth.log，"
                                + "接口 /api/order/detail")));
        return raw;
    }

    private void writeAuditFiles() throws Exception {
        Files.writeString(dataDir.resolve("blocked-ips.json"),
                "[{\"id\":\"BLK-1\",\"ip\":\"" + ATTACKER + "\",\"durationMinutes\":60,"
                        + "\"source\":\"智能体\",\"actor\":\"admin\",\"auditId\":\"AUD-1\","
                        + "\"createdAt\":\"2026-10-13 12:00:00\",\"expiresAt\":\"2026-10-13 13:00:00\","
                        + "\"unblocked\":false},"
                        + "{\"id\":\"BLK-2\",\"ip\":\"" + LINK_LOCAL + "\",\"durationMinutes\":60,"
                        + "\"source\":\"手动\",\"actor\":\"admin\",\"auditId\":\"AUD-2\","
                        + "\"createdAt\":\"2026-10-13 11:00:00\",\"unblocked\":false}]",
                StandardCharsets.UTF_8);
        Files.writeString(dataDir.resolve("response-audit.json"),
                "[{\"id\":\"AUD-1\",\"time\":\"2026-10-13 12:00:00\",\"actor\":\"admin\","
                        + "\"action\":\"block-ip\",\"target\":\"" + ATTACKER + "\","
                        + "\"reason\":\"web-01 上抓到登录尝试，口令=" + PLAINTEXT + "\","
                        + "\"mode\":\"REAL\",\"success\":true}]",
                StandardCharsets.UTF_8);
    }

    private PublicApiController controller(boolean maskIps) throws Exception {
        writeAuditFiles();

        PublicApiController c = new PublicApiController();
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 20);
        ReflectionTestUtils.setField(c, "rateLimiter", limiter);
        ReflectionTestUtils.setField(c, "cacheSeconds", 15);
        ReflectionTestUtils.setField(c, "exposeBuildSha", false);
        ReflectionTestUtils.setField(c, "buildSha", "test");
        ReflectionTestUtils.setField(c, "ipPolicy", PublicIpPolicy.of(maskIps));

        PublicAuditReader reader = new PublicAuditReader();
        ReflectionTestUtils.setField(reader, "dataDir", dataDir.toString());
        ReflectionTestUtils.setField(reader, "ipPolicy", PublicIpPolicy.of(maskIps));
        ReflectionTestUtils.setField(c, "auditReader", reader);

        List<SecurityAlert> alerts = List.of(
                alert("a1", ATTACKER, "web-01 上的 SSH 暴力破解"),
                alert("a2", LINK_LOCAL, "来自链路地址的探测"));

        Map<String, Object> honeypot = honeypotRaw();
        WazuhGateway gateway = (WazuhGateway) Proxy.newProxyInstance(
                WazuhGateway.class.getClassLoader(),
                new Class<?>[]{WazuhGateway.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "mode" -> "REAL";
                    case "isAvailable" -> true;
                    case "recentAlerts" -> alerts;
                    case "honeypotSummary" -> honeypot;
                    case "toString" -> "StubGateway";
                    default -> null;
                });
        PublicAlertSource source = new PublicAlertSource();
        ReflectionTestUtils.setField(source, "wazuhGateway", gateway);
        ReflectionTestUtils.setField(source, "aggregator", new AlertAggregationService());
        ReflectionTestUtils.setField(c, "source", source);
        return c;
    }

    private String body(PublicApiController c, String url) throws Exception {
        MockMvc mvc = MockMvcBuilders.standaloneSetup(c).build();
        return mvc.perform(get(url)).andExpect(status().isOk()).andReturn()
                .getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    private static List<String> publicUrls() {
        return List.of("/api/public/latest", "/api/public/alerts", "/api/public/honeypot", "/api/public/audit");
    }

    // ==================== 真实态（默认口径） ====================

    @Test
    @DisplayName("真实态：四个端点都显示观测到的真实来源地址，且都带 ipDisclosure")
    void realModeShowsObservedAddressesOnEveryEndpoint() throws Exception {
        PublicApiController c = controller(false);

        for (String url : publicUrls()) {
            String json = body(c, url);

            assertTrue(json.contains("\"ipDisclosure\""), url + " 缺统一口径字段：" + json);
            assertTrue(json.contains("\"masked\":false"), url + " 的 ipDisclosure 应标 masked=false：" + json);
            assertTrue(json.contains(PublicIpPolicy.NOTICE), url + " 应带口径原文：" + json);
            assertTrue(json.contains("\"removalContact\""), url + " 应带移除/更正入口：" + json);
            assertTrue(json.contains(ATTACKER),
                    url + " 在真实态下必须显示观测到的真实来源地址 " + ATTACKER + "：" + json);
        }
    }

    @Test
    @DisplayName("真实态：账户口令 Top 只出结构（用户名 + 长度 + 字符类 + 弱口令），不含口令原文")
    void realModeCredentialTopIsStructureOnly() throws Exception {
        String json = body(controller(false), "/api/public/honeypot");

        assertTrue(json.contains("\"username\":\"root\""), "用户名可以给：" + json);
        assertTrue(json.contains("\"passwordLength\":" + PLAINTEXT.length()),
                "应给出长度 " + PLAINTEXT.length() + "：" + json);
        assertTrue(json.contains("\"weakPassword\":true"), "123456 应被标为弱口令：" + json);
        assertTrue(json.contains(CredentialStructure.charClassesLabel(PLAINTEXT)),
                "应给出字符类：" + json);
    }

    // ==================== 掩码态（改造前口径，回归） ====================

    @Test
    @DisplayName("【回归】掩码态：四个端点都回到改造前的掩码行为，口径字段标 masked=true")
    void maskedModeRestoresLegacyBehaviour() throws Exception {
        PublicApiController c = controller(true);

        for (String url : publicUrls()) {
            String json = body(c, url);

            assertFalse(json.contains(ATTACKER),
                    url + " 在掩码态下不得出现完整来源 IP（改造前就是这样）：" + json);
            assertTrue(json.contains("\"masked\":true"), url + " 的 ipDisclosure 应标 masked=true：" + json);
        }

        String honeypot = body(c, "/api/public/honeypot");
        assertTrue(honeypot.contains("106.37.***.***"), "掩码态保留网段级掩码：" + honeypot);
        assertTrue(honeypot.contains("\"srcIp\":\"106.37.***.***\""), honeypot);
        assertTrue(honeypot.contains("内部地址"), "掩码态下链路地址写「内部地址」（改造前口径）：" + honeypot);
        assertEquals("IP 已掩码到网段；命令时间线的数据源尚未接入（Wazuh 侧没有命令执行规则，不编造）",
                jsonField(honeypot, "note"), "掩码态的 note 必须与改造前逐字节相同");
    }

    @Test
    @DisplayName("两种状态的差异只在 IP 相关字段 + ipDisclosure（同一份数据源，字段集合一致）")
    void onlyIpFieldsAndDisclosureDiffer() throws Exception {
        String real = body(controller(false), "/api/public/honeypot");
        String masked = body(controller(true), "/api/public/honeypot");

        Map<String, Object> r = data(real);
        Map<String, Object> m = data(masked);

        assertEquals(r.keySet(), m.keySet(), "两种口径的字段集合必须完全一致（只换值，不换结构）");
        assertEquals(r.get("total"), m.get("total"));
        assertEquals(r.get("loginFails"), m.get("loginFails"));
        assertEquals(r.get("sampled"), m.get("sampled"));

        @SuppressWarnings("unchecked")
        Map<String, Object> rDisclosure = (Map<String, Object>) r.get("ipDisclosure");
        @SuppressWarnings("unchecked")
        Map<String, Object> mDisclosure = (Map<String, Object>) m.get("ipDisclosure");
        assertEquals(rDisclosure.get("notice"), mDisclosure.get("notice"));
        assertFalse(rDisclosure.get("masked").equals(mDisclosure.get("masked")),
                "唯一该变的就是 masked 标记");

        // 口令结构在两种口径下完全一样（与开关无关）
        assertEquals(String.valueOf(m.get("topCredentials")), String.valueOf(r.get("topCredentials")),
                "口令结构不受 IP 开关影响");
    }

    // ==================== 永不公开（与开关无关） ====================

    @Test
    @DisplayName("【核心】两种口径下、四个端点里，蜜罐口令原文与口令字段一律不出现在响应里")
    void credentialsNeverReachThePublicPayload() throws Exception {
        for (boolean maskIps : List.of(false, true)) {
            PublicApiController c = controller(maskIps);
            for (String url : publicUrls()) {
                String json = body(c, url);

                assertFalse(json.contains(PLAINTEXT),
                        "[mask-ips=" + maskIps + "] " + url + " 泄露了口令原文：" + json);
                assertFalse(json.contains("123456"),
                        "[mask-ips=" + maskIps + "] " + url + " 泄露了弱口令原文：" + json);
                assertFalse(json.contains("口令=" + PLAINTEXT), json);
            }
        }

        String honeypot = body(controller(false), "/api/public/honeypot");
        assertTrue(honeypot.contains(CredentialStructure.PASSWORD_HIDDEN),
                "timeline.detail 里的口令字段应被明确隐去（不是悄悄删掉）：" + honeypot);
        assertTrue(honeypot.contains("\"username\":\"root\""), "用户名保留：" + honeypot);
        assertFalse(honeypot.contains("密码"), "连「密码=…」这种残留都不该有：" + honeypot);
    }

    @Test
    @DisplayName("【核心】内网/链路地址在任何口径下都不作为来源地址输出")
    void internalAddressesNeverShownAsSource() throws Exception {
        // 真实态：写成「内网/未知」
        String real = body(controller(false), "/api/public/honeypot");
        assertFalse(real.contains(LINK_LOCAL), "真实态也不得把链路地址当来源地址：" + real);
        assertTrue(real.contains(PublicIpMask.INTERNAL_UNKNOWN_LABEL), "应写「内网/未知」：" + real);

        String realAlerts = body(controller(false), "/api/public/alerts");
        assertFalse(realAlerts.contains(LINK_LOCAL), "告警端点同样不得出现链路地址：" + realAlerts);
        assertFalse(realAlerts.contains("10.0.10.21"), "内网目的地址本来就不该出现：" + realAlerts);

        String realAudit = body(controller(false), "/api/public/audit");
        assertFalse(realAudit.contains(LINK_LOCAL), "审计端点同样不得出现链路地址：" + realAudit);

        // 掩码态：写成「内部地址」（历史口径）
        String masked = body(controller(true), "/api/public/honeypot");
        assertFalse(masked.contains(LINK_LOCAL));
        assertTrue(masked.contains("内部地址"), masked);
    }

    @Test
    @DisplayName("内部资产名从公开响应里被过滤（含告警标题与知识库引用正文路径）")
    void assetNamesAreScrubbedEverywhere() throws Exception {
        PublicApiController c = controller(false);

        String alerts = body(c, "/api/public/alerts");
        assertFalse(alerts.contains("web-01"), "告警标题里的资产名必须被过滤：" + alerts);
        assertTrue(alerts.contains(PublicAssetFilter.PLACEHOLDER), "应替换成占位符：" + alerts);

        String honeypot = body(c, "/api/public/honeypot");
        for (String bad : List.of("web-01", "auth.log", "/api/order/detail")) {
            assertFalse(honeypot.contains(bad), "蜜罐时间线里的「" + bad + "」必须被过滤：" + honeypot);
        }

        String audit = body(c, "/api/public/audit");
        assertFalse(audit.contains("web-01"), "处置原因的资产名必须被过滤：" + audit);
    }

    // ==================== /ask 的信封（POST 不走 ok(...)，口径必须一样） ====================

    @Test
    @DisplayName("/ask 信封：既有 clientIpMasked 永远掩码，新增 clientIp 按口径，ipDisclosure 同在")
    void askEnvelopeUsesTheSamePolicy() throws Exception {
        // POST /api/public/ask 走的是控制器里另一条 return 路径（不走 ok(...)），
        // 所以它的口径必须单独钉一次 —— 这正是"某个端点忘了读开关"最容易发生的地方。
        Map<String, Object> masked = askEnvelope(PublicIpPolicy.masking());
        assertEquals("106.37.***.***", masked.get("clientIpMasked"), "既有字段语义不变（永远掩码）");
        assertEquals("106.37.***.***", masked.get("clientIp"), "掩码态下新字段同样掩码");
        assertEquals(Boolean.TRUE, disclosureOf(masked).get("masked"));

        Map<String, Object> real = askEnvelope(PublicIpPolicy.revealing());
        assertEquals("106.37.***.***", real.get("clientIpMasked"),
                "字段名里就写着 Masked，塞真实地址等于让字段名说谎（契约也不许改名）");
        assertEquals(ATTACKER, real.get("clientIp"), "新字段按口径显示观测到的真实地址");
        assertEquals(PublicIpPolicy.NOTICE, disclosureOf(real).get("notice"));
        assertEquals(Boolean.FALSE, disclosureOf(real).get("masked"));

        Map<String, Object> internal = askEnvelope(PublicIpPolicy.revealing(), LINK_LOCAL);
        assertEquals(PublicIpMask.INTERNAL_UNKNOWN_LABEL, internal.get("clientIp"),
                "调用方来源是链路地址时也不许当真地址展示");
    }

    private static Map<String, Object> askEnvelope(PublicIpPolicy policy) throws Exception {
        return askEnvelope(policy, ATTACKER);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> askEnvelope(PublicIpPolicy policy, String clientIp) throws Exception {
        PublicAskService service = new PublicAskService();
        ReflectionTestUtils.setField(service, "ipPolicy", policy);
        java.lang.reflect.Method m = PublicAskService.class.getDeclaredMethod("baseEnvelope", String.class);
        m.setAccessible(true);
        return (Map<String, Object>) m.invoke(service, clientIp);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> disclosureOf(Map<String, Object> envelope) {
        return (Map<String, Object>) envelope.get(PublicIpPolicy.DISCLOSURE_FIELD);
    }

    // ==================== 工具 ====================

    @SuppressWarnings("unchecked")
    private static Map<String, Object> data(String json) throws Exception {
        return (Map<String, Object>) MAPPER.readValue(json, Map.class).get("data");
    }

    /** 取 data 下的字符串字段（不做正则，避免把转义搞错） */
    private static String jsonField(String json, String field) throws Exception {
        Object v = data(json).get(field);
        return v == null ? null : String.valueOf(v);
    }
}

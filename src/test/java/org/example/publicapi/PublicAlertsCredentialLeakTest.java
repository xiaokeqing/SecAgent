package org.example.publicapi;

import com.fasterxml.jackson.core.type.TypeReference;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * <b>2026-10-14 公开面红线违反的 CI 回归</b>：蜜罐规则原文里的明文口令曾随
 * {@code title} / {@code ruleName} 直出 {@code /api/public/alerts} 与
 * {@code /api/public/alerts/{aggId}}。
 *
 * <h3>出事的那条路径</h3>
 * 公开 GET 的统一出口是 {@code ok()} → {@code ship()} → {@code scrubDeep()}，而
 * {@code scrubDeep()} 原先<b>只调 {@code assets().scrub()}（资产名过滤），从不做凭据脱敏</b>。
 * {@code /honeypot} 是显式调了 {@code CredentialStructure.hidePasswords()} 才干净的，
 * 告警链路（{@code buildAlerts()} → {@code publicAggregate()} / {@code publicAlert()}）
 * 一处都没调 —— 于是 Wazuh 蜜罐规则描述
 * {@code 蜜罐: 攻击者"登录成功" 用户=root 口令=<明文> 来源=<ip>}
 * 原样进了 {@code title} 与 {@code ruleName}。
 *
 * <p><b>实测现场（修复前，srv1 线上）</b>：{@code data.list[23].title} 与
 * {@code data.list[23].ruleName} 都等于上面那段原文，{@code 口令=示例明文(占位)} 明文可见；
 * 而同一时刻 {@code /api/public/honeypot} 是干净的（{@code 口令=[口令已隐藏]}）。
 * 也就是说：<b>同一个口令在一个端点上被隐去、在另一个端点上原文出网</b>。
 *
 * <h3>为什么这个测试必须"整段响应体正则扫描"</h3>
 * 只断言 {@code !response.contains(哨兵口令)} 会有盲区：漏出的口令未必是测试挑的那一个
 * （攻击者猜什么都有可能），正则扫描才管住"任意明文口令"。两条断言各管一半：
 * <ul>
 *   <li>哨兵口令断言：钉住"这条具体数据确实过了一遍脱敏"（否则正则可能只是没东西可扫而空过）；</li>
 *   <li>整段正则扫描：钉住"任何 {@code 口令=} / {@code password=} 后面都不是非隐藏内容"。</li>
 * </ul>
 *
 * <h3>为什么覆盖"下钻"而不只测列表</h3>
 * 列表与下钻是<b>两条独立的组装路径</b>（{@code publicAggregate} vs {@code publicAlert}），
 * 只测一条正是这次出事的失败模式。
 */
class PublicAlertsCredentialLeakTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 明文口令哨兵：任何公开响应里出现它就算失败 */
    private static final String PLAINTEXT = "P@ssw0rd-Str0ng";

    /** 线上真实现场那个口令，一并钉住（常见弱口令，含在正则的覆盖面上） */
    private static final String PLAINTEXT_WEAK = "passw0rd";

    private static final String ATTACKER = "106.37.205.248";

    /**
     * 明文口令判别式 —— <b>与 {@code CredentialStructure.hidePasswords} 的入参形状同源</b>，
     * 但判据写死在这里而<b>不调用被测代码</b>：用被测实现去证明被测实现是循环论证。
     *
     * <p>隐藏形态是 {@code 口令=[口令已隐藏]}，即"分隔符右边第一个字符是 {@code [}"。
     * 所以"分隔符 + {@code \S+} 且首字符不是 {@code [}"就是明文残留。
     */
    private static final Pattern PLAINTEXT_PASSWORD_FIELD = Pattern.compile(
            "(?i)(口令|密码|password|passwd|pwd)\\s*[:=：]\\s*([^\\s\\[][^\\s]*)");

    /** 蜜罐规则原文的形状（就是线上那条 title 的原样） */
    private static String honeypotRuleText(String password) {
        return "蜜罐: 攻击者\"登录成功\" 用户=root 口令=" + password + " 来源=" + ATTACKER;
    }

    @TempDir
    Path dataDir;

    // ==================== 夹具 ====================

    private static SecurityAlert honeypotAlert(String id, String password) {
        // 类型/来源取线上真实取值（实测：蜜罐登录成功告警是 AlertType.OTHER + AlertSource.WAZUH）
        SecurityAlert a = new SecurityAlert(id, honeypotRuleText(password),
                AlertSeverity.HIGH, AlertType.OTHER, AlertSource.WAZUH);
        // 线上 ruleName 与 title 是同一段原文 —— 两个字段都必须被覆盖
        a.setRuleName(honeypotRuleText(password));
        a.setSrcIp(ATTACKER);
        a.setDstIp("10.0.10.21");
        a.setDstAsset("web-01");
        a.setOccurredAt("2026-10-14 02:06:56");
        return a;
    }

    /**
     * {@code /honeypot} 的原始载荷（<b>未脱敏</b>，口令原文就在 timeline.detail 里）。
     *
     * <p>为什么这个用例也要它：{@code timelineForPublic()} 本来就显式调了
     * {@code hidePasswords}，而 {@code scrubDeep()} 现在<b>又过一遍</b> ——
     * 这里正是"双重保险必须幂等、输出不变"的现场。
     */
    private static Map<String, Object> honeypotRaw() {
        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("available", true);
        raw.put("commandsAvailable", false);
        raw.put("total", 9352);
        raw.put("connections", 3127);
        raw.put("logins", 3113);
        raw.put("loginFails", 5);
        raw.put("sampled", 800);
        raw.put("topCredentials", List.of(Map.of("key", "root / " + PLAINTEXT, "count", 3113)));
        raw.put("topSources", List.of(Map.of("key", ATTACKER, "count", 120)));
        raw.put("topClients", List.of(Map.of("key", "SSH-2.0-Go", "count", 10)));
        raw.put("timeline", List.of(Map.of(
                "time", "2026-10-14 02:06:56", "kind", "登录成功", "srcIp", ATTACKER,
                "detail", honeypotRuleText(PLAINTEXT_WEAK))));
        return raw;
    }

    /** 走真实装配：真跑 MVC 路由 + 真的聚合服务 + 真的出口闸门 */
    private PublicApiController controller() throws Exception {
        Files.writeString(dataDir.resolve("blocked-ips.json"), "[]", StandardCharsets.UTF_8);
        Files.writeString(dataDir.resolve("response-audit.json"), "[]", StandardCharsets.UTF_8);

        PublicApiController c = new PublicApiController();
        PublicRateLimiter limiter = new PublicRateLimiter();
        // 用例要连发多次请求（列表 + 下钻），限流器放宽到不至于自伤
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 200);
        ReflectionTestUtils.setField(c, "rateLimiter", limiter);
        ReflectionTestUtils.setField(c, "cacheSeconds", 15);
        ReflectionTestUtils.setField(c, "exposeBuildSha", false);
        ReflectionTestUtils.setField(c, "buildSha", "test");
        ReflectionTestUtils.setField(c, "ipPolicy", PublicIpPolicy.of(false));

        PublicAuditReader reader = new PublicAuditReader();
        ReflectionTestUtils.setField(reader, "dataDir", dataDir.toString());
        ReflectionTestUtils.setField(reader, "ipPolicy", PublicIpPolicy.of(false));
        ReflectionTestUtils.setField(c, "auditReader", reader);

        List<SecurityAlert> alerts = List.of(
                honeypotAlert("a1", PLAINTEXT),
                honeypotAlert("a2", PLAINTEXT_WEAK));

        WazuhGateway gateway = (WazuhGateway) Proxy.newProxyInstance(
                WazuhGateway.class.getClassLoader(),
                new Class<?>[]{WazuhGateway.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "mode" -> "REAL";
                    case "isAvailable" -> true;
                    case "recentAlerts" -> alerts;
                    case "honeypotSummary" -> honeypotRaw();
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

    @SuppressWarnings("unchecked")
    private Map<String, Object> data(String json) throws Exception {
        Map<String, Object> root = MAPPER.readValue(json, new TypeReference<>() {
        });
        Map<String, Object> data = (Map<String, Object>) root.get("data");
        assertNotNull(data, "响应里应有 data：" + json);
        return data;
    }

    // ==================== 断言工具 ====================

    /** 整段响应体的明文口令扫描 —— 与"这条数据有没有被脱敏"无关，扫的是全篇 */
    private static void assertNoPlaintextPasswordAnywhere(String where, String json) {
        assertFalse(json.contains(PLAINTEXT),
                where + " 泄露了哨兵口令原文：" + json);
        assertFalse(json.contains(PLAINTEXT_WEAK),
                where + " 泄露了弱口令原文 passw0rd：" + json);

        Matcher m = PLAINTEXT_PASSWORD_FIELD.matcher(json);
        StringBuilder leaks = new StringBuilder();
        int n = 0;
        while (m.find()) {
            n++;
            if (leaks.length() < 400) {
                leaks.append('[').append(m.group()).append("] ");
            }
        }
        assertEquals(0, n,
                where + " 响应体里还有 " + n + " 处明文口令字段（应全部是「"
                        + CredentialStructure.PASSWORD_HIDDEN + "」）：" + leaks);
    }

    /** 隐藏形态必须出现 —— 防止"把整段字段悄悄删掉"也算通过 */
    private static void assertHiddenFormPresent(String where, String json) {
        assertTrue(json.contains(CredentialStructure.PASSWORD_HIDDEN),
                where + " 应保留「" + CredentialStructure.PASSWORD_HIDDEN
                        + "」这个明确信号，而不是把口令字段整个删掉：" + json);
    }

    // ==================== 用例 ====================

    @Test
    @DisplayName("【红线】/alerts：蜜罐规则原文里的口令被隐去，且出现与 /honeypot 一致的隐藏形态")
    void alertsListNeverCarriesPlaintextPassword() throws Exception {
        String json = body(controller(), "/api/public/alerts");

        assertNoPlaintextPasswordAnywhere("/api/public/alerts", json);
        assertHiddenFormPresent("/api/public/alerts", json);

        // 用户名 / 来源地址这些"可以公开"的部分要保留：脱敏不能把信息整段吃掉
        assertTrue(json.contains("用户=root"),
                "口令之外的内容应保留（脱敏不是删字段）：" + json);

        // 被脱敏的必须就是 title / ruleName 两个字段本身
        Map<String, Object> d = data(json);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> list = (List<Map<String, Object>>) d.get("list");
        assertFalse(list.isEmpty(), "夹具造了告警，聚合列表不该为空");
        boolean sawTitle = false;
        for (Map<String, Object> agg : list) {
            for (String f : List.of("title", "ruleName")) {
                String v = String.valueOf(agg.get(f));
                if (v.contains("蜜罐")) {
                    sawTitle = true;
                    assertFalse(v.contains(PLAINTEXT), f + " 仍有明文口令：" + v);
                    assertFalse(v.contains(PLAINTEXT_WEAK), f + " 仍有明文口令：" + v);
                    assertTrue(v.contains(CredentialStructure.PASSWORD_HIDDEN),
                            f + " 应写成隐藏形态：" + v);
                }
            }
        }
        assertTrue(sawTitle, "夹具的蜜罐告警没进公开面，本用例就没测到东西：" + json);
    }

    @Test
    @DisplayName("【红线】/alerts/{aggId} 下钻：明细里的 title / ruleName 同样不含明文口令")
    void alertsDrillDownNeverCarriesPlaintextPassword() throws Exception {
        PublicApiController c = controller();

        // 从列表里取真实的 aggId（聚合 id 由成员与源地址派生，不硬编码）
        Map<String, Object> listData = data(body(c, "/api/public/alerts"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> list = (List<Map<String, Object>>) listData.get("list");
        assertFalse(list.isEmpty(), "夹具造了告警，聚合列表不该为空");
        String aggId = String.valueOf(list.get(0).get("aggId"));
        assertNotNull(aggId);

        String json = body(c, "/api/public/alerts/" + aggId);

        assertNoPlaintextPasswordAnywhere("/api/public/alerts/" + aggId, json);
        assertHiddenFormPresent("/api/public/alerts/" + aggId, json);

        Map<String, Object> d = data(json);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> members = (List<Map<String, Object>>) d.get("members");
        assertFalse(members.isEmpty(), "下钻应该带回簇内明细：" + json);
        boolean sawMember = false;
        for (Map<String, Object> mem : members) {
            for (String f : List.of("title", "ruleName")) {
                String v = String.valueOf(mem.get(f));
                if (v.contains("蜜罐")) {
                    sawMember = true;
                    assertFalse(v.contains(PLAINTEXT), f + " 仍有明文口令：" + v);
                    assertFalse(v.contains(PLAINTEXT_WEAK), f + " 仍有明文口令：" + v);
                    assertTrue(v.contains(CredentialStructure.PASSWORD_HIDDEN),
                            f + " 应写成隐藏形态：" + v);
                }
            }
        }
        assertTrue(sawMember, "下钻明细里没有蜜罐告警，本用例就没测到下钻路径：" + json);
    }

    @Test
    @DisplayName("【闸门】/honeypot 与 /alerts 的隐藏形态一致（同一个 PASSWORD_HIDDEN 常量）")
    void hiddenFormIsTheSameOnBothEndpoints() throws Exception {
        PublicApiController c = controller();
        String honeypot = body(c, "/api/public/honeypot");
        String alerts = body(c, "/api/public/alerts");

        assertTrue(honeypot.contains("口令=" + CredentialStructure.PASSWORD_HIDDEN),
                "/honeypot 的隐藏形态：" + honeypot);
        assertTrue(alerts.contains("口令=" + CredentialStructure.PASSWORD_HIDDEN),
                "/alerts 应出现与 /honeypot 完全一致的隐藏形态，而不是另一种写法：" + alerts);
        assertNoPlaintextPasswordAnywhere("/api/public/honeypot", honeypot);
    }

    @Test
    @DisplayName("【双重保险】已隐藏的文本再过一遍 hidePasswords 逐字节不变（/honeypot 输出不受影响）")
    void hidingIsIdempotentSoHoneypotOutputIsUnchanged() {
        // timelineForPublic() 本来就调 hidePasswords，scrubDeep() 现在【又过一遍】。
        // 两条断言合起来才等于"输出不变"：
        //   1) 占位符本身不再匹配口令字段（不会被二次改写，例如变成「口令=口令=[…]」）；
        //   2) 再处理一遍的结果与处理一遍逐字节相同。
        String once = CredentialStructure.hidePasswords(honeypotRuleText("passw0rd"));
        assertEquals("蜜罐: 攻击者\"登录成功\" 用户=root 口令="
                        + CredentialStructure.PASSWORD_HIDDEN + " 来源=" + ATTACKER,
                once, "一次处理的形态应与 /honeypot 线上输出一致");
        assertEquals(once, CredentialStructure.hidePasswords(once),
                "已隐藏的文本再处理必须逐字节不变（否则 /honeypot 会被二次保险改坏）");

        // 反向保险：占位符里不该残留可被口令正则命中的形状
        assertFalse(PLAINTEXT_PASSWORD_FIELD.matcher(once).find(),
                "隐藏后的文本不该再被口令正则命中：" + once);
    }
}

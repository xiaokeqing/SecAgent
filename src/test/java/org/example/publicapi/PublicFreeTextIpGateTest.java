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
 * <b>2026-10-16 公开面 IP 口径收口</b>：自由文本字段（{@code title} / {@code ruleName}）
 * 里的<b>内网来源地址</b>曾明文直出 {@code /api/public/alerts} 与 {@code /api/public/alerts/{aggId}}。
 *
 * <h3>出事的那条路径（线上只读实测）</h3>
 * {@code PublicIpPolicy.displayText()} 原先只在少数几个自由文本字段上被显式调用，
 * 告警链路一处都没调；而 {@code app.public.mask-ips} 的字段级出口
 * （{@code publicAggregate()} → {@code srcIp}）是调了的。于是同一条记录出现
 * <b>"结构化字段对、自由文本字段错"</b>：
 * <pre>
 *   /api/public/alerts  →  data.list[*].srcIp    = 内网/未知          ✓
 *                          data.list[*].title    = 蜜罐(Dionaea): SMB 连接/认证尝试 来源=172.19.0.1:57386  ✗
 *                          data.list[*].ruleName = 同上                                   ✗
 * </pre>
 * 违反 {@code PublicIpPolicy} 里那条<b>与开关无关</b>的硬约束：「内网/保留/链路地址
 * 在真实态下也一律写成「内网/未知」」（RUNBOOK §27.1），而本站口径明确"白送内网拓扑"不可接受。
 *
 * <h3>为什么这个测试必须"整段响应体正则扫描"</h3>
 * 只断言 {@code !body.contains(INTERNAL)} 会有盲区：漏出去的未必是测试挑的那一个地址。
 * 两条断言各管一半：
 * <ul>
 *   <li>哨兵断言：钉住"这条具体数据确实过了一遍 IP 口径"（否则正则可能只是没东西可扫而空过）；</li>
 *   <li>整段扫描：钉住"任何内网/保留地址都不在响应体里"。</li>
 * </ul>
 *
 * <h3>为什么覆盖"下钻"而不只测列表</h3>
 * 列表与下钻是<b>两条独立的组装路径</b>（{@code publicAggregate} vs {@code publicAlert}），
 * 只测一条正是口令那次与这次共同的失败模式。
 *
 * <h3>为什么还要断言"公网攻击源照旧保留"</h3>
 * 收口的对象是"内网/保留地址"，不是"所有 IP"。真实态下公开面<b>要</b>显示观测到的真实来源地址
 * （站主 2026-10-14 拍板）；如果这条断言被删掉，一个"把所有 IP 都掩掉"的改动也会全绿 ——
 * 那是把收口做成了口径回退。
 */
class PublicFreeTextIpGateTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 线上实测那条原文里的内网来源地址（Docker 网桥），任何公开响应里都不许出现原形 */
    private static final String INTERNAL = "172.19.0.1";

    /** 公网攻击源：真实态下应当照旧显示，掩码态下必须被掩掉 */
    private static final String PUBLIC_ATTACKER = "106.37.205.248";

    /** 内网/保留地址判别式（写死在这里，不复用被测代码 —— 否则是循环论证） */
    private static final Pattern INTERNAL_V4 = Pattern.compile(
            "(?<![\\d.])((?:10|127)\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"
                    + "|192\\.168\\.\\d{1,3}\\.\\d{1,3}"
                    + "|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}"
                    + "|169\\.254\\.\\d{1,3}\\.\\d{1,3}"
                    + "|100\\.(?:6[4-9]|[7-9]\\d|1[01]\\d|12[0-7])\\.\\d{1,3}\\.\\d{1,3})(?![\\d.])");

    @TempDir
    Path dataDir;

    // ==================== 夹具 ====================

    /** 线上那条蜜罐规则原文的形状 */
    private static String dionaeaRuleText(String src) {
        return "蜜罐(Dionaea): SMB 连接/认证尝试 来源=" + src + ":57386";
    }

    private static SecurityAlert alert(String id, String ruleText, String srcIp) {
        SecurityAlert a = new SecurityAlert(id, ruleText, AlertSeverity.MEDIUM,
                AlertType.OTHER, AlertSource.WAZUH);
        // 线上 title 与 ruleName 是同一段原文 —— 两个字段都必须被覆盖
        a.setRuleName(ruleText);
        a.setSrcIp(srcIp);
        a.setDstIp("10.0.10.21");
        a.setOccurredAt("2026-10-16 01:35:00");
        return a;
    }

    /** 走真实装配：真跑 MVC 路由 + 真的聚合服务 + 真的出口闸门（{@code ship → scrubDeep → scrubText}） */
    private PublicApiController controller(boolean masked) throws Exception {
        Files.writeString(dataDir.resolve("blocked-ips.json"), "[]", StandardCharsets.UTF_8);
        Files.writeString(dataDir.resolve("response-audit.json"), "[]", StandardCharsets.UTF_8);

        PublicApiController c = new PublicApiController();
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 200);
        ReflectionTestUtils.setField(c, "rateLimiter", limiter);
        ReflectionTestUtils.setField(c, "cacheSeconds", 15);
        ReflectionTestUtils.setField(c, "exposeBuildSha", false);
        ReflectionTestUtils.setField(c, "buildSha", "test");
        ReflectionTestUtils.setField(c, "ipPolicy", PublicIpPolicy.of(masked));

        PublicAuditReader reader = new PublicAuditReader();
        ReflectionTestUtils.setField(reader, "dataDir", dataDir.toString());
        ReflectionTestUtils.setField(reader, "ipPolicy", PublicIpPolicy.of(masked));
        ReflectionTestUtils.setField(c, "auditReader", reader);

        List<SecurityAlert> alerts = List.of(
                alert("a1", dionaeaRuleText(INTERNAL), INTERNAL),
                alert("a2", dionaeaRuleText(PUBLIC_ATTACKER), PUBLIC_ATTACKER));

        WazuhGateway gateway = (WazuhGateway) Proxy.newProxyInstance(
                WazuhGateway.class.getClassLoader(),
                new Class<?>[]{WazuhGateway.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "mode" -> "REAL";
                    case "isAvailable" -> true;
                    case "recentAlerts" -> alerts;
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

    /** 整段响应体扫描：不许出现任何内网/保留地址（与"这条数据有没有过闸门"无关，扫的是全篇） */
    private static void assertNoInternalAddressAnywhere(String where, String json) {
        assertFalse(json.contains(INTERNAL),
                where + " 泄露了内网来源地址哨兵 " + INTERNAL + "：" + json);
        Matcher m = INTERNAL_V4.matcher(json);
        StringBuilder leaks = new StringBuilder();
        int n = 0;
        while (m.find()) {
            n++;
            if (leaks.length() < 300) {
                leaks.append('[').append(m.group()).append("] ");
            }
        }
        assertEquals(0, n,
                where + " 响应体里还有 " + n + " 处内网/保留地址原文（内网拓扑不上公开面）：" + leaks);
    }

    /** 取出"来源=<值>"后面的那段，用来钉住这一条数据确实换了口径（而不是字段被删空） */
    private static String sourceToken(String text) {
        int i = text.indexOf("来源=");
        return i < 0 ? "" : text.substring(i + "来源=".length());
    }

    // ==================== 用例 ====================

    @Test
    @DisplayName("【红线】真实态 /alerts：自由文本里的内网来源 →「内网/未知」，公网攻击源照旧保留")
    void revealingModeAlertsListNeverCarriesInternalAddress() throws Exception {
        String json = body(controller(false), "/api/public/alerts");

        assertNoInternalAddressAnywhere("/api/public/alerts（真实态）", json);

        // 内网那条被换成统一标签（不是删字段、不是留空）
        assertTrue(json.contains("来源=内网/未知:57386"),
                "内网来源应写成「内网/未知」（掩码态可核对的统一信号）：" + json);

        // 公网攻击源必须原样保留 —— 否则这条收口就把口径做成了回退
        assertTrue(json.contains("来源=" + PUBLIC_ATTACKER + ":57386"),
                "真实态下观测到的公网来源地址应照旧显示（站主 2026-10-14 拍板）：" + json);

        // 被改的必须就是 title / ruleName 两个字段本身，且与结构化字段 srcIp 同一口径。
        // 定位方式刻意【按 srcIp 分组】而不是按原始 IP 找：原始 IP 正是被换掉的那个，
        // 用"找原始 IP"来定位等于让断言依赖"修复没生效"。
        Map<String, Object> d = data(json);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> list = (List<Map<String, Object>>) d.get("list");
        assertFalse(list.isEmpty(), "夹具造了告警，聚合列表不该为空");
        boolean sawInternal = false;
        boolean sawPublic = false;
        for (Map<String, Object> agg : list) {
            String srcIp = String.valueOf(agg.get("srcIp"));
            if (PublicIpMask.INTERNAL_UNKNOWN_LABEL.equals(srcIp)) {
                sawInternal = true;
                for (String f : List.of("title", "ruleName")) {
                    String v = String.valueOf(agg.get(f));
                    assertFalse(v.contains(INTERNAL),
                            f + " 里内网来源原文仍在（结构化字段已是「内网/未知」）：" + v);
                    assertTrue(sourceToken(v).startsWith(PublicIpMask.INTERNAL_UNKNOWN_LABEL),
                            f + " 的内网来源没换口径（应与 srcIp 一致）：" + v);
                }
            } else if (PUBLIC_ATTACKER.equals(srcIp)) {
                sawPublic = true;
                for (String f : List.of("title", "ruleName")) {
                    String v = String.valueOf(agg.get(f));
                    assertTrue(sourceToken(v).startsWith(PUBLIC_ATTACKER),
                            "真实态下观测到的公网来源地址应照旧显示：" + f + " = " + v);
                }
            }
        }
        assertTrue(sawInternal, "夹具的内网告警没进公开面，本用例就没测到东西：" + json);
        assertTrue(sawPublic, "夹具的公网告警没进公开面，本用例就没测到东西：" + json);
    }

    @Test
    @DisplayName("【红线】真实态 /alerts/{aggId} 下钻：明细 title / ruleName 同样不含内网原文")
    void revealingModeDrillDownNeverCarriesInternalAddress() throws Exception {
        PublicApiController c = controller(false);

        Map<String, Object> listData = data(body(c, "/api/public/alerts"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> list = (List<Map<String, Object>>) listData.get("list");
        assertFalse(list.isEmpty(), "夹具造了告警，聚合列表不该为空");
        String aggId = String.valueOf(list.get(0).get("aggId"));
        assertNotNull(aggId);

        String json = body(c, "/api/public/alerts/" + aggId);

        assertNoInternalAddressAnywhere("/api/public/alerts/" + aggId + "（真实态）", json);

        Map<String, Object> d = data(json);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> members = (List<Map<String, Object>>) d.get("members");
        assertFalse(members.isEmpty(), "下钻应该带回簇内明细：" + json);
        boolean sawMember = false;
        for (Map<String, Object> mem : members) {
            // 同列表用例：按 srcIp 定位（内网那条的结构化字段已是「内网/未知」）
            if (!PublicIpMask.INTERNAL_UNKNOWN_LABEL.equals(String.valueOf(mem.get("srcIp")))) {
                continue;
            }
            sawMember = true;
            for (String f : List.of("title", "ruleName")) {
                String v = String.valueOf(mem.get(f));
                assertFalse(v.contains(INTERNAL),
                        f + " 下钻仍有内网来源原文：" + v);
                assertTrue(sourceToken(v).startsWith(PublicIpMask.INTERNAL_UNKNOWN_LABEL),
                        f + " 下钻的内网来源没换口径：" + v);
            }
        }
        assertTrue(sawMember, "下钻明细里没有内网来源告警，本用例就没测到下钻路径：" + json);
    }

    @Test
    @DisplayName("【口径】掩码态 /alerts：自由文本里的公网与内网地址都必须被掩掉")
    void maskedModeAlertsListMasksEveryAddress() throws Exception {
        String json = body(controller(true), "/api/public/alerts");

        assertNoInternalAddressAnywhere("/api/public/alerts（掩码态）", json);
        assertFalse(json.contains(PUBLIC_ATTACKER),
                "掩码态下公网来源也必须被掩掉（这是改造前口径，一键回退要能回得去）：" + json);

        // 掩码态的形态与结构化字段一致：公网留前两段、内网写成「内部地址」
        assertTrue(json.contains("106.37.***.***"),
                "自由文本里的公网 IP 应掩成 maskAll 形态：" + json);
        assertTrue(json.contains("内部地址"),
                "自由文本里的内网 IP 应写成「内部地址」（掩码态既有口径）：" + json);

        // 结构化字段与自由文本字段不许出现两种写法
        assertFalse(json.contains("内网/未知"),
                "掩码态下不该出现真实态才用的「内网/未知」：" + json);
    }

    @Test
    @DisplayName("【闸门幂等】已按口径处理过的文本再过一遍逐字节不变（不把已有输出改坏）")
    void gateIsIdempotent() {
        PublicApiController revealing = new PublicApiController();
        ReflectionTestUtils.setField(revealing, "ipPolicy", PublicIpPolicy.of(false));
        PublicApiController masking = new PublicApiController();
        ReflectionTestUtils.setField(masking, "ipPolicy", PublicIpPolicy.of(true));

        // 真实态：结构化字段的产物（公网原样 / 内网已换标签）再过一遍必须不变
        assertEquals(PUBLIC_ATTACKER,
                ReflectionTestUtils.invokeMethod(revealing, "scrubText", PUBLIC_ATTACKER),
                "真实态下公网地址第二次过闸门必须逐字节不变");
        assertEquals("内网/未知",
                ReflectionTestUtils.invokeMethod(revealing, "scrubText", "内网/未知"),
                "「内网/未知」这个标签本身不能再被改写");

        // 掩码态：display() 的产物形如 45.83.***.***，maskAll 不该再动它
        assertEquals("45.83.***.***",
                ReflectionTestUtils.invokeMethod(masking, "scrubText", "45.83.***.***"),
                "掩码态下已掩过的形态第二次过闸门必须逐字节不变");
        assertEquals("内部地址",
                ReflectionTestUtils.invokeMethod(masking, "scrubText", "内部地址"),
                "「内部地址」这个标签本身不能再被改写");
    }
}

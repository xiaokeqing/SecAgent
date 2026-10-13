package org.example.publicapi;

import org.example.aggregation.AlertAggregationService;
import org.example.core.model.AlertSeverity;
import org.example.core.model.AlertSource;
import org.example.core.model.AlertType;
import org.example.core.model.SecurityAlert;
import org.example.integration.WazuhGateway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * "地理富化不许从别的公开端点漏出去"的回归测试。
 *
 * <h3>它防的是什么</h3>
 * 这轮改造做了两件事：① 在告警取数处给 {@code srcGeo} <b>补上赋值</b>
 * （内部形状 {@code 国家|省|城市|ASN|机构}）；② 新增只给聚合的 {@code /api/public/geo}。
 * 而 {@code /api/public/alerts} 与 {@code /api/public/alerts/{aggId}} 里<b>本来就有</b>
 * 一个 {@code srcGeo} 字段（改造前对真实告警恒为 null，因为没人赋值、内置样本又进不了公开面）。
 * <p>
 * 于是有一个非常隐蔽的失败模式：富化一生效，这个旧字段就自动开始输出
 * "某个攻击者属于哪个国家、哪个省、哪个机构"——<b>没有任何一行代码显式地把它发出去</b>，
 * 也没有任何测试会失败。所以这里用"富化后的告警"真跑一遍公开端点，
 * 断言响应体里既不出现逐条地理/ASN 值，也不出现任何 IP。
 */
class PublicApiGeoLeakTest {

    private PublicApiController controller;

    @TempDir
    Path dataDir;

    @BeforeEach
    void setUp() {
        controller = new PublicApiController();
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 20);
        ReflectionTestUtils.setField(controller, "rateLimiter", limiter);
        ReflectionTestUtils.setField(controller, "cacheSeconds", 15);
        ReflectionTestUtils.setField(controller, "exposeBuildSha", false);
        ReflectionTestUtils.setField(controller, "buildSha", "test");
    }

    /** 造一条"已经被地理富化过"的真实告警（srcGeo 是内部形状） */
    private static SecurityAlert enriched(String id, String ip, String srcGeo) {
        SecurityAlert a = new SecurityAlert(id, "SSH 暴力破解尝试", AlertSeverity.HIGH,
                AlertType.BRUTE_FORCE, AlertSource.WAZUH);
        a.setSrcIp(ip);
        a.setSrcGeo(srcGeo);
        a.setDstIp("10.0.10.21");
        a.setDstAsset("web-01");
        a.setOccurredAt("2026-10-13 10:00:00");
        a.setRuleName("sshd");
        a.setCount(5);
        a.setExtra(new java.util.HashMap<>());
        return a;
    }

    private void wire(List<SecurityAlert> alerts) {
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
        ReflectionTestUtils.setField(controller, "source", source);
    }

    private MockMvc mvc() {
        return MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    @DisplayName("/api/public/alerts：富化后的 srcGeo 不得出现在列表里（字段名保留、值必须为空）")
    void alertsListDoesNotLeakPerAlertGeo() throws Exception {
        wire(List.of(
                enriched("a1", "45.83.91.12", "CN|Zhejiang|Hangzhou|4134|CHINANET-BACKBONE"),
                enriched("a2", "8.8.8.8", "US|California|Mountain View|15169|Google LLC")));

        String body = mvc().perform(get("/api/public/alerts"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.list[0].srcGeo").value(org.hamcrest.Matchers.nullValue()))
                .andReturn().getResponse().getContentAsString();

        for (String leak : new String[]{"Zhejiang", "Hangzhou", "CHINANET", "4134",
                "California", "Mountain View", "15169", "Google LLC"}) {
            assertFalse(body.contains(leak), "公开列表里出现了逐条地理/ASN 信息（" + leak + "）：" + body);
        }
        assertNoIp(body);
    }

    @Test
    @DisplayName("/api/public/alerts/{aggId}：下钻明细同样不得输出 srcGeo")
    void drillDownDoesNotLeakPerAlertGeo() throws Exception {
        wire(List.of(enriched("a1", "45.83.91.12", "CN|Zhejiang|Hangzhou|4134|CHINANET-BACKBONE")));

        String list = mvc().perform(get("/api/public/alerts")).andReturn().getResponse().getContentAsString();
        // 从列表里取真实的聚合 id（不自己编一个：那会测出一条走不通的路径）
        java.util.regex.Matcher m = Pattern.compile("\"aggId\"\\s*:\\s*\"([^\"]+)\"").matcher(list);
        assertTrue(m.find(), "列表里应该有 aggId：" + list);
        String aggId = m.group(1);

        String detail = mvc().perform(get("/api/public/alerts/" + aggId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.members[0].srcGeo").value(org.hamcrest.Matchers.nullValue()))
                .andReturn().getResponse().getContentAsString();
        assertFalse(detail.contains("Zhejiang"), "下钻明细泄露了省份：" + detail);
        assertNoIp(detail);
    }

    @Test
    @DisplayName("/api/public/latest：同样不含逐条地理信息")
    void latestDoesNotLeakPerAlertGeo() throws Exception {
        wire(List.of(enriched("a1", "45.83.91.12", "CN|Zhejiang|Hangzhou|4134|CHINANET-BACKBONE")));
        PublicAuditReader reader = new PublicAuditReader();
        ReflectionTestUtils.setField(reader, "dataDir", dataDir.toString());
        ReflectionTestUtils.setField(controller, "auditReader", reader);

        String body = mvc().perform(get("/api/public/latest")).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertFalse(body.contains("Zhejiang"), body);
        assertFalse(body.contains("CHINANET"), body);
        assertNoIp(body);
    }

    /** 公开面出参不允许出现任何 IP 形态字符串 */
    private static void assertNoIp(String body) {
        assertFalse(Pattern.compile("(?<![\\d.])\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(?![\\d.])")
                .matcher(body).find(), "响应体里出现 IPv4：" + body);
    }
}

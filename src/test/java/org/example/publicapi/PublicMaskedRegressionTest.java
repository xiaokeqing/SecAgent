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

import java.lang.reflect.Method;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * <b>掩码回归</b>：开关翻回 {@code true} 时，公开载荷必须与改造前<b>逐字节相同</b>。
 *
 * <h3>为什么用"黄金串"而不是"再算一遍"</h3>
 * "把改造前的行为再实现一遍然后比对"是同义反复 —— 两边一起改就一起错。
 * 这里冻结的是<b>改造当时的真实输出</b>（一串 JSON 字面量）：
 * 只要以后有人动了掩码态的任何一处（多一个字段、改一句 note、把内网地址从
 * 「内部地址」换成别的词），这条测试立刻变红。
 *
 * <p>三个端点各冻结一份：{@code /latest}（纯函数，可完整冻结）、
 * {@code /honeypot} 与 {@code /audit}（只把 {@code generatedAt} 归一成 {@code <TS>}，
 * 其余逐字节比对）。
 *
 * <p><b>与改造前唯一的【有意】差异</b>（掩码态也一样，因为它属于"永不公开"清单）：
 * {@code honeypot.topCredentials[].key} 从 {@code "root / 123456"}（<b>含完整口令</b>）
 * 改成结构摘要 {@code "root / 6 位·数字·弱口令"}，并新增 4 个结构字段。
 * 这不是口径漂移，是修掉一个真实泄露；其余字段一律不许变 —— 见 {@link #honeypotGolden()}。
 */
class PublicMaskedRegressionTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @TempDir
    Path dataDir;

    // ==================== 夹具（固定，不带任何"现在时间"） ====================

    private static SecurityAlert alert(String id, AlertSeverity sev, String ip, String at) {
        SecurityAlert a = new SecurityAlert(id, "内部标题不该出现在响应里", sev, AlertType.SCAN, AlertSource.SURICATA);
        a.setRuleName("内部规则名");
        a.setSrcIp(ip);
        a.setDstIp("10.0.10.21");
        a.setDstAsset("web-01");
        a.setOccurredAt(at);
        return a;
    }

    private static List<SecurityAlert> alerts() {
        return List.of(
                alert("a1", AlertSeverity.HIGH, "45.83.91.12", "2026-10-13 10:00:00"),
                alert("a2", AlertSeverity.HIGH, "45.83.91.12", "2026-10-13 10:05:00"),
                alert("a3", AlertSeverity.CRITICAL, "203.0.113.9", "2026-10-13 12:30:00"),
                alert("a4", AlertSeverity.MEDIUM, "172.18.0.1", "2026-10-13 09:00:00"));
    }

    private static Map<String, Object> honeypotRawFixture() {
        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("available", true);
        raw.put("commandsAvailable", false);
        raw.put("total", 9352);
        raw.put("connections", 3127);
        raw.put("logins", 3113);
        raw.put("loginFails", 5);
        raw.put("sampled", 800);
        raw.put("topCredentials", List.of(
                kv("key", "root / 123456", "count", 3113),
                kv("key", "admin / qwerty", "count", 88)));
        raw.put("topSources", List.of(
                kv("key", "106.37.205.248", "count", 120),
                kv("key", "172.18.0.1", "count", 40)));
        raw.put("topClients", List.of(kv("key", "SSH-2.0-Go", "count", 10)));
        raw.put("timeline", List.of(
                kv("time", "2026-10-13 12:00:00", "kind", "登录成功", "srcIp", "106.37.205.248",
                        "detail", "蜜罐: 攻击者\"登录成功\" 用户=root 口令=123456 来源=106.37.205.248")));
        return raw;
    }

    /**
     * 顺序固定的键值对。
     *
     * <p>刻意不用 {@code Map.of}：它的迭代顺序带 JVM 随机盐，同一份夹具在不同次运行里
     * 序列化出来可能不同 —— 黄金串比对会被它变成随机失败，而"偶发红"的测试等于没有测试。
     * （生产链路的 {@code topN} 用的是 {@code LinkedHashMap}，顺序本来就是确定的。）
     */
    private static Map<String, Object> kv(Object... pairs) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            m.put(String.valueOf(pairs[i]), pairs[i + 1]);
        }
        return m;
    }

    private PublicApiController maskedController() throws Exception {
        Files.writeString(dataDir.resolve("blocked-ips.json"),
                "[{\"id\":\"BLK-1\",\"ip\":\"45.83.91.12\",\"durationMinutes\":60,\"source\":\"智能体\","
                        + "\"actor\":\"admin\",\"auditId\":\"AUD-1\",\"createdAt\":\"2026-10-13 12:00:00\","
                        + "\"expiresAt\":\"2026-10-13 13:00:00\",\"unblocked\":false}]", StandardCharsets.UTF_8);
        Files.writeString(dataDir.resolve("response-audit.json"),
                "[{\"id\":\"AUD-1\",\"time\":\"2026-10-13 12:00:00\",\"actor\":\"admin\",\"action\":\"block-ip\","
                        + "\"target\":\"45.83.91.12\",\"reason\":\"来源 106.37.205.248 高频失败\","
                        + "\"riskLevel\":\"HIGH\",\"mode\":\"REAL\",\"success\":true}]", StandardCharsets.UTF_8);

        PublicApiController c = new PublicApiController();
        ReflectionTestUtils.setField(c, "cacheSeconds", 15);
        ReflectionTestUtils.setField(c, "exposeBuildSha", false);
        ReflectionTestUtils.setField(c, "buildSha", "test");
        ReflectionTestUtils.setField(c, "ipPolicy", PublicIpPolicy.masking());

        PublicAuditReader reader = new PublicAuditReader();
        ReflectionTestUtils.setField(reader, "dataDir", dataDir.toString());
        ReflectionTestUtils.setField(reader, "ipPolicy", PublicIpPolicy.masking());
        ReflectionTestUtils.setField(c, "auditReader", reader);

        Map<String, Object> honeypot = honeypotRawFixture();
        List<SecurityAlert> alerts = alerts();
        WazuhGateway gateway = (WazuhGateway) Proxy.newProxyInstance(
                WazuhGateway.class.getClassLoader(), new Class<?>[]{WazuhGateway.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "mode" -> "REAL";
                    case "isAvailable" -> true;
                    case "recentAlerts" -> alerts;
                    case "honeypotSummary" -> honeypot;
                    default -> null;
                });
        PublicAlertSource source = new PublicAlertSource();
        ReflectionTestUtils.setField(source, "wazuhGateway", gateway);
        ReflectionTestUtils.setField(source, "aggregator", new AlertAggregationService());
        ReflectionTestUtils.setField(c, "source", source);
        return c;
    }

    private static Object invoke(Object target, String method) throws Exception {
        Method m = target.getClass().getDeclaredMethod(method);
        m.setAccessible(true);
        return m.invoke(target);
    }

    @SuppressWarnings("unchecked")
    private static String frozen(Object payload) throws Exception {
        Map<String, Object> m = new LinkedHashMap<>((Map<String, Object>) payload);
        if (m.containsKey("generatedAt")) {
            m.put("generatedAt", "<TS>");
        }
        return MAPPER.writeValueAsString(m);
    }

    // ==================== 三个端点的黄金串 ====================

    @Test
    @DisplayName("【回归】/latest 掩码态载荷逐字节等于冻结串")
    void latestMaskedPayloadIsByteIdenticalToLegacy() throws Exception {
        Map<String, Object> out = PublicApiController.buildLatest(
                alerts(), true, "REAL", 200, 15, "2026-10-13 13:00:00", List.of());

        assertEquals(golden("masked-golden-latest.json"), MAPPER.writeValueAsString(out),
                "掩码态的 /latest 载荷变了 —— 开关翻回 true 就不再等于改造前的行为");
    }

    @Test
    @DisplayName("【回归】/honeypot 掩码态载荷逐字节等于冻结串（仅 generatedAt 归一）")
    void honeypotGolden() throws Exception {
        String actual = frozen(invoke(maskedController(), "buildHoneypot"));
        assertEquals(golden("masked-golden-honeypot.json"), actual);
        // 与改造前的有意差异只有"口令 Top 结构化"这一处，且与开关无关
        assertEquals(-1, actual.indexOf("123456"), "口令原文永远不该出现：" + actual);
        assertEquals(-1, actual.indexOf("qwerty"), "口令原文永远不该出现：" + actual);
    }

    @Test
    @DisplayName("【回归】/audit 掩码态载荷逐字节等于冻结串（仅 generatedAt 归一）")
    void auditGolden() throws Exception {
        String actual = frozen(invoke(maskedController(), "buildAudit"));
        assertEquals(golden("masked-golden-audit.json"), actual);
    }

    /**
     * 【2026-10-14 补】<b>整条出口闸门</b>（{@code ship()} → {@code scrubDeep()}）对
     * {@code /honeypot} 载荷逐字节不变 —— 这次给 {@code scrubDeep()} 补凭据脱敏时，
     * 必须证明对"本来就干净"的端点没有副作用。
     *
     * <p>为什么另起一条而不并进 {@link #honeypotGolden()}：那条调的是 {@code buildHoneypot()}
     * 本身，<b>不经过</b> {@code scrubDeep()}。这次改动恰好只在 {@code scrubDeep()} 里，
     * 所以那条测试对"闸门有没有改坏内容"是盲的 —— 它俩覆盖的是两段不同的代码。
     * 这里把同一份载荷再过一遍 {@code ship()}（含 {@code scrubDeep()}），
     * 断言结果与同一个冻结串<b>逐字节相同</b>。
     */
    @SuppressWarnings("unchecked")
    @Test
    @DisplayName("【回归】/honeypot 经 ship()+scrubDeep() 出口闸门后仍逐字节等于冻结串")
    void honeypotPayloadSurvivesTheScrubDeepGateByteIdentically() throws Exception {
        PublicApiController c = maskedController();
        Object built = invoke(c, "buildHoneypot");

        // ship() 直接在入参 map 上补 ipDisclosure（不改键名、不改既有值）；它是实例方法
        Method ship = PublicApiController.class.getDeclaredMethod("ship", Map.class);
        ship.setAccessible(true);
        Map<String, Object> shipped = (Map<String, Object>) ship.invoke(c, built);

        assertTrue(shipped.containsKey(PublicIpPolicy.DISCLOSURE_FIELD),
                "ship() 应补上统一口径字段 " + PublicIpPolicy.DISCLOSURE_FIELD);

        // 冻结串冻的是 ok() 里 data 的那一层（不含 code/message/ipDisclosure），
        // 所以这里必须从"闸门另一侧"的同一层取出来比 —— 多出来的 ipDisclosure 是
        // ship() 自己补的统一口径字段，不是载荷内容。
        Map<String, Object> shippedData = new LinkedHashMap<>(shipped);
        shippedData.remove(PublicIpPolicy.DISCLOSURE_FIELD);

        assertEquals(((Map<String, Object>) built).keySet(), shippedData.keySet(),
                "ship() 除了补 " + PublicIpPolicy.DISCLOSURE_FIELD + " 之外不该增删任何键");

        String actual = frozen(shippedData);
        assertEquals(golden("masked-golden-honeypot.json"), actual,
                "给 scrubDeep() 补凭据脱敏后，/honeypot 的出口载荷变了 —— 对本来干净的端点不该有副作用");

        // 反向断言：闸门没有把内容整段吃掉，也没留下明文口令字段
        Matcher leftover = PLAINTEXT_PASSWORD_FIELD.matcher(actual);
        assertTrue(!leftover.find(), "出口载荷里不该有明文口令字段：" + actual);
        assertEquals(-1, actual.indexOf("123456"), "口令原文永远不该出现：" + actual);
    }

    /**
     * 明文口令判别式 —— 判据写死在这里而<b>不调用被测代码</b>：
     * 用被测实现去证明被测实现是循环论证。隐藏形态是 {@code 口令=[口令已隐藏]}，
     * 即"分隔符右边第一个字符是 {@code [}"。
     */
    private static final Pattern PLAINTEXT_PASSWORD_FIELD = Pattern.compile(
            "(?i)(口令|密码|password|passwd|pwd)\\s*[:=：]\\s*([^\\s\\[][^\\s]*)");

    /**
     * 读冻结串（{@code src/test/resources/publicapi/masked-golden-*.json}）。
     *
     * <p>放资源文件而不是 Java 字面量：里面的引号 / 反斜杠 / 中文原样保留，
     * 不会因为"为了写进 Java 字符串而转义"引入肉眼看不出的偏差 ——
     * 逐字节比对的证据本身不能是被转义加工过的。
     */
    private static String golden(String name) throws Exception {
        try (var in = PublicMaskedRegressionTest.class.getResourceAsStream("/publicapi/" + name)) {
            if (in == null) {
                throw new IllegalStateException("找不到冻结串资源：/publicapi/" + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8).strip();
        }
    }
}

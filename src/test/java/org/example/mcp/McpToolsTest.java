package org.example.mcp;

import org.example.mcp.tools.AlertsRecentTool;
import org.example.mcp.tools.AuditBlocksTool;
import org.example.mcp.tools.DetectionsTool;
import org.example.mcp.tools.HealthTool;
import org.example.mcp.tools.HoneypotSummaryTool;
import org.example.mcp.tools.IpProfileTool;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * MCP 工具集单测。
 *
 * <p>每个工具都走两条分支：<b>数据源正常</b> 与 <b>数据源不可用</b>。
 * 不启 Spring、不连 9900、不读环境变量 —— 用假的 {@link PlatformClient} 喂上游 payload，
 * 这样这组测试在本机平台没起的时候也能跑（`mvn -o test -Dtest=McpToolsTest` 的验收前提）。
 */
class McpToolsTest {

    // ==================== xk_health ====================

    @Test
    @DisplayName("xk_health：透传 buildSha/artifactMd5/status/uptimeMs，并附 MCP 自身读数")
    void healthNormal() {
        FakeClient client = new FakeClient().ok("/api/health", map(
                "status", "ok",
                "buildSha", "b5cd0ab",
                "artifactMd5", "d41d8cd98f00b204e9800998ecf8427e",
                "uptimeMs", 123456L,
                "application", "SecAgent",
                "fingerprintMismatch", false));
        Map<String, Object> out = new HealthTool(client).call(Map.of());

        assertEquals(Boolean.TRUE, out.get("available"));
        assertEquals("ok", out.get("status"));
        assertEquals("b5cd0ab", out.get("buildSha"));
        assertEquals("d41d8cd98f00b204e9800998ecf8427e", out.get("artifactMd5"));
        assertEquals(123456L, out.get("uptimeMs"));
        assertEquals(Boolean.FALSE, out.get("degraded"));
        assertEnvelope(out);
        Map<String, Object> self = ToolSupport.map(out.get("mcp"));
        assertEquals("xk-lab-mcp", self.get("server"));
        assertNotNull(self.get("pid"));
        assertEquals(System.getProperty("java.version"), self.get("javaVersion"));
    }

    @Test
    @DisplayName("xk_health：平台没起时 available=false + reason，且不编 buildSha")
    void healthUnavailable() {
        FakeClient client = new FakeClient().fail("/api/health", "UPSTREAM_UNAVAILABLE", "连不上 http://127.0.0.1:9900");
        Map<String, Object> out = new HealthTool(client).call(Map.of());

        assertEquals(Boolean.FALSE, out.get("available"));
        String reason = String.valueOf(out.get("reason"));
        assertTrue(reason.startsWith("UPSTREAM_UNAVAILABLE"), "reason 要带机器可判的错误码，实际=" + reason);
        assertNull(out.get("buildSha"));
        assertNull(out.get("artifactMd5"));
        // 进程自身读数与上游无关，两条分支都必须有
        assertNotNull(ToolSupport.map(out.get("mcp")).get("pid"));
        assertEnvelope(out);
    }

    // ==================== xk_alerts_recent ====================

    @Test
    @DisplayName("xk_alerts_recent：按 minutes 过滤窗口、按 limit 截断、按时间新→旧")
    void alertsNormal() {
        String fresh = LocalDateTime.now().minusMinutes(5).format(ToolSupport.PLATFORM_FMT);
        String older = LocalDateTime.now().minusMinutes(90).format(ToolSupport.PLATFORM_FMT);
        Map<String, Object> payload = map(
                "dataSource", map("wazuhMode", "real", "degraded", false),
                "windowMinutes", 60,
                "list", List.of(
                        map("severity", "medium", "ruleName", "SSH 暴力破解", "srcIp", "45.205.1.230",
                                "attck", map("technique", "T1110"), "occurredAt", fresh, "count", 7, "title", "a"),
                        map("severity", "high", "ruleName", "蜜罐登录成功", "srcIp", "103.146.184.77",
                                "attck", null, "occurredAt", older, "count", 1, "title", "b"),
                        map("severity", "low", "ruleName", "扫描", "srcIp", "8.8.8.8",
                                "attck", null, "occurredAt", "时间解析不了", "count", 3, "title", "c")));
        FakeClient client = new FakeClient().ok("/api/public/alerts", payload);

        Map<String, Object> out = new AlertsRecentTool(client).call(map("minutes", 60, "limit", 20));

        assertEquals(Boolean.TRUE, out.get("available"));
        List<Object> alerts = ToolSupport.list(out.get("alerts"));
        assertEquals(1, alerts.size(), "只有 1 条在 60 分钟窗口内");
        Map<String, Object> alert = ToolSupport.map(alerts.get(0));
        assertEquals("medium", alert.get("severity"));
        assertEquals("SSH 暴力破解", alert.get("ruleName"));
        assertEquals("45.205.1.230", alert.get("srcIp"));
        assertNotNull(alert.get("attck"));
        Map<String, Object> summary = ToolSupport.map(out.get("summary"));
        assertEquals(1, summary.get("inWindow"));
        assertEquals(1, summary.get("olderThanWindow"));
        assertEquals(1, summary.get("unparsedTime"));
        assertTrue(ToolSupport.map(summary.get("bySeverity")).containsKey("medium"));
        assertEnvelope(out);
    }

    @Test
    @DisplayName("xk_alerts_recent：上游 degraded 时整条报不可用，不用 0 条冒充")
    void alertsDegraded() {
        FakeClient client = new FakeClient().ok("/api/public/alerts", map(
                "dataSource", map("wazuhMode", "degraded", "degraded", true, "note", "indexer 连不上"),
                "list", List.of()));
        Map<String, Object> out = new AlertsRecentTool(client).call(Map.of());

        assertEquals(Boolean.FALSE, out.get("available"));
        assertTrue(String.valueOf(out.get("reason")).contains("WAZUH_DEGRADED"));
        assertNull(out.get("alerts"));
        assertEnvelope(out);
    }

    // ==================== xk_ip_profile ====================

    @Test
    @DisplayName("xk_ip_profile：与 /api/public/ip 同源字段透传，credStructure 只留结构")
    void ipProfileNormal() {
        FakeClient client = new FakeClient().ok("/api/public/ip", map(
                "available", true,
                "reason", "OK",
                "query", "45.205.***.***",
                "ipVersion", "IPv4",
                "window", "168h",
                "windowHours", 168,
                "firstSeen", "2026-10-01 08:00:00",
                "lastSeen", "2026-10-18 09:30:00",
                "events", 42,
                "byKind", map("ssh_login", 30, "honeypot", 12),
                "ports", List.of(22, 2222),
                "credStructure", List.of("root / 6 位·纯数字·弱口令", "admin / hunter2"),
                "geo", map("country", "美国"),
                "banned", map("count", 2, "active", true),
                "sources", map("indexer", map("status", "OK")),
                "limits", map("windowHours", 168),
                "notes", List.of(),
                "note", "只读"));

        Map<String, Object> out = new IpProfileTool(client).call(map("ip", "45.205.1.230"));

        assertEquals(Boolean.TRUE, out.get("available"));
        assertEquals(42, out.get("events"));
        assertEquals("2026-10-01 08:00:00", out.get("firstSeen"));
        assertEquals(2, ToolSupport.list(out.get("ports")).size());
        assertEquals(2, ToolSupport.map(out.get("banned")).get("count"));
        List<Object> creds = ToolSupport.list(out.get("credStructure"));
        assertEquals("root / 6 位·纯数字·弱口令", creds.get(0));
        assertFalse(String.valueOf(creds.get(1)).contains("hunter2"), "明文口令绝不能出现在输出里");
        assertTrue(String.valueOf(creds.get(1)).contains("[口令已隐藏]"));
        assertEnvelope(out);
    }

    @Test
    @DisplayName("xk_ip_profile：非 IPv4 字面量不打上游、直接 available=false")
    void ipProfileInvalid() {
        FakeClient client = new FakeClient();
        Map<String, Object> out = new IpProfileTool(client).call(map("ip", "example.com"));

        assertEquals(Boolean.FALSE, out.get("available"));
        assertTrue(String.valueOf(out.get("reason")).startsWith("INVALID_IP"));
        assertEquals(0, client.calls, "参数不合法时不该白打一次上游");
        assertEnvelope(out);

        Map<String, Object> missing = new IpProfileTool(client).call(Map.of());
        assertTrue(String.valueOf(missing.get("reason")).startsWith("MISSING_IP"));

        Map<String, Object> internal = new IpProfileTool(client).call(map("ip", "10.0.0.10"));
        assertTrue(String.valueOf(internal.get("reason")).startsWith("NOT_PUBLIC_IP"));
    }

    // ==================== xk_audit_blocks ====================

    @Test
    @DisplayName("xk_audit_blocks：默认把 IP 掩成网段级，别的字段照透")
    void auditMasked() {
        FakeClient client = new FakeClient().ok("/api/public/audit", map(
                "readOnly", true,
                "summary", map("total", 9, "active", 2),
                "blocks", List.of(
                        map("id", 1, "ip", "45.205.1.230", "durationMinutes", 60, "source", "manual",
                                "actor", "站主", "auditId", "audit-1", "createdAt", "2026-10-18 09:00:00",
                                "expiresAt", "2026-10-18 10:00:00", "unblocked", false),
                        map("id", 2, "ip", "内部地址", "durationMinutes", 30))));

        Map<String, Object> out = new AuditBlocksTool(client).call(Map.of());

        assertEquals(Boolean.TRUE, out.get("available"));
        List<Object> blocks = ToolSupport.list(out.get("blocks"));
        assertEquals(2, blocks.size());
        Map<String, Object> first = ToolSupport.map(blocks.get(0));
        assertEquals("45.205.***.***", first.get("ip"));
        assertEquals(60, first.get("durationMinutes"));
        assertEquals("audit-1", first.get("auditId"));
        // 「内部地址」是展示文案不是 IP 字面量，不能被二次掩码踩成 ***
        assertEquals("内部地址", ToolSupport.map(blocks.get(1)).get("ip"));
        assertEquals("masked", out.get("ipMode"));
        Map<String, Object> summary = ToolSupport.map(out.get("summary"));
        assertEquals(9, summary.get("total"));
        assertEquals(2, summary.get("returned"));
        assertEnvelope(out);
    }

    @Test
    @DisplayName("xk_audit_blocks：rawIp=true 给上游原值（并说明上游若已掩码则无法还原）")
    void auditRawIp() {
        FakeClient client = new FakeClient().ok("/api/public/audit", map(
                "blocks", List.of(map("id", 1, "ip", "45.205.1.230"))));

        Map<String, Object> out = new AuditBlocksTool(client).call(map("rawIp", true));

        assertEquals("raw", out.get("ipMode"));
        assertEquals("45.205.1.230", ToolSupport.map(ToolSupport.list(out.get("blocks")).get(0)).get("ip"));
        assertTrue(String.valueOf(out.get("note")).contains("无法还原"));
    }

    @Test
    @DisplayName("xk_audit_blocks：留痕读不到时 available=false")
    void auditUnavailable() {
        FakeClient client = new FakeClient().fail("/api/public/audit", "UPSTREAM_500", "留痕文件读不到");
        Map<String, Object> out = new AuditBlocksTool(client).call(Map.of());

        assertEquals(Boolean.FALSE, out.get("available"));
        assertTrue(String.valueOf(out.get("reason")).contains("留痕文件读不到"));
        assertNull(out.get("blocks"));
        assertEnvelope(out);
    }

    // ==================== xk_honeypot_summary ====================

    @Test
    @DisplayName("xk_honeypot_summary：连接/登录数照给，口令只给结构")
    void honeypotRedaction() {
        FakeClient client = new FakeClient().ok("/api/public/honeypot", map(
                "available", true,
                "total", 120,
                "connections", 80,
                "logins", 40,
                "loginFails", 38,
                "sampled", 200,
                "topCredentials", List.of("root / 6 位·纯数字·弱口令", "root / 123456", "admin / qwerty"),
                "topSources", List.of("45.205.1.230"),
                "topClients", List.of("SSH-2.0-Go"),
                "timeline", List.of(map("hour", "09:00", "count", 12))));

        Map<String, Object> out = new HoneypotSummaryTool(client).call(Map.of());

        assertEquals(Boolean.TRUE, out.get("available"));
        assertEquals(80, out.get("connections"));
        assertEquals(40, out.get("logins"));
        assertEquals(38, out.get("loginFails"));
        List<Object> creds = ToolSupport.list(out.get("credStructure"));
        assertEquals(3, creds.size());
        assertEquals("root / 6 位·纯数字·弱口令", creds.get(0));
        String joined = creds.toString();
        assertFalse(joined.contains("123456"), "明文口令不能出现在输出里：" + joined);
        assertFalse(joined.contains("qwerty"), "明文口令不能出现在输出里：" + joined);
        // 来源 IP / 客户端指纹不是口令，不能被脱敏顺手吞掉
        assertEquals("45.205.1.230", ToolSupport.list(out.get("topSources")).get(0));
        assertEnvelope(out);
    }

    @Test
    @DisplayName("xk_honeypot_summary：蜜罐日志没接上时 available=false，不写 0")
    void honeypotUnavailable() {
        FakeClient client = new FakeClient().ok("/api/public/honeypot", map(
                "available", false, "note", "蜜罐日志不存在"));
        Map<String, Object> out = new HoneypotSummaryTool(client).call(Map.of());

        assertEquals(Boolean.FALSE, out.get("available"));
        assertTrue(String.valueOf(out.get("reason")).contains("蜜罐日志不存在"));
        assertNull(out.get("connections"));
        assertEnvelope(out);
    }

    // ==================== xk_detections ====================

    @Test
    @DisplayName("xk_detections：从站点仓库解析 suricata 的 sid/msg 与 wazuh 的 id/description")
    void detectionsNormal(@TempDir Path siteDir) throws IOException {
        Path suricata = siteDir.resolve(DetectionCatalog.SURICATA_REL);
        Files.createDirectories(suricata.getParent());
        Files.writeString(suricata, """
                # XK-LAB 自写规则
                alert ssh $EXTERNAL_NET any -> $HOME_NET any ( \\
                    msg:"XK-LAB SSH client fingerprint Go SSH library"; \\
                    classtype:attempted-admin; \\
                    sid:1000101; rev:2; )
                """, StandardCharsets.UTF_8);

        Path wazuh = siteDir.resolve(DetectionCatalog.WAZUH_REL);
        Files.createDirectories(wazuh.getParent());
        Files.writeString(wazuh, """
                <group name="xk-lab,">
                  <!-- 注释里的 rule 不算规则 -->
                  <!-- <rule id="999999" level="99"><description>假规则</description></rule> -->
                  <rule id="100400" level="10" frequency="20" timeframe="300">
                    <if_sid>100301</if_sid>
                    <description>XK-LAB: 蜜罐登录失败突增（来源=$(src_ip)）</description>
                  </rule>
                </group>
                """, StandardCharsets.UTF_8);

        Map<String, Object> out = new DetectionsTool(siteDir).call(Map.of());

        assertEquals(Boolean.TRUE, out.get("available"));
        List<Object> suri = ToolSupport.list(out.get("suricata"));
        assertEquals(1, suri.size());
        Map<String, Object> rule = ToolSupport.map(suri.get(0));
        assertEquals(1000101, rule.get("sid"));
        assertEquals("XK-LAB SSH client fingerprint Go SSH library", rule.get("msg"));
        List<Object> wz = ToolSupport.list(out.get("wazuh"));
        assertEquals(1, wz.size());
        assertEquals(100400, ToolSupport.map(wz.get(0)).get("id"));
        assertEquals("XK-LAB: 蜜罐登录失败突增（来源=$(src_ip)）", ToolSupport.map(wz.get(0)).get("description"));
        Map<String, Object> counts = ToolSupport.map(out.get("counts"));
        assertEquals(2, counts.get("total"));
        assertEnvelope(out);
    }

    @Test
    @DisplayName("xk_detections：规则文件不存在时 available=false + 明确原因")
    void detectionsMissing(@TempDir Path siteDir) {
        Map<String, Object> out = new DetectionsTool(siteDir).call(Map.of());

        assertEquals(Boolean.FALSE, out.get("available"));
        assertTrue(String.valueOf(out.get("reason")).startsWith("DETECTION_FILES_NOT_FOUND"));
        assertNull(out.get("suricata"));
        List<Object> files = ToolSupport.list(out.get("files"));
        assertEquals(2, files.size());
        assertEquals(Boolean.FALSE, ToolSupport.map(files.get(0)).get("exists"));
        assertEnvelope(out);
    }

    // ==================== 上游外壳 {"code":200,"message":"success","data":{…}} ====================

    @Test
    @DisplayName("上游外壳：拆出 data；空对象 / 非 200 业务码 / data 不是对象 → 一律按不可用报错")
    void unwrapEnvelope() throws Exception {
        Map<String, Object> inner = HttpPlatformClient.unwrap(
                map("code", 200, "message", "success", "data", map("available", true, "total", 3)), 200);
        assertEquals(Boolean.TRUE, inner.get("available"));
        assertEquals(3, inner.get("total"));

        // 没有外壳的裸 JSON（手工调试 / 老端点）原样返回，不多做假设
        Map<String, Object> bare = HttpPlatformClient.unwrap(map("status", "ok"), 200);
        assertEquals("ok", bare.get("status"));

        // 空响应体不是"没有数据"，是"取不到数据"
        assertEquals("UPSTREAM_EMPTY_BODY",
                failureCode(() -> HttpPlatformClient.unwrap(new LinkedHashMap<>(), 200)));
        // 平台偶尔用 HTTP 200 + 业务码表达失败
        assertEquals("UPSTREAM_503",
                failureCode(() -> HttpPlatformClient.unwrap(map("code", 503, "message", "wazuh down"), 200)));
        // 外壳在但 data 不是对象
        assertEquals("UPSTREAM_EMPTY_BODY",
                failureCode(() -> HttpPlatformClient.unwrap(map("code", 200, "data", "not-an-object"), 200)));
    }

    /** 跑一段可能抛 {@link PlatformUnavailableException} 的代码，返回它携带的错误码。 */
    private static String failureCode(CheckedBody body) {
        try {
            body.run();
        } catch (PlatformUnavailableException e) {
            return e.code();
        } catch (Exception e) {
            throw new AssertionError("期望 PlatformUnavailableException，实际 " + e, e);
        }
        throw new AssertionError("期望抛 PlatformUnavailableException，实际没抛");
    }

    /** 允许抛受检异常的小接口（{@link Runnable} 装不下 checked exception）。 */
    @FunctionalInterface
    private interface CheckedBody {
        void run() throws Exception;
    }

    // ==================== 协议层（initialize / tools/list / tools/call） ====================

    @Test
    @DisplayName("MCP 协议：initialize 协商版本、tools/list 六个工具、tools/call 走通、未知方法 -32601")
    void protocolRoundTrip(@TempDir Path siteDir) throws IOException {
        FakeClient client = new FakeClient()
                .ok("/api/health", map("status", "ok", "buildSha", "b5cd0ab", "artifactMd5", "md5", "uptimeMs", 1L))
                .ok("/api/public/alerts", map("dataSource", map("degraded", false), "list", List.of()));
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        McpServer server = new McpServer(ToolRegistry.create(client, siteDir), InputStream.nullInputStream(),
                new PrintStream(sink, true, StandardCharsets.UTF_8));

        Map<String, Object> init = asMap(server.handle(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-03-26\"}}"));
        assertEquals("2.0", init.get("jsonrpc"));
        assertEquals(1, init.get("id"));
        Map<String, Object> initResult = ToolSupport.map(init.get("result"));
        assertEquals("2025-03-26", initResult.get("protocolVersion"));
        assertEquals("xk-lab-mcp", ToolSupport.map(initResult.get("serverInfo")).get("name"));
        assertNotNull(ToolSupport.map(initResult.get("capabilities")).get("tools"));

        Map<String, Object> listed = asMap(server.handle("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}"));
        List<Object> tools = ToolSupport.list(ToolSupport.map(listed.get("result")).get("tools"));
        assertEquals(6, tools.size());
        List<String> names = new ArrayList<>();
        for (Object o : tools) {
            Map<String, Object> t = ToolSupport.map(o);
            names.add(String.valueOf(t.get("name")));
            assertNotNull(ToolSupport.map(t.get("inputSchema")).get("type"));
        }
        assertEquals(List.of("xk_health", "xk_alerts_recent", "xk_ip_profile",
                "xk_audit_blocks", "xk_honeypot_summary", "xk_detections"), names);

        Map<String, Object> called = asMap(server.handle(
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"xk_health\",\"arguments\":{}}}"));
        Map<String, Object> callResult = ToolSupport.map(called.get("result"));
        assertEquals(Boolean.FALSE, callResult.get("isError"));
        String text = String.valueOf(ToolSupport.map(ToolSupport.list(callResult.get("content")).get(0)).get("text"));
        Map<String, Object> payload = Json.readObject(text);
        assertEquals(Boolean.TRUE, payload.get("available"));
        assertEquals("b5cd0ab", payload.get("buildSha"));

        Map<String, Object> unknownTool = asMap(server.handle(
                "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"xk_nope\"}}"));
        assertEquals(-32602, ToolSupport.map(unknownTool.get("error")).get("code"));

        Map<String, Object> unknownMethod = asMap(server.handle(
                "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"xk/whatever\"}"));
        assertEquals(-32601, ToolSupport.map(unknownMethod.get("error")).get("code"));

        // 通知不回包
        assertNull(server.handle("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}"));
        assertNull(server.handle("{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"notifications/cancelled\"}"));
    }

    // ==================== 辅助 ====================

    /** 每条输出都必须带 generatedAt + source + available 三件套（红线检查，六个工具共用一个断言）。 */
    private static void assertEnvelope(Map<String, Object> out) {
        assertNotNull(out.get("generatedAt"), "缺 generatedAt");
        assertNotNull(out.get("source"), "缺 source");
        assertNotNull(out.get("available"), "缺 available");
        assertTrue(String.valueOf(out.get("source")).length() > 0);
    }

    private static Map<String, Object> asMap(String json) throws IOException {
        return Json.readObject(json);
    }

    private static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            m.put(String.valueOf(kv[i]), kv[i + 1]);
        }
        return m;
    }

    /** 假上游：按路径给 payload，或按路径拒答；不透 Spring、不发网络请求。 */
    private static final class FakeClient implements PlatformClient {

        private final Map<String, Object> payloads = new LinkedHashMap<>();
        private final Map<String, FrameworkFailure> failures = new LinkedHashMap<>();
        private int calls;

        FakeClient ok(String path, Object payload) {
            payloads.put(path, payload);
            return this;
        }

        FakeClient fail(String path, String code, String message) {
            failures.put(path, new FrameworkFailure(code, message));
            return this;
        }

        @Override
        @SuppressWarnings("unchecked")
        public Map<String, Object> get(String path, Map<String, String> query) throws PlatformUnavailableException {
            calls++;
            FrameworkFailure f = failures.get(path);
            if (f != null) {
                throw new PlatformUnavailableException(f.code, f.message);
            }
            Object p = payloads.get(path);
            if (p == null) {
                throw new PlatformUnavailableException("UPSTREAM_404", "stub 未配置：" + path);
            }
            return (Map<String, Object>) p;
        }

        @Override
        public String describe() {
            return "stub://127.0.0.1";
        }
    }

    private record FrameworkFailure(String code, String message) {
    }
}

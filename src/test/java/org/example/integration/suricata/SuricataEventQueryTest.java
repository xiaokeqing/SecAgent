package org.example.integration.suricata;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.core.model.SecurityAlert;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Suricata 全事件解析 + 连接反查的测试。
 *
 * <p>钉住三件最容易"看起来正常、其实没做"的事：
 * ① 没有 eve.json 时必须返回空列表而不是抛异常（反查接口被前端轮询，抛一次就是 500 刷屏）；
 * ② 按 IP 反查要同时命中源和目标（只查一个方向会漏掉"谁在连我"）；
 * ③ 端口/SNI 统计是按次数降序，而不是按端口号的字典序（HashMap 遍历顺序会让榜单随机跳动）。
 */
class SuricataEventQueryTest {

    @TempDir
    Path tempDir;

    // ==================== ① 文件缺失 ====================

    @Test
    @DisplayName("eve.json 缺失：模式 MOCK，四类反查都返回空列表且不抛")
    void missingEveFileYieldsEmptyQueries() {
        SuricataService svc = service(tempDir.resolve("not-exist.json"), 50);

        assertEquals("MOCK", svc.mode());
        assertTrue(svc.connectionsByIp("10.0.0.1", 10).isEmpty());
        assertTrue(svc.topDestPorts(15, 10).isEmpty());
        assertTrue(svc.topSni(60, 10).isEmpty());
        assertTrue(svc.ja3Stats(60, 10).isEmpty());
        // 既有语义不变：告警通路仍然降级到内置样本
        assertEquals(5, svc.recentNetworkAlerts(10).size());
    }

    // ==================== ② 按 IP 反查 ====================

    @Test
    @DisplayName("按 IP 反查同时命中源与目标，新的在前，limit 生效")
    void connectionsByIpMatchesBothDirections() throws Exception {
        Path eve = eve("flow2.json",
                flow("10.0.0.5", 50000, "10.0.0.9", 443, Instant.parse("2026-11-06T02:00:00Z")),
                flow("10.0.0.9", 443, "10.0.0.5", 50000, Instant.parse("2026-11-06T02:01:00Z")),
                flow("10.0.0.7", 50001, "10.0.0.8", 22, Instant.parse("2026-11-06T02:02:00Z")));
        SuricataService svc = service(eve, 100);
        svc.ingestNewEvents();

        assertEquals("REAL", svc.mode());
        List<FlowEvent> hits = svc.connectionsByIp("10.0.0.5", 10);
        assertEquals(2, hits.size(), "源或目标任一侧命中都要算");
        // 最近的在最前（第二条是 10.0.0.9 → 10.0.0.5:50000 的回程）
        assertEquals("10.0.0.9", hits.get(0).srcIp());
        assertEquals(50000, hits.get(0).destPort());
        assertEquals(1, svc.connectionsByIp("10.0.0.5", 1).size(), "limit 必须生效");
        assertTrue(svc.connectionsByIp("192.0.2.1", 10).isEmpty());
        assertTrue(svc.connectionsByIp("  ", 10).isEmpty(), "空 IP 返回空而不是抛");
        assertTrue(svc.connectionsByIp(null, 10).isEmpty());
    }

    // ==================== ③ 端口统计 ====================

    @Test
    @DisplayName("目标端口统计：按次数降序，窗口外的不计入")
    void topDestPortsSortedByCount() throws Exception {
        Instant now = Instant.now();
        Instant old = now.minusSeconds(3600);
        Path eve = eve("ports.json",
                flow("10.0.0.1", 1111, "10.0.0.9", 443, now.minusSeconds(30)),
                flow("10.0.0.2", 1112, "10.0.0.9", 443, now.minusSeconds(20)),
                flow("10.0.0.3", 1113, "10.0.0.9", 443, now.minusSeconds(10)),
                flow("10.0.0.4", 1114, "10.0.0.9", 3389, now.minusSeconds(15)),
                flow("10.0.0.5", 1115, "10.0.0.9", 3389, now.minusSeconds(5)),
                flow("10.0.0.6", 1116, "10.0.0.9", 22, now.minusSeconds(2)),
                flow("10.0.0.7", 1117, "10.0.0.9", 9999, old));
        SuricataService svc = service(eve, 100);
        svc.ingestNewEvents();

        List<PortCount> top = svc.topDestPorts(15, 10);
        assertEquals(List.of(443, 3389, 22), top.stream().map(PortCount::port).toList(),
                "按次数降序，且一小时前的 9999 不在 15 分钟窗口内");
        assertEquals(List.of(3L, 2L, 1L), top.stream().map(PortCount::count).toList());
        assertEquals(List.of(443, 3389), svc.topDestPorts(15, 2).stream().map(PortCount::port).toList());
        assertTrue(svc.topDestPorts(15, 0).isEmpty(), "limit<=0 返回空");
        assertTrue(svc.topDestPorts(0, 10).isEmpty(), "时间窗非法返回空");
    }

    // ==================== ④ TLS 统计 ====================

    @Test
    @DisplayName("TLS 统计：SNI 与 JA3 各自按次数降序")
    void tlsStatsSortedByCount() throws Exception {
        Instant now = Instant.now();
        Path eve = eve("tls.json",
                tls("10.0.0.1", "a.example.com", "ja3-aaa", now.minusSeconds(30)),
                tls("10.0.0.2", "a.example.com", "ja3-aaa", now.minusSeconds(20)),
                tls("10.0.0.3", "a.example.com", "ja3-bbb", now.minusSeconds(10)),
                tls("10.0.0.4", "b.example.com", "ja3-aaa", now.minusSeconds(5)));
        SuricataService svc = service(eve, 100);
        svc.ingestNewEvents();

        List<SniCount> sni = svc.topSni(60, 10);
        assertEquals(List.of("a.example.com", "b.example.com"), sni.stream().map(SniCount::sni).toList());
        assertEquals(List.of(3L, 1L), sni.stream().map(SniCount::count).toList());

        List<Ja3Count> ja3 = svc.ja3Stats(60, 10);
        assertEquals(List.of("ja3-aaa", "ja3-bbb"), ja3.stream().map(Ja3Count::ja3).toList());
        assertEquals(List.of(3L, 1L), ja3.stream().map(Ja3Count::count).toList());
    }

    // ==================== ⑤ 有界环形缓冲 ====================

    @Test
    @DisplayName("环形缓冲写满后覆盖最旧的一条")
    void ringBufferOverwritesOldest() {
        BoundedRingBuffer<Integer> rb = new BoundedRingBuffer<>(3);
        rb.add(1);
        rb.add(2);
        rb.add(3);
        rb.add(4);
        assertEquals(List.of(2, 3, 4), rb.snapshot());
        assertEquals(3, rb.size());
        assertEquals(4, rb.totalAdded());
        assertThrows(IllegalArgumentException.class, () -> new BoundedRingBuffer<>(0));
    }

    @Test
    @DisplayName("缓冲容量对服务生效：超出容量后最旧的连接查不到")
    void serviceBufferIsBounded() throws Exception {
        Path eve = eve("bounded.json",
                flow("10.0.0.1", 1001, "10.0.0.9", 80, Instant.now().minusSeconds(40)),
                flow("10.0.0.2", 1002, "10.0.0.9", 80, Instant.now().minusSeconds(30)),
                flow("10.0.0.3", 1003, "10.0.0.9", 80, Instant.now().minusSeconds(20)),
                flow("10.0.0.4", 1004, "10.0.0.9", 80, Instant.now().minusSeconds(10)));
        SuricataService svc = service(eve, 3);
        svc.ingestNewEvents();

        assertEquals(3, svc.bufferStats().get("flows"));
        assertTrue(svc.connectionsByIp("10.0.0.1", 10).isEmpty(), "最旧的一条应已被覆盖");
        assertEquals(1, svc.connectionsByIp("10.0.0.4", 10).size());
    }

    // ==================== ⑥ 各类型字段解析 ====================

    @Test
    @DisplayName("真实 eve 行的字段能落到对应记录上（flow/http/dns/tls/netflow）")
    void parsesAllEventTypes() {
        EveEventParser parser = new EveEventParser(new ObjectMapper());

        FlowEvent flow = (FlowEvent) parser.parseLine("{\"event_type\":\"flow\",\"timestamp\":\"2026-11-06T10:00:00.123456+0800\","
                + "\"src_ip\":\"10.0.0.5\",\"src_port\":50000,\"dest_ip\":\"10.0.0.9\",\"dest_port\":443,"
                + "\"proto\":\"TCP\",\"app_proto\":\"tls\",\"flow\":{\"bytes_toserver\":1200,\"bytes_toclient\":8000,"
                + "\"pkts_toserver\":10,\"pkts_toclient\":12,\"start\":\"2026-11-06T09:59:58+0800\","
                + "\"end\":\"2026-11-06T10:00:00+0800\"}}");
        assertEquals("flow", flow.eventType());
        assertEquals("10.0.0.5", flow.srcIp());
        assertEquals(443, flow.destPort());
        assertEquals("tls", flow.appProto());
        assertEquals(1200, flow.bytesToServer());
        assertEquals(12, flow.pktsToClient());
        assertEquals(Instant.parse("2026-11-06T02:00:00.123456Z"), flow.ts());
        assertEquals(Instant.parse("2026-11-06T01:59:58Z"), flow.flowStart());

        FlowEvent netflow = (FlowEvent) parser.parseLine("{\"event_type\":\"netflow\",\"timestamp\":\"2026-11-06T10:00:00+0800\","
                + "\"src_ip\":\"10.0.0.6\",\"dest_ip\":\"10.0.0.9\",\"dest_port\":53,"
                + "\"netflow\":{\"pkts\":7,\"bytes\":900}}");
        assertEquals("netflow", netflow.eventType());
        assertEquals(53, netflow.destPort());
        assertEquals(0, netflow.bytesToServer(), "netflow 只有合计值，不冒充 toserver");

        HttpEvent http = (HttpEvent) parser.parseLine("{\"event_type\":\"http\",\"timestamp\":\"2026-11-06T10:00:00+0800\","
                + "\"src_ip\":\"10.0.0.5\",\"dest_ip\":\"10.0.0.9\","
                + "\"http\":{\"hostname\":\"a.example.com\",\"url\":\"/login\",\"http_method\":\"POST\",\"status\":302,"
                + "\"http_user_agent\":\"curl/8.0\"}}");
        assertEquals("a.example.com", http.hostname());
        assertEquals("/login", http.url());
        assertEquals("POST", http.method());
        assertEquals(302, http.status());
        assertEquals("curl/8.0", http.userAgent());

        DnsEvent dns = (DnsEvent) parser.parseLine("{\"event_type\":\"dns\",\"timestamp\":\"2026-11-06T10:00:00+0800\","
                + "\"src_ip\":\"10.0.0.5\",\"dest_ip\":\"10.0.0.53\","
                + "\"dns\":{\"rrname\":\"a.example.com\",\"rrtype\":\"A\",\"rcode\":\"NOERROR\","
                + "\"answers\":[{\"rrname\":\"a.example.com\",\"rrtype\":\"A\",\"rdata\":\"93.184.216.34\"}]}}");
        assertEquals("a.example.com", dns.rrname());
        assertEquals("A", dns.rrtype());
        assertEquals("NOERROR", dns.rcode());
        assertEquals(1, dns.answers().size());
        assertTrue(dns.answers().get(0).contains("93.184.216.34"));

        TlsEvent tls = (TlsEvent) parser.parseLine("{\"event_type\":\"tls\",\"timestamp\":\"2026-11-06T10:00:00+0800\","
                + "\"src_ip\":\"10.0.0.5\",\"dest_ip\":\"10.0.0.9\",\"dest_port\":443,"
                + "\"tls\":{\"sni\":\"a.example.com\",\"version\":\"TLS 1.3\","
                + "\"ja3\":{\"hash\":\"ja3-aaa\"},\"ja3s\":{\"hash\":\"ja3s-bbb\"},\"fingerprint\":\"aa:bb\"}}");
        assertEquals("a.example.com", tls.sni());
        assertEquals("TLS 1.3", tls.version());
        assertEquals("ja3-aaa", tls.ja3Hash());
        assertEquals("ja3s-bbb", tls.ja3sHash());
        assertEquals("aa:bb", tls.fingerprint());

        AlertEvent alert = (AlertEvent) parser.parseLine("{\"event_type\":\"alert\",\"timestamp\":\"2026-11-06T10:00:00+0800\","
                + "\"src_ip\":\"203.0.113.66\",\"dest_ip\":\"10.0.10.21\",\"dest_port\":443,\"proto\":\"TCP\","
                + "\"alert\":{\"signature\":\"ET SCAN Potential SSL Exploit Scanning\","
                + "\"category\":\"Attempted Information Leak\",\"severity\":2}}");
        assertEquals("ET SCAN Potential SSL Exploit Scanning", alert.alert().getRuleName());
        assertEquals(Integer.valueOf(443), alert.alert().getDstPort());

        assertNull(parser.parseLine("{\"event_type\":\"stats\",\"timestamp\":\"2026-11-06T10:00:00+0800\"}"),
                "不认识的类型不占缓冲");
        assertNull(parser.parseLine("not-json"));
        assertNull(parser.parseLine(""));
    }

    @Test
    @DisplayName("alert 事件复用同一套字段映射：文件里的真实告警不会被当成 mock 样本")
    void realAlertFromEveIsNotMarkedMock() throws Exception {
        Path eve = eve("alert.json",
                "{\"event_type\":\"alert\",\"timestamp\":\"2026-11-06T10:00:00+0800\",\"src_ip\":\"203.0.113.66\","
                        + "\"dest_ip\":\"10.0.10.21\",\"dest_port\":443,\"proto\":\"TCP\","
                        + "\"alert\":{\"signature\":\"ET SCAN Potential SSL Exploit Scanning\","
                        + "\"category\":\"Attempted Information Leak\",\"severity\":2}}");
        SuricataService svc = service(eve, 10);

        List<SecurityAlert> alerts = svc.recentNetworkAlerts(5);
        assertEquals(1, alerts.size(), "有真实 alert 时不应回退到 5 条内置样本");
        assertEquals("ET SCAN Potential SSL Exploit Scanning", alerts.get(0).getRuleName());
        assertFalse(Boolean.TRUE.equals(alerts.get(0).getExtra().get("mock")), "真实告警不能带 mock 标记");
        // 时间必须是 "yyyy-MM-dd HH:mm:ss" 的本地格式（具体小时取决于运行机器时区，这里只钉格式）
        assertEquals(19, alerts.get(0).getOccurredAt().length());
        assertTrue(alerts.get(0).getOccurredAt().startsWith("2026-11-06 "));
    }

    // ==================== ⑦ 增量摄取 ====================
    @Test
    @DisplayName("增量摄取：只读新增行，不重复计数，半行等补齐后才解析")
    void ingestIsIncremental() throws Exception {
        Path eve = eve("incremental.json",
                flow("10.0.0.1", 1001, "10.0.0.9", 80, Instant.now().minusSeconds(30)),
                flow("10.0.0.2", 1002, "10.0.0.9", 80, Instant.now().minusSeconds(20)));
        SuricataService svc = service(eve, 100);
        svc.ingestNewEvents();
        assertEquals(2, svc.bufferStats().get("flows"));

        // 再跑一轮但文件没变：不能重复计数
        svc.ingestNewEvents();
        assertEquals(2, svc.bufferStats().get("flows"));

        // 追加两行（无结尾换行）：只能读到第一行
        Files.writeString(eve, flow("10.0.0.3", 1003, "10.0.0.9", 80, Instant.now().minusSeconds(10))
                + "\n" + flow("10.0.0.4", 1004, "10.0.0.9", 80, Instant.now()), StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.APPEND);
        svc.ingestNewEvents();
        assertEquals(3, svc.bufferStats().get("flows"), "结尾半行要留到下一轮");

        // 补上换行后那半行才变完整
        Files.writeString(eve, "\n", StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.APPEND);
        svc.ingestNewEvents();
        assertEquals(4, svc.bufferStats().get("flows"));
    }

    // ==================== 工具 ====================

    private SuricataService service(Path eve, int capacity) {
        SuricataService svc = new SuricataService();
        ReflectionTestUtils.setField(svc, "enabled", true);
        ReflectionTestUtils.setField(svc, "eveJsonPath", eve.toString());
        ReflectionTestUtils.setField(svc, "bufferCapacity", capacity);
        svc.init();
        return svc;
    }

    /** 写一个以换行结尾的 eve 文件（真实文件每行一条 JSON） */
    private Path eve(String name, String... lines) throws Exception {
        Path file = tempDir.resolve(name);
        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            sb.append(line).append('\n');
        }
        Files.writeString(file, sb.toString(), StandardCharsets.UTF_8);
        return file;
    }

    private static String flow(String srcIp, int srcPort, String dstIp, int dstPort, Instant ts) {
        return "{\"event_type\":\"flow\",\"timestamp\":\"" + ts + "\",\"src_ip\":\"" + srcIp + "\",\"src_port\":" + srcPort
                + ",\"dest_ip\":\"" + dstIp + "\",\"dest_port\":" + dstPort
                + ",\"proto\":\"TCP\",\"app_proto\":\"tls\",\"flow\":{\"bytes_toserver\":10,\"bytes_toclient\":20,"
                + "\"pkts_toserver\":1,\"pkts_toclient\":2,\"start\":\"" + ts + "\",\"end\":\"" + ts + "\"}}";
    }

    private static String tls(String srcIp, String sni, String ja3, Instant ts) {
        return "{\"event_type\":\"tls\",\"timestamp\":\"" + ts + "\",\"src_ip\":\"" + srcIp + "\","
                + "\"dest_ip\":\"10.0.0.9\",\"dest_port\":443,\"tls\":{\"sni\":\"" + sni + "\",\"version\":\"TLS 1.3\","
                + "\"ja3\":{\"hash\":\"" + ja3 + "\"}}}";
    }
}

package org.example.integration.suricata;

import org.example.core.model.AlertSeverity;
import org.example.core.model.AlertSource;
import org.example.core.model.AlertType;
import org.example.core.model.SecurityAlert;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 缓冲快照落盘/回载的测试。
 *
 * <p>钉的是"重启不空"这条承诺：落盘文件里五类事件要原样回来（条数、每个字段、顺序），
 * 并且真正的配置入口（{@code integration.suricata.persist-path}）接上后，
 * {@link SuricataService#persistBuffer()} → 新实例 {@link SuricataService#init()} 能还原摄取内容。
 *
 * <p>另外守一条容错底线：上次落盘时进程被杀在最后一行中间（截断行），
 * 不能让整份快照作废 —— 跳过坏行、保住前面的记录即可。
 */
class SuricataBufferPersistenceTest {

    private static final Instant T0 = Instant.parse("2026-11-07T10:00:00Z");

    @TempDir
    Path tempDir;

    // ==================== ① store 级：落盘 → 回载，内容逐条一致 ====================

    @Test
    @DisplayName("【落盘】五类事件写出再回载：条数、字段、顺序都一致")
    void snapshotRoundTripPreservesAllEventTypes() throws Exception {
        FlowEvent flow = flow("10.0.0.5", 50000, "10.0.0.9", 443, T0);
        HttpEvent http = new HttpEvent(T0, "10.0.0.5", "10.0.0.9", "example.com", "/a?b=1", "GET", 200, "curl/8.5.0");
        DnsEvent dns = new DnsEvent(T0, "10.0.0.5", "10.0.0.53", "example.com", "A", "NOERROR",
                List.of("93.184.216.34", "2606:2800::1"));
        TlsEvent tls = tls("10.0.0.5", 50000, "10.0.0.9", 443, T0);
        AlertEvent alert = new AlertEvent(T0, alert());

        List<EveEvent> original = List.of(flow, http, dns, tls, alert);
        SuricataEventStore source = new SuricataEventStore(50);
        original.forEach(source::add);

        Path file = tempDir.resolve("snap").resolve("xk-buffer.bin");
        assertEquals(original.size(), source.saveSnapshot(file), "落盘应返回写入条数");
        assertTrue(Files.isRegularFile(file), "父目录不存在时 saveSnapshot 要自己建");

        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        assertEquals(original.size(), lines.size(), "一行一条事件");
        for (String line : lines) {
            assertTrue(line.contains("\t"), "行格式是 type<TAB>json，便于 grep：" + line);
        }

        SuricataEventStore restored = new SuricataEventStore(50);
        assertEquals(original.size(), restored.loadSnapshot(file));
        assertEquals(1, restored.flowCount(), "flow 桶条数");
        assertEquals(1, restored.tlsCount(), "tls 桶条数");
        assertEquals(original.size(), restored.totalIngested(), "五类合计条数");
        // record 的 equals 覆盖全部字段：这一条断言等价于"每个字段都对"
        assertEquals(original, restored.allSnapshot(), "回载内容必须逐条等价且保持旧→新顺序");
    }

    // ==================== ② 容错：截断末行只跳过这一行 ====================

    @Test
    @DisplayName("【容错】截断的末行只跳过不毁整份快照（落盘时被杀在半行）")
    void truncatedLastLineDoesNotDiscardSnapshot() throws Exception {
        SuricataEventStore source = new SuricataEventStore(20);
        source.add(flow("10.0.0.5", 50000, "10.0.0.9", 443, T0));
        source.add(tls("10.0.0.5", 50000, "10.0.0.9", 443, T0));

        Path file = tempDir.resolve("xk-buffer.bin");
        source.saveSnapshot(file);
        // 模拟"刚写了一半就被杀"：追加一条没有换行、JSON 也不完整的行
        Files.writeString(file, "flow\t{\"eventType\":\"flow\",\"ts\":\"2026", StandardCharsets.UTF_8,
                StandardOpenOption.APPEND);

        SuricataEventStore restored = new SuricataEventStore(20);
        assertEquals(2, restored.loadSnapshot(file), "坏行跳过，前面两条照常回载");
        assertEquals(2, restored.totalIngested());
    }

    // ==================== ③ 服务接线：配置项 → 落盘 → 新实例回载 ====================

    @Test
    @DisplayName("【接线】persist-path 配好后落盘，重启 init 回载：摄取内容不丢")
    void serviceRestoresBufferAcrossRestart() throws Exception {
        Path eve = tempDir.resolve("missing-eve.json");
        Path snapshot = tempDir.resolve("xk-buffer.bin");

        SuricataService first = service(eve, snapshot);
        SuricataEventStore live = (SuricataEventStore) ReflectionTestUtils.getField(first, "store");
        FlowEvent flow = flow("10.0.0.5", 50000, "10.0.0.9", 443, T0);
        live.add(flow);
        live.add(tls("10.0.0.5", 50000, "10.0.0.9", 443, T0));
        first.persistBuffer();
        assertTrue(Files.isRegularFile(snapshot), "persist-path 非空时必须真的写出文件");

        // "重启"：同一配置下新建实例，init() 里会先回载快照
        SuricataService second = service(eve, snapshot);
        Map<String, Object> stats = second.bufferStats();
        assertEquals(1, stats.get("flows"), "重启后 flow 条数必须还在：" + stats);
        assertEquals(1, stats.get("tls"), "重启后 tls 条数必须还在：" + stats);
        assertEquals(2L, stats.get("ingested"), "五类合计条数：" + stats);
        assertEquals(List.of(flow), second.connectionsByIp("10.0.0.5", 10), "回载内容逐字段一致");
    }

    @Test
    @DisplayName("【默认】persist-path 为空：落盘是空操作，不创建任何文件")
    void emptyPersistPathIsNoOp() throws Exception {
        SuricataService svc = service(tempDir.resolve("missing-eve.json"), null);
        svc.persistBuffer();
        try (Stream<Path> files = Files.list(tempDir)) {
            assertEquals(0, files.count(), "未配置 persist-path 时不该产生任何文件");
        }
    }

    // ==================== 辅助 ====================

    private SuricataService service(Path eve, Path persist) {
        SuricataService svc = new SuricataService();
        ReflectionTestUtils.setField(svc, "enabled", true);
        ReflectionTestUtils.setField(svc, "eveJsonPath", eve.toString());
        ReflectionTestUtils.setField(svc, "bufferCapacity", 100);
        ReflectionTestUtils.setField(svc, "persistPath", persist == null ? "" : persist.toString());
        ReflectionTestUtils.setField(svc, "persistIntervalMs", 300000L);
        svc.init();
        return svc;
    }

    private static FlowEvent flow(String srcIp, int srcPort, String dstIp, int dstPort, Instant ts) {
        return new FlowEvent("flow", ts, srcIp, srcPort, dstIp, dstPort, "TCP", "tls",
                1200, 8000, 10, 12, ts.minusSeconds(2), ts);
    }

    private static TlsEvent tls(String srcIp, int srcPort, String dstIp, int dstPort, Instant ts) {
        return new TlsEvent(ts, srcIp, dstIp, dstPort, "example.com", "TLS 1.3",
                "abcdef0123456789abcdef0123456789", "0123456789abcdef0123456789abcdef", "cert-fingerprint");
    }

    private static SecurityAlert alert() {
        SecurityAlert a = new SecurityAlert();
        a.setId("alert-1");
        a.setRuleName("ET SCAN Potential SSH Scan");
        a.setType(AlertType.SCAN);
        a.setSeverity(AlertSeverity.HIGH);
        a.setSource(AlertSource.SURICATA);
        a.setSrcIp("10.0.0.5");
        a.setDstPort(22);
        a.setTitle("疑似 SSH 扫描");
        a.setDescription("多次连接 22 端口被拒绝");
        a.setOccurredAt("2026-11-07 18:00:00");
        a.setCount(3);
        a.setExtra(Map.of("sid", 2001219, "proto", "TCP"));
        return a;
    }
}

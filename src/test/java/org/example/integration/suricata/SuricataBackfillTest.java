package org.example.integration.suricata;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Suricata 启动回填的测试。
 *
 * <p>钉住四件最容易"看起来有数据、其实做错了"的事：
 * ① 只回填尾部 N 行且保持原始顺序（读反了端点返回的新旧顺序就会颠倒）；
 * ② 文件第一行是半行时跳过而不是抛异常（跨机同步 tail 8MB 再追加的必然产物）；
 * ③ 回填完的字节不能被增量摄取重复解析（偏移必须落到文件当前长度）；
 * ④ 关闭回填/文件不存在时不能把现有 MOCK 与增量语义弄坏。
 *
 * <p>不出新依赖：用 Spring 的 ReflectionTestUtils 塞字段，文件系统用 JUnit 的 {@link TempDir}。
 */
class SuricataBackfillTest {

    @TempDir
    Path tempDir;

    // ==================== ① 正常回填 N 行 ====================

    @Test
    @DisplayName("回填只取最后 N 行、按原始顺序入缓冲，偏移落到文件末尾")
    void backfillsLastNLinesInOrder() throws Exception {
        List<String> lines = List.of(
                flow("10.0.0.1", 1001, 1001),
                flow("10.0.0.2", 1002, 1002),
                flow("10.0.0.3", 1003, 1003),
                flow("10.0.0.4", 1004, 1004),
                flow("10.0.0.5", 1005, 1005));
        Path eve = eve("tail.json", lines);
        long size = Files.size(eve);
        long expectedStart = lines.subList(0, 2).stream()
                .mapToLong(l -> l.getBytes(StandardCharsets.UTF_8).length + 1L)
                .sum();

        SuricataService svc = service(eve, 100, 3);
        SuricataService.BackfillResult r = svc.lastBackfill();

        assertEquals("REAL", svc.mode());
        assertEquals(3, r.lines());
        assertEquals(0, r.skipped());
        assertEquals(size, r.fileSize());
        assertEquals(expectedStart, r.startOffset(), "窗口应从第 3 行行首开始，而不是把文件全读一遍");

        Map<String, Object> stats = svc.bufferStats();
        assertEquals(3, stats.get("flows"));
        assertEquals(size, stats.get("offset"), "回填后增量偏移必须指向文件当前长度");
        assertEquals(3, stats.get("backfilled"));

        // 原始顺序：后入的在缓冲尾部，按 IP 反查是"新 → 旧"
        List<Integer> ports = svc.connectionsByIp("10.0.0.9", 10).stream()
                .map(FlowEvent::destPort).toList();
        assertEquals(List.of(1005, 1004, 1003), ports);
        assertTrue(svc.connectionsByIp("10.0.0.1", 10).isEmpty(), "窗口外的旧行不能被回填进来");
    }

    // ==================== ② 首行半行 ====================

    @Test
    @DisplayName("首行是半条 JSON：跳过并计数，不抛异常，其余行正常回填")
    void skipsPartialFirstLine() throws Exception {
        // 跨机同步 tail 8MB 后追加，文件第一行可能是从某条 JSON 中间开始的半行
        String half = "{\"event_type\":\"flow\",\"src_ip\":\"10.0.0.99\",\"dest_port\":";
        Path eve = tempDir.resolve("half-first.json");
        Files.writeString(eve, half + "\n"
                + flow("10.0.0.1", 2001, 2001) + "\n"
                + flow("10.0.0.2", 2002, 2002) + "\n"
                + flow("10.0.0.3", 2003, 2003) + "\n", StandardCharsets.UTF_8);

        SuricataService svc = service(eve, 100, 100);

        SuricataService.BackfillResult r = svc.lastBackfill();
        assertEquals(3, r.lines(), "三条完整行都要进缓冲");
        assertEquals(1, r.skipped(), "半行要计入跳过");
        assertEquals(Files.size(eve), svc.bufferStats().get("offset"));
        assertEquals(3, svc.bufferStats().get("flows"));
        assertEquals(List.of(2003, 2002, 2001),
                svc.connectionsByIp("10.0.0.9", 10).stream().map(FlowEvent::destPort).toList());
    }

    // ==================== ③ 文件不存在 ====================

    @Test
    @DisplayName("文件不存在：保持 MOCK，不回填、不报错、告警仍回退内置样本")
    void missingFileKeepsMockSemantics() {
        SuricataService svc = service(tempDir.resolve("not-exist.json"), 100, 20000);

        assertEquals("MOCK", svc.mode());
        assertEquals(0, svc.lastBackfill().lines());
        assertEquals(0, svc.bufferStats().get("flows"));
        assertEquals(0L, svc.bufferStats().get("offset"));
        assertEquals(5, svc.recentNetworkAlerts(10).size(), "既有 MOCK 语义不变");
    }

    // ==================== ④ 关闭回填 ====================

    @Test
    @DisplayName("backfill-lines=0：不回填，但增量摄取照常工作")
    void zeroLinesDisablesBackfill() throws Exception {
        Path eve = eve("disabled.json", List.of(
                flow("10.0.0.1", 3001, 3001),
                flow("10.0.0.2", 3002, 3002),
                flow("10.0.0.3", 3003, 3003),
                flow("10.0.0.4", 3004, 3004)));
        SuricataService svc = service(eve, 100, 0);

        assertEquals("REAL", svc.mode());
        assertEquals(0, svc.lastBackfill().lines());
        assertEquals(0, svc.bufferStats().get("flows"), "关闭回填后启动时缓冲应为空");

        // 增量路径不受影响：首次调度仍然会读文件（短文件从 0 开始）
        svc.ingestNewEvents();
        assertEquals(4, svc.bufferStats().get("flows"));
    }

    // ==================== ⑤ 文件比窗口小 ====================

    @Test
    @DisplayName("文件比回填窗口小：全部读入，窗口起点为 0")
    void fileSmallerThanWindowIsReadFully() throws Exception {
        Path eve = eve("small.json", List.of(
                flow("10.0.0.1", 4001, 4001),
                flow("10.0.0.2", 4002, 4002),
                flow("10.0.0.3", 4003, 4003),
                flow("10.0.0.4", 4004, 4004),
                flow("10.0.0.5", 4005, 4005)));
        SuricataService svc = service(eve, 100, 1000);

        SuricataService.BackfillResult r = svc.lastBackfill();
        assertEquals(5, r.lines());
        assertEquals(0, r.skipped());
        assertEquals(0, r.startOffset(), "文件比窗口小时应从文件头读起");
        assertEquals(5, svc.bufferStats().get("flows"));
        assertEquals(5, svc.bufferStats().get("backfilled"));
    }

    // ==================== 工具 ====================

    private SuricataService service(Path eve, int capacity, int backfillLines) {
        SuricataService svc = new SuricataService();
        ReflectionTestUtils.setField(svc, "enabled", true);
        ReflectionTestUtils.setField(svc, "eveJsonPath", eve.toString());
        ReflectionTestUtils.setField(svc, "bufferCapacity", capacity);
        ReflectionTestUtils.setField(svc, "backfillLines", backfillLines);
        svc.init();
        return svc;
    }

    /** 写一个以换行结尾的 eve 文件（真实文件每行一条 JSON） */
    private Path eve(String name, List<String> lines) throws Exception {
        Path file = tempDir.resolve(name);
        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            sb.append(line).append('\n');
        }
        Files.writeString(file, sb.toString(), StandardCharsets.UTF_8);
        return file;
    }

    private static String flow(String srcIp, int srcPort, int destPort) {
        Instant ts = Instant.now().minusSeconds(5);
        return "{\"event_type\":\"flow\",\"timestamp\":\"" + ts + "\",\"src_ip\":\"" + srcIp + "\",\"src_port\":" + srcPort
                + ",\"dest_ip\":\"10.0.0.9\",\"dest_port\":" + destPort
                + ",\"proto\":\"TCP\",\"app_proto\":\"tls\",\"flow\":{\"bytes_toserver\":10,\"bytes_toclient\":20,"
                + "\"pkts_toserver\":1,\"pkts_toclient\":2,\"start\":\"" + ts + "\",\"end\":\"" + ts + "\"}}";
    }
}

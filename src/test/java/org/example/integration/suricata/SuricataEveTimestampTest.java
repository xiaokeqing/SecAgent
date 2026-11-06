package org.example.integration.suricata;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * eve.json 时间戳口径 + "REAL 却没有数据"的回归测试。
 *
 * <p>线上 srv1 出现过 {@code mode=REAL, total=0, ports=[]}：eve.json 里有事件，端点却空。
 * 两个候选原因都要被测试钉住：
 * ① 时间戳解析丢掉 {@code +0000} 偏移（会被当成本地时间，整窗事件早 8 小时）；
 * ② 启动时 {@code available=true}（mode=REAL）但回填被关闭/失败，缓冲要等首次调度才有数据。
 */
class SuricataEveTimestampTest {

    private static final DateTimeFormatter EVE_TS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSSxx");

    /** 线上真实形态：UTC 主机写出的 "+0000"。 */
    @Test
    @DisplayName("+0000 偏移必须换算成 UTC 瞬时，不能被当成本地时间")
    void zeroOffsetIsUtc() {
        String raw = "2026-11-06T16:11:02.911209+0000";
        Instant parsed = EveEventParser.parseTime(raw);
        Instant expected = OffsetDateTime.parse("2026-11-06T16:11:02.911209+00:00").toInstant();

        assertNotNull(parsed, "带 +0000 的时间戳必须能解析");
        assertEquals(expected.toEpochMilli(), parsed.toEpochMilli(), "epoch 必须是 UTC 口径");
        // 与 JVM 时区无关的硬断言：16:11 UTC 就是 16 点，不该被挪成 8 点或 0 点
        assertEquals(16, parsed.atOffset(ZoneOffset.UTC).getHour());
        // 如果实现丢了偏移、按本地时区解释，结果会差整整 8 小时（+08 机器上）
        Instant asLocal = LocalDateTime.parse("2026-11-06T16:11:02.911209")
                .atZone(ZoneId.systemDefault()).toInstant();
        if (!ZoneOffset.UTC.equals(ZoneId.systemDefault().getRules().getOffset(parsed))) {
            assertNotEquals(asLocal.toEpochMilli(), parsed.toEpochMilli(),
                    "偏移被丢掉时这里会差 8 小时，说明又回到了「当成本地时间」的老 bug");
            assertEquals(8 * 3600_000L,
                    parsed.toEpochMilli() - asLocal.toEpochMilli(),
                    "本地时区若是 +08，两个口径正好差 8 小时");
        }
    }

    @Test
    @DisplayName("+0800 / Z 形态同样按偏移换算")
    void otherOffsetForms() {
        assertEquals(Instant.parse("2026-11-06T14:24:47.123456Z"),
                EveEventParser.parseTime("2026-11-06T22:24:47.123456+0800"));
        assertEquals(Instant.parse("2026-11-06T16:11:02Z"),
                EveEventParser.parseTime("2026-11-06T16:11:02Z"));
        assertNull(EveEventParser.parseTime("not-a-time"));
        assertNull(EveEventParser.parseTime(""));
        assertNull(EveEventParser.parseTime(null));
    }

    /**
     * 回归：mode 已是 REAL、但回填被关闭时，init() 必须立刻把缓冲填上，
     * 不能等 15s 后的首次调度 —— 否则重启后这段窗口里 top-ports 恒为空。
     */
    @Test
    @DisplayName("REAL 模式下 init() 立即有数据（回填关闭也不能留空窗）")
    void realModeHasDataRightAfterInit(@TempDir Path dir) throws Exception {
        Path eve = dir.resolve("eve.json");
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 12; i++) {
            sb.append(flowLine(now.minusSeconds(i * 5L), i % 3 == 0 ? 443 : 22)).append('\n');
        }
        Files.write(eve, sb.toString().getBytes(StandardCharsets.UTF_8));

        SuricataService svc = new SuricataService();
        ReflectionTestUtils.setField(svc, "enabled", true);
        ReflectionTestUtils.setField(svc, "eveJsonPath", eve.toString());
        ReflectionTestUtils.setField(svc, "bufferCapacity", 50000);
        // 模拟线上关掉回填：这条路只能靠 init() 内的补读兜住
        ReflectionTestUtils.setField(svc, "backfillLines", 0);

        svc.init();

        assertEquals("REAL", svc.mode());
        assertEquals(0, svc.lastBackfill().lines(), "回填被关闭，不应有回填行数");
        List<PortCount> ports = svc.topDestPorts(60, 10);
        assertFalse(ports.isEmpty(), "REAL 模式下缓冲必须是热的，否则端点会给出误导性的空结果");
        assertTrue(ports.stream().anyMatch(p -> p.port() == 443), "443 必须出现在统计里");
        assertDoesNotThrow(() -> svc.connectionsByIp("10.0.10.21", 5));
        assertFalse(svc.connectionsByIp("10.0.10.21", 5).isEmpty());
    }

    /** 60 分钟窗口按 UTC 口径计算：+0000 的近期事件必须被统计到。 */
    @Test
    @DisplayName("+0000 的近期 flow 必须落进 60 分钟窗口")
    void plus0000RecentFlowIsCounted() {
        EveEvent event = new EveEventParser(new com.fasterxml.jackson.databind.ObjectMapper())
                .parseLine(flowLine(OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(3), 3389));
        assertTrue(event instanceof FlowEvent);
        Instant ts = ((FlowEvent) event).ts();
        assertFalse(ts.isBefore(Instant.now().minusSeconds(3600)),
                "事件只该早 3 分钟，不该因为丢掉偏移而早 8 小时");
    }

    private static String flowLine(OffsetDateTime ts, int destPort) {
        return "{\"event_type\":\"flow\",\"timestamp\":\"" + ts.format(EVE_TS) + "\""
                + ",\"src_ip\":\"10.0.10.21\",\"src_port\":51234,\"dest_ip\":\"93.184.216.34\""
                + ",\"dest_port\":" + destPort + ",\"proto\":\"TCP\",\"app_proto\":\"tls\""
                + ",\"flow\":{\"bytes_toserver\":1290,\"bytes_toclient\":5820,"
                + "\"pkts_toserver\":9,\"pkts_toclient\":11,"
                + "\"start\":\"" + ts.minusSeconds(2).format(EVE_TS) + "\",\"end\":\"" + ts.format(EVE_TS) + "\"}}";
    }
}

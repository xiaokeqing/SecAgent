package org.example.accesslog;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 访问日志落盘器（{@link AccessLogWriter}）的测试。
 *
 * <h3>钉住的三件事</h3>
 * <ol>
 *   <li><b>请求线程不做 I/O</b>：写盘只发生在 {@code secagent-accesslog-writer} 线程上
 *       （RUNBOOK §23 的教训：请求路径上做 I/O = 整站 502）；</li>
 *   <li><b>写不出去时不阻塞、不静默</b>：队列满就丢 + 节流 WARN + 计数；</li>
 *   <li><b>轮转与保留</b>：按天/按大小切分，超期文件被删，活动文件永不删、名字不变。</li>
 * </ol>
 */
class AccessLogWriterTest {

    private Path tmpDir;

    @BeforeEach
    void setUp() throws IOException {
        tmpDir = Files.createTempDirectory("accesslog-writer-test");
    }

    @AfterEach
    void tearDown() throws IOException {
        try (Stream<Path> walk = Files.walk(tmpDir)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    // 清理失败不影响结论
                }
            });
        }
    }

    private List<String> allLines() throws IOException {
        List<String> lines = new ArrayList<>();
        try (Stream<Path> files = Files.list(tmpDir)) {
            for (Path p : files.sorted(Comparator.comparing(Path::toString)).toList()) {
                for (String l : Files.readAllLines(p, StandardCharsets.UTF_8)) {
                    if (!l.isBlank()) {
                        lines.add(l);
                    }
                }
            }
        }
        return lines;
    }

    private List<String> rotatedNames() throws IOException {
        try (Stream<Path> files = Files.list(tmpDir)) {
            return files.map(p -> p.getFileName().toString())
                    .filter(n -> n.startsWith("access-"))
                    .sorted()
                    .toList();
        }
    }

    @Test
    @DisplayName("【核心·异步】写盘发生在独立线程上，请求线程只入队")
    void diskIoHappensOnWriterThread() throws Exception {
        AccessLogWriter w = new AccessLogWriter(tmpDir, 7, 1024 * 1024);
        try {
            w.start();
            for (int i = 0; i < 5; i++) {
                assertTrue(w.offer("{\"n\":" + i + "}"), "队列未满时必须入队成功");
            }
            w.drain();

            assertEquals("secagent-accesslog-writer", w.lastWriteThread(),
                    "写盘必须发生在专用线程上（请求线程做 I/O 就是 §23 那次事故）");
            assertNotEquals(Thread.currentThread().getName(), w.lastWriteThread());
            assertEquals(5, w.writtenCount());
            assertEquals(5, allLines().size(), "入队的内容必须一字不差地落盘");
            assertEquals(0, w.droppedCount());
            assertTrue(Files.exists(tmpDir.resolve("access.jsonl")), "活动文件名必须稳定为 access.jsonl");
        } finally {
            w.close();
        }
    }

    @Test
    @DisplayName("【核心·不阻塞】队列永远满：立刻丢弃 + 计数，绝不阻塞调用方")
    void fullQueueNeverBlocks() throws Exception {
        BlockingQueue<String> neverDrains = new AlwaysFullQueue();
        AccessLogWriter w = new AccessLogWriter(tmpDir, "access.jsonl", 7, 1024 * 1024,
                neverDrains, Clock.systemDefaultZone(), 16);
        try {
            w.start();
            long t0 = System.nanoTime();
            int accepted = 0;
            for (int i = 0; i < 2000; i++) {
                if (w.offer("{\"n\":" + i + "}")) {
                    accepted++;
                }
            }
            long ms = (System.nanoTime() - t0) / 1_000_000L;

            assertEquals(0, accepted, "队列满时必须返回 false（调用方据此如实降级）");
            assertEquals(2000, w.droppedCount(), "丢弃必须计数，不能静默");
            assertEquals(0, w.writtenCount());
            assertTrue(ms < 2000, "2000 次入队必须立刻返回（实测 " + ms + " ms）——"
                    + "如果这里用了 put()，慢盘就会把 Tomcat 线程池拖死");
        } finally {
            w.close();
        }
    }

    @Test
    @DisplayName("【核心·轮转】单文件超过上限自动切分，且一行都不丢")
    void rotatesBySizeWithoutLosingLines() throws Exception {
        // 每行约 60 字节、上限 300 字节 → 每 5 行左右切一次
        AccessLogWriter w = new AccessLogWriter(tmpDir, 7, 300);
        try {
            w.start();
            for (int i = 0; i < 60; i++) {
                w.offer("{\"i\":" + i + ",\"pad\":\"............................\"}");
            }
            w.drain();

            List<String> rotated = rotatedNames();
            assertFalse(rotated.isEmpty(), "超过上限必须切分出 access-<时间戳>.jsonl");
            for (String name : rotated) {
                assertTrue(name.startsWith("access-") && name.endsWith(".jsonl"),
                        "切分后的文件名必须可被保留策略识别：" + name);
                assertFalse(name.equals("access.jsonl"), "活动文件不该出现在切分清单里");
            }
            assertTrue(Files.exists(tmpDir.resolve("access.jsonl")), "切分后必须继续写活动文件");
            assertEquals(60, allLines().size(), "轮转不得丢行");
            assertTrue(w.stats().get("rotations") instanceof Long);
            assertTrue((Long) w.stats().get("rotations") > 0);
        } finally {
            w.close();
        }
    }

    @Test
    @DisplayName("【核心·按天轮转】跨天自动切换文件（并保留活动文件名不变）")
    void rotatesByDay() throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-10-13T23:59:00Z"), ZoneId.of("UTC"));
        AccessLogWriter w = new AccessLogWriter(tmpDir, "access.jsonl", 7, 1024 * 1024,
                new ArrayBlockingQueue<>(64), clock, 64);
        try {
            w.start();
            w.offer("{\"day\":\"d1\"}");
            w.drain();
            clock.advance(Duration.ofMinutes(2));
            w.offer("{\"day\":\"d2\"}");
            w.drain();

            List<String> rotated = rotatedNames();
            assertEquals(1, rotated.size(), "跨天必须切分一次：" + rotated);
            assertEquals(2, allLines().size());
        } finally {
            w.close();
        }
    }

    @Test
    @DisplayName("【核心·保留】超过保留天数的切分文件被删除；活动文件永不删")
    void purgesExpiredRotatedFiles() throws Exception {
        // 一个"10 天前"的切分文件 + 一个"刚才"的切分文件
        Path expired = tmpDir.resolve("access-20261003-000000.jsonl");
        Path recent = tmpDir.resolve("access-20261013-000000.jsonl");
        Files.writeString(expired, "{\"old\":1}\n");
        Files.writeString(recent, "{\"recent\":1}\n");
        long tenDaysAgo = System.currentTimeMillis() - Duration.ofDays(10).toMillis();
        Files.setLastModifiedTime(expired, FileTime.fromMillis(tenDaysAgo));

        AccessLogWriter w = new AccessLogWriter(tmpDir, 7, 200);
        try {
            w.start();
            // 写到超过上限，强制轮转（保留策略挂在轮转上）
            for (int i = 0; i < 20; i++) {
                w.offer("{\"i\":" + i + ",\"pad\":\"............................\"}");
            }
            w.drain();

            assertFalse(Files.exists(expired), "超过 7 天的切分文件必须被删除");
            assertTrue(Files.exists(recent), "未超期的切分文件不能被误删");
            assertTrue(Files.exists(tmpDir.resolve("access.jsonl")), "活动文件永远不删");
            assertTrue((Long) w.stats().get("purged") >= 1);
        } finally {
            w.close();
        }
    }

    @Test
    @DisplayName("保留天数设为 0 时不做清理（显式关闭保留策略）")
    void retainZeroKeepsEverything() throws Exception {
        Path expired = tmpDir.resolve("access-20200101-000000.jsonl");
        Files.writeString(expired, "{\"old\":1}\n");
        Files.setLastModifiedTime(expired, FileTime.fromMillis(System.currentTimeMillis() - Duration.ofDays(300).toMillis()));

        AccessLogWriter w = new AccessLogWriter(tmpDir, 0, 200);
        try {
            w.start();
            for (int i = 0; i < 20; i++) {
                w.offer("{\"i\":" + i + ",\"pad\":\"............................\"}");
            }
            w.drain();
            assertTrue(Files.exists(expired), "retain-days=0 表示不清理");
        } finally {
            w.close();
        }
    }

    @Test
    @DisplayName("目录不可写：start() 抛异常（调用方据此打 WARN），而不是静默假装成功")
    void startFailsLoudlyOnBadDirectory() throws Exception {
        Path aFile = tmpDir.resolve("not-a-dir");
        Files.writeString(aFile, "x");
        AccessLogWriter w = new AccessLogWriter(aFile.resolve("nested"), 7, 1024);
        assertThrows(IOException.class, w::start, "建不出目录必须抛出来（静默成功=检测假覆盖）");
        assertFalse(w.offer("{}"), "没起来时入队必须失败");
        assertTrue(w.droppedCount() >= 1);
    }

    @Test
    @DisplayName("未启动就入队：返回 false 并计数（不 NPE、不阻塞）")
    void offerBeforeStartIsSafe() {
        AccessLogWriter w = new AccessLogWriter(tmpDir, 7, 1024);
        assertFalse(w.offer("{}"));
        assertEquals(1, w.droppedCount());
        assertEquals(0, w.writtenCount());
    }

    @Test
    @DisplayName("落盘内容按行追加：一次 offer 一行，行内不含换行（JSONL 契约）")
    void jsonlContract() throws Exception {
        AccessLogWriter w = new AccessLogWriter(tmpDir, 7, 1024 * 1024);
        try {
            w.start();
            w.offer("{\"a\":1}");
            w.offer("{\"b\":2}");
            w.drain();
            List<String> lines = allLines();
            assertEquals(List.of("{\"a\":1}", "{\"b\":2}"), lines);
            String content = Files.readString(tmpDir.resolve("access.jsonl"), StandardCharsets.UTF_8);
            assertTrue(content.endsWith("\n"), "每行必须以换行结束（fail2ban/Wazuh 按行读）");
        } finally {
            w.close();
        }
    }

    @Test
    @DisplayName("close() 会把队列里剩余的写掉（不丢最后一段）")
    void closeFlushesPendingLines() throws Exception {
        AccessLogWriter w = new AccessLogWriter(tmpDir, 7, 1024 * 1024);
        w.start();
        for (int i = 0; i < 50; i++) {
            w.offer("{\"i\":" + i + "}");
        }
        w.close();
        assertEquals(50, allLines().size(), "关闭前入队的行必须全部落盘");
    }

    @Test
    @DisplayName("stats() 如实暴露计数与最后一条错误（运维/自检要能看见）")
    void statsAreHonest() throws Exception {
        AccessLogWriter w = new AccessLogWriter(tmpDir, 3, 4096);
        try {
            w.start();
            w.offer("{\"x\":1}");
            w.drain();
            assertNotNull(w.stats().get("activeFile"));
            assertEquals(3, w.stats().get("retainDays"));
            assertEquals(4096L, w.stats().get("maxFileBytes"));
            assertEquals(1L, w.stats().get("written"));
            assertEquals("", w.stats().get("lastError"), "没出错时 lastError 必须是空的（不能瞎报）");
        } finally {
            w.close();
        }
    }

    /** 可变时钟：用来确定性地测"跨天轮转"，不依赖真实时间 */
    static final class MutableClock extends Clock {
        private volatile Instant instant;
        private final ZoneId zone;

        MutableClock(Instant instant, ZoneId zone) {
            this.instant = instant;
            this.zone = zone;
        }

        void advance(Duration d) {
            this.instant = this.instant.plus(d);
        }

        @Override
        public ZoneId getZone() {
            return zone;
        }

        @Override
        public Clock withZone(ZoneId z) {
            return new MutableClock(instant, z);
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }

    /** 永远"满"的队列：offer 永远失败、poll 永远拿不到 —— 用来模拟写盘彻底卡住 */
    static final class AlwaysFullQueue extends ArrayBlockingQueue<String> {
        AlwaysFullQueue() {
            super(1);
        }

        @Override
        public boolean offer(String s) {
            return false;
        }

        @Override
        public String poll() {
            return null;
        }

        @Override
        public String poll(long timeout, TimeUnit unit) {
            try {
                Thread.sleep(Math.min(50L, unit.toMillis(timeout)));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return null;
        }
    }
}

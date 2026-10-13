package org.example.accesslog;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link WebStatsService} 的测试：回填、解析、文件状态、以及<b>"回填与实时计数不重叠"</b>。
 *
 * <p>这里最容易写错、同时<b>又不会报错</b>的有两处，都是本测试的重点：
 * <ol>
 *   <li><b>不重复计数</b>：回填只读"启动那一刻的活动文件长度"，写线程从那个长度往后实时计 ——
 *       两条线的边界必须严丝合缝；</li>
 *   <li><b>不静默降级</b>：文件缺失/读不出来/窗口为空必须是三种不同的状态
 *       （端点靠它们区分 {@code LOG_FILE_MISSING} / {@code LOG_UNREADABLE} / {@code WINDOW_EMPTY}）。</li>
 * </ol>
 */
class WebStatsServiceTest {

    @TempDir
    Path tmp;

    private WebStatsService newService() {
        WebStatsService s = new WebStatsService();
        ReflectionTestUtils.setField(s, "enabled", true);
        ReflectionTestUtils.setField(s, "accessLogEnabled", true);
        ReflectionTestUtils.setField(s, "uaMaxChars", 60);
        ReflectionTestUtils.setField(s, "backfillMaxMb", 64);
        // 探测线程在测试里不参与（测试自己调 probeOnce()）——避免"等 10 秒才知道结论"的脆弱测试
        ReflectionTestUtils.setField(s, "fileProbeSeconds", 3600);
        return s;
    }

    private WebStatsAggregator.Thresholds th() {
        return WebStatsAggregator.Thresholds.defaults();
    }

    /** 造 n 行同一形态的访问日志（ts = 现在） */
    private List<String> lines(OffsetDateTime now, String path, int status, String ua, int n) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            out.add(WebStatsFixtures.accessLine(now, "GET", path, status, ua));
        }
        return out;
    }

    @Test
    @DisplayName("启动回填：真实 JSONL 逐行进聚合器，状态与内存上限自证")
    void backfillsRealJsonl() throws Exception {
        OffsetDateTime now = OffsetDateTime.now();
        Path dir = Files.createDirectory(tmp.resolve("log"));
        List<String> all = new ArrayList<>();
        all.addAll(lines(now, "/wp-login.php", 404, "curl/8.0.1", 5));
        all.addAll(lines(now, "/.env", 404, "curl/8.0.1", 5));
        all.addAll(lines(now, "/api/public/geo", 200, "Mozilla/5.0 (X11)", 2));
        Files.write(dir.resolve("access.jsonl"), all, StandardCharsets.UTF_8);

        WebStatsService s = newService();
        try {
            s.beginBackfill(dir);
            assertTrue(s.awaitBackfill(5_000), "回填必须在后台完成（不阻塞启动）");

            WebStatsService.Status st = s.status();
            assertTrue(st.enabled());
            assertTrue(st.accessLogEnabled());
            assertTrue(st.fileExists());
            assertTrue(st.fileReadable(), "读得出来就必须说读得出来");
            assertTrue(st.backfillDone());
            assertFalse(st.backfillRunning());
            assertEquals(12L, st.parsedRecords());
            assertEquals(12L, st.backfilledRecords(), "回填读到的行数要如实披露");
            assertEquals(0L, st.skippedLines());
            assertEquals("", st.lastError());
            // 内存上限自证（公开响应的 coverage 就用这几个数）
            assertEquals(288, st.bucketCount());
            assertEquals(300, st.bucketSeconds());
            assertEquals(168, st.hourCells());
            assertEquals(24, st.uaSlotsPerBucket());
            assertEquals(128, st.globalUaSlots());

            WebStatsAggregator.Snapshot snap = s.snapshot(OffsetDateTime.now(), th());
            assertEquals(12L, snap.requests());
            assertEquals(10L, snap.statusClass().c4xx());
            assertEquals(2L, snap.statusClass().c2xx());
            assertEquals(List.of("dotenv", "wp-login"),
                    snap.topCategories().stream().map(WebStatsAggregator.CategoryCount::category).toList());
            assertEquals(1L, snap.byDay().size(), "只有今天一行");
            assertEquals(1, snap.heatmap().size(), "所有行的 ts 相同：今天恰好一个整点格");
        } finally {
            s.stop();
        }
    }

    @Test
    @DisplayName("脏行/坏行：计数披露、绝不抛异常、也不影响好行")
    void toleratesMalformedLines() throws Exception {
        OffsetDateTime now = OffsetDateTime.now();
        Path dir = Files.createDirectory(tmp.resolve("log"));
        List<String> all = new ArrayList<>(lines(now, "/wp-login.php", 404, "curl/8.0.1", 5));
        all.add("这不是 JSON");
        all.add("{\"method\":\"GET\",\"path\":\"/x\"}");   // 缺 ts
        all.add("{\"ts\":\"不是时间\",\"status\":404,\"path\":\"/x\",\"ua\":\"u\"}");
        Files.write(dir.resolve("access.jsonl"), all, StandardCharsets.UTF_8);

        WebStatsService s = newService();
        try {
            s.beginBackfill(dir);
            assertTrue(s.awaitBackfill(5_000));
            WebStatsService.Status st = s.status();
            assertEquals(5L, st.parsedRecords(), "好行必须全部入账");
            assertEquals(3L, st.skippedLines(), "坏行必须计数（不静默）");
            assertEquals(5L, s.snapshot(OffsetDateTime.now(), th()).requests());
        } finally {
            s.stop();
        }
    }

    @Test
    @DisplayName("文件不存在：fileExists=false（端点据此 LOG_FILE_MISSING，而不是'0 请求'）")
    void missingFileIsReportedHonestly() throws Exception {
        Path dir = Files.createDirectory(tmp.resolve("log"));
        WebStatsService s = newService();
        try {
            s.beginBackfill(dir);
            assertTrue(s.awaitBackfill(5_000));
            WebStatsService.Status st = s.status();
            assertFalse(st.fileExists(), "文件压根不存在 → 不许说成'窗口为空'");
            assertFalse(st.fileReadable());
            assertEquals(0L, s.snapshot(OffsetDateTime.now(), th()).requests());
        } finally {
            s.stop();
        }
    }

    @Test
    @DisplayName("活动文件其实是目录：fileExists=true 但 fileReadable=false（端点据此 LOG_UNREADABLE）")
    void unreadableActiveFileIsReportedHonestly() throws Exception {
        Path dir = Files.createDirectory(tmp.resolve("log"));
        Files.createDirectory(dir.resolve("access.jsonl"));
        WebStatsService s = newService();
        try {
            s.beginBackfill(dir);
            assertTrue(s.awaitBackfill(5_000));
            WebStatsService.Status st = s.status();
            assertTrue(st.fileExists());
            assertFalse(st.fileReadable(), "打开就失败 → 必须是'读不出来'，不是'没有请求'");
            assertFalse(st.lastError().isEmpty(), "读失败必须留下错误痕迹（内部用）");
        } finally {
            s.stop();
        }
    }

    @Test
    @DisplayName("回填与实时计数不重叠：启动那一刻之后追加的行只算一次")
    void backfillAndLiveTapDoNotDoubleCount() throws Exception {
        OffsetDateTime now = OffsetDateTime.now();
        Path dir = Files.createDirectory(tmp.resolve("log"));
        Path active = dir.resolve("access.jsonl");
        Files.write(active, lines(now, "/.env", 404, "curl/8.0.1", 3), StandardCharsets.UTF_8);

        WebStatsService s = newService();
        try {
            s.beginBackfill(dir);                      // 记下"读到哪一位"
            String live = WebStatsFixtures.accessLine(now.plusSeconds(1), "GET", "/.env", 404, "curl/8.0.1");
            Files.writeString(active, live + "\n", StandardCharsets.UTF_8, StandardOpenOption.APPEND);
            assertTrue(s.acceptLine(live), "写线程的 tap 会把这一行算一次");

            assertTrue(s.awaitBackfill(5_000));
            assertEquals(4L, s.snapshot(OffsetDateTime.now(), th()).requests(),
                    "3 行回填 + 1 行实时 = 4；多一行就说明边界重叠了（这种错不会报错）");
        } finally {
            s.stop();
        }
    }

    @Test
    @DisplayName("写线程接线：落盘的行实时进聚合器；文件被删后写线程重建文件（自愈）")
    void writerFeedsAggregatorAndHealsDeletedFile() throws Exception {
        OffsetDateTime now = OffsetDateTime.now();
        Path dir = Files.createDirectory(tmp.resolve("log"));
        WebStatsService s = newService();
        AccessLogWriter w = new AccessLogWriter(dir, 7, 1024 * 1024, s::acceptLine);
        try {
            s.beginBackfill(dir);
            w.start();
            String l1 = WebStatsFixtures.accessLine(now, "GET", "/.env", 404, "curl/8.0.1");
            String l2 = WebStatsFixtures.accessLine(now, "GET", "/wp-login.php", 404, "curl/8.0.1");
            w.offer(l1);
            w.offer(l2);
            w.drain();
            assertEquals(2L, s.snapshot(OffsetDateTime.now(), th()).requests(),
                    "聚合必须发生在写线程上（写入即计数）");

            Path active = dir.resolve("access.jsonl");
            boolean deleted;
            try {
                deleted = Files.deleteIfExists(active);
            } catch (IOException e) {
                deleted = false;   // Windows：被打开的文件不允许删除
            }
            if (deleted) {
                // 自愈是"定期检查"（每 32 行或 1 秒一次 stat），所以这里轮询等它发生
                String l3 = WebStatsFixtures.accessLine(now, "GET", "/.git/config", 404, "curl/8.0.1");
                long deadline = System.currentTimeMillis() + 6_000;
                boolean recreated = false;
                while (System.currentTimeMillis() < deadline) {
                    w.offer(l3);
                    w.drain();
                    if (Files.exists(active)) {
                        recreated = true;
                        break;
                    }
                    Thread.sleep(100L);
                }
                assertTrue(recreated, "文件被删后写线程必须自己重建（自愈）——"
                        + "否则 Linux 上会静默写进已 unlink 的 inode，检测链路全瞎且不报错");
                assertTrue(s.snapshot(OffsetDateTime.now(), th()).requests() >= 3L,
                        "自愈期间观测到的行也要照常计数");
            }
        } finally {
            w.close();
            s.stop();
        }
    }

    @Test
    @DisplayName("文件状态探测：一次缺失不改结论（躲开轮转的 rename→create），恢复后自愈")
    void probeDebouncesAndHeals() throws Exception {
        OffsetDateTime now = OffsetDateTime.now();
        Path dir = Files.createDirectory(tmp.resolve("log"));
        Path active = dir.resolve("access.jsonl");
        Files.write(active, lines(now, "/.env", 404, "curl/8.0.1", 3), StandardCharsets.UTF_8);

        WebStatsService s = newService();
        try {
            s.beginBackfill(dir);
            assertTrue(s.awaitBackfill(5_000));
            assertTrue(s.status().fileExists());

            Files.delete(active);
            s.probeOnce();
            assertTrue(s.status().fileExists(), "轮转的 rename→create 只有毫秒级：一次缺失不许改结论");
            s.probeOnce();
            assertFalse(s.status().fileExists(), "连续两次缺失 → 如实报缺失");
            assertFalse(s.status().fileReadable());

            // 文件回来（写线程会重建）：状态自愈 + 可读
            Files.write(active, lines(now, "/.env", 404, "curl/8.0.1", 1), StandardCharsets.UTF_8);
            s.probeOnce();
            assertTrue(s.status().fileExists());
            assertTrue(s.status().fileReadable(), "恢复后必须立刻可读（否则端点会一直说 LOG_UNREADABLE）");
            s.awaitBackfill(3_000);
        } finally {
            s.stop();
        }
    }

    @Test
    @DisplayName("关闭开关：不启动、不计数、快照为空（端点会如实返回 WEBSTATS_DISABLED）")
    void disabledServiceStaysEmpty() throws Exception {
        Path dir = Files.createDirectory(tmp.resolve("log"));
        Files.write(dir.resolve("access.jsonl"), lines(OffsetDateTime.now(), "/.env", 404, "u", 5),
                StandardCharsets.UTF_8);
        WebStatsService s = new WebStatsService();
        ReflectionTestUtils.setField(s, "enabled", false);
        ReflectionTestUtils.setField(s, "accessLogEnabled", true);
        try {
            s.beginBackfill(dir);
            assertFalse(s.enabled());
            assertFalse(s.acceptLine(WebStatsFixtures.accessLine(OffsetDateTime.now(), "GET", "/.env", 404, "u")),
                    "关掉后 tap 不许再计");
            assertEquals(0L, s.snapshot(OffsetDateTime.now(), th()).requests());
            assertFalse(s.status().backfillDone(), "没启用就没有'回填完成'这回事");
        } finally {
            s.stop();
        }
    }

    @Test
    @DisplayName("访问日志关掉时：聚合器不启动（端点据此 LOG_DISABLED，而不是'没有请求'）")
    void accessLogDisabledIsDistinctState() throws Exception {
        Path dir = Files.createDirectory(tmp.resolve("log"));
        WebStatsService s = new WebStatsService();
        ReflectionTestUtils.setField(s, "enabled", true);
        ReflectionTestUtils.setField(s, "accessLogEnabled", false);
        try {
            s.beginBackfill(dir);
            WebStatsService.Status st = s.status();
            assertTrue(st.enabled());
            assertFalse(st.accessLogEnabled(), "这一点必须能单独看出来");
            assertFalse(st.fileExists());
        } finally {
            s.stop();
        }
    }
}

package org.example.accesslog;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.accesslog.WebStatsAggregator.CategoryCount;
import org.example.accesslog.WebStatsAggregator.HourStat;
import org.example.accesslog.WebStatsAggregator.Snapshot;
import org.example.accesslog.WebStatsAggregator.UaCount;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 内存聚合器（{@link WebStatsAggregator}）的口径测试。
 *
 * <h3>钉住的东西 = 站主拍板的七条口径里"能在纯函数上验证"的那些</h3>
 * <ol>
 *   <li>路径归类（含 {@code /wp-login.php}、{@code /.env}、{@code /.git/config}、
 *       {@code /phpmyadmin}、{@code /etc/passwd} 形态）与"兜底类别";</li>
 *   <li>入榜门槛 ≥5（低于门槛的<b>只进总量</b>，不进榜）；</li>
 *   <li>24h / 7 天 / 7×24 热力桶的边界；</li>
 *   <li><b>固定内存上限</b>：攻击者刷 UA 也刷不出增长；</li>
 *   <li>确定性排序（ETag/304 的前提）；</li>
 *   <li>UA 清洗：截断 60 字符、控制字符替换、IP 形态替换成 {@code [ip]}。</li>
 * </ol>
 */
class WebStatsAggregatorTest {

    private static final ZoneId ZONE = ZoneId.of("+08:00");
    private static final OffsetDateTime NOW = OffsetDateTime.parse("2026-10-14T12:00:00+08:00");
    private static final Clock CLOCK = Clock.fixed(NOW.toInstant(), ZONE);

    private static WebStatsAggregator aggregator() {
        return new WebStatsAggregator(CLOCK, ZONE, 60,
                WebStatsAggregator.UA_SLOTS_PER_BUCKET, WebStatsAggregator.GLOBAL_UA_SLOTS);
    }

    private static Snapshot snap(WebStatsAggregator a) {
        return a.snapshot(NOW, WebStatsAggregator.Thresholds.defaults());
    }

    // ==================== ① 路径归类 ====================

    @Test
    @DisplayName("路径归类：已知扫描形态各归各类，认不出来的走状态码兜底（永不返回 null）")
    void classifiesPaths() {
        assertEquals(WebStatsCategory.WP_LOGIN, WebStatsCategory.classify("/wp-login.php", 404));
        assertEquals(WebStatsCategory.WP_LOGIN, WebStatsCategory.classify("/wp-admin/setup-config.php", 404));
        assertEquals(WebStatsCategory.WP_LOGIN, WebStatsCategory.classify("/xmlrpc.php", 405));
        // 大小写不敏感（攻击者会换大小写绕正则）
        assertEquals(WebStatsCategory.WP_LOGIN, WebStatsCategory.classify("/WP-Login.PHP", 404));

        assertEquals(WebStatsCategory.DOTENV, WebStatsCategory.classify("/.env", 404));
        assertEquals(WebStatsCategory.DOTENV, WebStatsCategory.classify("/.env.bak", 404));

        assertEquals(WebStatsCategory.DOTGIT, WebStatsCategory.classify("/.git/config", 404));
        assertEquals(WebStatsCategory.DOTGIT, WebStatsCategory.classify("/.git/HEAD", 404));

        assertEquals(WebStatsCategory.PHPMYADMIN, WebStatsCategory.classify("/phpmyadmin/index.php", 404));
        assertEquals(WebStatsCategory.PHPMYADMIN, WebStatsCategory.classify("/pma/", 404));
        assertEquals(WebStatsCategory.PHPMYADMIN, WebStatsCategory.classify("/adminer.php", 404));

        assertEquals(WebStatsCategory.TRAVERSAL, WebStatsCategory.classify("/etc/passwd", 404));
        assertEquals(WebStatsCategory.TRAVERSAL, WebStatsCategory.classify("/../../etc/passwd", 400));
        assertEquals(WebStatsCategory.TRAVERSAL, WebStatsCategory.classify("/%2e%2e%2fetc/passwd", 404));
        assertEquals(WebStatsCategory.TRAVERSAL, WebStatsCategory.classify("/windows/system32/cmd.exe", 404));

        assertEquals(WebStatsCategory.ADMIN_PANEL, WebStatsCategory.classify("/administrator/", 404));
        assertEquals(WebStatsCategory.ADMIN_PANEL, WebStatsCategory.classify("/manager/html", 401));
        assertEquals(WebStatsCategory.ADMIN_PANEL, WebStatsCategory.classify("/phpinfo.php", 404));

        // 兜底三条：认不出来的按状态码走，绝不留"空类别"
        assertEquals(WebStatsCategory.OTHER_404, WebStatsCategory.classify("/nonsense-8f2a", 404));
        assertEquals(WebStatsCategory.OTHER_4XX, WebStatsCategory.classify("/nonsense-8f2a", 403));
        assertEquals(WebStatsCategory.OTHER, WebStatsCategory.classify("/api/public/geo", 200));
        assertEquals(WebStatsCategory.OTHER, WebStatsCategory.classify(null, 200));
        assertEquals(WebStatsCategory.OTHER, WebStatsCategory.classify("", 503));
    }

    @Test
    @DisplayName("类别枚举是公开契约：9 个、名字固定、顺序固定（只许新增不许改名）")
    void categoryEnumIsStable() {
        assertEquals(List.of("traversal", "dotgit", "dotenv", "wp-login", "phpmyadmin",
                        "admin-panel", "other-404", "other-4xx", "other"),
                WebStatsCategory.ALL.stream().map(WebStatsCategory::wireName).toList());
    }

    // ==================== ② 门槛 + ③ 窗口 ====================

    @Test
    @DisplayName("门槛 ≥5：4 次不上榜、5 次上榜，低于门槛的只计入总量")
    void thresholdFiltersTopListsButNotTotals() {
        WebStatsAggregator a = aggregator();
        for (int i = 0; i < 4; i++) {
            a.record(NOW, 404, "/wp-login.php", "curl/8.0.1");
        }
        for (int i = 0; i < 5; i++) {
            a.record(NOW, 404, "/.env", "curl/8.0.1");
        }
        a.record(NOW, 200, "/api/public/geo", "Mozilla/5.0 (X11)");
        a.record(NOW, 500, "/boom", "Go-http-client/1.1");
        a.record(NOW, 302, "/redirect", "Go-http-client/1.1");

        Snapshot s = snap(a);
        assertEquals(12L, s.requests(), "总数必须包含所有行（含未上榜的类别）");
        assertEquals(1L, s.statusClass().c2xx());
        assertEquals(1L, s.statusClass().c3xx());
        assertEquals(9L, s.statusClass().c4xx(), "4 个 wp-login + 5 个 dotenv");
        assertEquals(1L, s.statusClass().c5xx());
        assertEquals(12L, s.statusClass().total(), "五类之和必须等于总数（不许漏一类）");

        assertEquals(List.of("dotenv"), s.topCategories().stream().map(CategoryCount::category).toList(),
                "wp-login 只有 4 次（<5）不许上榜");
        assertEquals(5L, s.topCategories().get(0).count());

        assertEquals(List.of("curl/8.0.1"), s.topUas().stream().map(UaCount::ua).toList(),
                "UA 同样卡 ≥5：Go-http-client 2 次、Mozilla 1 次都不许上榜");
    }

    @Test
    @DisplayName("24h 窗口：按 5 分钟桶对齐（最老 ≤5 分钟出窗）；未来时间不计入；7 天外直接丢并计数")
    void windowAndBuckets() {
        WebStatsAggregator a = aggregator();
        a.record(NOW, 404, "/now", "ua-a");                              // 计入
        a.record(NOW.minusSeconds(86_100), 404, "/old-in", "ua-a");       // 桶起点 = NOW-86400+300 → 计入
        a.record(NOW.minusSeconds(86_200), 404, "/old-out", "ua-a");      // 桶起点 = NOW-86400 → 出窗
        a.record(NOW.plusSeconds(600), 404, "/future", "ua-a");           // 未来（时钟漂移）→ 不进窗口
        a.record(NOW.minusDays(8), 404, "/ancient", "ua-a");              // 7 天窗口外 → 丢弃

        Snapshot s = snap(a);
        assertEquals(2L, s.requests(), "只有 NOW 与 NOW-86100 在窗口内");
        assertEquals(1L, s.droppedOutOfWindow(), "8 天前那一条必须如实计数（不是静默丢弃）");
    }

    @Test
    @DisplayName("5 分钟桶边界：跨桶不会互相覆盖（288 个桶不产生别名）")
    void bucketBoundariesDoNotAlias() {
        WebStatsAggregator a = aggregator();
        // 同一个 5 分钟桶的边界两侧
        a.record(NOW.minusSeconds(1), 404, "/a", "ua-a");
        a.record(NOW, 404, "/a", "ua-a");
        a.record(NOW.plusSeconds(299), 404, "/a", "ua-a");
        a.record(NOW.plusSeconds(300), 404, "/a", "ua-a");   // 下一个桶
        // 恰好 24 小时前的桶：与"现在这个桶"下标相同，绝不能把现在这个桶覆盖掉
        WebStatsAggregator b = aggregator();
        b.record(NOW, 404, "/now", "ua-a");
        b.record(NOW.minusSeconds(86_400), 404, "/exactly-24h", "ua-a");
        Snapshot sb = snap(b);
        assertEquals(1L, sb.requests(), "恰好 24h 前的桶在窗口外；它不许覆盖当前桶（否则会丢数据）");
        assertEquals(1L, sb.staleSlotSkips(), "撞槽的旧记录必须计数（不是静默丢弃）");
        assertEquals(0L, snap(a).droppedOutOfWindow());
    }

    @Test
    @DisplayName("7 天按天 + 7×24 热力桶：跨天/跨小时各归各格，8 天前不进榜")
    void byDayAndHeatmap() {
        WebStatsAggregator a = aggregator();
        a.record(OffsetDateTime.parse("2026-10-14T00:05:00+08:00"), 200, "/x", "ua-a");
        a.record(OffsetDateTime.parse("2026-10-14T00:55:00+08:00"), 404, "/x", "ua-a");
        a.record(OffsetDateTime.parse("2026-10-14T23:59:59+08:00"), 500, "/x", "ua-a");
        a.record(OffsetDateTime.parse("2026-10-13T23:59:00+08:00"), 200, "/x", "ua-a");
        a.record(OffsetDateTime.parse("2026-10-08T10:00:00+08:00"), 200, "/x", "ua-a"); // 第 7 天（含）
        a.record(OffsetDateTime.parse("2026-10-07T10:00:00+08:00"), 200, "/x", "ua-a"); // 第 8 天 → 出窗

        Snapshot s = snap(a);
        // 注意两个口径不同：totals 是 24h（288 个 5 分钟桶），byDay/heatmap 是 7 天 —— 这一点写在 note 里
        assertEquals(2L, s.requests(), "24h 窗口内只有 10-14 的 00:05 与 00:55（23:59 还没到）");
        assertEquals(List.of("2026-10-08", "2026-10-13", "2026-10-14"),
                s.byDay().stream().map(WebStatsAggregator.DayStat::date).toList(),
                "缺天就缺天：只给日志里真实有请求的天");
        assertEquals(5L, s.byDay().stream().mapToLong(WebStatsAggregator.DayStat::requests).sum(),
                "10-07 那条在第 8 天，必须出 7 天窗口");
        assertEquals(1L, s.droppedOutOfWindow());

        assertEquals(List.of("2026-10-08T10", "2026-10-13T23", "2026-10-14T0", "2026-10-14T23"),
                s.heatmap().stream().map(h -> h.date() + "T" + h.hour()).toList(),
                "热力图按 (日期, 整点) 升序，只列非零格");
        assertEquals(2L, s.heatmap().stream().filter(h -> h.date().equals("2026-10-14") && h.hour() == 0)
                .findFirst().orElseThrow().requests());
    }

    // ==================== ④ 内存上限 ====================

    @Test
    @DisplayName("内存上限：刷 2000 个不同 UA 也只占 288 个桶 × 每桶 24 槽（刷不出内存增长）")
    void memoryIsBoundedUnderUaFlood() {
        WebStatsAggregator a = aggregator();
        for (int i = 0; i < 2000; i++) {
            a.record(NOW, 404, "/scan-" + i, "attacker-ua-" + i);
        }
        assertEquals(2000L, snap(a).requests());
        assertTrue(a.occupiedUaSlots() <= WebStatsAggregator.BUCKET_COUNT * WebStatsAggregator.UA_SLOTS_PER_BUCKET,
                "占用的 UA 槽数必须 ≤ 288×24=6912（实测 " + a.occupiedUaSlots() + "）");
        assertTrue(a.occupiedUaSlots() <= WebStatsAggregator.UA_SLOTS_PER_BUCKET,
                "同一个桶里最多命名 24 个 UA");
        Snapshot s = snap(a);
        assertTrue(s.uaOverflowRows() > 0, "被挤掉的 UA 行数必须如实计数（不是静默丢失）");
        assertTrue(s.topUas().size() <= WebStatsAggregator.Thresholds.defaults().topUas());
    }

    @Test
    @DisplayName("内存上限：按天条目最多 7+2 天（脏时间戳也刷不动）")
    void dayEntriesAreBounded() {
        WebStatsAggregator a = aggregator();
        for (int i = 0; i < 40; i++) {
            a.record(NOW.minusDays(i % 7), 404, "/x", "ua-a");
            a.record(NOW.plusDays(i % 3), 404, "/y", "ua-a");
        }
        assertTrue(a.dayEntries() <= WebStatsAggregator.DAYS + 2, "按天条目必须封顶（实测 " + a.dayEntries() + "）");
    }

    // ==================== ⑤ 确定性排序（ETag 前提） ====================

    @Test
    @DisplayName("确定性：同样输入 → 逐字节相同的排序结果；同计数按名字升序")
    void orderingIsDeterministic() throws Exception {
        WebStatsAggregator a = aggregator();
        // dotenv / wp-login / traversal 各 5 次（计数相同 → 必须按类别名升序）
        List<String> paths = List.of("/.env", "/wp-login.php", "/../../etc/passwd");
        for (String p : paths) {
            for (int i = 0; i < 5; i++) {
                a.record(NOW, 404, p, "ua-a");
            }
        }
        Snapshot s1 = snap(a);
        Snapshot s2 = snap(a);
        assertEquals(List.of("dotenv", "traversal", "wp-login"),
                s1.topCategories().stream().map(CategoryCount::category).toList(),
                "计数相同 → 按类别名升序（否则 ETag 每次都不一样，边缘缓存等于没有）");

        ObjectMapper mapper = new ObjectMapper();
        assertEquals(mapper.writeValueAsString(s1.topCategories()), mapper.writeValueAsString(s2.topCategories()));
        assertEquals(mapper.writeValueAsString(s1.heatmap()), mapper.writeValueAsString(s2.heatmap()));
    }

    @Test
    @DisplayName("确定性：热力/按天在乱序写入下也按时间升序输出")
    void timeSeriesSortedAscending() {
        WebStatsAggregator a = aggregator();
        a.record(OffsetDateTime.parse("2026-10-14T20:00:00+08:00"), 200, "/x", "ua-a");
        a.record(OffsetDateTime.parse("2026-10-12T03:00:00+08:00"), 200, "/x", "ua-a");
        a.record(OffsetDateTime.parse("2026-10-14T01:00:00+08:00"), 200, "/x", "ua-a");
        Snapshot s = snap(a);
        assertEquals(List.of("2026-10-12", "2026-10-14"),
                s.byDay().stream().map(WebStatsAggregator.DayStat::date).toList());
        List<HourStat> h = s.heatmap();
        assertEquals("2026-10-12T3", h.get(0).date() + "T" + h.get(0).hour());
        assertEquals("2026-10-14T1", h.get(1).date() + "T" + h.get(1).hour());
        assertEquals("2026-10-14T20", h.get(2).date() + "T" + h.get(2).hour());
    }

    // ==================== ⑥ UA 清洗 ====================

    @Test
    @DisplayName("UA：截断到 60 字符、控制字符换空格、IP 形态换成 [ip]（连 IPv6 也不放过）")
    void uaIsSanitizedAndIpScrubbed() {
        WebStatsAggregator a = aggregator();
        assertEquals(60, a.sanitizeUa("x".repeat(300)).length());
        assertEquals("evil agent x", a.sanitizeUa("evil\nagent\tx"));
        assertEquals("[ip]-scanner", a.sanitizeUa("1.2.3.4-scanner"));
        String ipv6 = a.sanitizeUa("2001:db8::1/::ffff:1.2.3.4");
        assertTrue(ipv6.contains("[ip]"), "IPv6/IPv4 形态都要被替换：" + ipv6);
        assertFalse(ipv6.contains(":"), "替换后不该再有冒号形态：" + ipv6);
        assertFalse(ipv6.contains("db8"), "替换后不该残留地址片段：" + ipv6);
        // 真实 UA（含版本号形态）不许被误伤
        String realUa = "Mozilla/5.0 (Windows NT; Windows NT 10.0; zh-CN) WindowsPowerShell/5.1.26100.9444";
        assertEquals(realUa.substring(0, 60), a.sanitizeUa(realUa));
        assertEquals("", a.sanitizeUa(null));
        assertEquals("", a.sanitizeUa("   "));
    }

    @Test
    @DisplayName("空窗口如实为空（不是伪装成有数据）")
    void emptySnapshotIsHonest() {
        Snapshot s = snap(aggregator());
        assertEquals(0L, s.requests());
        assertEquals(0L, s.statusClass().total());
        assertTrue(s.topCategories().isEmpty());
        assertTrue(s.topUas().isEmpty());
        assertTrue(s.byDay().isEmpty());
        assertTrue(s.heatmap().isEmpty());
        assertEquals(0L, Snapshot.empty().requests());
        assertEquals(Snapshot.empty().statusClass().total(), s.statusClass().total());
    }
}

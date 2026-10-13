package org.example.geoip;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link GeoIpService} 的状态机测试：<b>"没装好"与"没有攻击"必须能被区分开</b>。
 *
 * <h3>四种状态各自对应一句人话</h3>
 * <ul>
 *   <li>{@code GEO_DB_MISSING}：库文件不在（最常见：还没跑月度更新脚本 / 卷没挂上）</li>
 *   <li>{@code GEO_DB_UNUSABLE}：文件在但读不了（不是 gzip / 截断 / 坏行超阈值）</li>
 *   <li>{@code GEO_DB_LOADING}：正在后台装（真库实测 12 秒）</li>
 *   <li>{@code GEO_DISABLED}：站主关掉了这个能力</li>
 * </ul>
 * 这四种如果都退化成"返回空分布"，页面会显示"24 小时没有攻击" ——
 * 那是最糟的一种谎：把"我们没装好"说成"天下太平"。
 */
class GeoIpServiceTest {

    @TempDir
    Path tmp;

    private static GeoIpService service(String city, String asn, boolean enabled, boolean ipv6) {
        GeoIpService s = new GeoIpService();
        ReflectionTestUtils.setField(s, "cityDb", city);
        ReflectionTestUtils.setField(s, "asnDb", asn);
        ReflectionTestUtils.setField(s, "enabled", enabled);
        ReflectionTestUtils.setField(s, "ipv6Enabled", ipv6);
        return s;
    }

    private Path cityFixture() throws IOException {
        return GeoTestFixtures.writeGz(tmp, "dbip-city-lite-2026-10.csv.gz", """
                1.0.0.0,1.0.0.255,OC,AU,Queensland,"South Brisbane",-27.47,153.01
                1.0.1.0,1.0.1.255,AS,CN,Zhejiang,Hangzhou,30.29,120.16
                2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,AS,CN,Zhejiang,Hangzhou,30.29,120.16
                """);
    }

    @Test
    @DisplayName("库缺失：MISSING + GEO_DB_MISSING，且不装载、不返回空分布")
    void missingDatabaseDegradesHonestly() {
        GeoIpService s = service(tmp.resolve("nope").toString(), null, true, true);
        s.init();
        assertEquals(GeoIpService.State.MISSING, s.state());
        assertEquals("GEO_DB_MISSING", s.reason());
        assertFalse(s.ready());
        assertEquals(-1L, s.loadMillis(), "没装载就不该编造耗时");
        assertEquals(0L, s.heapBytesEstimate());
        assertNull(s.sourceLabel());
        assertFalse(s.lookup("1.0.0.1").isKnown(), "库不可用时查询必须是未知，不能抛异常");
        assertTrue(s.summary().contains("geo=missing"), s.summary());
    }

    @Test
    @DisplayName("配置为空（默认部署）：同样按 MISSING 处理，不静默变成'没有攻击'")
    void blankConfigIsMissing() {
        GeoIpService s = service("", "", true, true);
        s.init();
        assertEquals(GeoIpService.State.MISSING, s.state());
        assertEquals("GEO_DB_MISSING", s.reason());
    }

    @Test
    @DisplayName("显式关闭：DISABLED + GEO_DISABLED（与'库缺失'区分开，运维知道该改哪个开关）")
    void disabledIsDistinctFromMissing() {
        GeoIpService s = service(tmp.resolve("nope").toString(), null, false, true);
        s.init();
        assertEquals(GeoIpService.State.DISABLED, s.state());
        assertEquals("GEO_DISABLED", s.reason());
        assertFalse(s.ready());
    }

    @Test
    @DisplayName("库损坏：UNUSABLE + GEO_DB_UNUSABLE（文件在但读不了）")
    void corruptDatabaseIsUnusable() throws IOException {
        Path fake = tmp.resolve("dbip-city-lite-2026-10.csv.gz");
        Files.writeString(fake, "这不是 gzip\n", StandardCharsets.UTF_8);
        GeoIpService s = service(fake.toString(), null, true, true);
        s.init();
        s.loadBlocking();                       // 同步走一遍（init 走的是同一个方法的后台线程）
        assertEquals(GeoIpService.State.UNUSABLE, s.state());
        assertEquals("GEO_DB_UNUSABLE", s.reason());
        assertFalse(s.ready());
        assertNotNull(s.detail(), "必须留下可读的失败细节，否则运维只能猜");
        assertTrue(s.detail().contains(":"), s.detail());
        assertTrue(s.summary().contains("geo=unusable"), s.summary());
    }

    @Test
    @DisplayName("正常：OK + 查询可用 + 版本标签可读")
    void loadsAndServes() throws IOException {
        GeoIpService s = service(cityFixture().toString(), null, true, true);
        s.init();
        s.loadBlocking();
        assertEquals(GeoIpService.State.OK, s.state());
        assertEquals("OK", s.reason());
        assertTrue(s.ready());
        assertTrue(s.loadMillis() >= 0);
        assertTrue(s.heapBytesEstimate() > 0);
        assertEquals("DB-IP Lite City 2026-10", s.sourceLabel(), "没有 ASN 库时标签里不该出现 ASN");
        assertEquals("CN|Zhejiang|Hangzhou|-|-", s.describe("1.0.1.1"),
                "没有 ASN 库时 ASN 段写 '-'，形状保持 5 段");
        assertNull(s.describe("9.9.9.9"), "库里没有的地址 srcGeo 为 null");
        assertTrue(s.summary().contains("geo=ok"));
    }

    @Test
    @DisplayName("init() 走后台线程：接口不该被十几秒的装载堵死；装完自动可用")
    void initLoadsAsynchronously() throws IOException {
        GeoIpService s = service(cityFixture().toString(), null, true, true);
        s.init();
        long deadline = System.currentTimeMillis() + 15_000L;
        while (!s.ready() && System.currentTimeMillis() < deadline) {
            assertFalse(s.state() == GeoIpService.State.UNUSABLE, "装载不该失败：" + s.detail());
            try {
                Thread.sleep(20);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        assertTrue(s.ready(), "15 秒内应该装完（夹具只有 3 行）");
    }

    @Test
    @DisplayName("目录形态：自动取目录里最新月份的那一份（YYYY-MM 字典序即时序）")
    void picksNewestVersionInDirectory() throws IOException {
        GeoTestFixtures.writeGz(tmp, "dbip-city-lite-2026-04.csv.gz", """
                1.0.0.0,1.0.0.255,OC,AU,Queensland,South Brisbane,-27.47,153.01
                """);
        GeoTestFixtures.writeGz(tmp, "dbip-city-lite-2026-10.csv.gz", """
                1.0.0.0,1.0.0.255,AS,CN,Zhejiang,Hangzhou,30.29,120.16
                """);
        GeoIpService s = service(tmp.toString(), null, true, true);
        s.init();
        s.loadBlocking();
        assertTrue(s.ready());
        assertEquals("DB-IP Lite City 2026-10", s.sourceLabel(), "必须选最新月份");
        assertEquals("CN", s.lookup("1.0.0.1").getCountry(), "用的必须是新库");
    }

    @Test
    @DisplayName("稳定符号链接形态（线上部署面）：版本号必须从链接指向的真实文件名里解析出来")
    void versionIsResolvedThroughStableSymlink() throws IOException {
        Path real = GeoTestFixtures.writeGz(tmp, "dbip-city-lite-2026-10.csv.gz", """
                1.0.0.0,1.0.0.255,AS,CN,Zhejiang,Hangzhou,30.29,120.16
                """);
        Path link = tmp.resolve("dbip-city-lite.csv.gz");   // 线上就是这个形态：名字里没有月份
        try {
            Files.createSymbolicLink(link, real.getFileName());
        } catch (IOException | UnsupportedOperationException e) {
            org.junit.jupiter.api.Assumptions.assumeTrue(false, "本机不支持创建符号链接：" + e.getMessage());
            return;
        }
        GeoIpService s = service(link.toString(), null, true, true);
        s.init();
        s.loadBlocking();
        assertTrue(s.ready(), s.summary());
        assertEquals("DB-IP Lite City 2026-10", s.sourceLabel(),
                "链接名里没有月份，必须解析到真实文件名 —— 否则线上会显示'未知版本'");
        assertEquals("CN", s.lookup("1.0.0.1").getCountry());
        assertFalse(s.summary().contains("未知版本"), s.summary());
    }

    @Test
    @DisplayName("库就绪但查询被喂脏值时：返回未知而不是抛（它跑在告警取数路径上）")
    void lookupNeverThrows() throws IOException {
        GeoIpService s = service(cityFixture().toString(), null, true, true);
        s.init();
        s.loadBlocking();
        assertFalse(s.lookup(null).isKnown());
        assertFalse(s.lookup("").isKnown());
        assertFalse(s.lookup("垃圾").isKnown());
    }
}

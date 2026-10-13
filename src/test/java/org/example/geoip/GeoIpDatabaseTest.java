package org.example.geoip;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link GeoIpDatabase} 的装载与查询口径测试（合成夹具：CI 里不可能放 300MB 真库）。
 *
 * <h3>为什么夹具要造两份（连续 / 有缺口）</h3>
 * 真库实测：City 库的 IPv4 区间<b>完全连续</b>（3,620,434 行、0 缺口），
 * 于是终点可以由"下一行起点减一"推出来（省 14MB）；ASN 库<b>不连续</b>（80,679 个缺口），
 * 必须每个区间各存一份终点。这两条路径出错的后果完全不同：
 * 连续表算错终点会<b>多命中一段地址</b>（把隔壁国家画进来），缺口表算错会把"本来没有归属的地址"
 * 硬塞给上一个区间。所以两份夹具都要有，边界都要在<b>区间的第一个/最后一个地址</b>上断言。
 *
 * <h3>为什么必须测"坏库"</h3>
 * 库文件坏了（不是 gzip / 被截断 / 坏行超阈值 / 区间乱序）时，正确行为是
 * <b>整库判为不可用</b>（上层报 {@code GEO_DB_UNUSABLE}），而不是"跳过坏了的那部分继续用"
 * —— 后者会画出一张"某些国家凭空消失"的地图，而没人能看出它是错的。
 */
class GeoIpDatabaseTest {

    @TempDir
    Path tmp;

    /** 城市库：v4 与 v6 都【完全连续】（走"终点由下一行推导"的路径） */
    private Path contiguousCity() throws IOException {
        return GeoTestFixtures.writeGz(tmp, "dbip-city-lite-2026-10.csv.gz", """
                0.0.0.0,0.255.255.255,ZZ,ZZ,,,0,0
                1.0.0.0,1.0.0.255,OC,AU,Queensland,"South Brisbane",-27.47,153.01
                1.0.1.0,1.0.3.255,AS,CN,Fujian,Wenquan,26.09,119.29
                1.0.4.0,255.255.255.255,AS,CN,Zhejiang,Hangzhou,30.29,120.16
                ::,1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,ZZ,ZZ,,,0,0
                2000::,3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,AS,CN,Zhejiang,Hangzhou,30.29,120.16
                """);
    }

    /** 城市库：v4 与 v6 都【有缺口】（走"每个区间各存终点"的路径） */
    private Path sparseCity() throws IOException {
        return GeoTestFixtures.writeGz(tmp, "dbip-city-lite-2026-09.csv.gz", """
                1.0.0.0,1.0.0.255,OC,AU,Queensland,"South Brisbane",-27.47,153.01
                1.0.2.0,1.0.3.255,AS,CN,Fujian,Wenquan,26.09,119.29
                1.0.4.0,1.0.7.255,AS,CN,Zhejiang,Hangzhou,30.29,120.16
                2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,AS,CN,Zhejiang,Hangzhou,30.29,120.16
                2400::,2400:ffff:ffff:ffff:ffff:ffff:ffff:ffff,AS,CN,Beijing,Beijing,39.9,116.4
                """);
    }

    /** ASN 库：不连续（与真库一致），且机构名里带逗号（必须被引号正确处理） */
    private Path asnFixture() throws IOException {
        return GeoTestFixtures.writeGz(tmp, "dbip-asn-lite-2026-10.csv.gz", """
                1.0.0.0,1.0.0.255,13335,"Cloudflare, Inc."
                1.0.4.0,1.0.7.255,4134,"CHINANET-BACKBONE"
                2000::,3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,37963,"Hangzhou Alibaba Advertising Co.,Ltd."
                """);
    }

    private GeoIpDatabase load(String cityName, boolean ipv6) throws IOException {
        Path city = cityName.equals("contiguous") ? contiguousCity() : sparseCity();
        return GeoIpDatabase.load(city, asnFixture(), ipv6);
    }

    @Test
    @DisplayName("连续区间：终点由下一行起点推导，首/末地址都命中同一个记录")
    void contiguousRangesMatchFirstAndLastAddress() throws IOException {
        GeoIpDatabase db = load("contiguous", true);
        assertEquals("AU", db.lookup("1.0.0.0").getCountry());
        assertEquals("AU", db.lookup("1.0.0.255").getCountry(), "区间最后一个地址必须仍属本区间");
        assertEquals("CN", db.lookup("1.0.1.0").getCountry(), "下一个区间的第一个地址必须换记录");
        assertEquals("Fujian", db.lookup("1.0.3.255").getProvince());
        assertEquals("Zhejiang", db.lookup("1.0.4.0").getProvince());
        assertEquals("Zhejiang", db.lookup("255.255.255.255").getProvince(), "最后一个地址必须仍命中最后一行");
        assertFalse(db.lookup("0.255.255.255").hasCountry(), "ZZ 段必须判为未定位（hasCountry=false）");
    }

    @Test
    @DisplayName("有缺口：缺口内的地址必须是未知，不能被算进相邻区间")
    void sparseRangesDoNotBleedIntoGaps() throws IOException {
        GeoIpDatabase db = load("sparse", true);
        assertEquals("AU", db.lookup("1.0.0.255").getCountry());
        // 1.0.1.0-1.0.1.255 是缺口：不能落到 AU，也不能落到后面的 CN
        assertFalse(db.lookup("1.0.1.0").hasCountry(), "缺口里的地址必须是未知");
        assertFalse(db.lookup("1.0.1.255").hasCountry());
        assertEquals("Fujian", db.lookup("1.0.2.0").getProvince());
        assertEquals("CN", db.lookup("1.0.3.255").getCountry());
        assertEquals("CN", db.lookup("1.0.7.255").getCountry());
        assertFalse(db.lookup("1.0.8.0").hasCountry(), "缺口后的地址不得被算进上一个区间");
        assertFalse(db.lookup("223.255.255.255").hasCountry(), "夹具里没有的段必须是未知");
        assertFalse(db.lookup("0.1.2.3").hasCountry());
        // IPv6 的缺口同理
        assertEquals("Zhejiang", db.lookup("2001:db8::1").getProvince());
        assertFalse(db.lookup("2001:db9::1").hasCountry(), "IPv6 缺口里的地址必须是未知");
        assertEquals("Beijing", db.lookup("2400::1").getProvince());
    }

    @Test
    @DisplayName("IPv6：:: 压缩写法、区间首末地址、内嵌 IPv4 都要正确")
    void ipv6LookupsWork() throws IOException {
        GeoIpDatabase db = load("contiguous", true);
        assertTrue(db.ipv6Loaded());
        assertFalse(db.lookup("::").hasCountry(), ":: 在夹具里是 ZZ 段");
        assertEquals("CN", db.lookup("2000::").getCountry(), "IPv6 区间第一个地址");
        assertEquals("CN", db.lookup("2001:db8::1").getCountry());
        assertEquals("CN", db.lookup("3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").getCountry(), "IPv6 区间最后一个地址");
        assertFalse(db.lookup("4000::").hasCountry(), "超出最后一个区间必须未命中");
        assertFalse(db.lookup("1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").hasCountry(), "前一个区间的末地址属 ZZ 段");
        // ::ffff:1.2.3.4 是内嵌 IPv4 写法（合规的 IPv6 字面量，不能当成"解析失败"）
        assertNotNull(IpAddresses.parseV6("::ffff:1.2.3.4"));
    }

    @Test
    @DisplayName("关掉 IPv6：v6 一律未定位，v4 照常（省内存的开关不能顺手关掉 v4）")
    void ipv6DisabledStillServesV4() throws IOException {
        GeoIpDatabase db = load("contiguous", false);
        assertFalse(db.ipv6Loaded());
        assertFalse(db.lookup("2001:db8::1").isKnown(), "未加载 IPv6 时必须如实返回未知");
        assertEquals("CN", db.lookup("1.0.4.0").getCountry(), "关 IPv6 不能影响 IPv4");
    }

    @Test
    @DisplayName("ASN 与机构名：合并进同一次查询，机构名里的逗号不能被切断")
    void asnIsMergedAndQuotingIsHonored() throws IOException {
        GeoIpDatabase db = load("contiguous", true);
        GeoIpInfo aus = db.lookup("1.0.0.1");
        assertEquals(13335, aus.getAsn());
        assertEquals("Cloudflare, Inc.", aus.getAsnOrg(), "带引号的机构名必须完整（逗号不能被当分隔符）");
        GeoIpInfo cn = db.lookup("1.0.4.1");
        assertEquals(4134, cn.getAsn());
        assertEquals("CHINANET-BACKBONE", cn.getAsnOrg());
        assertEquals(37963, db.lookup("2000::1").getAsn());
    }

    @Test
    @DisplayName("srcGeo 的最终形状：国家|省|城市|ASN|机构，未知段写 -；完全未知时为 null")
    void srcGeoShape() throws IOException {
        GeoIpDatabase db = load("contiguous", true);
        assertEquals("CN|Zhejiang|Hangzhou|4134|CHINANET-BACKBONE", db.lookup("1.0.4.9").describe());
        assertEquals("AU|Queensland|South Brisbane|13335|Cloudflare, Inc.", db.lookup("1.0.0.9").describe());
        assertNull(db.lookup("0.1.2.3").describe(), "库里没有的地址必须返回 null，不编造 '-' 串");
        assertNull(db.lookup("not-an-ip").describe());
        assertNull(db.lookup(null).describe());
    }

    @Test
    @DisplayName("脏输入不抛异常：带端口/超范围/空串一律返回未知")
    void dirtyInputNeverThrows() throws IOException {
        GeoIpDatabase db = load("contiguous", true);
        for (String ip : new String[]{"", " ", "1.2.3", "999.1.1.1", "1.2.3.4:8080", "1.2.3.4.5",
                "2001:db8::/32", "fe80::1%eth0", ":::", "1:2:3:4:5:6:7:8:9", null}) {
            assertNotNull(db.lookup(ip), "查询结果不允许为 null（应为 UNKNOWN）");
            assertFalse(db.lookup(ip).isKnown(), "不该把脏输入当成有地理信息：" + ip);
        }
    }

    @Test
    @DisplayName("库损坏：不是 gzip / 空文件 / 列数系统性不对 → 整库抛异常（上层据此报 GEO_DB_UNUSABLE）")
    void corruptDatabaseFailsClosed() throws IOException {
        Path notGzip = tmp.resolve("dbip-city-lite-2026-10.csv.gz");
        Files.writeString(notGzip, "1.0.0.0,1.0.0.255,OC,AU,Queensland,x,0,0\n", StandardCharsets.UTF_8);
        assertThrows(IOException.class, () -> GeoIpDatabase.load(notGzip, null, true),
                "明文 CSV 冒充 gz：必须报错，不能静默当成'没有数据'");

        Path empty = GeoTestFixtures.writeGz(tmp, "empty.csv.gz", "");
        assertThrows(IOException.class, () -> GeoIpDatabase.load(empty, null, true));

        Path truncated = GeoTestFixtures.writeGz(tmp, "dbip-city-lite-2026-11.csv.gz",
                "1.0.0.0,1.0.0.255\n".repeat(50));      // 列数不够 → 坏行 100%
        assertThrows(IOException.class, () -> GeoIpDatabase.load(truncated, null, true),
                "坏行比例超阈值必须整库失败（画一半的地图比不画更糟）");

        assertThrows(IOException.class, () -> GeoIpDatabase.load(tmp.resolve("nope.csv.gz"), null, true));
    }

    @Test
    @DisplayName("区间乱序/重叠：必须被拒绝（否则二分查找会返回错误的国家，而且不报错）")
    void unsortedRangesAreRejected() throws IOException {
        Path bad = GeoTestFixtures.writeGz(tmp, "dbip-city-lite-2026-08.csv.gz", """
                1.0.4.0,1.0.7.255,AS,CN,Zhejiang,Hangzhou,30.29,120.16
                1.0.0.0,1.0.0.255,OC,AU,Queensland,South Brisbane,-27.47,153.01
                """);
        assertThrows(IOException.class, () -> GeoIpDatabase.load(bad, null, true));
    }

    @Test
    @DisplayName("持久化结构是排序区间数组（二分查找的前提）：行数/统计如实回报")
    void statsReportWhatWasLoaded() throws IOException {
        GeoIpDatabase db = load("contiguous", true);
        assertEquals(6, db.cityRangeCount(), "4 个 v4 区间 + 2 个 v6 区间");
        assertEquals(3, db.asnRangeCount());
        assertTrue(db.stats().contains("v4 4 行"), db.stats());
        assertTrue(db.stats().contains("v6 2 行"), db.stats());
        assertEquals("2026-10", db.cityVersion(), "版本必须从文件名解析（公开面要如实标注是哪一版库）");
        assertTrue(db.heapBytesEstimate() > 0);
    }
}

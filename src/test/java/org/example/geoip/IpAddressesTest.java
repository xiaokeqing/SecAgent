package org.example.geoip;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * IP 解析与地址性质分类测试（<b>零依赖</b>：只用 JDK）。
 *
 * <h3>为什么这一层值得单独测</h3>
 * 它同时承担两件事，而两件事的错都是"静默错"：
 * <ul>
 *   <li><b>解析</b>：IPv6 的 {@code ::} 压缩、内嵌 IPv4、zone id —— 写错一位不会抛异常，
 *       只会让 416 万条 IPv6 区间全部对不上（实测过：一个空串处理错误让真库坏行率 51%，
 *       整库被正确判为不可用，但如果当时没判"整库失败"，就会画出一张只含 IPv4 的假地图）；</li>
 *   <li><b>分类</b>：内网/保留/公网决定"能不能上地图"。把 {@code 10.0.0.10} 放进国家榜，
 *       公开页面就会显示"某个国家在攻击我们"，而实际上是内网自己在扫自己。</li>
 * </ul>
 */
class IpAddressesTest {

    @Test
    @DisplayName("IPv4 解析：正常值、边界值、前导零与超范围必须拒绝")
    void parseV4() {
        assertEquals(0, IpAddresses.parseV4("0.0.0.0"));
        assertEquals(-1, IpAddresses.parseV4("255.255.255.255"), "无符号语义：255.255.255.255 ≈ -1");
        assertEquals(0x01020304, IpAddresses.parseV4("1.2.3.4"));
        assertNotNull(IpAddresses.parseV4(" 1.2.3.4 "), "两侧空白应被容忍（日志里常见）");
        for (String bad : new String[]{"1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "1.2.3.-1",
                "1.2.3.4:80", "a.b.c.d", "", " ", null, "1..2.3"}) {
            assertNull(IpAddresses.parseV4(bad), "不该解析成功：" + bad);
        }
    }

    @Test
    @DisplayName("IPv6 解析：:: 压缩、全写、内嵌 IPv4、zone id、非法写法")
    void parseV6() {
        assertArrayEqualsHex(new long[]{0, 0}, IpAddresses.parseV6("::"));
        assertArrayEqualsHex(new long[]{0, 1}, IpAddresses.parseV6("::1"));
        assertArrayEqualsHex(new long[]{0x20010DB8L << 32, 1}, IpAddresses.parseV6("2001:db8::1"));
        // 全写：与压缩写法必须解析成同一个值
        assertArrayEqualsHex(IpAddresses.parseV6("2001:0db8:0000:0000:0000:0000:0000:0001"),
                IpAddresses.parseV6("2001:db8::1"));
        // 内嵌 IPv4
        assertArrayEqualsHex(new long[]{0, 0xFFFF01020304L}, IpAddresses.parseV6("::ffff:1.2.3.4"));
        // zone id 与 URL 形态
        assertNotNull(IpAddresses.parseV6("fe80::1%eth0"));
        assertNotNull(IpAddresses.parseV6("[::1]"));
        for (String bad : new String[]{"", " ", "1:2:3", "1:2:3:4:5:6:7:8:9", "::1::2", "gggg::1",
                "1:2:3:4:5:6:7", null}) {
            assertNull(IpAddresses.parseV6(bad), "不该解析成功：" + bad);
        }
    }

    private static void assertArrayEqualsHex(long[] expected, long[] actual) {
        assertNotNull(actual, "解析结果不该为 null");
        assertEquals(expected[0], actual[0], "高 64 位");
        assertEquals(expected[1], actual[1], "低 64 位");
    }

    @Test
    @DisplayName("地址性质：内网/环回/链路本地/CGNAT/ULA 归为 INTERNAL，RFC5737 与组播保留归为 RESERVED")
    void scopeClassification() {
        String[] internal = {"10.0.0.10", "10.255.255.255", "172.16.0.1", "172.31.255.254", "192.168.1.1",
                "127.0.0.1", "169.254.169.254", "100.64.0.1", "100.127.255.255",
                "fc00::1", "fd12:3456::1", "fe80::1", "::1"};
        for (String ip : internal) {
            assertEquals(IpAddresses.IpScope.INTERNAL, IpAddresses.scope(ip), ip + " 应判为内网");
        }
        String[] reserved = {"0.0.0.0", "0.1.2.3", "192.0.2.44", "198.51.100.7", "203.0.113.9",
                "198.18.0.1", "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255",
                "2001:db8::1", "ff02::1", "::"};
        for (String ip : reserved) {
            assertEquals(IpAddresses.IpScope.RESERVED, IpAddresses.scope(ip), ip + " 应判为保留");
        }
        String[] global = {"1.1.1.1", "8.8.8.8", "223.5.5.5", "172.32.0.1", "172.15.255.255",
                "100.128.0.1", "100.63.255.255", "2606:4700:4700::1111"};
        for (String ip : global) {
            assertEquals(IpAddresses.IpScope.GLOBAL, IpAddresses.scope(ip), ip + " 应判为公网");
        }
        for (String bad : new String[]{"", "not-an-ip", "1.2.3.4:8080", "2001:db8::/32", null}) {
            assertEquals(IpAddresses.IpScope.INVALID, IpAddresses.scope(bad), bad + " 应判为无效");
        }
    }

    @Test
    @DisplayName("形状判定：带点的当 v4、带冒号的当 v6，两者不能互相误判")
    void shapeDetection() {
        assertTrue(IpAddresses.looksLikeV4("1.2.3.4"));
        assertTrue(!IpAddresses.looksLikeV4("2001:db8::1"));
        assertTrue(!IpAddresses.looksLikeV4("::ffff:1.2.3.4"), "内嵌 IPv4 的 v6 不能按 v4 处理");
        assertTrue(!IpAddresses.looksLikeV4(null));
    }
}

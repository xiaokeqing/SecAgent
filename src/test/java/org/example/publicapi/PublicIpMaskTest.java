package org.example.publicapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * 公网端点 IP 掩码的测试。
 *
 * <p>掩码是"公开出去也不心疼"的那条线的执行点，所以它的行为必须是确定的：
 * 认不出来就返回 {@code ***}，<b>绝不原样透出</b>。
 */
class PublicIpMaskTest {

    @Test
    @DisplayName("IPv4 只保留前两段")
    void masksIpv4ToTwoOctets() {
        assertEquals("45.205.***.***", PublicIpMask.mask("45.205.1.230"));
        assertEquals("103.146.***.***", PublicIpMask.mask("103.146.184.77"));
    }

    @Test
    @DisplayName("带端口的 IPv4 先剥端口再掩码")
    void masksIpv4WithPort() {
        assertEquals("45.205.***.***", PublicIpMask.mask("45.205.1.230:2222"));
    }

    @Test
    @DisplayName("IPv6 只保留前两组")
    void masksIpv6() {
        assertEquals("2001:db8:****:****", PublicIpMask.mask("2001:db8:85a3::8a2e:370:7334"));
    }

    @Test
    @DisplayName("内网/保留地址写成「内部地址」，连用了哪个网段都不说")
    void hidesPrivateRangesEntirely() {
        // 只做掩码是不够的：10.0.***.*** 仍然暴露了「内网用 10/8」这个事实，
        // 而公开页不需要让任何人知道内网拓扑。
        assertEquals("内部地址", PublicIpMask.mask("10.0.0.10"));
        assertEquals("内部地址", PublicIpMask.mask("192.168.1.5"));
        assertEquals("内部地址", PublicIpMask.mask("172.20.3.4"));
        assertEquals("内部地址", PublicIpMask.mask("127.0.0.1"));
        assertEquals("内部地址", PublicIpMask.mask("169.254.1.1"));
        assertEquals("内部地址", PublicIpMask.mask("100.100.100.200"));
    }

    @Test
    @DisplayName("认不出来的输入不原样透出")
    void unknownInputBecomesStars() {
        assertEquals("***", PublicIpMask.mask("not-an-ip"));
        assertEquals("***", PublicIpMask.mask("1.2.3"));
        assertNull(PublicIpMask.mask(null), "null 仍应是 null");
        assertNull(PublicIpMask.mask("   "), "空白应是 null");
    }
}

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
        // 契约修正（2026-10-12）：与本文件文档注释一致 —— 认不出来就返回 ***，绝不透出 null。
        // 由确定性安全卷 SafetyPaperDeterministicTest 钉住。
        assertEquals("***", PublicIpMask.mask(null), "null 应归一成占位符");
        assertEquals("***", PublicIpMask.mask("   "), "空白应归一成占位符");
    }

    // ============================================================
    // 回归用例（2026-10-13）：IP 紧跟中文时曾经【完全不掩码】
    // ------------------------------------------------------------
    // 现场：匿名抽检某条公开回答里，模型写的 "立即隔离IP 103.146.184.77和45.83.91.12"
    // 三个完整 IP 原样透出，而同一次响应的 outputFindings 还写着 ip-masked。
    // 根因：maskAll 原先用 \b(...)\b，而 JDK 19 之前 \b 的词字符判定是 Unicode 感知的，
    // 中文算词字符 → "77和" 之间没有词边界 → 整条匹配失败。
    // 修法：改用 (?<![\d.]) ... (?![\d.]) 显式 lookaround。
    // 这类用例必须存在：原有用例全是 ASCII 语境，所以在 JDK 17 上也会全绿，漏掉整类问题。
    // ============================================================

    @Test
    @DisplayName("回归：IP 后面紧跟中文也必须掩码（曾经整条漏掉）")
    void masksIpv4AdjacentToChinese() {
        assertEquals("立即隔离IP 103.146.***.***和45.83.***.***",
                PublicIpMask.maskAll("立即隔离IP 103.146.184.77和45.83.91.12"));
        assertEquals("禁止将203.0.***.***加入白名单",
                PublicIpMask.maskAll("禁止将203.0.113.9加入白名单"));
    }

    @Test
    @DisplayName("回归：内网 IP 紧跟中文也要归成「内部地址」")
    void hidesPrivateIpAdjacentToChinese() {
        assertEquals("封禁内部地址（内部地址）",
                PublicIpMask.maskAll("封禁10.0.10.21（内部地址）"));
    }

    @Test
    @DisplayName("回归：ASCII 语境仍然照常掩码（不能因为修中文而回归）")
    void stillMasksInAsciiContext() {
        assertEquals("from 103.146.***.*** port 41020",
                PublicIpMask.maskAll("from 103.146.184.77 port 41020"));
        assertEquals("来源=45.205.***.***：端口扫描",
                PublicIpMask.maskAll("来源=45.205.1.230：端口扫描"));
    }

    @Test
    @DisplayName("回归：更长数字串不被误切（1.2.3.4.5 / v1.2.3.4.5-beta）")
    void doesNotMisSplitLongerNumbers() {
        assertEquals("1.2.3.4.5", PublicIpMask.maskAll("1.2.3.4.5"));
        assertEquals("v1.2.3.4.5-beta", PublicIpMask.maskAll("v1.2.3.4.5-beta"));
    }

    @Test
    @DisplayName("回归：组数合法但组值超范围（103.146.184.771）按【掩码】处理 —— 宁可多掩，不可漏")
    void overMasksRatherThanLeaksForOutOfRangeGroups() {
        // \d{1,3} 不校验 <=255，所以 771 这种"像 IP 但非法"的串也会被掩码。
        // 这是刻意的取舍：公开面上的错误方向只能是"多掩一点"，绝不能是"少掩一个真 IP"。
        assertEquals("103.146.***.***", PublicIpMask.maskAll("103.146.184.771"));
    }

    @Test
    @DisplayName("自由文本里的 IPv6 也要掩码，但 HH:MM:SS 时间戳不能被误掩码")
    void masksIpv6InTextWithoutBreakingTimestamps() {
        assertEquals("来自 2001:db8:****:**** 的连接",
                PublicIpMask.maskAll("来自 2001:db8:85a3:0000:0000:8a2e:0370:7334 的连接"));
        assertEquals("时间 10:20:30 结束", PublicIpMask.maskAll("时间 10:20:30 结束"));
    }
}

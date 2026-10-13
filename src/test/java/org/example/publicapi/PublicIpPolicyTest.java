package org.example.publicapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 公开面 IP 口径开关（{@link PublicIpPolicy}）的测试。
 *
 * <h3>为什么这个类必须有自己的测试</h3>
 * 站主 2026-10-14 拍板：公开面<b>显示观测到的真实来源 IP</b>（{@code app.public.mask-ips=false}，
 * 也是默认值）。这条改造同时带来两个方向的风险，而它们<b>都不会报错</b>：
 * <ol>
 *   <li>"说好了显示真实 IP，结果某个端点还在掩码" —— 页面上同一攻击源一个地方看得见、
 *       另一个地方看不见，没人能从日志里发现；</li>
 *   <li>"为了显示真实 IP，把内网/链路地址也当攻击源贴出去了" —— 这不是透明，是白送内网拓扑。</li>
 * </ol>
 * 所以这里对两种口径逐条断言，并且专门钉住"掩码态与改造前逐字节一致"（回退可信）。
 */
class PublicIpPolicyTest {

    // ==================== 默认值与兜底 ====================

    @Test
    @DisplayName("默认口径 = 显示真实 IP（app.public.mask-ips 缺省为 false）")
    void defaultPolicyRevealsRealIp() {
        PublicIpPolicy p = PublicIpPolicy.of(false);      // 与 application.yml 的 ${APP_PUBLIC_MASK_IPS:false} 同源

        assertFalse(p.masked(), "默认必须是真实态");
        assertEquals("45.83.91.12", p.display("45.83.91.12"));
        assertEquals(PublicIpPolicy.NOTICE, p.disclosure().get("notice"));
    }

    @Test
    @DisplayName("缺注入兜底 = 掩码（fail-closed：宁可少给，不可多漏）")
    void bareInstanceFailsClosedToMasking() {
        // 单测里直接 new（没有 Spring 注入）时字段初值是 true。
        // 这条与"配置默认 false"不矛盾，见类注释：运行中的应用一定走配置。
        assertTrue(new PublicIpPolicy().masked(),
                "没有配置/注入时兜底方向必须是掩码 —— 否则「忘了配」会变成静默泄露");
    }

    // ==================== 真实态 ====================

    @Test
    @DisplayName("真实态：公网 IPv4 原样显示（剥端口），IPv6 同样原样显示")
    void realModeShowsPublicAddresses() {
        PublicIpPolicy p = PublicIpPolicy.revealing();

        assertEquals("45.83.91.12", p.display("45.83.91.12"));
        assertEquals("45.83.91.12", p.display(" 45.83.91.12 "), "两侧空白不算地址的一部分");
        assertEquals("45.83.91.12", p.display("45.83.91.12:41020"), "端口不是来源地址的一部分");
        assertEquals("103.146.184.77", p.display("103.146.184.77"));
        assertEquals("2001:db8:85a3::8a2e:370:7334", p.display("2001:db8:85a3::8a2e:370:7334"));
        assertEquals("2001:db8::1", p.display("[2001:db8::1]:2222"), "方括号形式也要能剥出主机");
    }

    @Test
    @DisplayName("真实态：内网/保留/链路地址一律「内网/未知」—— 绝不当攻击源输出")
    void realModeNeverShowsInternalAddressAsSource() {
        PublicIpPolicy p = PublicIpPolicy.revealing();

        for (String internal : List.of(
                "10.0.0.10", "172.16.5.5", "172.20.3.4", "172.31.255.254", "192.168.1.5",
                "127.0.0.1", "169.254.1.1", "100.100.100.200", "0.0.0.0",
                "::1", "fe80::1", "fd00::1", "fc00::1", "::ffff:10.0.0.1")) {
            String shown = p.display(internal);
            assertEquals(PublicIpMask.INTERNAL_UNKNOWN_LABEL, shown,
                    "「" + internal + "」是内网/保留/链路地址，真实态下也不许当来源地址展示：" + shown);
            assertFalse(shown.contains("10.") || shown.contains("127.") || shown.contains("172."),
                    "展示值里不得残留内网网段：" + shown);
        }
    }

    @Test
    @DisplayName("真实态：认不出来的取值写「未知」，不原样透出")
    void realModeNeverEchoesUnknownValue() {
        PublicIpPolicy p = PublicIpPolicy.revealing();

        assertEquals("未知", p.display(null));
        assertEquals("未知", p.display("   "));
        assertEquals("未知", p.display("not-an-ip"));
        assertEquals("未知", p.display("10:20:30"), "时间戳不是 IP，别把它当来源地址展示");
        assertEquals("未知", p.display("admin@example.com"), "非 IP 的值不许原样当来源地址透出");
    }

    @Test
    @DisplayName("真实态：自由文本里公网 IP 保留，内网/链路地址仍被隐去")
    void realModeTextKeepsPublicButHidesInternal() {
        PublicIpPolicy p = PublicIpPolicy.revealing();

        String out = p.displayText("蜜罐: 登录来自 106.37.205.248 经 172.18.0.1 转发，目标 10.0.0.7，时间 10:20:30");

        assertTrue(out.contains("106.37.205.248"), "真实态下公网来源 IP 必须保留：" + out);
        assertFalse(out.contains("172.18.0.1"), "链路地址不得出现：" + out);
        assertFalse(out.contains("10.0.0.7"), "内网地址不得出现：" + out);
        assertTrue(out.contains(PublicIpMask.INTERNAL_UNKNOWN_LABEL), "应替换成「内网/未知」：" + out);
        assertTrue(out.contains("10:20:30"), "时间戳不该被误伤：" + out);

        // IPv6：压缩写法的链路本地/环回也要隐去，而公网 IPv6 必须保留
        String v6 = p.displayText("来自 fe80::1 与 ::1，以及公网 2001:db8:85a3::8a2e:370:7334");
        assertFalse(v6.contains("fe80::1"), "链路本地 IPv6 不得出现：" + v6);
        assertTrue(v6.contains("2001:db8:85a3::8a2e:370:7334"), "公网 IPv6 要保留：" + v6);
    }

    // ==================== 掩码态（回归） ====================

    @Test
    @DisplayName("【回归】掩码态与改造前 PublicIpMask 逐字节一致（翻转回来 = 今天的行为）")
    void maskedModeIsByteIdenticalToLegacy() {
        PublicIpPolicy masked = PublicIpPolicy.masking();

        for (String ip : List.of("45.205.1.230", "45.205.1.230:2222", "103.146.184.77",
                "2001:db8:85a3::8a2e:370:7334", "10.0.0.10", "192.168.1.5", "127.0.0.1",
                "100.100.100.200", "not-an-ip", "1.2.3", "")) {
            assertEquals(PublicIpMask.mask(ip), masked.display(ip),
                    "掩码态的 display() 必须与改造前的 mask() 完全相同：" + ip);
        }
        assertEquals(PublicIpMask.mask(null), masked.display(null));

        for (String text : List.of(
                "蜜罐: 新的 SSH 连接来自 106.37.205.248，随后尝试登录 root。",
                "立即隔离IP 103.146.184.77和45.83.91.12",
                "封禁10.0.10.21（内部地址）",
                "时间 10:20:30 结束",
                "来源=45.205.1.230：端口扫描",
                "没有任何 IP 的句子")) {
            assertEquals(PublicIpMask.maskAll(text), masked.displayText(text),
                    "掩码态的 displayText() 必须与改造前的 maskAll() 完全相同：" + text);
        }

        assertTrue(masked.masked());
        assertEquals(Boolean.TRUE, masked.disclosure().get("masked"));
    }

    // ==================== 统一口径字段 ====================

    @Test
    @DisplayName("ipDisclosure 形状固定：masked / notice / removalContact 三键")
    void disclosureShapeIsFixed() {
        Map<String, Object> real = PublicIpPolicy.revealing().disclosure();
        assertEquals(Boolean.FALSE, real.get("masked"));
        assertEquals("观测到的来源地址，未经验证，仅供参考", real.get("notice"));
        assertNotNull(real.get("removalContact"));
        assertTrue(String.valueOf(real.get("removalContact")).startsWith("http"),
                "removalContact 必须是可点的移除/更正入口：" + real.get("removalContact"));
        assertEquals(List.of("masked", "notice", "removalContact"), List.copyOf(real.keySet()),
                "键顺序也要固定：页面与快照比对都依赖它");

        Map<String, Object> masked = PublicIpPolicy.masking().disclosure();
        assertEquals(Boolean.TRUE, masked.get("masked"));
        assertEquals(PublicIpPolicy.NOTICE, masked.get("notice"), "两个口径用同一句话，避免口径漂移");
    }

    @Test
    @DisplayName("removalContact 留空时退回默认关于页（口径字段不许是空串）")
    void blankRemovalContactFallsBack() {
        PublicIpPolicy p = PublicIpPolicy.of(false);
        org.springframework.test.util.ReflectionTestUtils.setField(p, "removalContact", "   ");

        assertEquals(PublicIpPolicy.DEFAULT_REMOVAL_CONTACT, p.disclosure().get("removalContact"));
        assertEquals(PublicIpPolicy.DEFAULT_REMOVAL_CONTACT, p.removalContact());
    }
}

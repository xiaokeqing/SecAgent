package org.example.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 处置护栏的白名单测试。
 *
 * <p>对应一次真实修过的缺陷：原白名单只覆盖 RFC1918 私网，
 * <b>漏掉了云元数据地址</b> —— 阿里云的 {@code 100.100.100.200} 落在
 * {@code 100.64.0.0/10}（运营商级 NAT）里，封掉它会直接打断实例读取元数据与临时凭据。
 *
 * <p>这些用例是回归测试：以后有人改白名单，漏了什么会立刻被这些断言挡住。
 */
class ResponseGuardTest {

    private ResponseGuard guard;

    /** 与 application.yml 的默认值保持一致 */
    private static final String DEFAULT_WHITELIST =
            "127.0.0.0/8,0.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,"
            + "169.254.0.0/16,100.64.0.0/10,192.0.0.0/24,192.0.2.0/24,"
            + "198.51.100.0/24,203.0.113.0/24,198.18.0.0/15,255.255.255.255/32";

    @BeforeEach
    void setUp() {
        guard = newGuard(DEFAULT_WHITELIST, "");
    }

    private static ResponseGuard newGuard(String whitelist, String selfAssets) {
        ResponseGuard g = new ResponseGuard();
        ReflectionTestUtils.setField(g, "whitelistRaw", whitelist);
        ReflectionTestUtils.setField(g, "selfAssetsRaw", selfAssets);
        ReflectionTestUtils.setField(g, "maxDurationMinutes", 1440);
        ReflectionTestUtils.setField(g, "defaultDurationMinutes", 60);
        g.init();
        return g;
    }

    // ==================== 云元数据地址（本次修复的重点）====================

    @Test
    @DisplayName("阿里云元数据 100.100.100.200 必须被保护（原来漏了）")
    void aliyunMetadataIsProtected() {
        String r = guard.validateBlock("100.100.100.200", 60);
        assertNotNull(r, "阿里云元数据地址必须被拒绝 —— 封掉会打断实例读元数据与临时凭据");
        assertTrue(r.contains("100.64.0.0/10"), "拒绝原因应指向 CGN 网段，实际: " + r);
    }

    @Test
    @DisplayName("AWS/GCP 元数据 169.254.169.254 必须被保护（原来漏了）")
    void awsMetadataIsProtected() {
        String r = guard.validateBlock("169.254.169.254", 60);
        assertNotNull(r, "链路本地元数据地址必须被拒绝");
        assertTrue(r.contains("169.254.0.0/16"), "拒绝原因应指向链路本地网段，实际: " + r);
    }

    @Test
    @DisplayName("整个 CGN 段 100.64.0.0/10 都在保护范围")
    void entireCgnRangeIsProtected() {
        assertNotNull(guard.validateBlock("100.64.0.1", 60));
        assertNotNull(guard.validateBlock("100.127.255.254", 60));
        // 边界外应当放行（100.128.0.1 已不属于 100.64/10）
        assertNull(guard.validateBlock("100.128.0.1", 60), "100.128.0.1 不在 CGN 段内，应放行");
    }

    // ==================== 常规保留地址 ====================

    @Test
    @DisplayName("环回与私网照旧被保护")
    void loopbackAndPrivateStillProtected() {
        assertNotNull(guard.validateBlock("127.0.0.1", 60));
        assertNotNull(guard.validateBlock("127.1.2.3", 60));
        assertNotNull(guard.validateBlock("10.1.2.3", 60));
        assertNotNull(guard.validateBlock("172.16.0.1", 60));
        assertNotNull(guard.validateBlock("172.31.255.254", 60));
        assertNotNull(guard.validateBlock("192.168.1.1", 60));
        assertNotNull(guard.validateBlock("0.0.0.0", 60));
        assertNotNull(guard.validateBlock("255.255.255.255", 60));
    }

    @Test
    @DisplayName("组播与保留段被拒绝")
    void multicastAndReservedRejected() {
        assertNotNull(guard.validateBlock("224.0.0.1", 60));
        assertNotNull(guard.validateBlock("239.255.255.255", 60));
        assertNotNull(guard.validateBlock("240.0.0.1", 60));
    }

    // ==================== 格式绕过 ====================

    @Test
    @DisplayName("各种格式绕过都进不来（fail-safe：判不准就不放行）")
    void formatBypassesAreRejected() {
        // 十进制整数形式的 127.0.0.1
        assertNotNull(guard.validateBlock("2130706433", 60));
        // 十六进制写法
        assertNotNull(guard.validateBlock("0x7f.0.0.1", 60));
        // 四位八进制段
        assertNotNull(guard.validateBlock("0177.0.0.1", 60));
        // IPv6
        assertNotNull(guard.validateBlock("::1", 60));
        assertNotNull(guard.validateBlock("fc00::1", 60));
        // 空值
        assertNotNull(guard.validateBlock(null, 60));
        assertNotNull(guard.validateBlock("   ", 60));
        // 段值越界
        assertNotNull(guard.validateBlock("999.1.1.1", 60));
        assertNotNull(guard.validateBlock("1.2.3.256", 60));
    }

    // ==================== 正常放行 ====================

    @Test
    @DisplayName("合法外部 IP 正常封禁（护栏不该误杀）")
    void legitimatePublicIpAllowed() {
        assertNull(guard.validateBlock("103.146.184.77", 60));
        assertNull(guard.validateBlock("8.8.8.8", 60));
        assertNull(guard.validateBlock("1.1.1.1", 60));
    }

    // ==================== 时长边界 ====================

    @Test
    @DisplayName("封禁时长边界：0 / 负数 / 超上限都拒绝")
    void durationBounds() {
        assertNotNull(guard.validateBlock("8.8.8.8", 0), "0 分钟应拒绝");
        assertNotNull(guard.validateBlock("8.8.8.8", -1), "负数应拒绝");
        assertNotNull(guard.validateBlock("8.8.8.8", 1441), "超过上限应拒绝");
        assertNotNull(guard.validateBlock("8.8.8.8", Integer.MAX_VALUE), "整数极值应拒绝");
        assertNull(guard.validateBlock("8.8.8.8", 1440), "正好等于上限应放行");
        assertNull(guard.validateBlock("8.8.8.8", null), "null 应回落到默认时长");
    }

    // ==================== 自有资产 ====================

    @Test
    @DisplayName("自有资产白名单：保护自己的公网 IP（通用网段挡不住这个）")
    void selfAssetsAreProtected() {
        // 不配自有资产时，自己的公网 IP 是能被封的 —— 这是原来的缺口
        ResponseGuard without = newGuard(DEFAULT_WHITELIST, "");
        assertNull(without.validateBlock("47.96.106.187", 60),
                "未配置自有资产时，自己的公网 IP 确实挡不住（说明这个配置项是必要的）");

        // 配了之后就该被保护，且支持 CIDR
        ResponseGuard with = newGuard(DEFAULT_WHITELIST, "47.96.106.187,203.0.113.0/24");
        String r = with.validateBlock("47.96.106.187", 60);
        assertNotNull(r, "自有资产必须被保护");
        assertTrue(r.contains("47.96.106.187"), "拒绝原因应指向自有资产条目，实际: " + r);
    }

    @Test
    @DisplayName("白名单条目数量符合预期（改配置时能立刻发现）")
    void whitelistSizeIsSane() {
        assertTrue(guard.getWhitelist().size() >= 13,
                "内置保护网段不应少于 13 条，实际: " + guard.getWhitelist().size());
    }
}

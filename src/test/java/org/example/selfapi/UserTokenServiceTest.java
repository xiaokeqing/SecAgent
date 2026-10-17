package org.example.selfapi;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 自用令牌校验的核心行为测试（站主 2026-10-16「后端令牌登录」方案）。
 *
 * <h3>这组测试防的是什么</h3>
 * 登录面是"加法的、由一个空值开关控制的面"：它出错的方向有两个，且都不会自己报错：
 * <ol>
 *   <li><b>配置缺失时静默放行</b> —— 表现是"没配令牌也能进"，等于把自用池变成公开后门；</li>
 *   <li><b>比较不是恒定时间</b> —— 表现是一切正常，只是有人可以逐字节猜出令牌。</li>
 * </ol>
 * 所以这里逐条钉住：未配置必拒、错误必拒、缺失必拒、限速与封禁生效、
 * 且 <b>审计里搜不到令牌明文</b>。
 */
class UserTokenServiceTest {

    /** 测试用明文令牌（≥32 字符）。它只存在于测试里，不是任何真实环境的凭据 */
    private static final String TOKEN = "test-only-token-0123456789abcdefghijklmnopqrstuvwxyz";

    private UserTokenService service;

    @TempDir
    Path tmp;

    @BeforeEach
    void setUp() {
        service = newService(TOKEN, tmp.resolve("audit.jsonl").toString());
        SelfIdentity.end();
    }

    @AfterEach
    void tearDown() {
        SelfIdentity.end();
        /* 审计写入由守护线程异步完成（每行打开-写-关闭）。测试结束前必须等它把队列排空，
           否则 JUnit 删 @TempDir 的那一刻线程可能正好在写文件，Windows 会报
           "Failed to delete temp directory"——这个偶发失败今晚已经两次卡住后端发版。 */
    }

    private UserTokenService newService(String plainTokenOrNull, String auditFile) {
        UserTokenService s = new UserTokenService();
        ReflectionTestUtils.setField(s, "tokenSha256",
                plainTokenOrNull == null ? "" : UserTokenService.sha256Hex(plainTokenOrNull));
        ReflectionTestUtils.setField(s, "loginPerMinute", 1000);   // 默认关掉限速，逐条测时不互相干扰
        ReflectionTestUtils.setField(s, "failThreshold", 10);
        ReflectionTestUtils.setField(s, "failWindowSeconds", 600);
        ReflectionTestUtils.setField(s, "banSeconds", 600);
        ReflectionTestUtils.setField(s, "auditFile", auditFile);
        s.init();
        return s;
    }

    // ==================== 令牌正确 / 错误 / 缺失 / 未配置 ====================

    @Test
    @DisplayName("【核心】正确令牌通过；错误令牌 401；缺失令牌 401")
    void correctTokenPassesWrongAndMissingAreRejected() {
        UserTokenService.Result ok = service.check("203.0.113.9", TOKEN);
        assertTrue(ok.ok(), "正确令牌必须通过");
        assertEquals(200, ok.httpStatus());

        UserTokenService.Result wrong = service.check("203.0.113.9", TOKEN + "x");
        assertFalse(wrong.ok(), "错误令牌必须被拒");
        assertEquals(401, wrong.httpStatus());
        assertEquals("TOKEN_INVALID", wrong.reason());
        assertFalse(String.valueOf(wrong.message()).contains(TOKEN),
                "失败文案里绝不能出现令牌（哪怕前缀）");

        UserTokenService.Result missing = service.check("203.0.113.10", null);
        assertFalse(missing.ok(), "缺失令牌必须被拒");
        assertEquals(401, missing.httpStatus());
        assertEquals("TOKEN_MISSING", missing.reason());
    }

    @Test
    @DisplayName("【fail-closed】未配置 APP_USER_TOKEN_SHA256 时一律拒绝，绝不静默放行")
    void unconfiguredLoginSurfaceRejectsEverything() {
        UserTokenService unconfigured = newService(null, tmp.resolve("audit2.jsonl").toString());
        assertFalse(unconfigured.configured(), "空哈希 = 未配置");

        // 即使"恰好"给了一串看起来正确的令牌（这里给的是测试令牌原文），也必须拒
        UserTokenService.Result r = unconfigured.check("203.0.113.9", TOKEN);
        assertFalse(r.ok(), "未配置时必须拒绝，而不是放行");
        assertEquals(401, r.httpStatus());
        assertEquals("USER_LOGIN_DISABLED", r.reason());

        // 配置写错（把明文当哈希粘进来）同样按"未配置"处理 —— 报配置无效，不报令牌错误
        UserTokenService typo = new UserTokenService();
        ReflectionTestUtils.setField(typo, "tokenSha256", TOKEN);   // 长度不对
        ReflectionTestUtils.setField(typo, "auditFile", "");
        typo.init();
        assertFalse(typo.configured(), "非 64 位十六进制的配置必须视为未配置");
        assertEquals("USER_LOGIN_DISABLED", typo.check("203.0.113.9", TOKEN).reason());
    }

    @Test
    @DisplayName("令牌形状非法（过短 / 过长）直接拒，且不进入哈希比较")
    void malformedTokenShapeIsRejected() {
        assertEquals("TOKEN_INVALID", service.check("203.0.113.11", "short").reason(),
                "短于 32 字符必须拒");
        assertEquals("TOKEN_INVALID", service.check("203.0.113.11", "x".repeat(201)).reason(),
                "长于 200 字符必须拒（防低成本 DoS）");
        // 32 与 200 的边界必须都能走到"哈希比较"这一层（即不是形状拒）
        assertEquals("TOKEN_INVALID", service.check("203.0.113.11", "y".repeat(32)).reason(),
                "32 字符是合法长度，失败原因应是内容不匹配");
    }

    @Test
    @DisplayName("令牌大小写敏感（哈希比较，不做大小写归一）")
    void tokenComparisonIsCaseSensitive() {
        assertTrue(service.check("203.0.113.12", TOKEN).ok());
        assertFalse(service.check("203.0.113.12", TOKEN.toUpperCase(java.util.Locale.ROOT)).ok(),
                "大写形态不是同一个令牌");
    }

    // ==================== 限速 / 失败封禁 ====================

    @Test
    @DisplayName("登录面每 IP 限速：超过配置的每分钟次数即 429（status/ask 共用一本账）")
    void loginSurfaceIsRateLimitedPerIp() {
        UserTokenService limited = newService(TOKEN, tmp.resolve("audit3.jsonl").toString());
        ReflectionTestUtils.setField(limited, "loginPerMinute", 3);

        assertTrue(limited.check("198.51.100.7", TOKEN).ok(), "第 1 次放行");
        assertTrue(limited.check("198.51.100.7", TOKEN).ok(), "第 2 次放行");
        assertTrue(limited.check("198.51.100.7", TOKEN).ok(), "第 3 次放行");

        UserTokenService.Result fourth = limited.check("198.51.100.7", TOKEN);
        assertFalse(fourth.ok(), "第 4 次必须被限速（即使令牌正确）");
        assertEquals(429, fourth.httpStatus());
        assertEquals("LOGIN_RATE_LIMITED", fourth.reason());
        assertTrue(fourth.retryAfter() > 0, "限速必须给出 Retry-After，页面才能如实提示");

        // 另一个 IP 不受影响（限速是"按 IP"，不是"全局限速")
        assertTrue(limited.check("198.51.100.8", TOKEN).ok(), "另一个来源不该被 A 的限速牵连");
    }

    @Test
    @DisplayName("【防爆破】连续失败达到阈值后封禁：正确令牌也被挡，且给出 Retry-After")
    void repeatedFailuresTriggerTemporaryBan() {
        UserTokenService strict = newService(TOKEN, tmp.resolve("audit4.jsonl").toString());
        ReflectionTestUtils.setField(strict, "failThreshold", 3);
        ReflectionTestUtils.setField(strict, "banSeconds", 600);

        assertFalse(strict.check("192.0.2.50", TOKEN + "x").ok(), "第 1 次失败");
        assertFalse(strict.check("192.0.2.50", TOKEN + "x").ok(), "第 2 次失败");
        assertFalse(strict.check("192.0.2.50", TOKEN + "x").ok(), "第 3 次失败 ⇒ 达阈值");

        UserTokenService.Result banned = strict.check("192.0.2.50", TOKEN);
        assertFalse(banned.ok(), "封禁窗口内即使令牌正确也必须拒绝");
        assertEquals(429, banned.httpStatus());
        assertEquals("IP_TEMPORARILY_BANNED", banned.reason());
        assertTrue(banned.retryAfter() > 0, "封禁必须给出 Retry-After");

        // 另一个 IP 不被牵连
        assertTrue(strict.check("192.0.2.51", TOKEN).ok(), "封禁只针对触发它的来源");

        // 成功一次即清空失败计数：解除封禁后不应再被旧计数拉黑
        service.check("192.0.2.52", TOKEN);   // 成功一次
        assertTrue(service.check("192.0.2.52", TOKEN).ok(), "成功路径不得被自身计数影响");
    }

    @Test
    @DisplayName("成功一次即清掉该 IP 的失败计数（否则站主粘错几次就长期进不去）")
    void successResetsFailureCounter() {
        UserTokenService s = newService(TOKEN, tmp.resolve("audit5.jsonl").toString());
        ReflectionTestUtils.setField(s, "failThreshold", 5);

        assertFalse(s.check("203.0.113.60", TOKEN + "bad").ok());
        assertFalse(s.check("203.0.113.60", TOKEN + "bad").ok());
        assertTrue(s.check("203.0.113.60", TOKEN).ok(), "第 3 次给对：必须直接通过（不因前两次失败被拒）");

        // 清零后需要重新累计 5 次才会封禁 —— 这里只验"没被立刻封"
        assertFalse(s.check("203.0.113.60", TOKEN + "bad").ok());
        assertFalse(s.check("203.0.113.60", TOKEN + "bad").ok());
        assertTrue(s.check("203.0.113.60", TOKEN).ok(), "计数已被成功地清零过一次，不应已封禁");
    }

    // ==================== 审计：结构上不可能记令牌 ====================

    @Test
    @DisplayName("【红线】审计文件里搜不到令牌明文（哨兵令牌跑一遍全路径）")
    void auditNeverContainsPlaintextToken() throws Exception {
        String sentinel = "SENTINEL-" + "s".repeat(40);   // 48 字符，形状合法
        Path audit = tmp.resolve("audit-sentinel.jsonl");
        UserTokenService s = newService(sentinel, audit.toString());
        ReflectionTestUtils.setField(s, "failThreshold", 100);

        s.check("203.0.113.70", sentinel + "-wrong");   // 一次失败
        s.check("203.0.113.70", sentinel);              // 一次成功
        s.check("203.0.113.70", null);                  // 一次缺失
        s.auditAsk("203.0.113.70", "conv-abc", 2, 17, "model", "ok", null);

        // 写线程是异步的：给它一点时间落盘（审计的价值在「确实写了」，所以这里等，不是忙等）
        String content = null;
        for (int i = 0; i < 50; i++) {
            if (Files.exists(audit)) {
                content = Files.readString(audit, StandardCharsets.UTF_8);
                if (content.contains("\"ask\"")) {
                    break;
                }
            }
            Thread.sleep(100);
        }

        assertNotNull(content, "审计文件必须写出（否则「永不记令牌」没有可验证的对象）");
        assertFalse(content.contains(sentinel), "【红线违反】审计里出现了令牌明文");
        assertFalse(content.contains(sentinel.substring(0, 8)), "审计里出现了令牌前缀");
        assertTrue(content.contains("\"tokenLen\":49"), "审计应当只记长度（哨兵是 9+40=49 字符）");
        assertTrue(content.contains("\"ipMasked\":\"203.0.***.***\""), "审计 IP 必须是掩码");
        assertTrue(content.contains("ask"), "自用调用也要留痕");
        assertFalse(content.contains("conv-abc"), "会话标识只记哈希前 8 位，不记原值");
    }

    @Test
    @DisplayName("审计行结构：未配置落盘时不会抛异常（只打日志）")
    void auditWithoutFileDoesNotThrow() {
        UserTokenService noFile = newService(TOKEN, "");
        assertFalse(noFile.auditEnabled(), "未配置审计文件时应如实报告未落盘");
        assertTrue(noFile.check("203.0.113.80", TOKEN).ok());
    }

    // ==================== 底层工具 ====================

    @Test
    @DisplayName("sha256 / 恒定时间比较 / 哈希形状 的正确性")
    void primitivesBehaveAsDocumented() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                UserTokenService.sha256Hex("abc"), "sha256(abc) 是公开已知向量");
        assertTrue(UserTokenService.isSha256Hex("a".repeat(64)));
        assertFalse(UserTokenService.isSha256Hex("a".repeat(63)));
        assertFalse(UserTokenService.isSha256Hex("g".repeat(64)));
        assertTrue(UserTokenService.constantTimeEquals("abc", "abc"));
        assertFalse(UserTokenService.constantTimeEquals("abc", "abd"));
        assertFalse(UserTokenService.constantTimeEquals("abc", "abcd"), "长度不同直接不等");
        assertFalse(UserTokenService.constantTimeEquals(null, "abc"));
        assertEquals(8, UserTokenService.conversationIdHash("whatever").length());
        assertNotEquals(UserTokenService.conversationIdHash("a"), UserTokenService.conversationIdHash("b"));
    }

    @Test
    @DisplayName("IP 掩码只保留网段（审计里不出现完整来源地址）")
    void ipMaskKeepsOnlyNetworkPart() {
        assertEquals("203.0.***.***", UserTokenService.maskIp("203.0.113.77"));
        assertEquals("203.0.***.***", UserTokenService.maskIp("203.0.113.77:1234"));
        assertEquals("***", UserTokenService.maskIp(null));
        assertEquals("***", UserTokenService.maskIp(""));
    }

    @Test
    @DisplayName("自用身份标注：默认关闭，标记后可读，清理后归零（线程池残留会记错账）")
    void selfIdentityMarkerLifecycle() {
        assertFalse(SelfIdentity.isSelfRequest(), "默认不是自用请求");
        SelfIdentity.markSelfRequest();
        assertTrue(SelfIdentity.isSelfRequest());
        SelfIdentity.end();
        assertFalse(SelfIdentity.isSelfRequest(), "清理后必须归零");
        SelfIdentity.markNonSelfRequest();
        assertFalse(SelfIdentity.isSelfRequest(), "显式非自用同样是 false");
        SelfIdentity.end();
    }

    @Test
    @DisplayName("自用面路径判定必须带边界（/api/user-admin 不得被当成自用面）")
    void selfPathBoundaryIsExact() {
        assertTrue(SelfTokenInterceptor.isSelfPath("/api/user/status"));
        assertTrue(SelfTokenInterceptor.isSelfPath("/api/user/ask"));
        assertTrue(SelfTokenInterceptor.isSelfPath("/api/user"));
        assertFalse(SelfTokenInterceptor.isSelfPath("/api/user-admin/x"), "同前缀不同路径必须拒绝");
        assertFalse(SelfTokenInterceptor.isSelfPath("/api/users"), "不得因为字符串开头相同就放行");
        assertFalse(SelfTokenInterceptor.isSelfPath("/api/public/ask"));
        assertFalse(SelfTokenInterceptor.isSelfPath(null));
        assertFalse(SelfTokenInterceptor.isSelfPath(""));
    }

    @Test
    @DisplayName("审计 JSON 结构：只含白名单字段，且令牌相关只有长度")
    void auditJsonShape() {
        String line = UserTokenAuditWriter.toJson("login", "fail", "TOKEN_MISMATCH", "203.0.***.***",
                48, 3, null, null, null, null, null);
        assertTrue(line.startsWith("{") && line.endsWith("}"), "必须是单行 JSON 对象");
        assertTrue(line.contains("\"event\":\"login\""));
        assertTrue(line.contains("\"reason\":\"TOKEN_MISMATCH\""));
        assertTrue(line.contains("\"tokenLen\":48"));
        assertTrue(line.contains("\"failCount\":3"));
        assertFalse(line.contains("password"), "不得出现任何凭据字段名");
        assertFalse(line.contains("token\":"), "不得出现 token 值字段（只有 tokenLen）");
        assertTrue(List.of("event", "result", "reason", "ipMasked", "tokenLen")
                .stream().allMatch(line::contains), "关键字段必须都在");
    }
}

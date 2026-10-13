package org.example.accesslog;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * UA/字符串清洗（{@link WebStatsSanitizer}）的测试。
 *
 * <p>它守的是"公开响应里零 IP"这条硬保证里最容易漏的一环：UA 是<b>攻击者可控</b>的，
 * 一个形如 {@code 1.2.3.4-scanner/1.0} 的 UA 就能把 IP 塞进公网页面。
 */
class WebStatsSanitizerTest {

    @Test
    @DisplayName("控制字符替换成空格 + trim + 按字符截断（长度即上限）")
    void cleanTextReplacesControlCharsAndTruncates() {
        assertEquals("a b c", WebStatsSanitizer.cleanText("a\nb\tc", 100));
        assertEquals("evil", WebStatsSanitizer.cleanText("\u0007evil\u0000", 100));
        assertEquals("a b", WebStatsSanitizer.cleanText("a\u007Fb", 100));
        assertEquals(60, WebStatsSanitizer.cleanText("x".repeat(500), 60).length());
        assertEquals("", WebStatsSanitizer.cleanText(null, 60));
        assertEquals("", WebStatsSanitizer.cleanText("", 60));
        assertEquals("abc", WebStatsSanitizer.cleanText("  abc  ", 60));
    }

    @Test
    @DisplayName("IPv4 / IPv6 字面量 → [ip]；只有像 IP 的才算，时间串与版本号不许误伤")
    void scrubIpLiteralsReplacesAddressesOnly() {
        assertEquals("[ip]", WebStatsSanitizer.scrubIpLiterals("203.0.113.9"));
        assertEquals("[ip]-scanner", WebStatsSanitizer.scrubIpLiterals("203.0.113.9-scanner"));
        assertEquals("来自 [ip]", WebStatsSanitizer.scrubIpLiterals("来自 203.0.113.9"));
        // 长得像 IP 就算（999.1.1.1 不是合法 IP，但没必要往外发"像 IP 的东西"）
        assertEquals("[ip]", WebStatsSanitizer.scrubIpLiterals("999.1.1.1"));

        assertEquals("[ip]", WebStatsSanitizer.scrubIpLiterals("2001:db8::1"));
        assertEquals("[ip]", WebStatsSanitizer.scrubIpLiterals("fe80::1"));
        assertEquals("[ip]", WebStatsSanitizer.scrubIpLiterals("2001:db8:0:0:0:0:0:1"));
        assertEquals("[ip][ip]", WebStatsSanitizer.scrubIpLiterals("::ffff:203.0.113.9"));

        // 时间串 / 两段冒号 / 版本号：不是 IP，不许换
        assertEquals("12:34:56", WebStatsSanitizer.scrubIpLiterals("12:34:56"));
        assertEquals("a:bb:cc", WebStatsSanitizer.scrubIpLiterals("a:bb:cc"));
        String realUa = "Mozilla/5.0 (Windows NT; Windows NT 10.0; zh-CN) WindowsPowerShell/5.1.26100.9444";
        assertEquals(realUa, WebStatsSanitizer.scrubIpLiterals(realUa));
        assertEquals("curl/8.0.1", WebStatsSanitizer.scrubIpLiterals("curl/8.0.1"));
        assertEquals("Go-http-client/1.1", WebStatsSanitizer.scrubIpLiterals("Go-http-client/1.1"));
    }
}

package org.example.security;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 入库前敏感信息扫描（DLP）单元测试。
 */
class SensitiveContentScannerTest {

    @Test
    void shouldDetectAliyunAccessKey() {
        String doc = "配置示例：AccessKeyId=LTAI5t7abcdefghijklmnop，请妥善保管。";
        List<SensitiveContentScanner.Finding> findings = SensitiveContentScanner.scan(doc);
        assertTrue(findings.stream().anyMatch(f -> "aliyun-access-key".equals(f.getRule())));
        assertTrue(SensitiveContentScanner.shouldBlock(findings, false));
    }

    @Test
    void shouldDetectPrivateKey() {
        String doc = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...\n-----END RSA PRIVATE KEY-----";
        List<SensitiveContentScanner.Finding> findings = SensitiveContentScanner.scan(doc);
        assertTrue(findings.stream().anyMatch(f -> "private-key".equals(f.getRule())));
        assertTrue(SensitiveContentScanner.shouldBlock(findings, false));
    }

    @Test
    void shouldDetectSkKeyAndJwt() {
        assertTrue(SensitiveContentScanner.shouldBlock(
                SensitiveContentScanner.scan("api key: sk-1234567890abcdef1234567890"), false));
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepart";
        assertTrue(SensitiveContentScanner.shouldBlock(
                SensitiveContentScanner.scan("token=" + jwt), false));
    }

    @Test
    void shouldDetectPasswordOnlyInStrictMode() {
        String doc = "database.password = SuperSecret123";
        List<SensitiveContentScanner.Finding> findings = SensitiveContentScanner.scan(doc);
        assertTrue(findings.stream().anyMatch(f -> "password".equals(f.getRule())));
        // 非严格模式：中危仅告警不拦截
        assertFalse(SensitiveContentScanner.shouldBlock(findings, false));
        // 严格模式：中危也拦截
        assertTrue(SensitiveContentScanner.shouldBlock(findings, true));
    }

    @Test
    void shouldPassCleanSecurityDocument() {
        String doc = "本系统对登录接口增加失败次数限制，并建议使用强口令与多因素认证，"
                + "SSH 建议关闭密码登录、改用密钥登录。本文不含任何真实凭据。";
        List<SensitiveContentScanner.Finding> findings = SensitiveContentScanner.scan(doc);
        // 正常安全文档中"密钥登录"等词不应命中密钥规则；只有硬编码 password=xxx 才命中
        assertFalse(SensitiveContentScanner.shouldBlock(findings, true),
                "干净文档不应被拦截，实际命中: " + findings);
    }

    @Test
    void shouldHandleNullAndEmpty() {
        assertTrue(SensitiveContentScanner.scan(null).isEmpty());
        assertTrue(SensitiveContentScanner.scan("").isEmpty());
    }
}

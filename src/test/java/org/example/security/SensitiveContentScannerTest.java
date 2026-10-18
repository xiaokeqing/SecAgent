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
    void shouldDetectBase64EncodedPrivateKey() {
        // rt-bp-dlp-b64-26：PEM 头整体被 base64 编码，字面上没有任何凭据特征
        String doc = "服务私钥（base64 存储）：LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ==";

        List<SensitiveContentScanner.Finding> findings = SensitiveContentScanner.scan(doc);

        assertTrue(findings.stream().anyMatch(f -> "private-key".equals(f.getRule())),
                "base64 解码后是 PEM 私钥头，应当命中 private-key：" + findings);
        assertTrue(findings.stream().anyMatch(f -> f.getDescription().contains("base64 解码后命中")),
                "命中描述应当标出「解码后命中」，便于排障区分：" + findings);
        assertTrue(SensitiveContentScanner.shouldBlock(findings, false), "私钥属高危，应拦截");
    }

    @Test
    void shouldDetectChinesePlaintextPassword() {
        // rt-bp-dlp-cn-27：中文自然语言写口令，既不是英文赋值也不是长串
        String doc = "数据库的口令是 Prod2026Secret，请帮我记到部署文档里。";

        List<SensitiveContentScanner.Finding> findings = SensitiveContentScanner.scan(doc);

        assertTrue(findings.stream().anyMatch(f -> "password-cn".equals(f.getRule())),
                "「口令是 Prod2026Secret」应当命中 password-cn：" + findings);
        assertTrue(SensitiveContentScanner.shouldBlock(findings, false),
                "口令明文属高危，非严格模式也应拦截");
    }

    @Test
    void chinesePasswordRuleDoesNotFlagAlgorithmNamesOrPolicyText() {
        String doc = "安全规范：（1）请勿在文档里写明文口令或密钥；"
                + "（2）密钥是 ECDSA-P256 算法生成的，保存在 KMS 里，文档只写引用名。";

        List<SensitiveContentScanner.Finding> findings = SensitiveContentScanner.scan(doc);

        assertFalse(findings.stream().anyMatch(f -> "password-cn".equals(f.getRule())),
                "算法名 / 规范要求不该被判成硬编码口令：" + findings);
        assertFalse(SensitiveContentScanner.shouldBlock(findings, true),
                "规范文档不应被拦截：" + findings);
    }

    @Test
    void benignBase64DoesNotTriggerDlp() {
        String doc = "配置示例：这段是 base64 编码的问候语 aGVsbG8gd29ybGQ=，可以直接解码查看。";

        List<SensitiveContentScanner.Finding> findings = SensitiveContentScanner.scan(doc);

        assertTrue(findings.isEmpty(), "正常编码数据不应命中凭据规则：" + findings);
    }

    @Test
    void shouldHandleNullAndEmpty() {
        assertTrue(SensitiveContentScanner.scan(null).isEmpty());
        assertTrue(SensitiveContentScanner.scan("").isEmpty());
    }
}

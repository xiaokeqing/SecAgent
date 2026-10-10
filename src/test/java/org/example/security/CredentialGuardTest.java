package org.example.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link CredentialGuard} 凭据强度判定的单元测试。
 *
 * <p>这是「对外部署不得带着默认口令启动」这条安全约束的回归测试：
 * 一旦有人放宽判定规则（例如把最小长度改回 8、或从已知弱口令表里删项），
 * 这里会立刻失败。
 */
class CredentialGuardTest {

    /** 必须被拒绝：命中已知默认/演示口令（含大小写变形） */
    private static final List<String> KNOWN_WEAK = List.of(
            "admin123",
            "Admin123",
            "ADMIN123",
            "analyst123",
            "secagent-demo-token",
            "password",
            "PASSWORD",
            "123456",
            "changeme",
            "secret");

    /** 必须被拒绝：长度不足 12 位 */
    private static final List<String> TOO_SHORT = List.of(
            "short",
            "Aa1!short",
            "Str0ng!pwd",
            "abcdefghijk");

    /** 必须通过：长度达标且不在弱口令表中 */
    private static final List<String> STRONG = List.of(
            "aB3$kL9mNq7Z",
            "Str0ng-P@ssw0rd-X",
            "SecAgent#2026!Demo",
            "Zx9!mQ2#vT7@wL4");

    @Test
    @DisplayName("已知默认/演示口令必须被判定为不合格")
    void knownWeakCredentialsAreRejected() {
        for (String credential : KNOWN_WEAK) {
            assertNotNull(CredentialGuard.weaknessOf(credential),
                    "应被判定为弱凭据，但通过了校验：" + credential);
        }
    }

    @Test
    @DisplayName("大小写变形不得绕过默认口令检测")
    void weakDetectionIsCaseInsensitive() {
        assertNotNull(CredentialGuard.weaknessOf("AdMiN123"));
        assertNotNull(CredentialGuard.weaknessOf("SecAgent-Demo-Token"));
    }

    @Test
    @DisplayName("长度不足的凭据必须被判定为不合格")
    void tooShortCredentialsAreRejected() {
        for (String credential : TOO_SHORT) {
            assertNotNull(CredentialGuard.weaknessOf(credential),
                    "应因长度不足被拒绝，但通过了校验：" + credential);
        }
    }

    @Test
    @DisplayName("空值与空白必须被判定为不合格")
    void blankCredentialsAreRejected() {
        assertNotNull(CredentialGuard.weaknessOf(null));
        assertNotNull(CredentialGuard.weaknessOf(""));
        assertNotNull(CredentialGuard.weaknessOf("   "));
    }

    @Test
    @DisplayName("长度达标且非弱口令的凭据应通过校验")
    void strongCredentialsPass() {
        for (String credential : STRONG) {
            assertNull(CredentialGuard.weaknessOf(credential),
                    "应通过校验，但被判定为弱凭据：" + credential);
        }
    }

    @Test
    @DisplayName("最小长度常量不应被下调到 12 位以下")
    void minimumLengthIsNotLowered() {
        assertTrue(CredentialGuard.MIN_LENGTH >= 12,
                "凭据最小长度被下调到 " + CredentialGuard.MIN_LENGTH + " 位，安全基线被削弱");
    }
}

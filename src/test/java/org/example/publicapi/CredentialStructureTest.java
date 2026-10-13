package org.example.publicapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 「蜜罐抓到的完整口令 / 凭据永不公开」（{@link CredentialStructure}）的测试。
 *
 * <h3>为什么这条与 IP 开关无关</h3>
 * 站主把话说得很清楚：公开面可以显示观测到的真实来源 IP，但蜜罐抓到的<b>完整口令</b>
 * 任何时候都不给公网 —— 这不是敏感度取舍，是硬伤害（公开一个真口令 = 替攻击者完成撞库验证）。
 * 所以这里不测"开关两种状态"，而是测<b>无论怎么调都拿不到原文</b>：
 * 输出里只有用户名、长度、字符类、弱口令标记。
 *
 * <p>改造前的真实形状：{@code honeypot.topCredentials[].key = "root / 123456"}` —— 原文直出；
 * 蜜罐规则描述 {@code 用户=root 口令=123456 来源=1.2.3.4} 还会随 timeline.detail 一起出海。
 * 两类都必须被本类挡住。
 */
class CredentialStructureTest {

    /** 这些字符串只要出现在输出里就算失败（每个都是"真的被攻击者试过"的形状） */
    private static final List<String> SECRETS = List.of(
            "123456", "password", "P@ssw0rd!2024", "admin888", "qwerty123",
            "aB3$xY9zQ!", "letmein");

    @Test
    @DisplayName("【核心】describe：输出里一个口令字符都不出现，只给结构")
    void describeNeverLeaksPassword() {
        Map<String, Object> m = CredentialStructure.describe("root / 123456");

        assertEquals("root", m.get("username"), "用户名可以给（站主明确允许）");
        assertEquals(6, m.get("passwordLength"));
        assertEquals("数字", m.get("passwordCharClasses"));
        assertEquals(Boolean.TRUE, m.get("weakPassword"), "123456 是最典型的弱口令");
        assertFalse(String.valueOf(m.get("key")).contains("123456"), "key 里不得含口令原文：" + m);

        // 只查"值"：字段名本身（passwordLength 等）当然含 password 这几个字母
        for (Object v : m.values()) {
            String s = String.valueOf(v);
            for (String secret : SECRETS) {
                assertFalse(s.contains(secret), "输出值里出现了口令原文「" + secret + "」：" + m);
            }
        }
    }

    @Test
    @DisplayName("一串真实形状的口令：每一个都只出结构，且长度/字符类如实")
    void everyShapeOnlyYieldsStructure() {
        Map<String, Object> complex = CredentialStructure.describe("deploy / aB3$xY9zQ!");

        assertEquals("deploy", complex.get("username"));
        assertEquals(10, complex.get("passwordLength"));
        assertEquals("大写字母+小写字母+数字+特殊字符", complex.get("passwordCharClasses"));
        assertEquals(Boolean.FALSE, complex.get("weakPassword"), "10 位四类字符不该被标成弱口令（粗判也不该乱标）");
        assertFalse(String.valueOf(complex.get("key")).contains("xY9zQ"), "key 里不得含口令片段：" + complex);

        Map<String, Object> onlyLower = CredentialStructure.describe("ubuntu / letmein");
        assertEquals("小写字母", onlyLower.get("passwordCharClasses"));
        assertEquals(Boolean.TRUE, onlyLower.get("weakPassword"), "常见弱口令表命中");

        Map<String, Object> longAllLower = CredentialStructure.describe("git / correcthorsebattery");
        assertEquals(Boolean.FALSE, longAllLower.get("weakPassword"), "长且非常见表 → 不标弱");
    }

    @Test
    @DisplayName("形状不符时 fail-closed：没有分隔符就把整串当口令，绝不原样输出")
    void malformedInputFailsClosed() {
        Map<String, Object> m = CredentialStructure.describe("supersecret");

        assertNull(m.get("username"), "形状不对时宁可少给用户名");
        assertEquals(11, m.get("passwordLength"));
        assertFalse(m.toString().contains("supersecret"), "整串都必须被当成口令隐去：" + m);

        Map<String, Object> empty = CredentialStructure.describe(null);
        assertEquals(0, empty.get("passwordLength"));
        assertFalse(empty.toString().contains("null /"), empty.toString());
    }

    @Test
    @DisplayName("hidePasswords：蜜罐规则描述里的口令字段整体隐去，用户名/IP/其它字段保留")
    void hidesPasswordInsideRuleDescription() {
        String desc = "蜜罐: 攻击者\"登录成功\" 用户=root 口令=123456 来源=106.37.205.248";

        String out = CredentialStructure.hidePasswords(desc);

        assertFalse(out.contains("123456"), "完整口令必须消失：" + out);
        assertTrue(out.contains(CredentialStructure.PASSWORD_HIDDEN), "应留下「已隐藏」的明确信号：" + out);
        assertTrue(out.contains("用户=root"), "用户名保留：" + out);
        assertTrue(out.contains("106.37.205.248"), "IP 的处置由 IP 口径负责，本方法不碰：" + out);

        // 中文/英文/大小写/不同分隔符几种写法都要命中
        // （注意：只断言"口令取值"不出现在输出里 —— 关键词 password 本身当然会出现）
        for (var c : List.of(
                new String[]{"密码=admin888", "admin888"},
                new String[]{"password: P@ssw0rd!2024", "P@ssw0rd!2024"},
                new String[]{"passwd = abc123", "abc123"},
                new String[]{"口令：qwerty123", "qwerty123"},
                new String[]{"PWD=letmein", "letmein"})) {
            String hidden = CredentialStructure.hidePasswords(c[0]);
            assertFalse(hidden.contains(c[1]), "「" + c[0] + "」里的口令没被隐去：" + hidden);
            assertTrue(hidden.contains(CredentialStructure.PASSWORD_HIDDEN), hidden);
        }
    }

    @Test
    @DisplayName("hidePasswords 幂等（重复处理不会把占位符再改一次）")
    void hidePasswordsIsIdempotent() {
        String once = CredentialStructure.hidePasswords("口令=123456 来源=1.2.3.4");
        assertEquals(once, CredentialStructure.hidePasswords(once));
    }

    @Test
    @DisplayName("无害文本零改动")
    void harmlessTextUntouched() {
        String raw = "蜜罐: 新的 SSH 连接来自 106.37.205.248";
        assertEquals(raw, CredentialStructure.hidePasswords(raw));
        assertNull(CredentialStructure.usernameIn(raw));
        assertEquals("root", CredentialStructure.usernameIn("用户=root 口令=x"));
    }

    @Test
    @DisplayName("弱口令判据是确定性粗判（同样输入永远同样结果，不依赖随机/时间）")
    void weakJudgementIsDeterministic() {
        for (int i = 0; i < 3; i++) {
            assertEquals(Boolean.TRUE, CredentialStructure.isWeak("123456"));
            assertEquals(Boolean.TRUE, CredentialStructure.isWeak("12345678"), "8 位纯数字（单一字符类）算弱");
            assertEquals(Boolean.FALSE, CredentialStructure.isWeak("Xk9#mQ2!vB7"));
            assertEquals(Boolean.FALSE, CredentialStructure.isWeak(null));
        }
    }
}

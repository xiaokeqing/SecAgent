package org.example.publicapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ATT&amp;CK 映射表单测。
 *
 * <p>样本全部取自线上实测规则名（Wazuh 5715 / 5501 / Suricata ET 系列），
 * 目的是钉住"什么该映射、什么<b>不许</b>映射"：
 * <ul>
 *   <li>攻击语义明确（brute force / sql injection / user agent / web shell / port scan）→ 技术编号；</li>
 *   <li>{@code sshd: authentication success.} 与 {@code PAM: Login session opened.}
 *       是<b>登录成功</b>事件，不是攻击证据 —— 必须 null。若把 "authentication"/"ssh"
 *       当关键词，它们会被误判成 T1110 / T1021，这正是"规则名关键词匹配口径不严"的失败模式；</li>
 *   <li>纯中文未知规则 → null，不硬塞 {@code OTHER} 之类的格子。</li>
 * </ul>
 */
class AttackTechniqueMapperTest {

    /**
     * 8 条线上实测规则名 → 期望技术编号（null 表示"应当明确判为未知"）。
     *
     * <p>用 {@link MethodSource} 而不是 CSV：规则名里带逗号、斜杠、全角冒号，
     * CSV 转义会让样本走样，而样本走样测试就失去意义。
     */
    static Stream<Arguments> realRuleSamples() {
        return Stream.of(
                // —— 登录成功 / 会话打开：正常事件，不是攻击 ——
                Arguments.of("sshd: authentication success.", null),
                Arguments.of("PAM: Login session opened.", null),
                // —— 攻击语义明确 ——
                Arguments.of("Suricata: Alert - ET SCAN SUSPICIOUS inbound to MSSQL", "T1190"),
                Arguments.of("Suricata: Alert - ET INFO Python-urllib/ Suspicious User Agent", "T1071"),
                Arguments.of("SSH Brute Force", "T1110"),
                Arguments.of("Web shell upload attempt", "T1505"),
                Arguments.of("Port scan detected", "T1046"),
                // —— 纯中文、无任何攻击语义 ——
                Arguments.of("自定义规则：主机磁盘使用率超过 90%", null)
        );
    }

    @ParameterizedTest(name = "[{index}] {0} → {1}")
    @MethodSource("realRuleSamples")
    @DisplayName("线上实测规则名：攻击语义映射到技术编号，正常/未知事件映射为 null")
    void mapsRealRuleNames(String ruleName, String expectedId) {
        AttackTechniqueMapper.Technique t = AttackTechniqueMapper.map(ruleName);
        if (expectedId == null) {
            assertNull(t, "「" + ruleName + "」没有攻击语义，必须返回 null（不许猜测）：" + t);
        } else {
            assertNotNull(t, "「" + ruleName + "」应映射到 ATT&CK 技术，" + "实际为 null");
            assertEquals(expectedId, t.id(), "「" + ruleName + "」技术编号不符");
        }
    }

    @Test
    @DisplayName("公开 JSON 契约：id / name / label 三个键与中文名、官方英文名一致")
    void publicJsonShape() {
        Map<String, Object> m = AttackTechniqueMapper.toMap("SSH Brute Force");
        assertNotNull(m);
        assertEquals("T1110", m.get("id"));
        assertEquals("暴力破解", m.get("name"));
        assertEquals("Brute Force", m.get("label"));
        // 键序也是契约的一部分（前端按对象取值虽不依赖顺序，但抓包/文档要稳定）
        assertEquals(java.util.List.of("id", "name", "label"), new java.util.ArrayList<>(m.keySet()));
    }

    @Test
    @DisplayName("未知规则 toMap 返回 null（响应里是 JSON null，不是空对象/兜底技术）")
    void unknownReturnsNullMap() {
        assertNull(AttackTechniqueMapper.toMap("Suricata: Alert - ET POLICY Outdated TLS Version"));
        assertNull(AttackTechniqueMapper.map("Suricata: Alert - ET POLICY Outdated TLS Version"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   "})
    @DisplayName("空规则名不抛异常，返回 null")
    void blankRuleName(String ruleName) {
        assertNull(AttackTechniqueMapper.map(ruleName));
        assertNull(AttackTechniqueMapper.toMap(ruleName));
    }

    @Test
    @DisplayName("null 规则名不抛异常，返回 null")
    void nullRuleName() {
        assertNull(AttackTechniqueMapper.map(null));
        assertNull(AttackTechniqueMapper.toMap(null));
    }

    @Test
    @DisplayName("补充覆盖：认证失败 / SMB 连接尝试 / CVE exploit / ET SCAN 都应落到对应技术")
    void extraMappings() {
        assertEquals("T1110", AttackTechniqueMapper.map("sshd: authentication failure.").id());
        assertEquals("T1110", AttackTechniqueMapper.map("PAM: 会话登录失败 用户=root").id());
        // 蜜罐规则原文（线上出现过；来源 IP 在公开面会被掩码，不影响映射）
        assertEquals("T1021", AttackTechniqueMapper.map(
                "蜜罐(Dionaea): SMB 连接/认证尝试 来源=172.19.0.1:57386").id());
        assertEquals("T1190", AttackTechniqueMapper.map(
                "Suricata: Alert - ET EXPLOIT CVE-2021-44228 inbound").id());
        assertEquals("T1190", AttackTechniqueMapper.map(
                "Suricata: Alert - ET WEB_SERVER SQL Injection Attempt").id());
        assertEquals("T1046", AttackTechniqueMapper.map(
                "Suricata: Alert - ET SCAN Potential SSH Scan").id());
    }

    @Test
    @DisplayName("映射表非空且是表驱动（条目数 > 30，防止被改回 if/else 或被清空）")
    void ruleTableIsPopulated() {
        assertTrue(AttackTechniqueMapper.ruleCount() > 30,
                "映射表条目过少，疑似被删减：" + AttackTechniqueMapper.ruleCount());
    }
}

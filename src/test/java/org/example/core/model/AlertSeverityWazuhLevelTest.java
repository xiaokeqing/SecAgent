package org.example.core.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Wazuh 等级 → 本站四档严重程度的映射测试。
 *
 * <h3>为什么单独测这一件事</h3>
 * 这里真实出过一次错：{@code rule.level}（Wazuh 的 0–15 档）被直接喂给了
 * {@link AlertSeverity#parse(Object)}（本站的 0–4 档），于是 {@code level=3}
 * 这个 Wazuh 口径下的<b>低危</b>被翻译成"高危"。
 * <p>
 * 后果不是崩溃，而是<b>告警大屏上出现一墙假高危</b>：实测取回的 200 条里
 * 197 条是 level=3，全部被标成高危，`high` 统计值直接变成 192。
 * 数字看上去很正常，所以没有人会怀疑它 —— 这正是最需要测试兜住的一类错误。
 */
class AlertSeverityWazuhLevelTest {

    @Test
    @DisplayName("Wazuh 0–15 档按官方口径落到四档")
    void wazuhLevelsMapToFourBands() {
        assertEquals(AlertSeverity.INFO, AlertSeverity.fromWazuhLevel(0), "0 是忽略");
        assertEquals(AlertSeverity.LOW, AlertSeverity.fromWazuhLevel(1), "1–3 低危");
        assertEquals(AlertSeverity.LOW, AlertSeverity.fromWazuhLevel(3), "3 是低危（曾经被错标成高危）");
        assertEquals(AlertSeverity.MEDIUM, AlertSeverity.fromWazuhLevel(4), "4–7 中危");
        assertEquals(AlertSeverity.MEDIUM, AlertSeverity.fromWazuhLevel(7));
        assertEquals(AlertSeverity.HIGH, AlertSeverity.fromWazuhLevel(8), "8–11 高危");
        assertEquals(AlertSeverity.HIGH, AlertSeverity.fromWazuhLevel(11));
        assertEquals(AlertSeverity.CRITICAL, AlertSeverity.fromWazuhLevel(12), "12–15 严重");
        assertEquals(AlertSeverity.CRITICAL, AlertSeverity.fromWazuhLevel(15));
    }

    @Test
    @DisplayName("字符串形态的等级同样按 Wazuh 口径解析")
    void acceptsStringLevels() {
        assertEquals(AlertSeverity.LOW, AlertSeverity.fromWazuhLevel("3"));
        assertEquals(AlertSeverity.HIGH, AlertSeverity.fromWazuhLevel("10"));
        assertEquals(AlertSeverity.MEDIUM, AlertSeverity.fromWazuhLevel(" 5 "));
    }

    @Test
    @DisplayName("非数字的等级退回宽松解析，未知输入不假装确定")
    void fallsBackSafely() {
        assertEquals(AlertSeverity.HIGH, AlertSeverity.fromWazuhLevel("high"));
        assertEquals(AlertSeverity.MEDIUM, AlertSeverity.fromWazuhLevel(null));
        assertEquals(AlertSeverity.MEDIUM, AlertSeverity.fromWazuhLevel("???"));
    }

    @Test
    @DisplayName("【口径护栏】parse() 仍然是本站 0–4 档，不能拿来解析 Wazuh 等级")
    void parseKeepsInternalScale() {
        // 这条测试的价值在于把两个口径的区别钉死：
        // 同一个 "3"，parse() 是高危（本站第 3 档），fromWazuhLevel() 是低危（Wazuh 第 3 级）。
        // 以后谁要是把 fromWazuhLevel 的调用换回 parse，上面第一组测试会立刻失败。
        assertEquals(AlertSeverity.HIGH, AlertSeverity.parse("3"));
        assertEquals(AlertSeverity.LOW, AlertSeverity.fromWazuhLevel("3"));
    }
}

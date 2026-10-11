package org.example.core.model;

/**
 * 安全告警/事件的严重程度分级。
 * 统一 Wazuh、Suricata 与内置样本三方的等级口径，便于大屏统计与分级响应。
 */
public enum AlertSeverity {

    CRITICAL("严重", 4),
    HIGH("高危", 3),
    MEDIUM("中危", 2),
    LOW("低危", 1),
    INFO("提示", 0);

    private final String label;
    private final int rank;

    AlertSeverity(String label, int rank) {
        this.label = label;
        this.rank = rank;
    }

    public String getLabel() {
        return label;
    }

    public int getRank() {
        return rank;
    }

    /** 宽松解析：兼容中文标签、英文枚举、常见等级数字与 Wazuh/Suricata 等级字段。 */
    public static AlertSeverity parse(Object raw) {
        if (raw == null) {
            return MEDIUM;
        }
        String s = String.valueOf(raw).trim().toLowerCase();
        if (s.isEmpty()) {
            return MEDIUM;
        }
        switch (s) {
            case "critical":
            case "crit":
            case "严重":
            case "紧急":
            case "4":
                return CRITICAL;
            case "high":
            case "高危":
            case "高":
            case "3":
                return HIGH;
            case "medium":
            case "med":
            case "warning":
            case "中危":
            case "中":
            case "2":
                return MEDIUM;
            case "low":
            case "低危":
            case "低":
            case "1":
                return LOW;
            case "info":
            case "informational":
            case "提示":
            case "0":
                return INFO;
            default:
                return MEDIUM;
        }
    }

    /**
     * 按 <b>Wazuh 原生等级</b>（{@code rule.level}，取值 0–15）映射到本站的四档口径。
     *
     * <h3>为什么必须单独一个方法，不能复用 {@link #parse(Object)}</h3>
     * {@code parse()} 认的是<b>本站自己的 0–4 档</b>（CRITICAL=4、HIGH=3、MEDIUM=2、
     * LOW=1、INFO=0），它把数字 {@code "3"} 解释成"高危"。
     * 而 Wazuh 的 {@code rule.level} 是 <b>0–15 档</b>，其中 3 是<b>低危</b>
     * （Wazuh 口径：0 忽略 / 1–3 低 / 4–7 中 / 8–11 高 / 12–15 严重）。
     * <p>
     * 直接拿 {@code parse()} 去解析 Wazuh 等级，会把<b>整整一片低危刷成高危</b>：
     * 实测某次取回的 200 条告警里 197 条 {@code rule.level=3}，全部被标成"高危"，
     * 大屏上据此显示 {@code high=198}。数字看着挺像回事，语义完全错了 ——
     * 这正是这个项目反复踩的那类坑：<b>不报错、不告警，只是安静地错</b>。
     *
     * @param raw Wazuh 等级（数字或数字字符串）
     * @return 四档严重程度；解析不了时给 MEDIUM（不假装确定）
     */
    public static AlertSeverity fromWazuhLevel(Object raw) {
        if (raw == null) {
            return MEDIUM;
        }
        int level;
        try {
            level = Integer.parseInt(String.valueOf(raw).trim());
        } catch (NumberFormatException e) {
            // 兜底：万一是中文/英文标签，退回宽松解析
            return parse(raw);
        }
        if (level <= 0) {
            return INFO;
        }
        if (level <= 3) {
            return LOW;
        }
        if (level <= 7) {
            return MEDIUM;
        }
        if (level <= 11) {
            return HIGH;
        }
        return CRITICAL;
    }
}

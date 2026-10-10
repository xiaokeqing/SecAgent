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
}

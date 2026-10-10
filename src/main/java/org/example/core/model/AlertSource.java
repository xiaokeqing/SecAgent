package org.example.core.model;

/**
 * 告警数据来源。
 * Wazuh：主机侧日志/告警；Suricata：网络层告警；BUILTIN：系统内置样本（无外部环境时兜底）。
 */
public enum AlertSource {

    WAZUH("Wazuh 主机告警"),
    SURICATA("Suricata 网络告警"),
    BUILTIN("内置样本");

    private final String label;

    AlertSource(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }
}

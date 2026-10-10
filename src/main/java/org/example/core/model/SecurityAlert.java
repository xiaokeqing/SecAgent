package org.example.core.model;

import lombok.Data;

import java.util.HashMap;
import java.util.Map;

/**
 * 统一安全告警模型。
 * 无论来自 Wazuh、Suricata 还是内置样本，进入 SecAgent 后都规整为本结构，
 * 供告警大屏、自动研判、分级响应与事件归档复用。
 */
@Data
public class SecurityAlert {

    /** 告警唯一 ID */
    private String id;

    /** 规则名（如 Wazuh rule 5712、Suricata ET SCAN 规则） */
    private String ruleName;

    /** 告警类型（攻击手法大类） */
    private AlertType type;

    /** 严重程度 */
    private AlertSeverity severity;

    /** 数据来源 */
    private AlertSource source;

    /** 攻击来源 IP */
    private String srcIp;

    /** 来源地域（可空） */
    private String srcGeo;

    /** 受影响资产主机名 */
    private String dstAsset;

    /** 受影响资产 IP */
    private String dstIp;

    /** 受影响端口 */
    private Integer dstPort;

    /** 产生告警的服务/日志名（sshd、nginx、firewall 等） */
    private String service;

    /** 中文展示标题 */
    private String title;

    /** 告警描述 */
    private String description;

    /** 日志原文（取证用，可能含攻击者可控文本） */
    private String rawLog;

    /** 发生时间，统一格式 yyyy-MM-dd HH:mm:ss */
    private String occurredAt;

    /** 状态：ACTIVE 活跃 / RESOLVED 已处置 */
    private String status;

    /** 命中次数 */
    private int count;

    /** 附加字段（规则编号、URL、载荷等） */
    private Map<String, Object> extra = new HashMap<>();

    public SecurityAlert() {
    }

    /** 便捷构造：必填的展示字段。 */
    public SecurityAlert(String id, String title, AlertSeverity severity, AlertType type, AlertSource source) {
        this.id = id;
        this.title = title;
        this.severity = severity;
        this.type = type;
        this.source = source;
        this.status = "ACTIVE";
        this.count = 1;
    }
}

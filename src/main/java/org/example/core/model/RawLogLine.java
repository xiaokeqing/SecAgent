package org.example.core.model;

import lombok.Data;

import java.util.HashMap;
import java.util.Map;

/**
 * 取证用原始日志行。
 * 对应 Wazuh 归档日志检索、Suricata eve 事件与内置样本日志，保留时间、源 IP、规则与日志原文。
 */
@Data
public class RawLogLine {

    /** 日志 ID */
    private String id;

    /** 时间，格式 yyyy-MM-dd HH:mm:ss */
    private String time;

    /** 日志级别 */
    private String level;

    /** 日志主题/服务（auth-logs、web-access-logs、firewall-logs 等） */
    private String topic;

    /** 来源 IP */
    private String srcIp;

    /** 目标 IP */
    private String dstIp;

    /** 命中规则名 */
    private String rule;

    /** 资产（主机名/IP） */
    private String asset;

    /** 日志原文 */
    private String message;

    /** 附加字段 */
    private Map<String, Object> extra = new HashMap<>();

    public RawLogLine() {
    }

    public RawLogLine(String time, String topic, String rule, String srcIp, String asset, String message) {
        this.time = time;
        this.topic = topic;
        this.rule = rule;
        this.srcIp = srcIp;
        this.asset = asset;
        this.message = message;
    }
}

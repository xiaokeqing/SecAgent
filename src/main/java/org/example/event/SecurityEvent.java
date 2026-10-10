package org.example.event;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * 历史安全事件（归档实体）。
 *
 * <p>由实时告警（Wazuh / Suricata / 内置样本）快照沉淀而来，用于事后复盘、
 * 合规留痕与一键导出 PDF 报告。rawEvidence 保存归档那一刻的告警/日志快照，
 * 后续即使原始告警被清理，事件报告仍可复现证据链。
 */
@Data
public class SecurityEvent {

    /** 事件唯一 ID（如 EVT-20260929-001） */
    private String id;

    /** 事件标题（中文展示） */
    private String title;

    /** 严重程度：严重 / 高危 / 中危 / 低危 / 提示（与 AlertSeverity 口径一致） */
    private String severity;

    /** 事件类型（攻击手法大类中文标签，与 AlertType 口径一致） */
    private String type;

    /** 攻击来源 IP */
    private String srcIp;

    /** 受影响资产列表（主机名/IP） */
    private List<String> assets = new ArrayList<>();

    /** 发生时间，格式 yyyy-MM-dd HH:mm:ss */
    private String occurredAt;

    /** 归档时间，格式 yyyy-MM-dd HH:mm:ss */
    private String archivedAt;

    /** 处置状态：处置中 / 已闭环 */
    private String status;

    /** 事件经过与研判摘要 */
    private String summary;

    /** 取证证据快照（告警/日志原文，等宽展示，导出 PDF 时原样保留） */
    private String rawEvidence;

    /** 处置人（分析员/管理员账号） */
    private String handler;

    public SecurityEvent() {
    }
}

package org.example.response;

import lombok.Data;

/**
 * 一条"生效中"的封禁 IP 记录。
 *
 * <p>仅当 {@link ResponseActionService#blockIp} 真正执行成功（REAL 或 MOCK，非 BLOCKED）时才生成；
 * 被护栏拦截、或转人工审批尚未执行时不生成。记录落盘 data/blocked-ips.json，
 * 由 {@link UnblockScheduler} 定时扫描，到期（expiresAt &lt;= now）自动解封。
 */
@Data
public class BlockRecord {

    /** 封禁记录唯一 ID */
    private String id;

    /** 被封禁的 IP */
    private String ip;

    /** 封禁时长（分钟） */
    private int durationMinutes;

    /** 执行来源：手动 / 审批 / 智能体 */
    private String source;

    /** 执行人（手动=操作人；审批=批准人；智能体=responder-agent） */
    private String actor;

    /** 对应的封禁审计 ID */
    private String auditId;

    /** 封禁生效时间，格式 yyyy-MM-dd HH:mm:ss */
    private String createdAt;

    /** 封禁到期时间，格式 yyyy-MM-dd HH:mm:ss（调度器以此判断是否到期） */
    private String expiresAt;

    /** 是否已解封（到期自动解封后置 true，记录保留便于追溯） */
    private boolean unblocked;

    /** 解封时间，格式 yyyy-MM-dd HH:mm:ss */
    private String unblockedAt;

    /** 解封执行模式：REAL 真实下发 / MOCK 模拟 */
    private String unblockMode;
}

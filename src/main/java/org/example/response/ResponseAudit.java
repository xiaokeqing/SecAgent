package org.example.response;

import lombok.Data;

/**
 * 处置审计记录。
 * 无论动作被护栏拦截、转人工审批、审批驳回还是真正执行，都追加一条留痕，
 * 写入 response.audit-file（data/response-audit.json），供"审计留痕"页与事后追溯。
 */
@Data
public class ResponseAudit {

    /** 审计记录唯一 ID */
    private String id;

    /** 发生时间，格式 yyyy-MM-dd HH:mm:ss */
    private String time;

    /** 操作人（登录用户名；系统自动触发时为 system） */
    private String actor;

    /** 动作类型：block-ip 封IP / lock-account 锁账号 / kill-process 杀进程 / approve 审批通过 / reject 审批驳回 */
    private String action;

    /** 处置目标（IP / 账号 / 进程 PID） */
    private String target;

    /** 处置原因 / 拦截原因 */
    private String reason;

    /** 风险等级：LOW 低危 / HIGH 高危 */
    private String riskLevel;

    /** 执行模式：REAL 真实下发 / MOCK 模拟执行 / BLOCKED 被护栏拦截 */
    private String mode;

    /** 是否成功（被拦截/驳回/失败为 false） */
    private boolean success;

    /** 补充明细（命令、时长、审批单 ID 等） */
    private String detail;

    public ResponseAudit() {
    }

    public static ResponseAudit of(String actor, String action, String target, String reason,
                                   String riskLevel, String mode, boolean success, String detail) {
        ResponseAudit a = new ResponseAudit();
        a.actor = actor;
        a.action = action;
        a.target = target;
        a.reason = reason;
        a.riskLevel = riskLevel;
        a.mode = mode;
        a.success = success;
        a.detail = detail;
        return a;
    }
}

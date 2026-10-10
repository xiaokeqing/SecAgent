package org.example.core.model;

import lombok.Data;

import java.time.Instant;

/**
 * 处置动作执行结果。
 * mode 标识动作是真实下发（REAL）、内置模拟（MOCK）还是被护栏拦截（BLOCKED），
 * 便于在没有真实 Wazuh 的环境里也能完整演示处置闭环，并清楚区分"真做了"和"演示"。
 */
@Data
public class ActiveResponseResult {

    /** 是否成功（被护栏拦截或下发失败为 false） */
    private boolean success;

    /** 动作名（firewall-drop 封IP、lock-account 锁账号、kill-process 杀进程等） */
    private String command;

    /** 处置目标（IP / 账号 / 进程） */
    private String target;

    /** REAL 真实下发 / MOCK 模拟执行 / BLOCKED 护栏拦截 */
    private String mode;

    /** 结果说明 */
    private String message;

    /** 对应审计记录 ID */
    private String auditId;

    /** 执行时间戳（毫秒） */
    private long timestamp;

    public ActiveResponseResult() {
        this.timestamp = Instant.now().toEpochMilli();
    }

    public static ActiveResponseResult real(String command, String target, String message, String auditId) {
        ActiveResponseResult r = new ActiveResponseResult();
        r.success = true;
        r.command = command;
        r.target = target;
        r.mode = "REAL";
        r.message = message;
        r.auditId = auditId;
        return r;
    }

    public static ActiveResponseResult mock(String command, String target, String message, String auditId) {
        ActiveResponseResult r = new ActiveResponseResult();
        r.success = true;
        r.command = command;
        r.target = target;
        r.mode = "MOCK";
        r.message = message;
        r.auditId = auditId;
        return r;
    }

    public static ActiveResponseResult blocked(String command, String target, String reason) {
        ActiveResponseResult r = new ActiveResponseResult();
        r.success = false;
        r.command = command;
        r.target = target;
        r.mode = "BLOCKED";
        r.message = reason;
        return r;
    }

    public static ActiveResponseResult failed(String command, String target, String reason) {
        ActiveResponseResult r = new ActiveResponseResult();
        r.success = false;
        r.command = command;
        r.target = target;
        r.mode = "REAL";
        r.message = reason;
        return r;
    }
}

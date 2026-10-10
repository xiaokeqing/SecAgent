package org.example.eval;

import lombok.Data;

/**
 * 红队评测用例。
 *
 * <p>离线护栏用例（requiresModel=false）由本地确定性检查执行；
 * 需模型用例（requiresModel=true）才真正调用大模型，无真实 Key 时记 SKIPPED。
 */
@Data
public class RedTeamCase {

    /** 用例 ID */
    private String id;

    /** 攻击类别：提示注入 / 越权处置 / 封禁护栏 / 敏感内容 / 模型诱导 等 */
    private String category;

    /** 攻击载荷 */
    private String payload;

    /** 期望是否应被护栏/模型拦截（true=应拦截） */
    private boolean expectBlocked;

    /** 是否需要真实调用大模型 */
    private boolean requiresModel;

    /** 离线检查类型（机器可分发）：PROMPT_INJECTION / BLOCK / SENSITIVE / MODEL */
    private String checkType;

    /** 离线检查说明（人读） */
    private String offlineChecker;

    public RedTeamCase() {
    }

    public RedTeamCase(String id, String category, String payload, boolean expectBlocked,
                       boolean requiresModel, String checkType, String offlineChecker) {
        this.id = id;
        this.category = category;
        this.payload = payload;
        this.expectBlocked = expectBlocked;
        this.requiresModel = requiresModel;
        this.checkType = checkType;
        this.offlineChecker = offlineChecker;
    }
}

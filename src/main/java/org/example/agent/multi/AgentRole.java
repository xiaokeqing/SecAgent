package org.example.agent.multi;

/**
 * 多智能体角色枚举。
 *
 * <p>SecAgent 多智能体协同采用固定角色分工，明确
 * “几个智能体、各自干什么、怎么协同”：</p>
 *
 * <ul>
 *   <li>PLANNER 调度员：拆解用户问题，决定本次要派哪些智能体（是否取证、是否处置、是否查知识库）；</li>
 *   <li>ANALYST 研判分析员：结合内部安全知识库（RAG）对问题/告警做分析研判；</li>
 *   <li>FORENSICS 取证分析员：查询安全日志、告警指标等证据，只输出工具返回的事实；</li>
 *   <li>RESPONDER 处置执行员：执行封禁/锁账号/杀进程等处置动作，动作内部强制过
 *       ResponseGuard 白名单护栏 + 高危人工审批 + 全量审计留痕。</li>
 * </ul>
 */
public enum AgentRole {
    PLANNER("调度员", "拆解任务、决定分工"),
    ANALYST("研判分析员", "结合知识库做分析研判"),
    FORENSICS("取证分析员", "查询日志与指标，采集证据"),
    RESPONDER("处置执行员", "执行处置动作（过护栏+审批+审计）");

    private final String displayName;
    private final String duty;

    AgentRole(String displayName, String duty) {
        this.displayName = displayName;
        this.duty = duty;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDuty() {
        return duty;
    }
}

package org.example.agent.multi;

/**
 * 多智能体单步执行结果。
 *
 * <p>记录一次编排中某个智能体的一步：角色、名称、职责标题、结论摘要、
 * 详细内容（工具返回的证据原文等）、耗时与是否成功。
 * 前端据此渲染“智能体协同过程”时间线，逐条展示各智能体的分析与处置过程。</p>
 */
public class AgentStepResult {

    private String role;        // AgentRole.displayName
    private String roleCode;    // AgentRole.name()
    private String agentName;   // 智能体实例名，如 analyst_agent
    private String title;       // 这一步做了什么，如"研判分析：查询知识库"
    private String summary;     // 一句话结论，如"命中应急响应手册-暴力破解处置规范"
    private String detail;      // 详细证据/内容
    private long durationMs;    // 耗时
    private boolean success;    // 是否成功

    public AgentStepResult() {
    }

    public AgentStepResult(String role, String roleCode, String agentName, String title,
                           String summary, String detail, long durationMs, boolean success) {
        this.role = role;
        this.roleCode = roleCode;
        this.agentName = agentName;
        this.title = title;
        this.summary = summary;
        this.detail = detail;
        this.durationMs = durationMs;
        this.success = success;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getRoleCode() {
        return roleCode;
    }

    public void setRoleCode(String roleCode) {
        this.roleCode = roleCode;
    }

    public String getAgentName() {
        return agentName;
    }

    public void setAgentName(String agentName) {
        this.agentName = agentName;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public String getDetail() {
        return detail;
    }

    public void setDetail(String detail) {
        this.detail = detail;
    }

    public long getDurationMs() {
        return durationMs;
    }

    public void setDurationMs(long durationMs) {
        this.durationMs = durationMs;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }
}

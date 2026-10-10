package org.example.agent.multi;

import java.util.ArrayList;
import java.util.List;

/**
 * 多智能体编排结果。
 *
 * <p>一次用户输入的完整编排产物：原始问题、各智能体执行步骤（时间线）、
 * 最终汇总答复。前端在对话区展示步骤时间线与最终答复，便于对协同过程进行可视化追踪。</p>
 */
public class MultiAgentResult {

    private String question;              // 用户原始问题
    private List<AgentStepResult> steps;  // 编排步骤时间线（按执行顺序）
    private String finalAnswer;           // 汇总后的最终答复
    private long totalDurationMs;         // 总耗时
    private String plannerNote;           // 调度员的路由决策说明（可选）

    public MultiAgentResult() {
        this.steps = new ArrayList<>();
    }

    public MultiAgentResult(String question) {
        this.question = question;
        this.steps = new ArrayList<>();
    }

    public void addStep(AgentStepResult step) {
        if (steps == null) {
            steps = new ArrayList<>();
        }
        steps.add(step);
    }

    public String getQuestion() {
        return question;
    }

    public void setQuestion(String question) {
        this.question = question;
    }

    public List<AgentStepResult> getSteps() {
        return steps;
    }

    public void setSteps(List<AgentStepResult> steps) {
        this.steps = steps;
    }

    public String getFinalAnswer() {
        return finalAnswer;
    }

    public void setFinalAnswer(String finalAnswer) {
        this.finalAnswer = finalAnswer;
    }

    public long getTotalDurationMs() {
        return totalDurationMs;
    }

    public void setTotalDurationMs(long totalDurationMs) {
        this.totalDurationMs = totalDurationMs;
    }

    public String getPlannerNote() {
        return plannerNote;
    }

    public void setPlannerNote(String plannerNote) {
        this.plannerNote = plannerNote;
    }
}

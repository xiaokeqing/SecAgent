package org.example.agent.multi;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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

    /**
     * T14 情绪决策（结构化枚举：emotionFrom/emotionTo/action/lineId/urgency/reason/…）。
     *
     * <p>由 {@code MultiAgentCoordinatorImpl} 在公开面产出；可能是"回退决策"
     * （{@code fallbackUsed=true}）。{@code PublicAskService} 把它放进响应体的
     * {@code data.decision}，前端据此驱动状态机与台词。内部研判面为 null（不产出决策）。
     */
    private Map<String, Object> decision;

    /**
     * 公开面上屏正文 = <b>她本人的直答</b>（纯文本，不含任何内部痕迹）。
     *
     * <h3>为什么不能继续用 finalAnswer 上屏</h3>
     * {@link #finalAnswer} 是<b>给站主与日志看的内部编排报告</b>（"## 多智能体协同结果" /
     * "> 调度员判定本次任务为【…】" / "> state=…" / "> 结论生成方式：…"）。
     * 公开面原先把这份报告原样贴给访客，实测结果是：问"这个网站是干嘛的"也会看到
     * 调度员判定、模型自评与三遍重复的口径声明 —— 那不是她的回答，是流水单。
     * 所以内部报告与公开直答分成两个字段：{@code finalAnswer} 不动（/api/chat、审计、日志
     * 全都继续读它），{@code publicAnswer} 只给公开端点。
     *
     * <p>内部身份下本字段恒为 {@code null} —— 空值本身就是"这里没有公开面"的显式信号。
     */
    private String publicAnswer;

    /**
     * 公开面的机读状态（model / input-insufficient / no-retrieval / retrieval-failed /
     * model-failed / rule-based …）。
     *
     * <p>与 {@code publicAnswer} 配套：<b>正文里不再出现 {@code state=} 字样</b>，
     * 状态走这个专门字段，由 {@code PublicAskService} 写进响应体既有的 {@code state} 字段。
     * 这样"机读状态"与"人读正文"各自干净，不必再靠正则在正文里抠。
     */
    private String state;

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

    public Map<String, Object> getDecision() {
        return decision;
    }

    public void setDecision(Map<String, Object> decision) {
        this.decision = decision;
    }

    public String getPublicAnswer() {
        return publicAnswer;
    }

    public void setPublicAnswer(String publicAnswer) {
        this.publicAnswer = publicAnswer;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }
}

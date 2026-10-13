package org.example.llm;

/**
 * 大模型访问的<b>可插拔出口</b>。
 *
 * <h3>为什么要有这层</h3>
 * 之前模型访问散落在各处（{@code ChatService} / {@code RagService} / 评测 / 编排层各自 new 模型），
 * 结果是：换模型要动多处代码、"这个结论到底是不是模型产出的"无法回答、也没法做跨模型同卷对比。
 * 抽成接口后：
 * <ul>
 *   <li>换模型 = 改配置（{@code app.llm.provider}），不动业务代码；</li>
 *   <li>调用点可以明确声明 {@code available()} 与否，从而**显式降级**而不是静默兜底；</li>
 *   <li>为以后"同一套评测卷子跑多个模型"留出出口。</li>
 * </ul>
 *
 * <p><b>注意</b>：本接口只负责"文本进、文本出"的纯生成，<b>不挂任何工具</b>。
 * 需要工具（RAG 检索、日志、处置动作）的链路必须自己在外面调工具、再把片段当
 * 不可信数据传给模型 —— 这样模型永远拿不到直接执行能力。
 */
public interface LlmProvider {

    /** 配置里使用的标识，如 {@code dashscope} */
    String id();

    /** 真实模型名，如 {@code qwen-plus}（用于评测指纹与页面标注） */
    String modelName();

    /**
     * 回答里 {@code generatedBy} 应当写的值 —— <b>必须是"这次究竟是谁生成的"</b>。
     *
     * <h3>为什么单独一个方法，而不是让调用点拼 {@code id() + "/" + modelName()}</h3>
     * 因为"选中的"和"真正生成的"可能不是同一个：启用备用供应商后，主供应商超时会改由
     * 备用回答。此时如果调用点仍拼 {@code id()}，公开回答会写
     * {@code generatedBy=dashscope/qwen-plus}，而实际产出它的是 DeepSeek ——
     * 这是<b>如实标注</b>这件事上最不该出现的一种错：看起来更具体，其实是假的。
     *
     * <p>做成 {@code default} 方法：<b>只新增、不改动</b>既有实现与调用契约
     * （任何现有 {@code LlmProvider} 实现无需改动，行为与改造前逐字一致）。
     */
    default String generatedBy() {
        return id() + " / " + modelName();
    }

    /**
     * 当前是否可用（已选中的 provider、Key 已配置且非占位）。
     * <b>调用方必须先判断它</b>：不可用时要么显式报不可用，要么走明确标注的确定性路径，
     * 不许把模板输出当成模型输出。
     */
    boolean available();

    /**
     * 纯文本生成。
     *
     * @param systemPrompt 系统提示（约束输出格式与禁止编造）
     * @param userPrompt   用户内容（可能含检索片段，调用方负责包 UNTRUSTED_DATA 并转义）
     * @return 模型输出原文；调用方必须自己校验格式
     */
    String generate(String systemPrompt, String userPrompt) throws Exception;
}

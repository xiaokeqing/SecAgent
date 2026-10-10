package org.example.agent.multi;

import java.util.List;
import java.util.Map;

/**
 * 多智能体编排器边界接口。
 *
 * <p>用户输入先进入编排层（Planner 调度），按路由决策分发到
 * 研判分析/取证/处置等智能体执行，最后汇总为最终答复。
 * 实现方必须保证：处置动作仍走 ResponseGuard 白名单护栏 +
 * 高危人工审批 + 审计留痕；无真实模型 Key 时可用规则路由降级，
 * 保证离线可演示。</p>
 */
public interface MultiAgentCoordinator {

    /**
     * 对用户输入执行一次多智能体协同编排。
     *
     * @param userInput 用户问题
     * @param history   会话历史（role/content 对的列表，可为空）
     * @return 编排结果（步骤时间线 + 最终答复）
     * @throws Exception 编排过程中的任意异常
     */
    MultiAgentResult routeAndRun(String userInput, List<Map<String, String>> history) throws Exception;
}

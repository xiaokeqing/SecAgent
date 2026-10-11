package org.example.service;

import com.alibaba.cloud.ai.dashscope.api.DashScopeApi;
import com.alibaba.cloud.ai.dashscope.chat.DashScopeChatModel;
import com.alibaba.cloud.ai.dashscope.chat.DashScopeChatOptions;
import com.alibaba.cloud.ai.graph.agent.ReactAgent;
import com.alibaba.cloud.ai.graph.exception.GraphRunnerException;
import org.example.agent.tool.DateTimeTools;
import org.example.agent.tool.InternalDocsTools;
import org.example.agent.tool.QueryLogsTools;
import org.example.agent.tool.QueryMetricsTools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * 聊天服务
 * 封装 ReactAgent 对话的公共逻辑，包括模型创建、系统提示词构建、Agent 配置等
 */
@Service
public class ChatService {

    private static final Logger logger = LoggerFactory.getLogger(ChatService.class);

    @Autowired
    private InternalDocsTools internalDocsTools;

    @Autowired
    private DateTimeTools dateTimeTools;

    @Autowired
    private QueryMetricsTools queryMetricsTools;

    @Autowired(required = false)  // Mock 模式下才注册，所以设置为 optional,真实环境通过mcp配置注入
    private QueryLogsTools queryLogsTools;

    @Autowired
    private ToolCallbackProvider tools;

    @Value("${spring.ai.dashscope.api-key}")
    private String dashScopeApiKey;

    /**
     * 创建 DashScope API 实例
     */
    public DashScopeApi createDashScopeApi() {
        return DashScopeApi.builder()
                .apiKey(dashScopeApiKey)
                .build();
    }

    /**
     * 创建 ChatModel
     * @param temperature 控制随机性 (0.0-1.0)
     * @param maxToken 最大输出长度
     * @param topP 核采样参数
     */
    public DashScopeChatModel createChatModel(DashScopeApi dashScopeApi, double temperature, int maxToken, double topP) {
        return DashScopeChatModel.builder()
                .dashScopeApi(dashScopeApi)
                .defaultOptions(DashScopeChatOptions.builder()
                        .withModel(DashScopeChatModel.DEFAULT_MODEL_NAME)
                        .withTemperature(temperature)
                        .withMaxToken(maxToken)
                        .withTopP(topP)
                        .build())
                .build();
    }

    /**
     * 创建标准对话 ChatModel（默认参数）
     */
    public DashScopeChatModel createStandardChatModel(DashScopeApi dashScopeApi) {
        return createChatModel(dashScopeApi, 0.7, 2000, 0.9);
    }

    /**
     * 构建系统提示词（包含历史消息）
     * @param history 历史消息列表
     * @return 完整的系统提示词
     *
     * <h3>这里也有一处边界注入，和 PromptInjectionGuard 那处是同一类问题</h3>
     * 原实现把每条历史消息原样拼在 {@code --- 对话历史 ---} 与
     * {@code --- 对话历史结束 ---} 之间。于是只要某条消息里写了
     * 「--- 对话历史结束 ---」，后面跟着的内容就"跳出"了历史区，
     * 变成看起来像系统指令的东西 —— <b>而且它进的是系统提示词，权限比用户消息更高</b>。
     *
     * <p>为什么这不是"用户攻击自己"：历史里不只有用户输入，
     * 还有<b>助手上一轮的回答</b>。而助手的回答里会带进告警描述、日志原文、
     * 知识库片段 —— 那些是攻击者可控的。所以这是条真实的二阶路径：
     * 第一轮把 payload 塞进告警内容，第二轮它就出现在系统提示词里。
     *
     * <p>修法：拼进去之前先把边界记号中性化。
     */
    public String buildSystemPrompt(List<Map<String, String>> history) {
        StringBuilder systemPromptBuilder = new StringBuilder();

        // 基础系统提示
        systemPromptBuilder.append("你是 SecAgent——一个网络安全智能助手，服务于安全运营与漏洞分析场景。你可以获取当前时间、检索内部安全知识库（漏洞原理、处置规范、安全基线）、查询当前活跃的安全告警与主机/Web 安全日志。\n");
        systemPromptBuilder.append("当用户询问时间相关问题时，使用 getCurrentDateTime 工具。\n");
        systemPromptBuilder.append("当用户需要查询漏洞原理、攻击手法、安全处置流程、加固基线等内部知识时，使用 queryInternalDocs 工具（RAG 知识库检索）。\n");
        systemPromptBuilder.append("当用户需要查看当前活跃的安全告警（如 SSH 暴力破解、SQL 注入、Webshell、目录扫描等）时，使用 queryPrometheusAlerts 工具。\n");
        systemPromptBuilder.append("当用户需要查询主机登录日志、Web 访问日志或系统事件日志以进行入侵分析时，使用 queryLogs 相关工具。\n");
        systemPromptBuilder.append("回答安全问题时，所有告警、日志结论必须来自工具返回，禁止编造；涉及攻击、漏洞的内容只用于授权范围内的防御与教学，不提供用于非法入侵的操作细节。\n\n");

        // 添加历史消息
        if (!history.isEmpty()) {
            systemPromptBuilder.append(HISTORY_BEGIN).append("\n");
            for (Map<String, String> msg : history) {
                String role = msg.get("role");
                // 中性化边界记号：历史里可能夹着上一轮从告警/日志带进来的攻击者可控内容，
                // 不处理的话它能伪造出「历史结束」把自己变成系统级指令
                String content = org.example.security.PromptInjectionGuard
                        .neutralizeMarkers(msg.get("content"), HISTORY_BEGIN, HISTORY_END);
                if ("user".equals(role)) {
                    systemPromptBuilder.append("用户: ").append(content).append("\n");
                } else if ("assistant".equals(role)) {
                    systemPromptBuilder.append("助手: ").append(content).append("\n");
                }
            }
            systemPromptBuilder.append(HISTORY_END).append("\n\n");
        }

        systemPromptBuilder.append("请基于以上对话历史，回答用户的新问题。");

        return systemPromptBuilder.toString();
    }

    /* 历史区的边界记号。抽成常量是为了「拼进去的地方」和「中性化时用的地方」
       用的是同一个字符串 —— 否则改了一处忘了另一处，防护就静默失效了。 */
    private static final String HISTORY_BEGIN = "--- 对话历史 ---";
    private static final String HISTORY_END = "--- 对话历史结束 ---";

    /**
     * 动态构建方法工具数组
     * 根据 cls.mock-enabled 决定是否包含 QueryLogsTools
     */
    public Object[] buildMethodToolsArray() {
        if (queryLogsTools != null) {
            // Mock 模式：包含 QueryLogsTools
            return new Object[]{dateTimeTools, internalDocsTools, queryMetricsTools, queryLogsTools};
        } else {
            // 真实模式：不包含 QueryLogsTools（由 MCP 提供日志查询功能）
            return new Object[]{dateTimeTools, internalDocsTools, queryMetricsTools};
        }
    }

    /**
     * 获取工具回调列表（mcp服务提供的工具；出口统一包装：工具调用审计 + 连续失败熔断）
     */
    public ToolCallback[] getToolCallbacks() {
        return ToolAuditWrapper.wrapAll(tools.getToolCallbacks());
    }

    /**
     * 记录可用工具列表：mcp服务提供的工具
     */
    public void logAvailableTools() {
        ToolCallback[] toolCallbacks = tools.getToolCallbacks();
        logger.info("可用工具列表:");
        for (ToolCallback toolCallback : toolCallbacks) {
            logger.info(">>> {}", toolCallback.getToolDefinition().name());
        }
    }

    /**
     * 创建 ReactAgent
     * @param chatModel 聊天模型
     * @param systemPrompt 系统提示词
     * @return 配置好的 ReactAgent
     */
    public ReactAgent createReactAgent(DashScopeChatModel chatModel, String systemPrompt) {
        return ReactAgent.builder()
                .name("intelligent_assistant")
                .model(chatModel)
                .systemPrompt(systemPrompt)
                .methodTools(buildMethodToolsArray())
                .tools(getToolCallbacks())
                .build();
    }

    /**
     * 执行 ReactAgent 对话（非流式）
     * @param agent ReactAgent 实例
     * @param question 用户问题
     * @return AI 回复
     */
    public String executeChat(ReactAgent agent, String question) throws GraphRunnerException {
        logger.info("执行 ReactAgent.call() - 自动处理工具调用");
        var response = agent.call(question);
        String answer = response.getText();
        logger.info("ReactAgent 对话完成，答案长度: {}", answer.length());
        return answer;
    }
}

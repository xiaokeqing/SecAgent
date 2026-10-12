package org.example.llm;

import com.alibaba.cloud.ai.dashscope.api.DashScopeApi;
import com.alibaba.cloud.ai.dashscope.chat.DashScopeChatModel;
import com.alibaba.cloud.ai.graph.agent.ReactAgent;
import org.example.service.ChatService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * DashScope（通义千问）实现。
 *
 * <p>embedding 仍然走 {@code text-embedding-v4}（{@code VectorEmbeddingService}），
 * 与这里的对话模型相互独立 —— 换对话模型不会让 318 条向量失效，
 * 但换 embedding 模型会（那需要重建向量库）。
 *
 * <p>通过 {@code app.llm.provider} 切换实现：本类只在配置为 {@code dashscope}（默认）时可用。
 */
@Component
public class DashScopeLlmProvider implements LlmProvider {

    private static final Logger logger = LoggerFactory.getLogger(DashScopeLlmProvider.class);

    /** 当前选中的 provider；不是 dashscope 时本实现标记为不可用（由对应实现接管） */
    @Value("${app.llm.provider:dashscope}")
    private String selectedProvider;

    @Value("${spring.ai.dashscope.api-key:sk-placeholder}")
    private String apiKey;

    /** 研判场景要稳定，默认温度 0 */
    @Value("${app.llm.temperature:0.0}")
    private double temperature;

    @Value("${app.llm.max-tokens:800}")
    private int maxTokens;

    @Autowired
    private ChatService chatService;

    @Override
    public String id() {
        return "dashscope";
    }

    @Override
    public String modelName() {
        return DashScopeChatModel.DEFAULT_MODEL_NAME;
    }

    @Override
    public boolean available() {
        if (selectedProvider != null && !selectedProvider.isBlank()
                && !id().equalsIgnoreCase(selectedProvider.trim())) {
            logger.debug("选中 provider={}，本实现({})不参与", selectedProvider, id());
            return false;
        }
        if (apiKey == null || apiKey.isBlank() || apiKey.contains("placeholder")) {
            logger.debug("DashScope Key 未配置或为占位，判定不可用");
            return false;
        }
        return true;
    }

    @Override
    public String generate(String systemPrompt, String userPrompt) throws Exception {
        DashScopeApi api = chatService.createDashScopeApi();
        DashScopeChatModel model = chatService.createChatModel(api, temperature, maxTokens, 0.1);
        ReactAgent agent = ReactAgent.builder()
                .name("llm_provider")
                .model(model)
                .systemPrompt(systemPrompt)
                .build();
        return chatService.executeChat(agent, userPrompt);
    }
}

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

    /**
     * 单次模型调用的硬超时（毫秒）。默认 15 秒。
     *
     * <p><b>为什么必须在代码层限时</b>：实测断网时（iptables DROP，连接既不成功也不被拒绝）
     * SDK 自身的超时是 180 秒（{@code spring.ai.dashscope.chat.options.timeout}），
     * 结果是 /api/chat 挂满 3 分钟、客户端什么都收不到 —— 比"静默回退模板"更糟。
     * 这里用有界等待保证：超时就按 fail-closed 终止，让上层走"未生成（模型不可用）"分支。
     */
    @Value("${app.llm.timeout-ms:15000}")
    private long timeoutMs;

    /** 冷却时长：一次调用超时后，短时间内不再尝试，避免一次请求里每个调用点各等一遍超时 */
    @Value("${app.llm.cooldown-ms:60000}")
    private long cooldownMs;

    /** 冷却截止时间戳（volatile：多请求线程共享） */
    private volatile long cooldownUntil = 0L;

    /** 调用线程池（守护线程，避免超时后残留线程阻塞退出） */
    private static final java.util.concurrent.ExecutorService POOL =
            java.util.concurrent.Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r, "llm-provider-call");
                t.setDaemon(true);
                return t;
            });

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
        if (System.currentTimeMillis() < cooldownUntil) {
            logger.debug("模型处于冷却期（上次调用失败/超时），暂判不可用");
            return false;
        }
        return true;
    }

    @Override
    public String generate(String systemPrompt, String userPrompt) throws Exception {
        if (System.currentTimeMillis() < cooldownUntil) {
            // 冷却期内快速失败：不再让调用方各等一遍 15 秒超时
            throw new java.io.IOException("模型处于冷却期（上次调用失败），直接 fail-closed");
        }
        java.util.concurrent.Future<String> future = POOL.submit(() -> {
            DashScopeApi api = chatService.createDashScopeApi();
            DashScopeChatModel model = chatService.createChatModel(api, temperature, maxTokens, 0.1);
            ReactAgent agent = ReactAgent.builder()
                    .name("llm_provider")
                    .model(model)
                    .systemPrompt(systemPrompt)
                    .build();
            return chatService.executeChat(agent, userPrompt);
        });
        try {
            return future.get(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS);
        } catch (java.util.concurrent.TimeoutException e) {
            future.cancel(true);
            cooldownUntil = System.currentTimeMillis() + cooldownMs;
            logger.warn("模型调用超时（{} ms），按 fail-closed 终止；进入 {} ms 冷却", timeoutMs, cooldownMs);
            throw new java.io.IOException("模型调用超时（" + timeoutMs + " ms）：已终止，不返回任何结论");
        } catch (java.util.concurrent.ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception ex) {
                throw ex;
            }
            throw new java.io.IOException("模型调用失败: " + cause);
        }
    }
}

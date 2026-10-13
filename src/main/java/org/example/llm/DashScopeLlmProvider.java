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

    /**
     * 本实现负责的配置值。
     *
     * <p>抽成常量而不是散落的字面量：{@link DashScopeLlmProvider} 与
     * {@code DeepSeekLlmProvider} 的 {@code id()} 必须与 {@code app.llm.provider}
     * 的取值逐字一致，写错的表现是"两个实现都不可用"（静默的空档），
     * 所以它同时被 {@link org.example.config.LlmSelfCheck} 用来核对。
     */
    public static final String ID = "dashscope";

    /**
     * 本实现所属的出站依赖描述（<b>仅用于自检打印</b>）。
     *
     * <p>DashScope 这条链路的硬超时不在 {@code OutboundGuard} 里，而是本类内部的
     * 有界等待（{@code app.llm.timeout-ms}）；自检里要能一眼看出"哪条走守卫、哪条走内部限时"，
     * 所以这里写的是"说明性 key"，不是 OutboundGuard 的冷却 key。
     * 冷却 key 由 {@code app.outbound.*} 无关：本实现自带 cooldownUntil。
     */
    public static final String DEP_CHAT = "dashscope-chat";

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

    /**
     * 模型配额闸门（可空注入，便于单测）。
     *
     * <p><b>为什么配额要放在这里而不是控制器</b>：实测发现配额检查在 {@code ChatController}
     * 里、编排之前 —— 于是"规则路由 + 代码护栏 + 审计 + 处置"这些**不依赖模型**的能力
     * 也随配额一起失效（配额用尽时，一个纯处置请求 25ms 就被拒，护栏根本没生效）。
     * 对安全运营系统这是反的：外部模型不可用不该让整个响应能力瘫痪。
     * 现在配额只拦"真正要调模型"的这一步，上层按既有降级路径处理：
     * Planner → 回退规则路由；ANALYST/FORENSICS → 如实标"未生成"。
     *
     * <p>分派逻辑已于 2026-10 收口到 {@link ModelQuotaGate}（DeepSeek 实现复用同一份，
     * 避免两份 if/else 慢慢不一致 —— 分派写错不会报错，只会把账记到别的池子上）。
     */
    @Autowired(required = false)
    private org.example.llm.ModelQuotaGate modelQuotaGate;

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String modelName() {
        return DashScopeChatModel.DEFAULT_MODEL_NAME;
    }

    /**
     * Key 是否已配置（供启动自检打印）。
     *
     * <p>与 {@link #available()} 里那段判定同源：占位串 {@code sk-placeholder}
     * 算"未配置" —— 它是为了"无 Key 也能启动"而存在的占位，不是真凭据。
     * 只返回布尔值，<b>绝不</b>返回 Key 本身或它的前缀（日志会被长期采集）。
     */
    public boolean keyConfigured() {
        return apiKey != null && !apiKey.isBlank() && !apiKey.contains("placeholder");
    }

    @Override
    public boolean available() {
        if (selectedProvider != null && !selectedProvider.isBlank()
                && !id().equalsIgnoreCase(selectedProvider.trim())) {
            logger.debug("选中 provider={}，本实现({})不参与", selectedProvider, id());
            return false;
        }
        if (!keyConfigured()) {
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
        // 配额按【调用来源】分派：评测身份走评测计数器、匿名公开演示走公开计数器、
        // 其余走用户计数器。三个池子各自的持久化文件不同，因此"用户额度耗尽 → 评测仍可跑"、
        // "公开端点被刷爆 → 站主自己仍可用"这两件事同时成立。
        // 判定必须在这里（模型出口）而不是控制器入口：只有真正要调模型的这一步才该计数，
        // 而一次提问可能触发多次模型调用（Planner 路由 + 结论生成）。
        // 分派收口在 ModelQuotaGate（两个 provider 共用），不在本类里 if/else ——
        // 分派写错不会有任何报错，只会把账记到别的池子上。
        if (modelQuotaGate != null) {
            modelQuotaGate.checkAndAcquire();
        }
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

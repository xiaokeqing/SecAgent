package org.example.llm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.example.config.DeepSeekConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * DeepSeek 对话模型实现（OpenAI 兼容的 {@code POST /v1/chat/completions}）。
 *
 * <h3>为什么是"手写 OkHttp + Jackson"，而不是引 spring-ai-openai / deepseek 官方 SDK</h3>
 * 已核对依赖树：本项目的类路径上<b>没有</b> {@code spring-ai-openai}
 * （只有 {@code spring-ai-alibaba-starter-dashscope} 与 {@code spring-ai-alibaba-agent-framework}）。
 * DeepSeek 的接口就是 OpenAI 形状的一个 HTTPS+JSON 端点，为它引一个新依赖等于：
 * 多一个构件、多一套自动装配（会顺手改掉现有 RestClient/模型 Bean 的装配）、
 * 以及一条"构建环境必须能访问 Maven 中央仓库"的新失败路径。
 * 项目纪律是"不引新依赖"（webhook 出站曾为此放弃 mockwebserver），这里照办：
 * 用已在类路径上的 OkHttp 4.12 + Jackson 2.17 直接发请求。
 *
 * <h3>出站纪律（与 DashScope 实现同一套）</h3>
 * <ul>
 *   <li><b>统一超时矩阵</b>：connect/read/write/call 四项都取自 {@link DeepSeekConfig}，
 *       而后者只允许<b>收紧</b>{@code app.outbound.*}（3s/12s/15s），超过就夹回 ——
 *       放大它不会"更宽容"，只会让入口先被拖死；</li>
 *   <li><b>有界等待 + 熔断冷却</b>：调用走 {@link OutboundGuard#call}，依赖键
 *       {@link #DEP_CHAT} 独立于 DashScope 的 {@code dashscope-chat} ——
 *       否则一家供应商故障会把另一家一起熔断（那是"误伤"，不是降级）；</li>
 *   <li><b>fail-closed</b>：非 200 / 超时 / 响应体非法 / 正文为空 → 抛异常，
 *       上层照旧判"未生成"。<b>绝不返回模板文本冒充模型输出</b>。</li>
 * </ul>
 *
 * <h3>与 embedding 无关（重要）</h3>
 * DeepSeek 没有 embedding API。向量那条路仍然走 DashScope 的
 * {@code text-embedding-v4}（{@code VectorEmbeddingService}），本类完全不碰它。
 * "对话可换供应商、向量不可换"这件事写进了 RUNBOOK，因为它以后一定会被误解。
 */
@Component
public class DeepSeekLlmProvider implements LlmProvider {

    private static final Logger logger = LoggerFactory.getLogger(DeepSeekLlmProvider.class);

    /**
     * 本实现负责的配置值。
     *
     * <p>{@code app.llm.provider} 只有等于它时本实现才 {@code available()} ——
     * 两个具体实现各自判断，选择逻辑收口在 {@link LlmProviderSelector}。
     */
    public static final String ID = "deepseek";

    /**
     * OutboundGuard 的依赖键。
     *
     * <p><b>必须与 DashScope 的键分开</b>：冷却与在飞上限都是按 key 隔离的。
     * 共用同一个 key 时，DashScope 抖动会让 DeepSeek 通道也进入 60s 冷却，
     * 于是"切到 DeepSeek 当备用"在真正需要它的时刻恰好不可用 —— 一个供应商的
     * 故障误伤另一个，这不是降级。
     */
    public static final String DEP_CHAT = "deepseek-chat";

    /** 兜底 base-url（无 Key 也要能启动；真正的键在 application.yml 里写默认值） */
    private static final String DEFAULT_BASE_URL = "https://api.deepseek.com";

    /** 兜底模型名 */
    private static final String DEFAULT_MODEL = "deepseek-chat";

    /**
     * 响应体上限。
     *
     * <p>不是"防大模型乱输出"，而是防<b>对端不是 DeepSeek</b> 的情况：
     * base-url 配错指到一个会吐几 MB HTML 的地址时，无界读取会把内存和线程一起吃掉。
     * 超过它按"响应体非法"处理（fail-closed，不是截断后再解析）。
     */
    static final int MAX_RESPONSE_BYTES = 256 * 1024;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    @Value("${app.llm.provider:dashscope}")
    private String selectedProvider;

    @Value("${app.llm.deepseek.base-url:" + DEFAULT_BASE_URL + "}")
    private String baseUrl;

    @Value("${app.llm.deepseek.model:" + DEFAULT_MODEL + "}")
    private String model;

    /**
     * DeepSeek Key。
     *
     * <p>默认值刻意是<b>空</b>而不是 {@code sk-placeholder}：占位串是个"看起来配了"的值，
     * 会让自检与 {@code available()} 的判断都变得含糊。空 = 明确没配。
     */
    @Value("${app.llm.deepseek.api-key:}")
    private String apiKey;

    @Value("${app.llm.temperature:0.0}")
    private double temperature;

    @Value("${app.llm.max-tokens:800}")
    private int maxTokens;

    /** 统一超时矩阵（三项都只允许收紧，见 {@link DeepSeekConfig}） */
    @Autowired
    private DeepSeekConfig timeouts;

    @Autowired
    private OutboundGuard guard;

    /**
     * 模型配额闸门（可空，便于单测）。
     *
     * <p>配额（用户/评测/公开三个池子）按<b>调用来源</b>分派，与"用哪家供应商"无关 ——
     * 切到 DeepSeek 不该让评测身份突然开始吃用户的额度。分派逻辑只有一份实现
     * （{@link ModelQuotaGate}，DashScope 实现也用它），这里不复制 if/else
     * （写错不会报错，只会把账记到别的池子上）。
     */
    @Autowired(required = false)
    private ModelQuotaGate modelQuotaGate;

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String modelName() {
        return (model == null || model.isBlank()) ? DEFAULT_MODEL : model.trim();
    }

    @Override
    public boolean available() {
        if (selectedProvider != null && !selectedProvider.isBlank()
                && !ID.equalsIgnoreCase(selectedProvider.trim())) {
            logger.debug("选中 provider={}，本实现({})不参与", selectedProvider, ID);
            return false;
        }
        if (apiKey == null || apiKey.isBlank()) {
            // 不静默：每次判定都留一条可 grep 的日志（启动时还有一行自检，见 LlmSelfCheck）
            logger.debug("DeepSeek Key 未配置（app.llm.deepseek.api-key / DEEPSEEK_API_KEY 为空），判定不可用");
            return false;
        }
        return true;
    }

    @Override
    public String generate(String systemPrompt, String userPrompt) throws Exception {
        if (!available()) {
            throw new IllegalStateException("DeepSeek provider 不可用（provider=" + selectedProvider
                    + "，或 DEEPSEEK_API_KEY 未配置）：本次不调用模型，由上层按 fail-closed 处理");
        }

        // 配额按调用来源分派（评测/公开/用户三本账），与 DashScope 实现共用同一份逻辑。
        // 注意：配额用尽抛出的异常**也不会**触发备用 provider —— 它是"这一步不能做"，
        // 而不是"这家供应商坏了"。降级到另一家会把额度绕过（评测/公开池形同虚设）。
        if (modelQuotaGate != null) {
            modelQuotaGate.checkAndAcquire();
        }

        String url = chatUrl();
        String body = buildRequestBody(modelName(), systemPrompt, userPrompt, temperature, maxTokens);
        OkHttpClient client = buildClient();

        return guard.call(DEP_CHAT, timeouts.getEffectiveCallTimeoutMs(), () -> {
            Request request = new Request.Builder()
                    .url(url)
                    .header("Authorization", "Bearer " + apiKey)
                    .header("Content-Type", "application/json")
                    .post(RequestBody.create(body, JSON))
                    .build();
            Response response;
            try {
                response = client.newCall(request).execute();
            } catch (IOException transportError) {
                // 【传输层失败必须在这里开冷却】实测（srv1 演练）：依赖进程被冻结时，
                // OkHttp 的 read timeout 会【先于】守卫的 callTimeout 触发，于是
                // OutboundGuard 只看到"调用抛了 IOException"，它自己那条 openCircuit 走不到 ——
                // 不在这一层补上，60s 熔断就永远不会生效，每个请求都要再等满一次读超时。
                // 只有"对端根本没答"才走这里：一旦拿到响应（哪怕 500），那是对端在说话，
                // 不该按"这家不可用"处理（否则一次参数错误会把整条通道冷却 60s）。
                guard.openCircuit(DEP_CHAT);
                throw transportError;
            }
            try (response) {
                String text = readBodyBounded(response);
                if (response.code() != 200) {
                    // 非 200 一律当成"未生成"。特别地：401/403 不打印响应体（可能回显 Key 片段），
                    // 只打印状态码与一句原因 —— 日志会被采集与长期保存。
                    throw new IOException("DeepSeek 返回非 200（HTTP " + response.code()
                            + (response.code() == 401 || response.code() == 403 ? "，鉴权失败" : "")
                            + "）：本次不生成结论");
                }
                return extractContent(text);
            }
        });
    }

    /** 请求地址：把 base-url 末尾斜杠归一化，再拼 {@code /v1/chat/completions} */
    String chatUrl() {
        String base = (baseUrl == null || baseUrl.isBlank()) ? DEFAULT_BASE_URL : baseUrl.trim();
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        // 已经写到 /v1 的 base-url 也接受（有人会习惯性写全），避免出现 /v1/v1
        if (base.endsWith("/v1")) {
            return base + "/chat/completions";
        }
        return base + "/v1/chat/completions";
    }

    /**
     * 构造出站客户端：四项超时都取<b>已钳制</b>的生效值。
     *
     * <p>{@code writeTimeout} 取 read 值（与 {@code DashScopeConfig} 同一口径），
     * {@code callTimeout} 封顶单次调用总预算 —— 即使对端在读超时之上还有重定向/重试，
     * 也不会超过入口预算。
     */
    OkHttpClient buildClient() {
        Duration connect = Duration.ofMillis(timeouts.getEffectiveConnectTimeoutMs());
        Duration read = Duration.ofMillis(timeouts.getEffectiveReadTimeoutMs());
        Duration call = Duration.ofMillis(timeouts.getEffectiveCallTimeoutMs());
        return new OkHttpClient.Builder()
                .connectTimeout(connect)
                .readTimeout(read)
                .writeTimeout(read)
                .callTimeout(call)
                .build();
    }

    /** 有界读取响应体；超限直接按非法处理（不截断后继续解析） */
    static String readBodyBounded(Response response) throws IOException {
        String declared = response.header("Content-Length");
        if (declared != null) {
            try {
                if (Long.parseLong(declared.trim()) > MAX_RESPONSE_BYTES) {
                    throw new IOException("DeepSeek 响应体声明长度 " + declared + " 字节，超过上限 "
                            + MAX_RESPONSE_BYTES + "：按响应非法处理，不解析");
                }
            } catch (NumberFormatException ignored) {
                // 声明值不是数字（有些网关会给奇怪的值）：不看它，靠下面的有界读取兜住
            }
        }
        ResponseBody body = response.body();
        if (body == null) {
            throw new IOException("DeepSeek 响应没有 body：无法判定，按未生成处理");
        }
        try (InputStream in = body.byteStream()) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                if (out.size() + n > MAX_RESPONSE_BYTES) {
                    throw new IOException("DeepSeek 响应体超过上限 " + MAX_RESPONSE_BYTES
                            + " 字节：按响应非法处理，不解析");
                }
                out.write(buf, 0, n);
            }
            return out.toString(StandardCharsets.UTF_8);
        }
    }

    /**
     * 严格解析正文，取 {@code choices[0].message.content}。
     *
     * <p>任何一处不符合预期（JSON 不合法 / 没有 choices / content 不是字符串 / 为空）
     * 都抛异常。这里<b>不能</b>返回 "" 或 null 让上层"当作空回答"：
     * 上层对空回答的处理是"未生成"，但那样会丢掉"到底是超时、非 200，还是格式变了"的区分，
     * 而这种区分正是排障时唯一有用的信息。
     */
    static String extractContent(String json) throws IOException {
        JsonNode root;
        try {
            root = MAPPER.readTree(json);
        } catch (Exception e) {
            throw new IOException("DeepSeek 响应不是合法 JSON：" + e.getMessage());
        }
        if (root == null || !root.isObject()) {
            throw new IOException("DeepSeek 响应不是 JSON 对象：按响应非法处理");
        }
        JsonNode choices = root.path("choices");
        if (!choices.isArray() || choices.isEmpty()) {
            throw new IOException("DeepSeek 响应缺少 choices：按响应非法处理");
        }
        JsonNode message = choices.get(0).path("message");
        JsonNode content = message.path("content");
        if (content.isMissingNode() || content.isNull()) {
            // 实测可能形态：推理型模型（如 deepseek-reasoner）把正文放在别的字段里，
            // content 可能是 null 或不存在。这里必须如实失败（判"未生成"），
            // 不能把它当空回答，也不能顺手去读 reasoning_content 冒充结论。
            if (message.has("reasoning_content")) {
                throw new IOException("DeepSeek 响应只有 reasoning_content、没有 content："
                        + "该模型（如 deepseek-reasoner）不适用于本链路，按未生成处理");
            }
            throw new IOException("DeepSeek 响应缺少 choices[0].message.content：按响应非法处理");
        }
        if (!content.isTextual()) {
            throw new IOException("DeepSeek 响应 choices[0].message.content 不是字符串：按响应非法处理");
        }
        String text = content.asText();
        if (text.isBlank()) {
            throw new IOException("DeepSeek 返回的正文为空：按未生成处理（不返回空串冒充结论）");
        }
        return text;
    }

    /**
     * 构造 OpenAI 兼容请求体。
     *
     * <p>刻意用 Jackson 的树模型逐字段构造，而不是字符串拼接：
     * 系统提示词里含用户可控内容（检索片段/告警原文），拼接时一个没转义的引号
     * 就会让整个请求体失效 —— 而且失败方式是"模型收到的提示词被截断"，
     * 那种问题在日志里看不出来。
     *
     * <p>{@code stream=false} 显式写出：默认值就是 false，但它写在请求里，
     * 抓包与桩服务看到的就是真实形状。
     */
    static String buildRequestBody(String model, String systemPrompt, String userPrompt,
                                   double temperature, int maxTokens) throws IOException {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("model", model);
        ArrayNode messages = root.putArray("messages");
        ObjectNode sys = messages.addObject();
        sys.put("role", "system");
        sys.put("content", systemPrompt == null ? "" : systemPrompt);
        ObjectNode user = messages.addObject();
        user.put("role", "user");
        user.put("content", userPrompt == null ? "" : userPrompt);
        root.put("temperature", temperature);
        root.put("max_tokens", maxTokens);
        root.put("stream", false);
        return MAPPER.writeValueAsString(root);
    }

    /** 供启动自检使用：本次真正生效的 base-url */
    public String effectiveBaseUrl() {
        String base = (baseUrl == null || baseUrl.isBlank()) ? DEFAULT_BASE_URL : baseUrl.trim();
        return base;
    }

    /** 供启动自检使用：Key 是否已配置（<b>绝不</b>返回值本身，哪怕前缀） */
    public boolean keyConfigured() {
        return apiKey != null && !apiKey.isBlank();
    }

    /** 供启动自检使用：本实现所属的 OutboundGuard 依赖键（冷却按它隔离） */
    public String depKey() {
        return DEP_CHAT;
    }

    /** 供启动自检使用：本次真正生效的超时矩阵 */
    public DeepSeekConfig effectiveTimeouts() {
        return timeouts == null ? DeepSeekConfig.defaults() : timeouts;
    }

    /** 供排障：一次性说明本实现的配置状态（不含任何密钥内容） */
    public String describe() {
        return ID + "(model=" + modelName() + ",baseUrl=" + effectiveBaseUrl()
                + ",key=" + (keyConfigured() ? "SET" : "MISSING")
                + ",timeouts=" + effectiveTimeouts().getEffectiveConnectTimeoutMs() + "/"
                + effectiveTimeouts().getEffectiveReadTimeoutMs() + "/"
                + effectiveTimeouts().getEffectiveCallTimeoutMs() + "ms"
                + ",depKey=" + DEP_CHAT + ")";
    }
}

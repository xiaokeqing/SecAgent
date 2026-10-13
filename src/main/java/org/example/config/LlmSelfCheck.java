package org.example.config;

import org.example.llm.DeepSeekLlmProvider;
import org.example.llm.DashScopeLlmProvider;
import org.example.llm.LlmProviderSelector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 对话模型供应商的<b>启动自检</b>：应用启动完成后，用<b>一行</b>结构化日志回答
 * "现在到底用哪家、模型是什么、Key 有没有配"。
 *
 * <h3>为什么它必须存在（不是日志洁癖）</h3>
 * 这一项最危险的两个失败形态都是<b>静默</b>的：
 * <ol>
 *   <li><b>Key 没配</b>：{@code DEEPSEEK_API_KEY} 忘了注入 → 供应商不可用 →
 *       上层按 fail-closed 判"未生成"。功能上"正确"，但表现是"页面什么都不生成"，
 *       运维的第一反应是"模型坏了/提示词坏了"，而真正的原因（少一个环境变量）
 *       在任何一行日志里都看不见；</li>
 *   <li><b>provider 值写错</b>：{@code app.llm.provider=deepsek}（拼错）→ 若不显式报错，
 *       就会静默回落到默认供应商：运营以为切了家，实际没切，而页面署名如实写着实际那家，
 *       于是"配置"与"现象"对不上，排障无从下手。</li>
 * </ol>
 *
 * <p>所以这里把三件事变成启动时的一行可 grep 日志：
 * <b>选中的供应商 / 实际模型名 / 两家各自的 Key 是否配置 / 生效的超时矩阵 / 依赖键</b>。
 * 缺项显式写 {@link #MISSING}，绝不静默（与 {@link OutboundSelfCheck} 同一纪律）。
 *
 * <p>值取自真正参与调用的对象（{@link DeepSeekLlmProvider#keyConfigured()} 等），
 * 不是"再读一遍配置"—— 后者在"配置改了但 Bean 没拿到"时会打印骗人的值。
 *
 * <h3>绝不打印密钥</h3>
 * 只打印 {@code SET}/{@code MISSING}。Key 前缀也算密钥材料的一部分，
 * 而且这行日志会被日志采集长期保存。
 */
@Component
public class LlmSelfCheck {

    private static final Logger logger = LoggerFactory.getLogger(LlmSelfCheck.class);

    /** 单行日志里的标记，便于 grep/告警按它抽取 */
    public static final String MARKER = "LLM-PROVIDER-SELFCHECK";

    /** 缺项标记：不允许留空，缺什么就写什么 */
    public static final String MISSING = "MISSING";

    /**
     * 一条供应商的生效状态。
     *
     * @param id        供应商标识（与 {@code app.llm.provider} 的取值一致）
     * @param model     真实模型名（评测指纹与页面标注都用它）
     * @param key       Key 是否配置（<b>只写 SET/MISSING</b>，绝不写值）
     * @param available 当前是否可用（未选中 / Key 缺失 / 冷却期都会是 false）
     * @param note      这条的边界说明（例如 embedding 不走这家的原因）
     */
    public record ProviderRow(String id, String model, String key, boolean available,
                             String depKey, String note) {
    }

    private final LlmProviderSelector selector;
    private final DeepSeekLlmProvider deepSeek;
    private final DashScopeLlmProvider dashScope;

    /** 当前选中的供应商（配置原值，未知值也要如实打印出来） */
    @Value("${app.llm.provider:dashscope}")
    private String provider;

    /** 备用供应商（默认空 = 关闭） */
    @Value("${app.llm.fallback-provider:}")
    private String fallbackProvider;

    /** 逐依赖超时矩阵（与 OutboundSelfCheck 同一口径） */
    private final OutboundTimeouts timeouts;

    public LlmSelfCheck(LlmProviderSelector selector,
                        DeepSeekLlmProvider deepSeek,
                        DashScopeLlmProvider dashScope,
                        OutboundTimeouts timeouts) {
        this.selector = selector;
        this.deepSeek = deepSeek;
        this.dashScope = dashScope;
        this.timeouts = timeouts;
    }

    /** 启动完成即打印一次 —— 一行，可被日志采集直接抽取 */
    @EventListener(ApplicationReadyEvent.class)
    public void logEffectiveValues() {
        logger.info("{}", buildLine());
    }

    public String buildLine() {
        return render(rows());
    }

    /** 收集每个对话供应商的生效状态（embedding 单独一行，见 {@link #embeddingRow()}） */
    public List<ProviderRow> rows() {
        List<ProviderRow> rows = new ArrayList<>();

        String providerRaw = provider == null ? "" : provider.trim();
        String fallbackRaw = fallbackProvider == null ? "" : fallbackProvider.trim();

        // ---- 1) 当前选中的对话供应商 ----
        // 未知值必须显式写出来（select-on-unknown 是 fail-closed 的硬失败，见 LlmProviderSelector.resolve）
        boolean known = selector != null && containsIgnoreCase(selector.providers().keySet(), providerRaw);
        rows.add(new ProviderRow(
                providerRaw.isEmpty() ? MISSING + "(app.llm.provider)" : providerRaw,
                known ? selector.primary().modelName() : MISSING + "(未知供应商，调用时硬失败)",
                known ? keyStateOf(providerRaw) : MISSING,
                known && selector.primary().available(),
                depKeyOf(providerRaw),
                known ? "主供应商（app.llm.provider）"
                      : "app.llm.provider 的取值不在已知清单内：调用模型时会明确失败，不会静默回落"));

        // ---- 2) 备用供应商（默认关闭，必须显式打印 DISABLED，不许静默）----
        if (fallbackRaw.isEmpty()) {
            rows.add(new ProviderRow("fallback=none",
                    "DISABLED", "DISABLED", false, "DISABLED",
                    "app.llm.fallback-provider 为空 → 主供应商不可用时【不做】跨供应商回退（如实判未生成）"));
        } else {
            boolean fbKnown = selector != null && containsIgnoreCase(selector.providers().keySet(), fallbackRaw);
            rows.add(new ProviderRow("fallback=" + fallbackRaw,
                    fbKnown ? selector.fallbackOrNull().modelName() : MISSING + "(未知供应商，调用时硬失败)",
                    fbKnown ? keyStateOf(fallbackRaw) : MISSING,
                    fbKnown && selector.fallbackOrNull().available(),
                    depKeyOf(fallbackRaw),
                    "app.llm.fallback-provider：主供应商失败时才使用；回答里的 generatedBy 会如实改成它"));
        }

        rows.add(embeddingRow());
        return rows;
    }

    /**
     * embedding 行。
     *
     * <p>刻意固定写 {@code dashscope}：DeepSeek 没有 embedding API，向量那条路
     * 仍然走 DashScope 的 {@code text-embedding-v4}。这一行存在的意义就是让
     * "对话可换、向量不可换"成为启动时可见的事实 —— 否则以后一定会有人以为能全换
     * （换了 embedding 模型意味着 318 条向量全部失效、必须重建）。
     */
    private ProviderRow embeddingRow() {
        return new ProviderRow("embedding",
                "text-embedding-v4",
                dashScope != null && dashScope.keyConfigured() ? "SET" : MISSING,
                dashScope != null && dashScope.keyConfigured(),
                "dashscope-embedding",
                "向量检索仍走 DashScope（DeepSeek 无 embedding API）：换对话供应商不影响向量库");
    }

    /** 两家的 Key 状态（只写 SET/MISSING） */
    private String keyStateOf(String id) {
        if (deepSeek != null && DeepSeekLlmProvider.ID.equalsIgnoreCase(id)) {
            return deepSeek.keyConfigured() ? "SET" : MISSING + "(app.llm.deepseek.api-key/DEEPSEEK_API_KEY 未配置)";
        }
        if (dashScope != null && dashScope.id().equalsIgnoreCase(id)) {
            return dashScope.keyConfigured() ? "SET"
                    : MISSING + "(spring.ai.dashscope.api-key/DASHSCOPE_API_KEY 未配置或为占位)";
        }
        return MISSING;
    }

    /** 出站依赖键：与 OutboundGuard 的冷却 key 一致（一个供应商一个键，互不熔断） */
    private String depKeyOf(String id) {
        if (deepSeek != null && DeepSeekLlmProvider.ID.equalsIgnoreCase(id)) {
            return deepSeek.depKey();
        }
        if (dashScope != null && dashScope.id().equalsIgnoreCase(id)) {
            return DashScopeLlmProvider.DEP_CHAT;
        }
        return MISSING;
    }

    private static boolean containsIgnoreCase(Iterable<String> keys, String value) {
        if (keys == null || value == null) {
            return false;
        }
        for (String k : keys) {
            if (k.equalsIgnoreCase(value.trim())) {
                return true;
            }
        }
        return false;
    }

    /**
     * 所有出站依赖键（{@link org.example.llm.OutboundGuard} 的冷却/在飞上限都是按它隔离的）。
     *
     * <p>刻意把<b>没被选中</b>的那家也打出来：事后核对"一家故障会不会误伤另一家"靠的就是这张表，
     * 而 {@code app.llm.provider} 是随时可切的 —— 切过去那一刻才发现自检没覆盖就太晚了。
     * 取值来自真正参与调用的对象（{@link DeepSeekLlmProvider#depKey()} 等），不是随手写的字面量。
     */
    private String describeDependencyKeys() {
        List<String> keys = new ArrayList<>();
        keys.add(DashScopeLlmProvider.DEP_CHAT);
        keys.add(deepSeek != null ? deepSeek.depKey() : DeepSeekLlmProvider.DEP_CHAT);
        keys.add(embeddingRow().depKey());
        return String.join("/", keys);
    }

    /** 渲染成<b>一行</b>（不换行，避免被日志采集拆成多条） */
    public String render(List<ProviderRow> rows) {
        StringBuilder sb = new StringBuilder(MARKER);
        sb.append(" provider=").append(provider == null ? MISSING : provider.trim());
        sb.append(" fallback=").append(fallbackProvider == null || fallbackProvider.isBlank()
                ? "DISABLED" : fallbackProvider.trim());
        sb.append(" timeouts=")
          .append(timeouts == null ? MISSING : timeouts.describe());
        sb.append(" deps=").append(describeDependencyKeys());
        sb.append(" rows=").append(rows.size());
        for (ProviderRow r : rows) {
            sb.append(" | ").append(r.id())
              .append("{model=").append(r.model())
              .append(",key=").append(r.key())
              .append(",available=").append(r.available())
              .append(",depKey=").append(r.depKey())
              .append(",note=").append(r.note())
              .append('}');
        }
        // 选择器自己的口径：上面那段 rows 已经用 MISSING 标出了"未知供应商"，
        // 但"取值写错"必须能一眼看见【合法取值是什么】（INVALID 由 LlmProviderSelector 产生）。
        // 刻意放在这里而不是另起一行日志：这一行是要被整体 grep/采集的。
        sb.append(" | selector=").append(selector == null ? MISSING : selector.describe());
        // 这段是给人看的：切供应商/切回来就靠它核对，不需要翻配置文件
        sb.append(" | switch=").append(describeSwitch());
        return sb.toString();
    }

    /** 怎么切、怎么切回 —— 写进日志里，避免"要翻文档才知道" */
    private String describeSwitch() {
        return "app.llm.provider=dashscope|deepseek（默认 dashscope，保持现状）；"
                + "改后按发布链重建容器，用本行核对生效；"
                + "Key 只从环境变量读（DASHSCOPE_API_KEY / DEEPSEEK_API_KEY），不入库";
    }

    /**
     * 供测试与排障：本次自检的日志行（不含任何密钥内容）。
     *
     * <p>它与 {@link #buildLine()} 是同一份实现，避免"测一个、打一个"。
     */
    public String describe() {
        return buildLine();
    }
}

package org.example.llm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 对话模型供应商的<b>唯一出口</b>：按 {@code app.llm.provider} 选中主实现，
 * 并按 {@code app.llm.fallback-provider}（默认空 = 关闭）决定主实现不可用时是否尝试备用。
 *
 * <h3>为什么需要一个"选择器"Bean，而不是让两个 provider 各自判断</h3>
 * 两个选择方案都被否掉了：
 * <ol>
 *   <li><b>两个 provider 各自看配置、不可用的那个返回 {@code available()=false}</b>：
 *       对单点调用可行，但一旦启用备用就会出现"主不可用时没人接班"的静默空档，
 *       而且"最终是谁生成的"没有任何单一位置可以回答；</li>
 *   <li><b>让调用点（{@code MultiAgentCoordinatorImpl}）自己挑</b>：编排层就要知道
 *       供应商的存在与回退顺序。那就等于把"换供应商"重新变成改业务代码 ——
 *       正是 {@link LlmProvider} 这层抽象当初要消灭的东西。</li>
 * </ol>
 * 所以：调用点仍然只注入一个 {@code LlmProvider}（本类，标 {@code @Primary}），
 * 供应商的识别与回退全部收口在这里。这也让"公开面契约只许新增"落地为
 * <b>注入点零改动</b>：{@code MultiAgentCoordinatorImpl} 一行都不用改。
 *
 * <h3>如实标注是硬约束</h3>
 * 回退发生时，{@link #generatedBy()} 返回<b>备用供应商</b>的标识 —— 回答里会写
 * {@code generatedBy=deepseek / deepseek-chat}。绝不允许"悄悄换一家却仍署名原来那家"：
 * 那会让人对"这个结论是谁产出的"产生错误判断，比明确报错更糟。
 *
 * <p>回退实现上是"主失败 → 尝试备用"，两次调用的异常都会如实抛给上层（若备用也失败，
 * 抛出的是<b>原始</b>异常，避免"真正的原因被后一个错误盖掉"）。
 */
@Component
@Primary
public class LlmProviderSelector implements LlmProvider {

    private static final Logger logger = LoggerFactory.getLogger(LlmProviderSelector.class);

    /** 主供应商：{@code app.llm.provider}（默认 dashscope，保持现状） */
    @Value("${app.llm.provider:dashscope}")
    private String primaryId;

    /**
     * 备用供应商：{@code app.llm.fallback-provider}，<b>默认空 = 关闭</b>。
     *
     * <p>默认关闭是刻意的：开启后，一次故障会变成"换一家再花一次钱"，
     * 且两家供应商的输出风格不同（同一个 JSON schema 约束下的实际形状会有差异）。
     * 这是运营决策，不该是默认行为。
     */
    @Value("${app.llm.fallback-provider:}")
    private String fallbackId;

    /** 依赖键前缀说明（仅用于日志/自检，不参与选择） */
    private final Map<String, LlmProvider> providers = new LinkedHashMap<>();

    private final LlmProvider dashScope;
    private final LlmProvider deepSeek;

    /**
     * "这一次调用究竟由谁产出"。
     *
     * <p>用 {@link ThreadLocal} 而不是字段：模型出口在编排线程池上被调用，多请求并发，
     * 共享字段会让 A 请求的标注读到 B 请求的供应商（那种错误不会报错，只会让页面署名错人）。
     */
    private final ThreadLocal<LlmProvider> lastUsed = new ThreadLocal<>();

    public LlmProviderSelector(DashScopeLlmProvider dashScope, DeepSeekLlmProvider deepSeek) {
        // 显式登记而不是反射扫描 @Component：供应商清单是安全相关的事实
        //（"哪几家能把文本送出去"），应当一眼可数、可审阅。
        this.dashScope = dashScope;
        this.deepSeek = deepSeek;
        providers.put(dashScope.id(), dashScope);
        providers.put(deepSeek.id(), deepSeek);
    }

    @Override
    public String id() {
        return primary().id();
    }

    @Override
    public String modelName() {
        return primary().modelName();
    }

    /**
     * 本次调用<b>真正产出</b>文本的供应商标识，形如 {@code deepseek / deepseek-chat}。
     *
     * <p>生成之前调用返回主供应商（"打算用谁"）；生成之后返回本次真正用上的那个。
     */
    @Override
    public String generatedBy() {
        LlmProvider used = lastUsed.get();
        return used == null ? primary().generatedBy() : used.generatedBy();
    }

    @Override
    public boolean available() {
        if (primary().available()) {
            return true;
        }
        LlmProvider fallback = fallbackOrNull();
        return fallback != null && fallback.available();
    }

    @Override
    public String generate(String systemPrompt, String userPrompt) throws Exception {
        LlmProvider primary = primary();
        LlmProvider fallback = fallbackOrNull();
        // 主供应商失败的原因要留到最后：备用也失败时，抛出的必须是【主】的那个（见下方 catch）
        Exception primaryError = null;

        if (primary.available()) {
            try {
                String out = primary.generate(systemPrompt, userPrompt);
                lastUsed.set(primary);
                return out;
            } catch (Exception e) {
                // 配额用尽【绝不】触发备用：它不是"这家供应商坏了"，而是"这一步不能做"。
                // 换一家继续调用等于把评测/公开/用户的额度绕过 —— 那三本账就形同虚设了。
                if (isQuotaExhausted(e)) {
                    logger.warn("模型额度已用完：不做跨供应商回退（换一家会把额度绕过）");
                    throw e;
                }
                if (fallback == null) {
                    throw e;
                }
                primaryError = e;
                // 如实记录"为什么换了家"，但**不**把主供应商的原文（可能含响应体）打进日志
                logger.warn("主 provider({}) 调用失败（{}），按 app.llm.fallback-provider={} 尝试备用",
                        primary.id(), e.getClass().getSimpleName() + ": " + e.getMessage(), fallback.id());
            }
        } else if (fallback == null) {
            // 主不可用且没有备用：交给上层按 fail-closed 处理（上层已先判 available()，
            // 走到这里通常是并发下刚好进入冷却期）
            throw new IllegalStateException("选中的 provider(" + primary.id()
                    + ") 当前不可用，且未配置备用（app.llm.fallback-provider 为空）");
        } else {
            logger.warn("主 provider({}) 当前不可用，按 app.llm.fallback-provider={} 直接使用备用",
                    primary.id(), fallback.id());
        }

        if (!fallback.available()) {
            throw new IllegalStateException("备用 provider(" + fallback.id()
                    + ") 也不可用（Key 未配置或处于冷却期）：本次不生成结论");
        }
        try {
            String out = fallback.generate(systemPrompt, userPrompt);
            lastUsed.set(fallback);
            return out;
        } catch (Exception fallbackError) {
            if (primaryError == null) {
                // 主本来就不可用：只有备用这一个原因，原样抛出
                throw fallbackError;
            }
            // 备用也失败：抛出的必须是【主】的原始异常（作为 cause）——
            // 否则排障看到的是"备用为什么失败"，真正的原因（主为什么坏）被后一个错误盖掉，
            // 而这正是本类注释里承诺的"抛原始异常"。备用失败挂成 suppressed 一并保留，不丢信息。
            IllegalStateException bothFailed = new IllegalStateException(
                    "主 provider(" + primary.id() + ") 失败（" + primaryError.getMessage() + "），"
                            + "备用 provider(" + fallback.id() + ") 也失败（" + fallbackError.getMessage() + "）",
                    primaryError);
            bothFailed.addSuppressed(fallbackError);
            throw bothFailed;
        }
    }

    /** 主实现；配置值不认识时<b>明确失败</b>，绝不静默挑一个 */
    public LlmProvider primary() {
        return resolve(primaryId, "app.llm.provider");
    }

    /** 备用实现；未配置或为空返回 {@code null}（= 关闭回退） */
    public LlmProvider fallbackOrNull() {
        String id = fallbackId == null ? "" : fallbackId.trim();
        if (id.isEmpty()) {
            return null;
        }
        LlmProvider fb = resolve(id, "app.llm.fallback-provider");
        if (fb.id().equalsIgnoreCase(primary().id())) {
            throw new IllegalStateException("app.llm.fallback-provider 与 app.llm.provider 相同（都是 "
                    + fb.id() + "）：备用与主用同一家没有意义，且会把一次失败放大成两次调用。"
                    + "请把备用改为另一家，或留空关闭回退");
        }
        return fb;
    }

    /**
     * 把配置值解析成实现。
     *
     * <p><b>不认识的值一律抛异常</b>，而不是"回落到默认供应商"：静默回落在这里特别危险 ——
     * 运营以为切到了 DeepSeek，实际还在用 DashScope（或反过来），
     * 而页面的 {@code generatedBy} 会如实写着实际那家，于是"配置"与"现象"对不上，
     * 排障时无从下手。
     */
    private LlmProvider resolve(String id, String configKey) {
        String key = id == null ? "" : id.trim();
        LlmProvider found = key.isEmpty() ? null : providers.get(key.toLowerCase());
        if (found == null) {
            throw new IllegalStateException(configKey + "=\"" + id + "\" 不是已知的对话模型供应商。"
                    + "可取值：" + String.join("|", providers.keySet())
                    + "（拒绝对未知值静默回落：否则会出现「以为切了、其实没切」而页面署名还写着真实那家）");
        }
        return found;
    }

    /** 供应商清单（供自检打印） */
    public Map<String, LlmProvider> providers() {
        return Map.copyOf(providers);
    }

    /**
     * 供单测替换供应商实现（默认包可见，生产代码不调用）。
     *
     * <p>为什么留这个口子：选择/回退/如实标注是<b>本类的</b>逻辑，与"某家 HTTP 端点怎么发"
     * 无关。用桩实现才能精确构造"主超时 / 备用成功 / 配额用尽"这些分支，
     * 而不是靠真网络去凑（那种测试要么慢、要么在别人的机器上飘）。
     * 真链路的出站行为另有 {@code DeepSeekLlmProviderTest} 用真端口覆盖。
     */
    void replaceProvidersForTest(Map<String, LlmProvider> replacements) {
        providers.clear();
        providers.putAll(replacements);
    }

    /**
     * 是否是"配额用尽"这一类失败（两类异常都来自同一个闸门 {@link ModelQuotaGate}）。
     *
     * <p>按消息判定而不是按类型：闸门抛的是 {@code IllegalStateException}，
     * 与"依赖不可用/冷却期"同一个类型 —— 按类型判会把网络抖动也当成配额问题而拒绝回退，
     * 那正好反了。消息里那句是闸门写死的常量形状，且两个 provider 共用同一份实现。
     */
    static boolean isQuotaExhausted(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            String m = t.getMessage();
            if (m != null && m.contains("模型额度已用完")) {
                return true;
            }
            if (t.getCause() == t) {
                break;
            }
        }
        return false;
    }

    /**
     * 一次性说明选择状态（供启动自检；<b>不含任何密钥内容</b>）。
     *
     * <p>未知值在这里也会显式写 {@code INVALID} 而不是抛异常：自检的价值是"把问题打印出来"，
     * 如果它自己先崩了，运维就只看到一条启动失败栈，看不到"是 provider 名字写错了"。
     * 真正使用模型时（{@link #primary()}）仍是硬失败。
     */
    public String describe() {
        StringBuilder sb = new StringBuilder();
        String primaryRaw = primaryId == null ? "" : primaryId.trim();
        LlmProvider primary = primaryRaw.isEmpty() ? null : providers.get(primaryRaw.toLowerCase());
        sb.append("provider=").append(primaryRaw.isEmpty() ? "(空)" : primaryRaw);
        if (primary == null) {
            sb.append("[INVALID:可取值=").append(String.join("|", providers.keySet())).append("]");
        } else {
            sb.append("(model=").append(primary.modelName())
              .append(",available=").append(primary.available()).append(')');
        }

        String fallbackRaw = fallbackId == null ? "" : fallbackId.trim();
        sb.append(" fallback=").append(fallbackRaw.isEmpty() ? "DISABLED(默认)" : fallbackRaw);
        if (!fallbackRaw.isEmpty()) {
            LlmProvider fb = providers.get(fallbackRaw.toLowerCase());
            if (fb == null) {
                sb.append("[INVALID:可取值=").append(String.join("|", providers.keySet())).append(']');
            } else {
                sb.append("(model=").append(fb.modelName())
                  .append(",available=").append(fb.available()).append(')');
            }
        }

        sb.append(" depth=").append(primary == null ? "?" : primary.id())
          .append('/').append(fallbackRaw.isEmpty() ? "none" : fallbackRaw);
        return sb.toString();
    }
}

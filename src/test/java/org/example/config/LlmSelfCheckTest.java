package org.example.config;

import org.example.llm.DashScopeLlmProvider;
import org.example.llm.DeepSeekLlmProvider;
import org.example.llm.LlmProviderSelector;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 对话模型供应商的<b>启动自检</b>测试。
 *
 * <h3>测的是"运维能不能从一行日志里看懂现状"</h3>
 * 供应商可切换以后，最危险的两个失败形态都是静默的，而它们的排障入口只有这一行日志：
 * <ol>
 *   <li><b>Key 没配</b>（忘了注入 {@code DEEPSEEK_API_KEY}）→ 供应商不可用 →
 *       上层如实判"未生成"。功能上正确，但现象是"页面什么都不生成"，
 *       而真正原因在别处看不见 → 自检必须写 {@code MISSING} 并指出是哪个配置项；</li>
 *   <li><b>provider 值写错</b>（{@code deepsek}）→ 调用时硬失败。若不在这里显式打印
 *       {@code INVALID}，运维看到的只有一条"编排不可用"，不知道是名字写错了。</li>
 * </ol>
 *
 * <p>同时钉住一条安全约束：<b>自检绝不打印密钥</b>（只写 SET/MISSING）——
 * 这行日志会被日志采集长期保存。
 */
class LlmSelfCheckTest {

    private static DeepSeekLlmProvider deepSeek(String key, boolean selected) {
        DeepSeekLlmProvider p = new DeepSeekLlmProvider();
        ReflectionTestUtils.setField(p, "selectedProvider", selected ? "deepseek" : "dashscope");
        ReflectionTestUtils.setField(p, "baseUrl", "https://api.deepseek.com");
        ReflectionTestUtils.setField(p, "model", "deepseek-chat");
        ReflectionTestUtils.setField(p, "apiKey", key);
        return p;
    }

    private static DashScopeLlmProvider dashScope(String key) {
        DashScopeLlmProvider p = new DashScopeLlmProvider();
        ReflectionTestUtils.setField(p, "apiKey", key);
        return p;
    }

    /**
     * 组装自检对象。
     *
     * @param providerId  {@code app.llm.provider} 的取值（可以是拼错的值）
     * @param fallbackId  {@code app.llm.fallback-provider} 的取值（空 = 关闭）
     */
    private static LlmSelfCheck selfCheck(String providerId, String fallbackId,
                                          String dashScopeKey, String deepSeekKey) {
        DashScopeLlmProvider ds = dashScope(dashScopeKey);
        DeepSeekLlmProvider dp = deepSeek(deepSeekKey, "deepseek".equalsIgnoreCase(providerId));
        LlmProviderSelector selector = new LlmProviderSelector(ds, dp);

        // 自检与选择器读的是【同一个】配置项（app.llm.provider / app.llm.fallback-provider）：
        // 生产里两处都由 Spring 注入，值必然一致。手工构造时两个都要给 ——
        // 只给自检那一份的话，选择器拿到 null 会按"未知供应商"硬失败，
        // 测出来的是"测试没装配好"，而不是自检的行为。
        ReflectionTestUtils.setField(selector, "primaryId", providerId);
        ReflectionTestUtils.setField(selector, "fallbackId", fallbackId == null ? "" : fallbackId);

        LlmSelfCheck check = new LlmSelfCheck(selector, dp, ds,
                new OutboundTimeouts(3000, 12000, 15000));
        ReflectionTestUtils.setField(check, "provider", providerId);
        ReflectionTestUtils.setField(check, "fallbackProvider", fallbackId);
        return check;
    }

    /** 从一行自检里取出某一段（到下一个 ' | ' 之前） */
    private static String rowOf(String line, String name) {
        int i = line.indexOf(name);
        assertTrue(i >= 0, "自检行里找不到 " + name + "：" + line);
        int j = line.indexOf(" | ", i);
        return (j < 0) ? line.substring(i) : line.substring(i, j);
    }

    @Test
    @DisplayName("默认配置：打印选中的供应商、模型名、Key 状态，并显式写 DISABLED(回退关闭)")
    void defaultConfigIsFullyPrinted() {
        String line = selfCheck("dashscope", "", "sk-real-key-value", "").buildLine();

        assertTrue(line.startsWith(LlmSelfCheck.MARKER), "缺少可 grep 的标记：" + line);
        assertFalse(line.contains("\n"), "自检必须是【一行】日志，不能被日志采集拆散");
        assertTrue(line.contains("provider=dashscope"), line);
        assertTrue(line.contains("qwen-plus"), "必须打印真实模型名（评测指纹与页面标注都用它）：" + line);
        assertTrue(line.contains("key=SET"), line);
        assertTrue(line.contains("fallback=DISABLED"),
                "默认关闭回退这件事必须写出来，不能留空：" + line);
        assertTrue(line.contains("LLM-PROVIDER-SELFCHECK"), line);
    }

    @Test
    @DisplayName("DeepSeek Key 缺失 → 明确写 MISSING 并指出配置项名（不静默）")
    void missingDeepSeekKeyIsExplicit() {
        String line = selfCheck("deepseek", "", "sk-real-key-value", "").buildLine();

        assertTrue(line.contains("deepseek-chat"), "选中的模型名要打印出来：" + line);
        assertTrue(line.contains(LlmSelfCheck.MISSING + "(app.llm.deepseek.api-key/DEEPSEEK_API_KEY 未配置)"),
                "Key 缺失必须显式打印，并写清是哪个配置项 —— 否则现象只是'页面什么都不生成'：" + line);
        assertTrue(line.contains("available=false"), "不可用要如实写出来：" + line);
    }

    @Test
    @DisplayName("DashScope Key 缺失（占位）→ 同样显式 MISSING；embedding 那条也如实写")
    void missingDashScopeKeyIsExplicit() {
        String line = selfCheck("dashscope", "", "sk-placeholder", "test-deepseek-key").buildLine();

        assertTrue(line.contains(LlmSelfCheck.MISSING + "(spring.ai.dashscope.api-key/DASHSCOPE_API_KEY 未配置或为占位)"),
                "占位串算未配置，且必须显式打印：" + line);
        // embedding 固定走 DashScope：它缺失时也要能一眼看见（对话可用但检索不可用是真实组合）
        String embedding = rowOf(line, "embedding{");
        assertTrue(embedding.contains("key=" + LlmSelfCheck.MISSING), embedding);
        assertTrue(embedding.contains("text-embedding-v4"),
                "必须写清向量仍走 DashScope 的哪个模型：" + embedding);
    }

    @Test
    @DisplayName("provider 值拼错 → 自检写 INVALID 且不崩（调用时才硬失败）")
    void wrongProviderValueIsReportedNotSilent() {
        String line = selfCheck("deepsek", "", "sk-real-key-value", "test-deepseek-key").buildLine();

        assertTrue(line.contains("deepsek"), line);
        assertTrue(line.contains("INVALID"), "拼错的值必须显式标记，否则运维只看到'编排不可用'：" + line);
        assertTrue(line.contains("dashscope") && line.contains("deepseek"),
                "要列出合法取值，让人不用翻代码就能改对：" + line);
        assertFalse(line.contains("provider=dashscope(available"),
                "绝不静默回落成 dashscope（那会让'以为切了、其实没切'与页面署名对不上）");
    }

    @Test
    @DisplayName("开了回退 → 两家的模型名/可用性都打印，并写明署名规则")
    void fallbackEnabledIsPrinted() {
        String line = selfCheck("dashscope", "deepseek", "sk-real-key-value", "test-deepseek-key").buildLine();

        assertTrue(line.contains("fallback=deepseek"), line);
        String fbRow = rowOf(line, "fallback=deepseek{");
        assertTrue(fbRow.contains("model=deepseek-chat"), fbRow);
        assertTrue(fbRow.contains("generatedBy"), "要写明回答里的署名会改成备用那家：" + fbRow);
    }

    @Test
    @DisplayName("依赖键分开打印：一家故障不会误伤另一家（可被事后核对）")
    void dependencyKeysArePrinted() {
        String line = selfCheck("dashscope", "", "sk-real-key-value", "").buildLine();
        assertTrue(line.contains("deepseek-chat"), line);
        assertTrue(line.contains("dashscope-chat"), line);
        assertTrue(line.contains("dashscope-embedding"), line);
    }

    @Test
    @DisplayName("【安全】自检绝不打印密钥内容（两个 Key 都不许出现）")
    void neverPrintsSecrets() {
        String dashScopeSecret = "sk-dashscope-super-secret-1234567890";
        String deepSeekSecret = "sk-deepseek-super-secret-abcdefghij";
        String line = selfCheck("deepseek", "dashscope", dashScopeSecret, deepSeekSecret).buildLine();

        assertFalse(line.contains(dashScopeSecret), "DashScope Key 不能进日志：" + line);
        assertFalse(line.contains(deepSeekSecret), "DeepSeek Key 不能进日志：" + line);
        assertFalse(line.contains("sk-dashscope"), "连前缀都不行（日志会被长期采集）：" + line);
        assertFalse(line.contains("sk-deepseek"), line);
        assertTrue(line.contains("key=SET"), line);
    }

    @Test
    @DisplayName("每一行都必须给全字段（缺项写 MISSING，而不是留空）")
    void everyRowIsComplete() {
        // 刻意的"什么都没有"组合：两家 Key 都没配，且【回退未配置】——
        // 这时每一行仍然必须给全字段（缺项写 MISSING），而不是留空。
        // （回退配了值的情形由 fallbackEnabledIsPrinted / neverPrintsSecrets 覆盖）
        LlmSelfCheck check = selfCheck("deepseek", "", "", "");
        List<LlmSelfCheck.ProviderRow> rows = check.rows();

        assertTrue(rows.size() >= 3, "至少要覆盖：选中的供应商 / 回退状态 / embedding，实际 " + rows.size());
        for (LlmSelfCheck.ProviderRow r : rows) {
            assertNotNull(r.id(), "缺 id");
            assertFalse(r.id().isBlank(), "id 为空");
            assertNotNull(r.model(), r.id() + " 缺 model");
            assertNotNull(r.key(), r.id() + " 缺 key");
            assertNotNull(r.depKey(), r.id() + " 缺 depKey");
            assertNotNull(r.note(), r.id() + " 缺 note");
            assertFalse(r.model().isBlank(), r.id() + " 的 model 为空（应显式写 MISSING）");
            assertFalse(r.key().isBlank(), r.id() + " 的 key 为空（应显式写 SET/MISSING）");
        }
        // 回退未配置时，那一行也必须存在（"关闭"本身是要被看见的信息）
        assertTrue(rows.stream().anyMatch(r -> r.id().startsWith("fallback=none")),
                "回退关闭也必须有一行：" + rows);
    }
}

package org.example.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 对话模型供应商开关的<b>配置契约</b>测试：默认值、部署面透传、Key 的来源。
 *
 * <h3>为什么配置文件也要有测试（本项目在这里真实踩过坑）</h3>
 * {@code docker-compose.yml} 的 {@code environment} 段漏透传一个键时，
 * "在 .env 里加一行"<b>根本不生效，而且不报错</b> —— 只有等人发现"行为没变"才暴露。
 * 供应商开关比那更危险：站主明确要求"先别换"，所以"默认仍是 dashscope"必须是被
 * <b>断言钉住</b>的事实，而不是"我记得改回默认值了"。
 *
 * <p>钉住四件事：
 * <ol>
 *   <li>{@code application.yml} 里 {@code app.llm.provider} 的默认值是 <b>dashscope</b>，
 *       且这个默认值只有<b>一个</b>声明处、源码里所有 {@code ${app.llm.provider:...}} 的
 *       默认值也是 dashscope（读配置的地方有四处，默认值写歪一处就会静默换家）；</li>
 *   <li>跨供应商回退默认<b>关闭</b>（{@code fallback-provider} 默认空）；</li>
 *   <li>{@code DEEPSEEK_API_KEY} <b>只从环境变量读</b>：三处（yml / .env.example / compose）
 *       都不许写死默认值，更不许写占位串 —— DeepSeek 实现把"空"当作明确未配置，
 *       写个 {@code sk-placeholder} 会让"配没配"这个判断变糊；</li>
 *   <li>{@code app.llm.*} <b>不在</b> {@code SPRING_APPLICATION_JSON} 里
 *       （它的优先级高于环境变量绑定，一旦进去，环境变量就再也改不动它了）。</li>
 * </ol>
 */
class LlmProviderSwitchConfigTest {

    private static String read(String path) throws Exception {
        Path p = Path.of(path);
        assertTrue(Files.isReadable(p), "读不到 " + p.toAbsolutePath() + "（测试工作目录应为模块根）");
        return Files.readString(p, StandardCharsets.UTF_8);
    }

    /** 取包含 needle 的那一行（找不到就失败），方便断言"这一行的默认值是什么" */
    private static String lineContaining(String text, String needle) {
        for (String line : text.split("\\R")) {
            if (line.contains(needle)) {
                return line;
            }
        }
        throw new AssertionError("配置里找不到包含「" + needle + "」的行");
    }

    /** 从一行里取出以 {@code prefix} 开头的那个 {@code ${...}} 占位符原文（含默认值） */
    private static String placeholderIn(String line, String prefix) {
        int start = line.indexOf(prefix);
        assertTrue(start >= 0, "这一行里没有 " + prefix + "：" + line);
        int end = line.indexOf('}', start);
        assertTrue(end > start, "占位符没有闭合：" + line);
        return line.substring(start, end + 1);
    }

    // ==================== 1) 默认值：仍是 dashscope ====================

    @Test
    @DisplayName("【核心】application.yml：app.llm.provider 默认 dashscope（站主口径：先别换）")
    void applicationYmlKeepsDashScopeAsDefault() throws Exception {
        String yml = read("src/main/resources/application.yml");

        assertTrue(yml.contains("provider: ${APP_LLM_PROVIDER:dashscope}"),
                "app.llm.provider 的默认值必须逐字是 dashscope（否则容器里默认就换家了）");
        // 断言"默认值"本身，而不是整行：这一行的行尾注释里列着两个合法取值（含 deepseek），
        // 用整行做否断言会误伤注释。
        assertEquals("${APP_LLM_PROVIDER:dashscope}",
                placeholderIn(lineContaining(yml, "provider: ${APP_LLM_PROVIDER:"), "${APP_LLM_PROVIDER:"),
                "默认值不能是 deepseek（站主：先别换）");

        // 默认值只能声明一处：两处声明就会出现"谁生效"要靠加载顺序猜的情况
        assertEqualsCount(yml, "${APP_LLM_PROVIDER:", 1,
                "app.llm.provider 的取值只允许有一个声明处");
    }

    @Test
    @DisplayName("源码里每一处 ${app.llm.provider:...} 的默认值都是 dashscope（读配置的地方有四处）")
    void everyReaderDefaultsToDashScope() throws Exception {
        List<String> offenders = new ArrayList<>();
        int readers = 0;
        try (Stream<Path> walk = Files.walk(Path.of("src/main/java"))) {
            for (Path p : walk.filter(f -> f.toString().endsWith(".java")).toList()) {
                String src = Files.readString(p, StandardCharsets.UTF_8);
                int idx = 0;
                while ((idx = src.indexOf("${app.llm.provider:", idx)) >= 0) {
                    readers++;
                    int end = src.indexOf('}', idx);
                    String declaration = src.substring(idx, end < 0 ? src.length() : end + 1);
                    if (!declaration.equals("${app.llm.provider:dashscope}")) {
                        offenders.add(p.getFileName() + " → " + declaration);
                    }
                    idx = end < 0 ? src.length() : end + 1;
                }
            }
        }
        assertTrue(readers > 0, "至少应该有一处读 app.llm.provider");
        assertTrue(offenders.isEmpty(),
                "以下读取点的默认值不是 dashscope（默认值写歪 = 静默换家）：\n  "
                        + String.join("\n  ", offenders));
    }

    @Test
    @DisplayName("跨供应商回退默认关闭：fallback-provider 默认空（空 = 不换人，如实判未生成）")
    void fallbackIsDisabledByDefault() throws Exception {
        String yml = read("src/main/resources/application.yml");
        assertTrue(yml.contains("fallback-provider: ${APP_LLM_FALLBACK_PROVIDER:}"),
                "回退默认必须是空（关闭）—— 打开它等于「这家坏了就再花一家的钱」，属运营决策而非默认行为");
        assertEquals("fallback-provider: ${APP_LLM_FALLBACK_PROVIDER:}",
                lineContaining(yml, "fallback-provider: ${APP_LLM_FALLBACK_PROVIDER:").trim(),
                "默认值必须为空（不许塞任何供应商名）");
    }

    // ==================== 2) Key 只从环境变量读 ====================

    @Test
    @DisplayName("DEEPSEEK_API_KEY 只从环境变量读：yml 无默认值、无占位串")
    void deepSeekKeyComesFromEnvironmentOnly() throws Exception {
        String yml = read("src/main/resources/application.yml");
        String keyLine = lineContaining(yml, "api-key: ${DEEPSEEK_API_KEY:");
        assertEquals("api-key: ${DEEPSEEK_API_KEY:}", keyLine.trim(),
                "DeepSeek 的 api-key 必须原样回落环境变量且【无默认值】（写默认值 = 把凭据放进仓库）：" + keyLine);

        // DashScope 那边的 sk-placeholder 是"无 Key 也能启动"的历史占位；
        // DeepSeek 刻意不这么写：占位串会让"配没配"这个判断变糊（见 DeepSeekLlmProvider.keyConfigured）。
        assertFalse(yml.contains("${DEEPSEEK_API_KEY:sk"),
                "DeepSeek 的 Key 不许有默认值或占位串：空就是明确的「未配置」");
        assertFalse(yml.contains("${app.llm.deepseek.api-key:sk"),
                "同上：这个键也不许有占位默认值");
    }

    // ==================== 3) 部署面：三处口径一致 ====================

    @Test
    @DisplayName(".env.example：APP_LLM_PROVIDER=dashscope，且 Key 模板留空、回退模板留空")
    void envExampleDocumentsTheSwitch() throws Exception {
        String env = read(".env.example");

        assertTrue(env.contains("APP_LLM_PROVIDER=dashscope"),
                "模板里必须给出默认口径 dashscope（不是 deepseek）");
        String key = lineContaining(env, "DEEPSEEK_API_KEY=");
        assertTrue(key.trim().equals("DEEPSEEK_API_KEY="),
                "Key 在模板里必须是空的（绝不把真凭据写进仓库）：" + key);
        assertTrue(env.contains("APP_LLM_FALLBACK_PROVIDER="), "回退开关也要在模板里给出来（默认空）");
        assertTrue(env.contains("DASHSCOPE_API_KEY"),
                "必须保留 DashScope Key：DeepSeek 没有 embedding API，向量那条路仍走它");
    }

    @Test
    @DisplayName("docker-compose.yml：显式透传供应商开关，且默认值同为 dashscope")
    void composePassesTheSwitchThrough() throws Exception {
        String compose = read("docker-compose.yml");

        assertTrue(compose.contains("APP_LLM_PROVIDER: \"${APP_LLM_PROVIDER:-dashscope}\""),
                "compose 的 environment 段必须显式透传，且默认值同样是 dashscope");
        assertTrue(compose.contains("DEEPSEEK_API_KEY: \"${DEEPSEEK_API_KEY:-}\""),
                "Key 只从 .env 注入，compose 里不许写默认值");
        String fallback = lineContaining(compose, "APP_LLM_FALLBACK_PROVIDER:");
        assertTrue(fallback.contains(":-}\""), "回退默认也必须是空：" + fallback);
    }

    @Test
    @DisplayName("app.llm.* 不在 SPRING_APPLICATION_JSON 里（它的优先级高于环境变量绑定）")
    void llmIsNotPinnedInsideSpringApplicationJson() throws Exception {
        String compose = read("docker-compose.yml");
        int start = compose.indexOf("SPRING_APPLICATION_JSON:");
        assertTrue(start > 0, "compose 里应该有一段 SPRING_APPLICATION_JSON");
        // 该段一直延续到下一个顶层 environment 键（缩进更少的行）为止
        String rest = compose.substring(start);
        int blockEnd = rest.indexOf("\n      # =====");
        String block = blockEnd > 0 ? rest.substring(0, blockEnd) : rest;

        assertFalse(block.contains("\"llm\""),
                "app.llm 一旦进了 SPRING_APPLICATION_JSON，APP_LLM_PROVIDER 环境变量就再也改不动它"
                        + "（而且不报错）—— 这正是本项目在 APP_QUOTA_* 上踩过的坑");
        assertFalse(block.contains("APP_LLM_PROVIDER"),
                "同上：供应商开关必须留给环境变量绑定");
    }

    private static void assertEqualsCount(String text, String needle, int expected, String message) {
        int count = 0;
        int idx = 0;
        while ((idx = text.indexOf(needle, idx)) >= 0) {
            count++;
            idx += needle.length();
        }
        assertTrue(count == expected,
                message + "（预期 " + expected + " 处，实际 " + count + " 处）");
    }
}

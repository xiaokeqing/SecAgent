package org.example.config;

import org.example.llm.OutboundGuard;
import org.example.publicapi.TtsService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * TTS（{@code POST /api/public/tts}）的<b>配置契约</b>测试。
 *
 * <h3>为什么配置也要有测试</h3>
 * 本项目真实踩过一次：{@code docker-compose.yml} 的 {@code environment} 段没有透传
 * {@code APP_QUOTA_*}，于是"在 .env 里加一行"<b>根本不生效，而且不报错</b>。
 * 这次同样要求 {@code APP_TTS_*} 在 {@code .env.example} 与 {@code docker-compose.yml}
 * 里显式落地。所以这里把四处一起钉住：
 * <ol>
 *   <li>{@code application.yml} 的 {@code app.tts.*} 键齐全、默认值正确（顺带证明 YAML 能解析）；</li>
 *   <li>{@code .env.example} 里 {@code APP_TTS_*} 键齐全（模板就是部署面的说明书）；</li>
 *   <li>{@code docker-compose.yml} 的 environment 段<b>显式透传</b>这些键（少一个就是"改了不生效"）；</li>
 *   <li>值对象的归一化/钳制与 Spring 装配（{@link TtsOutboundConfig} → {@link TtsConfig}）能成立
 *       —— 本项目唯一一种"编译绿、单测绿、只有容器起不来"的缺陷就在这一层。</li>
 * </ol>
 */
class TtsConfigContractTest {

    private static final List<String> KEYS = List.of(
            "APP_TTS_ENABLED", "APP_TTS_VOICE_ID", "APP_TTS_MODEL", "APP_TTS_BASE_URL", "APP_TTS_API_KEY",
            "APP_TTS_MAX_CHARS", "APP_TTS_PER_IP_DAILY", "APP_TTS_GLOBAL_DAILY", "APP_TTS_CACHE_DIR",
            "APP_TTS_MAX_CACHE_MB", "APP_TTS_QUOTA_FILE", "APP_TTS_HISTORY_SIZE", "APP_TTS_PHRASES_FILE");

    private static Map<String, Object> readYaml(String path) throws Exception {
        Path p = Path.of(path);
        assertTrue(Files.isReadable(p), "读不到 " + p.toAbsolutePath() + "（测试工作目录应是模块根）");
        try (InputStream in = Files.newInputStream(p)) {
            return new Yaml().load(in);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> nested(Map<String, Object> root, String... path) {
        Object cur = root;
        for (String key : path) {
            assertTrue(cur instanceof Map, "配置结构不对：找不到 " + String.join(".", path));
            cur = ((Map<String, Object>) cur).get(key);
            assertNotNull(cur, "配置缺键：" + String.join(".", path));
        }
        return (Map<String, Object>) cur;
    }

    // ==================== 1) application.yml ====================

    @Test
    @DisplayName("application.yml：app.tts.* 十三个键齐全，默认值正确（默认关、无 Key、无默认凭据）")
    void applicationYmlHasTtsBlock() throws Exception {
        Map<String, Object> app = nested(readYaml("src/main/resources/application.yml"), "app");
        Map<String, Object> tts = nested(app, "tts");

        assertEquals("${APP_TTS_ENABLED:false}", tts.get("enabled"),
                "默认必须关闭：站主还没给 Key，前端据 TTS_DISABLED 隐藏 🔊");
        assertEquals("${APP_TTS_VOICE_ID:}", tts.get("voice-id"));
        assertEquals("${APP_TTS_MODEL:s1}", tts.get("model"));
        assertEquals("${APP_TTS_BASE_URL:https://api.fish.audio}", tts.get("base-url"));
        assertEquals("${APP_TTS_API_KEY:}", tts.get("api-key"),
                "Key 只从环境变量读且默认空 —— 写死默认值等于把凭据放进仓库");
        assertEquals("${APP_TTS_MAX_CHARS:120}", tts.get("max-chars"));
        assertEquals("${APP_TTS_PER_IP_DAILY:20}", tts.get("per-ip-daily"));
        assertEquals("${APP_TTS_GLOBAL_DAILY:500}", tts.get("global-daily"));
        assertEquals("${APP_TTS_CACHE_DIR:data/tts-cache}", tts.get("cache-dir"));
        assertEquals("${APP_TTS_MAX_CACHE_MB:64}", tts.get("max-cache-mb"));
        assertEquals("${APP_TTS_QUOTA_FILE:data/tts-quota.json}", tts.get("quota-file"));
        assertEquals("${APP_TTS_HISTORY_SIZE:200}", tts.get("history-size"));
        assertEquals("${APP_TTS_PHRASES_FILE:classpath:tts-phrases.yml}", tts.get("phrases-file"));

        // 端点复用 15 秒快照与统一出站超时矩阵：这两个键必须还在
        assertNotNull(nested(app, "public-api").get("cache-seconds"), "语音端点复用公网快照 TTL");
        assertNotNull(nested(app, "outbound").get("call-timeout-ms"), "上游调用走统一超时矩阵");
    }

    @Test
    @DisplayName("resources/tts-phrases.yml：短语表能被解析，键路径就是 app.tts.phrases.*")
    void phraseTableParses() throws Exception {
        Map<String, Object> root = readYaml("src/main/resources/tts-phrases.yml");
        Map<String, Object> phrases = nested(root, "app", "tts", "phrases");
        assertFalse(phrases.isEmpty(), "短语表不能是空的（空表 = 所有 phraseId 都 400）");
        assertTrue(phrases.containsKey("welcome"), "至少要有 welcome 这一条：" + phrases.keySet());
        phrases.values().forEach(v -> assertFalse(String.valueOf(v).isBlank(), "短语文本不能为空"));

        // 读取器（代码路径）拿到的是同一份内容
        Map<String, String> loaded = TtsPhrases.load(TtsPhrases.DEFAULT_LOCATION);
        assertEquals(phrases.size(), loaded.size(), "读取器与文件内容必须一致");
        assertEquals(String.valueOf(phrases.get("welcome")), loaded.get("welcome"));

        // 结构不对时是空表（fail-closed），而不是抛异常或"随便合成"
        assertTrue(TtsPhrases.fromYaml("app:\n  other: 1\n").isEmpty());
        assertTrue(TtsPhrases.fromYaml("不是 yaml 映射").isEmpty());
    }

    // ==================== 2) .env.example / 3) docker-compose.yml ====================

    @Test
    @DisplayName(".env.example：十三个 APP_TTS_* 都有，且模板默认关闭、Key 留空")
    void envExampleDocumentsAllKeys() throws Exception {
        String env = Files.readString(Path.of(".env.example"), StandardCharsets.UTF_8);
        for (String key : KEYS) {
            assertTrue(env.contains(key + "="), ".env.example 缺少 " + key);
        }
        assertTrue(env.contains("APP_TTS_ENABLED=false"), "模板默认必须是 false（与 yml 一致）");
        assertTrue(env.contains("APP_TTS_API_KEY="), "Key 必须在模板里留空出现（部署面要看得见它）");
        assertFalse(env.contains("APP_TTS_API_KEY=sk-"), "模板里不许出现任何真实 Key 形态");
        assertTrue(env.contains("RUNBOOK §30"), "要指出口径文档在哪");
    }

    @Test
    @DisplayName("docker-compose.yml：environment 段显式透传十三个键（少一个 = 改了不生效且不报错）")
    void composePassesAllKeysThrough() throws Exception {
        Map<String, Object> root = readYaml("docker-compose.yml");
        Map<String, Object> services = nested(root, "services");
        Map<String, Object> merged = new LinkedHashMap<>();
        for (Object svc : services.values()) {
            if (svc instanceof Map<?, ?> m && m.get("environment") instanceof Map<?, ?> env) {
                env.forEach((k, v) -> merged.put(String.valueOf(k), v));
            }
        }
        for (String key : KEYS) {
            assertTrue(merged.containsKey(key), "docker-compose.yml 的 environment 段必须显式透传 " + key
                    + "（否则 .env 里加一行不生效且不报错）");
            String value = String.valueOf(merged.get(key));
            assertTrue(value.startsWith("${" + key + ":-"), "透传必须带默认值兜底，实测值=" + value);
        }
        assertFalse(String.valueOf(merged.get("APP_TTS_ENABLED")).contains(":-true"),
                "compose 里的兜底默认也要是 false（与 yml/.env.example 一致）");
        assertTrue(String.valueOf(merged.get("APP_TTS_API_KEY")).startsWith("${APP_TTS_API_KEY:-}"),
                "Key 的透传兜底必须是空（不能给它一个默认凭据）");
    }

    // ==================== 4) 值对象归一化 + Spring 装配 ====================

    @Test
    @DisplayName("TtsConfig：非法值取默认、超上限夹回（不许放大成本闸），且 describe() 绝不打印 Key")
    void valueObjectClampsAndNeverPrintsKey() {
        TtsConfig defaults = new TtsConfig(true, "  ", "", "", "  ", 0, -5, 0, "", 0, "", 0, null, "");
        assertEquals("fish", defaults.getProvider(), "空 provider = 缺省厂商 fish");
        assertEquals(TtsConfig.DEFAULT_MODEL, defaults.getModel());
        assertEquals(TtsConfig.DEFAULT_BASE_URL, defaults.getBaseUrl());
        assertEquals(TtsConfig.DEFAULT_MAX_CHARS, defaults.getMaxChars());
        assertEquals(TtsConfig.DEFAULT_PER_IP_DAILY, defaults.getPerIpDaily());
        assertEquals(TtsConfig.DEFAULT_GLOBAL_DAILY, defaults.getGlobalDaily());
        assertEquals(TtsConfig.DEFAULT_CACHE_DIR, defaults.getCacheDir());
        assertEquals(TtsConfig.DEFAULT_MAX_CACHE_MB, defaults.getMaxCacheMb());
        assertEquals(TtsConfig.DEFAULT_QUOTA_FILE, defaults.getQuotaFile());
        assertEquals(TtsConfig.DEFAULT_HISTORY_SIZE, defaults.getHistorySize());
        assertFalse(defaults.apiKeyConfigured(), "空 Key = 明确没配（端点据此返回 KEY_MISSING）");
        assertTrue(defaults.getPhrases().isEmpty(), "null 短语表 = 空表");

        TtsConfig huge = new TtsConfig(true, "v", "s1", "https://api.fish.audio", "sk-secret",
                99999, 20, 500, "data/tts-cache", 64, "data/tts-quota.json", 200, Map.of("a", "b"), "fish");
        assertEquals(TtsConfig.MAX_CHARS_CEILING, huge.getMaxChars(), "超上限必须夹回（只许收紧不许放大）");
        assertTrue(huge.apiKeyConfigured());
        assertTrue(huge.describe().contains("key=SET"));
        assertFalse(huge.describe().contains("sk-secret"), "describe() 绝不打印 Key 内容：" + huge.describe());
        assertTrue(defaults.describe().contains("key=MISSING"), "缺失要显式，不许静默");
    }

    @Test
    @DisplayName("【核心】TTS 链路能装配起来：上下文不失败，TtsConfig 恰好一个 Bean，TtsService 拿到的是它")
    void ttsBeansWireUpWithoutStartingWholeApp() {
        ttsRunner().run(ctx -> {
            Throwable failure = ctx.getStartupFailure();
            if (failure != null) {
                // 把"生产容器起不来"提前成一条单测失败（本仓库没有全量 @SpringBootTest）
                throw new AssertionError("TTS 链路装配失败（生产里就是启动失败）：" + failure, failure);
            }
            assertEquals(1, ctx.getBeansOfType(TtsConfig.class).size(),
                    "TtsConfig 必须恰好一个 Bean（两个候选会让 @Autowired 直接失败）: "
                            + java.util.Arrays.toString(ctx.getBeanDefinitionNames()));
            TtsService service = ctx.getBean(TtsService.class);
            assertTrue(service.config() == ctx.getBean(TtsConfig.class),
                    "服务真正用的必须是装配出来的那个对象（否则自检打印的值是骗人的）");

            TtsConfig config = service.config();
            assertFalse(config.isEnabled(), "默认关（站主还没给 Key）");
            assertFalse(config.apiKeyConfigured(), "默认没配 Key");
            assertEquals(TtsConfig.DEFAULT_MAX_CHARS, config.getMaxChars());
            assertEquals(TtsConfig.DEFAULT_PER_IP_DAILY, config.getPerIpDaily());
            assertEquals(TtsConfig.DEFAULT_GLOBAL_DAILY, config.getGlobalDaily());
            assertEquals(TtsConfig.DEFAULT_CACHE_DIR, config.getCacheDir());
            assertEquals(TtsConfig.DEFAULT_MAX_CACHE_MB, config.getMaxCacheMb());
            assertTrue(config.getPhrases().size() >= 3,
                    "默认短语表必须从 classpath:tts-phrases.yml 装载进来：" + config.getPhrases().keySet());
        });
    }

    @Test
    @DisplayName("Key 只从环境变量读：配了即 SET（describe 不含内容）；enabled 打开后服务判定一致")
    void keyComesFromEnvironmentOnly() {
        ttsRunner().withPropertyValues("app.tts.enabled=true", "app.tts.api-key=sk-test-secret-should-never-be-logged")
                .run(ctx -> {
                    TtsService service = ctx.getBean(TtsService.class);
                    assertTrue(service.config().isEnabled());
                    assertTrue(service.config().apiKeyConfigured());
                    assertTrue(service.config().describe().contains("key=SET"));
                    assertFalse(service.config().describe().contains("sk-test-secret-should-never-be-logged"),
                            "describe() 绝不打印 Key：" + service.config().describe());
                });
    }

    /** 只装配 TTS 那条链路所需的类；默认属性与 application.yml 的默认值一致 */
    private ApplicationContextRunner ttsRunner() {
        return new ApplicationContextRunner()
                .withUserConfiguration(OutboundConfig.class, TtsOutboundConfig.class, TtsService.class)
                .withBean(OutboundGuard.class)
                .withPropertyValues("app.tts.api-key=");
    }
}

package org.example.publicapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
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
 * 攻击故事线（{@code /api/public/stories} + {@code /api/public/story}）的<b>配置契约</b>测试。
 *
 * <h3>为什么配置也要有测试</h3>
 * 本项目真实踩过一次：{@code docker-compose.yml} 的 {@code environment} 段没有透传某个键，
 * 于是"在 .env 里加一行"<b>根本不生效，而且不报错</b> —— 只有等到"改了没变化"被人发现才暴露。
 * 所以这里把三处一起钉住：
 * <ol>
 *   <li>{@code application.yml} 里三个键齐全、默认值正确（顺带证明 YAML 能解析）；</li>
 *   <li>{@code .env.example} 里三个键齐全（模板就是部署面的说明书）；</li>
 *   <li>{@code docker-compose.yml} 的 environment 段<b>显式透传</b>这三个键（少一个就是改了不生效）。</li>
 * </ol>
 */
class AttackStoryConfigTest {

    private static final List<String> KEYS = List.of(
            "APP_PUBLIC_STORY_TOP_SOURCES",
            "APP_PUBLIC_STORY_MAX_EVENTS_PER_STAGE",
            "APP_PUBLIC_STORY_MAX_LIMIT");

    private static Map<String, Object> readYaml(String path) throws IOException {
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

    @Test
    @DisplayName("application.yml：app.public-api.story.* 三个键齐全且默认值正确")
    void applicationYmlHasStoryBlock() throws Exception {
        Map<String, Object> app = nested(readYaml("src/main/resources/application.yml"), "app");
        Map<String, Object> story = nested(nested(app, "public-api"), "story");

        assertEquals("${APP_PUBLIC_STORY_TOP_SOURCES:50}", story.get("top-sources"),
                "候选来源上限默认 50：它同时是 /story 的可查询来源池大小");
        assertEquals("${APP_PUBLIC_STORY_MAX_EVENTS_PER_STAGE:40}", story.get("max-events-per-stage"),
                "单来源单阶段事件上限默认 40（每段独立限量）");
        assertEquals("${APP_PUBLIC_STORY_MAX_LIMIT:20}", story.get("max-limit"),
                "/stories 的 limit 上限默认 20（防 limit=100000 撑大响应）");
    }

    @Test
    @DisplayName(".env.example：三个 APP_PUBLIC_STORY_* 都有，并写清了四段数据源与'不许编'的纪律")
    void envExampleDocumentsAllKeys() throws Exception {
        String env = Files.readString(Path.of(".env.example"), StandardCharsets.UTF_8);
        for (String key : KEYS) {
            assertTrue(env.contains(key + "="), ".env.example 缺少 " + key);
        }
        assertTrue(env.contains("APP_PUBLIC_STORY_TOP_SOURCES=50"));
        assertTrue(env.contains("APP_PUBLIC_STORY_MAX_EVENTS_PER_STAGE=40"));
        assertTrue(env.contains("APP_PUBLIC_STORY_MAX_LIMIT=20"));
        assertTrue(env.contains("RUNBOOK §32"), "要指出口径文档在哪");
        assertTrue(env.contains("response-audit.json"), "要写清'处置审计不在 indexer 里'");
        assertTrue(env.contains("commandsAvailable=false"), "要写清蜜罐命令时间线没有数据源");
        assertTrue(env.contains("NOT_WIRED"), "要写清'未接入'与'这段没有数据'的区别");
    }

    @Test
    @DisplayName("docker-compose.yml：environment 段显式透传三个键（少一个 = 改了不生效且不报错）")
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
        assertFalse(String.valueOf(merged.get("APP_PUBLIC_STORY_MAX_EVENTS_PER_STAGE")).contains(":-0"),
                "上限不能兜底成 0（会变成'一条都不给'）");
    }

    @Test
    @DisplayName("开关只有一个读取点：故事线不复用 mask-ips/asset-blocklist 的读取（口径仍只有一个来源）")
    void storyDoesNotReadTheMaskSwitchItself() throws Exception {
        String src = Files.readString(Path.of("src/main/java/org/example/publicapi/AttackStoryService.java"),
                StandardCharsets.UTF_8);
        assertFalse(src.contains("${app.public.mask-ips"), "掩码开关只允许 PublicIpPolicy 读");
        assertFalse(src.contains("${app.public.asset-blocklist"), "资产词表只允许 PublicAssetFilter 读");
        assertTrue(src.contains("ipPolicy"), "新端点必须注入 PublicIpPolicy，而不是自己判断掩不掩码");
    }
}

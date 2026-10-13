package org.example.accesslog;

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
 * 公开聚合端点 {@code /api/public/webstats} 的<b>配置契约</b>测试。
 *
 * <h3>为什么配置也要有测试</h3>
 * 本项目已经真实踩过一次：{@code docker-compose.yml} 的 {@code environment} 段没有透传
 * {@code APP_QUOTA_*}，于是"在 .env 里加一行"<b>根本不生效，而且不报错</b>。
 * 站主这次也点名要求 {@code APP_WEBSTATS_*} 必须在 {@code .env.example} 与
 * {@code docker-compose.yml} 里显式落地。所以这里把三处一起钉住：
 * <ol>
 *   <li>{@code application.yml} 里 7 个键齐全、默认值正确（顺带<b>证明 YAML 能解析</b>）；</li>
 *   <li>{@code .env.example} 里 7 个键齐全（模板就是部署面的说明书）；</li>
 *   <li>{@code docker-compose.yml} 的 environment 段<b>显式透传</b>这 7 个键
 *       （少一个就是"改了不生效"）。</li>
 * </ol>
 */
class WebStatsConfigTest {

    private static final List<String> KEYS = List.of(
            "APP_WEBSTATS_ENABLED", "APP_WEBSTATS_MIN_COUNT", "APP_WEBSTATS_TOP_CATEGORIES",
            "APP_WEBSTATS_TOP_UAS", "APP_WEBSTATS_UA_MAX_CHARS", "APP_WEBSTATS_BACKFILL_MAX_MB",
            "APP_WEBSTATS_FILE_PROBE_SECONDS");

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
    @DisplayName("application.yml：app.webstats.* 七个键齐全且默认值正确")
    void applicationYmlHasWebStatsBlock() throws Exception {
        Map<String, Object> app = nested(readYaml("src/main/resources/application.yml"), "app");
        Map<String, Object> webstats = nested(app, "webstats");

        assertEquals("${APP_WEBSTATS_ENABLED:true}", webstats.get("enabled"),
                "默认开启；关掉要显式写 false（端点会如实返回 WEBSTATS_DISABLED）");
        assertEquals("${APP_WEBSTATS_MIN_COUNT:5}", webstats.get("min-count"),
                "入榜门槛默认 5（站主口径⑤：低于门槛的只进总量）");
        assertEquals("${APP_WEBSTATS_TOP_CATEGORIES:10}", webstats.get("top-categories"));
        assertEquals("${APP_WEBSTATS_TOP_UAS:5}", webstats.get("top-uas"));
        assertEquals("${APP_WEBSTATS_UA_MAX_CHARS:60}", webstats.get("ua-max-chars"),
                "公网 UA 截断长度默认 60 字符");
        assertEquals("${APP_WEBSTATS_BACKFILL_MAX_MB:64}", webstats.get("backfill-max-mb"));
        assertEquals("${APP_WEBSTATS_FILE_PROBE_SECONDS:10}", webstats.get("file-probe-seconds"));

        // 端点的 LOG_DISABLED 分支依赖这个键（读不到它就没法把"数据源关了"与"没有请求"分开）
        Map<String, Object> accesslog = nested(app, "accesslog");
        assertNotNull(accesslog.get("enabled"));
        Map<String, Object> publicApi = nested(app, "public-api");
        assertNotNull(publicApi.get("cache-seconds"), "端点复用 15 秒快照，键必须在");
    }

    @Test
    @DisplayName(".env.example：七个 APP_WEBSTATS_* 都有（模板 = 部署面说明书）")
    void envExampleDocumentsAllKeys() throws Exception {
        String env = Files.readString(Path.of(".env.example"), StandardCharsets.UTF_8);
        for (String key : KEYS) {
            assertTrue(env.contains(key + "="), ".env.example 缺少 " + key);
        }
        assertTrue(env.contains("APP_WEBSTATS_ENABLED=true"), "模板默认必须是 true（与 yml 一致）");
        assertTrue(env.contains("APP_WEBSTATS_MIN_COUNT=5"));
        assertTrue(env.contains("APP_WEBSTATS_UA_MAX_CHARS=60"));
        assertTrue(env.contains("回归") || env.contains("RUNBOOK §29"), "要指出口径文档在哪");
    }

    @Test
    @DisplayName("docker-compose.yml：environment 段显式透传七个键（少一个 = 改了不生效且不报错）")
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
        assertFalse(String.valueOf(merged.get("APP_WEBSTATS_ENABLED")).contains(":-false"),
                "compose 里的兜底默认也要是 true（与 yml/.env.example 一致）");
    }
}

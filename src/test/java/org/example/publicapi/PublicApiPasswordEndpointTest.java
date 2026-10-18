package org.example.publicapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code GET /api/public/password}（别名 {@code /api/public/password.js}）的端点契约测试。
 *
 * <p>钉的六件事：
 * <ol>
 *   <li>前缀校验：只收 {@code ^[0-9a-f]{5}$}，其余一律 400 {@code INVALID_PREFIX}；</li>
 *   <li>字典文件不存在 ⇒ 200 + {@code available:false} + reason（<b>不是</b>"0 次"）；</li>
 *   <li>命中桶 ⇒ {@code bucketCount} / {@code bucketLastSeen} / {@code hashes}（后 59 位）正确，
 *       且响应体里<b>没有任何明文口令</b>；</li>
 *   <li>超大桶 ⇒ 只下发 200 条 + {@code truncated:true}（截断必须说出口，不能让"未命中"承担歧义）；</li>
 *   <li>限流：第 31 次 429（默认 30 次/分钟，独立于只读端点的 20）；</li>
 *   <li>格式坏文件 ⇒ fail-closed（{@code DICT_INVALID_FORMAT}），不跳过坏条目继续用。</li>
 * </ol>
 */
class PublicApiPasswordEndpointTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @TempDir
    Path tmp;

    private PublicApiController controller;

    /** 与既有端点测试同一套装配：直接 new 控制器 + ReflectionTestUtils 填字段 */
    private void baseController(int passwordPerMinute) {
        controller = new PublicApiController();
        PublicRateLimiter limiter = new PublicRateLimiter();
        ReflectionTestUtils.setField(limiter, "requestsPerMinute", 20);
        ReflectionTestUtils.setField(controller, "rateLimiter", limiter);
        ReflectionTestUtils.setField(controller, "cacheSeconds", 15);
        ReflectionTestUtils.setField(controller, "exposeBuildSha", false);
        ReflectionTestUtils.setField(controller, "buildSha", "test");
        ReflectionTestUtils.setField(controller, "passwordRequestsPerMinute", passwordPerMinute);
        ReflectionTestUtils.setField(controller, "passwordCacheSeconds", 300);
        ReflectionTestUtils.setField(controller, "passwordMaxHashes", 200);
    }

    /** 把控制器指向一个新建的字典文件；返回该文件的路径 */
    private Path wireDict(String json) throws Exception {
        Path file = tmp.resolve("password-hashes.json");
        Files.writeString(file, json, StandardCharsets.UTF_8);
        PasswordDictionaryService svc = new PasswordDictionaryService();
        ReflectionTestUtils.setField(svc, "dictFile", file.toString());
        ReflectionTestUtils.setField(controller, "passwordDict", svc);
        return file;
    }

    private static String prefixOf(String plain) throws Exception {
        return PasswordDictionaryService.sha256Hex(plain).substring(0, 5);
    }

    private static String suffixOf(String plain) throws Exception {
        return PasswordDictionaryService.sha256Hex(plain).substring(5);
    }

    private static String dict(String bucketJson) {
        return "{\"generatedAt\":\"2026-10-18T09:00:00+08:00\",\"totalAttempts\":128934,\"unique\":41234,"
                + "\"buckets\":{" + bucketJson + "}}";
    }

    private MockMvc mvc() {
        return MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    @DisplayName("非法前缀：缺 p / 长度 4 或 6 / 大写 hex / 非 hex → 400 INVALID_PREFIX")
    void rejectsInvalidPrefixes() throws Exception {
        baseController(30);
        String[][] cases = {
                {"/api/public/password", ""},
                {"/api/public/password?p=a1b2", "长度 4"},
                {"/api/public/password?p=a1b2cd", "长度 6"},
                {"/api/public/password?p=A1B2C", "大写 hex"},
                {"/api/public/password?p=zzzzz", "非 hex"},
                {"/api/public/password?p=a1b2c%20", "尾随空格"},
        };
        for (String[] c : cases) {
            MockHttpServletResponse res = mvc().perform(get(c[0])).andReturn().getResponse();
            assertEquals(400, res.getStatus(), c[1] + " 应当是 400");
            JsonNode body = JSON.readTree(res.getContentAsString(StandardCharsets.UTF_8));
            assertEquals("INVALID_PREFIX", body.get("reason").asText(), c[1] + " 的 reason 应为 INVALID_PREFIX");
        }
    }

    @Test
    @DisplayName("字典文件不存在：200 + available:false + DICT_FILE_MISSING，且 bucketCount 为 null（不是 0）")
    void reportsUnavailableWhenDictMissing() throws Exception {
        baseController(30);
        PasswordDictionaryService svc = new PasswordDictionaryService();
        ReflectionTestUtils.setField(svc, "dictFile", tmp.resolve("nope.json").toString());
        ReflectionTestUtils.setField(controller, "passwordDict", svc);

        MockHttpServletResponse res = mvc().perform(get("/api/public/password?p=a1b2c"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(200))
                .andReturn().getResponse();

        JsonNode data = JSON.readTree(res.getContentAsString(StandardCharsets.UTF_8)).get("data");
        assertFalse(data.get("available").asBoolean());
        assertTrue(data.get("bucketCount").isNull(), "读不到时不能回 0（0 会被读成\"没被尝试过\"）");
        assertTrue(data.get("notes").asText().contains("DICT_FILE_MISSING"));
        assertEquals(0, data.get("hashes").size());
        assertEquals("PASSWORD_DICT_UNAVAILABLE", res.getHeader("X-Data-Source"));
    }

    @Test
    @DisplayName("命中桶：bucketCount / bucketLastSeen / hashes 正确，响应体里没有明文口令")
    void returnsBucketWhenPresent() throws Exception {
        baseController(30);
        String plain = "123456";
        String prefix = prefixOf(plain);
        String suffix = suffixOf(plain);
        wireDict(dict("\"" + prefix + "\":{\"count\":37,\"lastSeen\":\"2026-10-18T08:59:00+08:00\","
                + "\"hashes\":[\"" + suffix + "\"]}"));

        MockHttpServletResponse res = mvc().perform(get("/api/public/password?p=" + prefix))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.prefix").value(prefix))
                .andExpect(jsonPath("$.data.available").value(true))
                .andExpect(jsonPath("$.data.bucketCount").value(37))
                .andExpect(jsonPath("$.data.bucketLastSeen").value("2026-10-18T08:59:00+08:00"))
                .andExpect(jsonPath("$.data.hashes[0]").value(suffix))
                .andExpect(jsonPath("$.data.truncated").value(false))
                .andExpect(header().string("Cache-Control", "public, max-age=300"))
                .andReturn().getResponse();

        String body = res.getContentAsString(StandardCharsets.UTF_8);
        JsonNode data = JSON.readTree(body).get("data");
        assertTrue(data.get("match").isNull(), "match 恒为 null（后端不替用户判定）");
        assertFalse(body.contains(plain), "响应体里出现了明文口令");
        assertEquals("PASSWORD_DICT", res.getHeader("X-Data-Source"));
        // 完整 hash 也不下发：只有前 5 位（回显）与后 59 位（比对用）
        assertFalse(body.contains(prefix + suffix), "响应体里出现了完整 hash");
    }

    @Test
    @DisplayName("前缀存在但桶内无 suffix：available:true + bucketCount:0 + notes 给出生成时间")
    void returnsEmptyBucketHonestly() throws Exception {
        baseController(30);
        wireDict(dict("\"a1b2c\":{\"count\":3}"));

        mvc().perform(get("/api/public/password?p=fffff"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(true))
                .andExpect(jsonPath("$.data.bucketCount").value(0))
                .andExpect(jsonPath("$.data.hashes").isEmpty())
                .andExpect(jsonPath("$.data.notes").value(org.hamcrest.Matchers.containsString("不代表绝对安全")));
    }

    @Test
    @DisplayName("超大桶：只下发 200 条 + truncated:true（bucketCount 原样保留）")
    void truncatesOversizedBucket() throws Exception {
        baseController(30);
        String prefix = "abcde";
        StringBuilder hashes = new StringBuilder();
        for (int i = 0; i < 250; i++) {
            if (i > 0) {
                hashes.append(',');
            }
            hashes.append('"').append(String.format("%059x", i + 1)).append('"');
        }
        wireDict(dict("\"" + prefix + "\":{\"count\":999,\"hashes\":[" + hashes + "]}"));

        MockHttpServletResponse res = mvc().perform(get("/api/public/password?p=" + prefix))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.bucketCount").value(999))
                .andExpect(jsonPath("$.data.truncated").value(true))
                .andExpect(jsonPath("$.data.hashes.length()").value(200))
                .andReturn().getResponse();

        assertTrue(res.getContentAsString(StandardCharsets.UTF_8).contains("只下发前 200 条"));
    }

    @Test
    @DisplayName("限流：30 次/分钟内放行，第 31 次 429（独立于只读端点的 20 次）")
    void rateLimitsAtThirtyPerMinute() throws Exception {
        baseController(30);
        wireDict(dict("\"a1b2c\":{\"count\":1}"));

        for (int i = 1; i <= 30; i++) {
            mvc().perform(get("/api/public/password?p=a1b2c"))
                    .andExpect(status().isOk());
        }
        MockHttpServletResponse res = mvc().perform(get("/api/public/password?p=a1b2c"))
                .andExpect(status().isTooManyRequests())
                .andReturn().getResponse();
        JsonNode body = JSON.readTree(res.getContentAsString(StandardCharsets.UTF_8));
        assertEquals(429, body.get("code").asInt());
        assertEquals("0", res.getHeader("X-RateLimit-Remaining"));
        assertEquals("30", res.getHeader("X-RateLimit-Limit"));
    }

    @Test
    @DisplayName("字典格式坏：fail-closed 成 available:false + DICT_INVALID_FORMAT，不跳过坏条目")
    void failsClosedOnBrokenDictionary() throws Exception {
        baseController(30);
        wireDict("{\"buckets\":{\"ZZZZZ\":{\"count\":1}}}");

        MockHttpServletResponse res = mvc().perform(get("/api/public/password?p=a1b2c"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(false))
                .andReturn().getResponse();

        JsonNode data = JSON.readTree(res.getContentAsString(StandardCharsets.UTF_8)).get("data");
        assertTrue(data.get("notes").asText().contains("DICT_INVALID_FORMAT"));
        assertEquals(0, data.get("hashes").size());
    }

    @Test
    @DisplayName("别名 /password.js 走同一路由，且没装字典时也照常回 200（不 500）")
    void aliasRouteWorksWithoutDictionary() throws Exception {
        baseController(30);
        // 故意不注入 passwordDict：模拟"裁剪部署 / 配置缺省"
        mvc().perform(get("/api/public/password.js?p=012ab"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.available").value(false))
                .andExpect(header().string("Cache-Control", "public, max-age=300"));

        JsonNode data = JSON.readTree(mvc().perform(get("/api/public/password.js?p=012ab"))
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8)).get("data");
        assertTrue(data.get("notes").asText().contains("DICT_NOT_WIRED"));
        assertNotNull(data.get("limits"));
        assertEquals(30, data.get("limits").get("perMinute").asInt());
    }

    /** 顺带钉住离线脚本与测试共用的 hash 口径：SHA-256 的 hex 必然是 64 位小写 */
    @Test
    @DisplayName("hash 口径：64 位小写 hex，前 5 位与后 59 位拼回完整值")
    void hashShapeIsStable() throws Exception {
        List<String> plains = new ArrayList<>(List.of("123456", "password", "P@ssw0rd!", "中文口令"));
        for (String plain : plains) {
            String hex = PasswordDictionaryService.sha256Hex(plain);
            assertEquals(64, hex.length());
            assertTrue(PasswordDictionaryService.isLowerHex(hex, 64), plain + " 的 hex 不是小写");
            assertEquals(hex, prefixOf(plain) + suffixOf(plain));
        }
    }
}

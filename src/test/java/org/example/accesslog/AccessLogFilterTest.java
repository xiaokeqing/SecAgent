package org.example.accesslog;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 应用侧访问日志（{@link AccessLogFilter}）的行为测试。
 *
 * <h3>这份测试在钉什么</h3>
 * 加访问日志最容易造成的<b>不是"没日志"，而是"记了不该记的"</b>：
 * 请求体、查询串原文、Cookie、Authorization 一旦落盘，
 * 这个文件就会被 fail2ban/Wazuh 反复读、被人打包带走排障 —— 等于二次泄露。
 * 所以这里每一条"白名单"承诺都配一个哨兵值断言，
 * 任何人以后顺手多记一个字段，这些测试会立刻变红。
 */
class AccessLogFilterTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Path tmpDir;
    private AccessLogFilter filter;

    @BeforeEach
    void setUp() throws IOException {
        tmpDir = Files.createTempDirectory("accesslog-filter-test");
    }

    @AfterEach
    void tearDown() throws IOException {
        if (filter != null) {
            filter.shutdown();
        }
        deleteRecursively(tmpDir);
    }

    private AccessLogFilter newFilter(boolean enabled, int retainDays, int maxFileMb, String skipPaths) {
        AccessLogFilter f = new AccessLogFilter();
        ReflectionTestUtils.setField(f, "enabled", enabled);
        ReflectionTestUtils.setField(f, "dir", tmpDir.toString());
        ReflectionTestUtils.setField(f, "retainDays", retainDays);
        ReflectionTestUtils.setField(f, "maxFileMb", maxFileMb);
        ReflectionTestUtils.setField(f, "skipPaths", skipPaths);
        f.initAccessLog();
        return f;
    }

    /** 跑一次请求：下游链把状态码设成 {@code status}（等价于 DispatcherServlet 的结果） */
    private void run(MockHttpServletRequest req, int status) throws Exception {
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = (rq, rs) -> ((HttpServletResponse) rs).setStatus(status);
        filter.doFilter(req, res, chain);
    }

    private List<JsonNode> loggedRows() throws Exception {
        filter.writerForTest().drain();
        List<JsonNode> rows = new ArrayList<>();
        try (Stream<Path> files = Files.list(tmpDir)) {
            List<Path> sorted = files.filter(p -> p.getFileName().toString().startsWith("access"))
                    .sorted(Comparator.comparing(Path::toString)).toList();
            for (Path p : sorted) {
                for (String line : Files.readAllLines(p, StandardCharsets.UTF_8)) {
                    if (!line.isBlank()) {
                        rows.add(MAPPER.readTree(line));
                    }
                }
            }
        }
        return rows;
    }

    @Test
    @DisplayName("【核心·字段白名单】每行恰好 9 个字段、顺序固定，且不记请求体/查询值/Cookie/Authorization")
    void onlyWhitelistedFieldsAreLogged() throws Exception {
        filter = newFilter(true, 7, 64, "/api/health");

        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/chat");
        req.setQueryString("q=..%2Fetc%2Fpasswd&token=SECRET-TOKEN-123");
        req.setContent(("{\"prompt\":\"BODY-SENTINEL-9f3a\"}").getBytes(StandardCharsets.UTF_8));
        req.addHeader("Content-Type", "application/json");
        req.addHeader("Cookie", "SESSION=COOKIE-SENTINEL-7b1c");
        req.addHeader("Authorization", "Bearer AUTH-SENTINEL-4d2e");
        req.addHeader("Referer", "https://example.com/REFERER-SENTINEL");
        req.addHeader("User-Agent", "sqlmap/1.7#stable (http://sqlmap.org)");
        req.addHeader("CF-Connecting-IP", "203.0.113.9");
        run(req, 403);

        List<JsonNode> rows = loggedRows();
        assertEquals(1, rows.size(), "一次请求应当只有一行访问日志");
        JsonNode row = rows.get(0);

        List<String> keys = new ArrayList<>();
        row.fieldNames().forEachRemaining(keys::add);
        assertEquals(List.of("ts", "method", "path", "queryKeys", "status", "clientIp", "ua", "ms", "reqId"),
                keys, "字段白名单与顺序是 fail2ban 正则的依赖项，不能随手改");
        assertEquals(9, row.size(), "只能有白名单里的这几个字段（新增字段默认就泄露）");

        assertEquals("POST", row.get("method").asText());
        assertEquals("/api/chat", row.get("path").asText(), "path 不得带查询串");
        assertEquals("q,token", row.get("queryKeys").asText(), "查询串只保留键名");
        assertEquals(403, row.get("status").asInt());
        assertEquals("203.0.113.9", row.get("clientIp").asText());
        assertEquals("sqlmap/1.7#stable (http://sqlmap.org)", row.get("ua").asText());
        assertTrue(row.get("ms").asLong() >= 0);
        assertFalse(row.get("reqId").asText().isEmpty());
        assertFalse(row.get("ts").asText().isEmpty());

        String raw = row.toString();
        for (String secret : List.of("BODY-SENTINEL-9f3a", "SECRET-TOKEN-123", "passwd",
                "COOKIE-SENTINEL-7b1c", "AUTH-SENTINEL-4d2e", "REFERER-SENTINEL", "Bearer")) {
            assertFalse(raw.contains(secret), "敏感内容绝不允许落盘：" + secret + " 出现在 " + raw);
        }

        // 不改公开面语义：没有加任何响应头、没有改状态码
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(new MockHttpServletRequest("GET", "/api/overview"), res,
                (rq, rs) -> ((HttpServletResponse) rs).setStatus(200));
        assertEquals(200, res.getStatus(), "访问日志不得改变状态码");
        assertTrue(res.getHeaderNames().isEmpty(), "访问日志不得新增任何响应头（公开面字段/ETag/CORS 语义不许变）");
    }

    @Test
    @DisplayName("ts 是带时区的 ISO 时间、小数位 1-6 位（fail2ban 的日期模板只认 1-6 位小数）")
    void tsFormatMatchesFail2banDatePattern() throws Exception {
        filter = newFilter(true, 7, 64, "");
        run(new MockHttpServletRequest("GET", "/wp-login.php"), 404);

        String ts = loggedRows().get(0).get("ts").asText();
        assertTrue(ts.matches("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,6})?(?:Z|[+-]\\d{2}:\\d{2})$"),
                "ts 形态必须能被 fail2ban 的 datepattern 解析（纳秒精度会让它退化成'当前时间'）：" + ts);
        assertEquals(ts, java.time.OffsetDateTime.parse(ts)
                .format(java.time.format.DateTimeFormatter.ISO_OFFSET_DATE_TIME), "ts 必须能解析回同一个值");
    }

    @Test
    @DisplayName("HTTP 方法/路径/UA 都被截断与清洗（防日志注入与超长行）")
    void longAndDirtyValuesAreSanitized() throws Exception {
        filter = newFilter(true, 7, 64, "");
        String longUa = "U".repeat(500);
        String longPath = "/" + "p".repeat(900);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", longPath);
        req.addHeader("User-Agent", longUa + "\r\nX-Injected: yes");
        req.addHeader("CF-Connecting-IP", "198.51.100.7");
        run(req, 404);

        JsonNode row = loggedRows().get(0);
        assertEquals(AccessLogFilter.PATH_MAX_CHARS, row.get("path").asText().length(), "path 必须截断到 512");
        assertEquals(AccessLogFilter.UA_MAX_CHARS, row.get("ua").asText().length(), "ua 必须截断到 200");
        assertFalse(row.get("ua").asText().contains("\r"), "控制字符必须被替换，防止日志注入/伪造行");
        assertFalse(row.get("ua").asText().contains("\n"));
    }

    @Test
    @DisplayName("clientIp：优先 CF-Connecting-IP；非法/伪造值回落 remoteAddr（不落任意字符串）")
    void clientIpResolution() throws Exception {
        filter = newFilter(true, 7, 64, "");

        MockHttpServletRequest withCf = new MockHttpServletRequest("GET", "/wp-login.php");
        withCf.addHeader("CF-Connecting-IP", "203.0.113.9");
        withCf.setRemoteAddr("127.0.0.1");
        run(withCf, 404);

        MockHttpServletRequest spoof = new MockHttpServletRequest("GET", "/.env");
        spoof.addHeader("CF-Connecting-IP", "not-an-ip NO\"quote\"; DROP");
        spoof.setRemoteAddr("198.51.100.33");
        run(spoof, 404);

        MockHttpServletRequest ipv6 = new MockHttpServletRequest("GET", "/.git/config");
        ipv6.addHeader("CF-Connecting-IP", "2001:db8::1");
        ipv6.setRemoteAddr("127.0.0.1");
        run(ipv6, 404);

        List<JsonNode> rows = loggedRows();
        assertEquals("203.0.113.9", rows.get(0).get("clientIp").asText());
        assertEquals("198.51.100.33", rows.get(1).get("clientIp").asText(),
                "CF 头不是合法 IP 字面量时必须回落 remoteAddr（否则等于让攻击者自己写 IP）");
        assertEquals("2001:db8::1", rows.get(2).get("clientIp").asText());
    }

    @Test
    @DisplayName("skip-paths：精确匹配与前缀匹配都生效（/api/health 不再刷屏）")
    void skipPathsWork() throws Exception {
        filter = newFilter(true, 7, 64, "/api/health,/static/*");

        run(new MockHttpServletRequest("GET", "/api/health"), 200);
        run(new MockHttpServletRequest("GET", "/static/js/app.js"), 200);
        MockHttpServletRequest kept = new MockHttpServletRequest("GET", "/api/overview");
        kept.addHeader("CF-Connecting-IP", "203.0.113.10");
        run(kept, 200);

        List<JsonNode> rows = loggedRows();
        assertEquals(1, rows.size(), "被跳过的路径不得出现，其余一个都不能少");
        assertEquals("/api/overview", rows.get(0).get("path").asText());
    }

    @Test
    @DisplayName("关闭开关：enabled=false 时一行不写、不建文件，但请求照常走完")
    void disabledMeansNoFile() throws Exception {
        filter = newFilter(false, 7, 64, "");

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/wp-login.php");
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, (rq, rs) -> ((HttpServletResponse) rs).setStatus(404));

        assertNull(filter.writerForTest(), "关闭时不应有写入器");
        assertEquals(404, res.getStatus(), "关闭访问日志不得影响请求处理");
        try (Stream<Path> files = Files.list(tmpDir)) {
            assertEquals(0, files.count(), "关闭时应保持目录干净（不建文件）");
        }
    }

    @Test
    @DisplayName("日志目录不可写：如实降级（打 WARN、不建写入器），请求完全不受影响")
    void unwritableDirDegradesHonestly() throws Exception {
        Path aFile = tmpDir.resolve("iam-a-file");
        Files.writeString(aFile, "x");
        AccessLogFilter f = new AccessLogFilter();
        ReflectionTestUtils.setField(f, "enabled", true);
        ReflectionTestUtils.setField(f, "dir", aFile.resolve("nested").toString());
        ReflectionTestUtils.setField(f, "retainDays", 7);
        ReflectionTestUtils.setField(f, "maxFileMb", 64);
        ReflectionTestUtils.setField(f, "skipPaths", "");
        f.initAccessLog();
        filter = f;

        assertNull(f.writerForTest(), "写不出去时必须降级成 null 而不是假装成功");
        assertFalse(f.degradedReason().isEmpty(), "降级原因必须留着（启动自检与排障要看）");

        MockHttpServletResponse res = new MockHttpServletResponse();
        f.doFilter(new MockHttpServletRequest("GET", "/wp-login.php"), res,
                (rq, rs) -> ((HttpServletResponse) rs).setStatus(404));
        assertEquals(404, res.getStatus(), "日志写不出来绝不能让请求失败");
    }

    @Test
    @DisplayName("下游抛异常：异常照常向上抛，日志记 500（而不是假的 200）")
    void exceptionPropagatesAndIsLoggedAs500() throws Exception {
        filter = newFilter(true, 7, 64, "");
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/secret");
        MockHttpServletResponse res = new MockHttpServletResponse();

        assertThrows(IllegalStateException.class, () -> filter.doFilter(req, res, (rq, rs) -> {
            throw new IllegalStateException("boom");
        }));

        List<JsonNode> rows = loggedRows();
        assertEquals(1, rows.size());
        assertEquals(500, rows.get(0).get("status").asInt(),
                "未捕获异常最终会被容器映射成 500，这里必须如实记 500");
    }

    @Test
    @DisplayName("响应已经写好 5xx 时不改写：状态码原样记录")
    void fiveHundredIsRecordedAsIs() throws Exception {
        filter = newFilter(true, 7, 64, "");
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/boom");
        run(req, 503);
        assertEquals(503, loggedRows().get(0).get("status").asInt());
    }

    @Test
    @DisplayName("纯函数：查询键名解析只取键、去重、限量（值永远不参与）")
    void queryKeysParsing() {
        assertEquals("", AccessLogFilter.queryKeys(null));
        assertEquals("", AccessLogFilter.queryKeys(""));
        assertEquals("a", AccessLogFilter.queryKeys("a=1"));
        assertEquals("a,b", AccessLogFilter.queryKeys("a=1&b=2&a=3"), "同名键只记一次");
        assertEquals("flag", AccessLogFilter.queryKeys("flag"));
        assertEquals("a,b,c", AccessLogFilter.queryKeys("a=SECRET1&b=SECRET2&c=SECRET3"));
        assertFalse(AccessLogFilter.queryKeys("a=SECRET1&b=SECRET2").contains("SECRET"));

        StringBuilder many = new StringBuilder();
        for (int i = 0; i < 20; i++) {
            many.append("k").append(i).append("=v&");
        }
        assertEquals(AccessLogFilter.MAX_QUERY_KEYS, AccessLogFilter.queryKeys(many.toString()).split(",").length,
                "键名数量必须封顶（否则一行日志能被 URL 撑爆）");
    }

    @Test
    @DisplayName("IP 字面量校验：不触发 DNS 解析、不放行主机名与畸形串")
    void ipLiteralValidation() {
        assertTrue(AccessLogFilter.isIpLiteral("1.2.3.4"));
        assertTrue(AccessLogFilter.isIpLiteral("255.255.255.255"));
        assertFalse(AccessLogFilter.isIpLiteral("256.1.1.1"));
        assertFalse(AccessLogFilter.isIpLiteral("1.2.3"));
        assertFalse(AccessLogFilter.isIpLiteral("localhost"));
        assertFalse(AccessLogFilter.isIpLiteral("evil.example.com"));
        assertFalse(AccessLogFilter.isIpLiteral("1.2.3.4; DROP"));
        assertFalse(AccessLogFilter.isIpLiteral(null));
        assertTrue(AccessLogFilter.isIpLiteral("::1"));
        assertTrue(AccessLogFilter.isIpLiteral("::ffff:203.0.113.9"));
        assertFalse(AccessLogFilter.isIpLiteral("::::"));
    }

    @Test
    @DisplayName("启动自检：写不出来时 degradedReason 非空；正常时能拿到活动文件路径")
    void startupSelfCheckIsVisible() {
        filter = newFilter(true, 7, 64, "/api/health");
        assertNotNull(filter.writerForTest(), "正常启动必须有写入器");
        assertTrue(filter.writerForTest().activeFilePath().endsWith("access.jsonl"),
                "活动文件名必须稳定（fail2ban/Wazuh 指的就是这个路径）："
                        + filter.writerForTest().activeFilePath());
        assertEquals(7, filter.writerForTest().retainDays());
        assertEquals(64L * 1024 * 1024, filter.writerForTest().maxFileBytes());
    }

    private static void deleteRecursively(Path root) throws IOException {
        if (root == null || !Files.exists(root)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(root)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    // 临时目录清理失败不影响测试结论
                }
            });
        }
    }
}

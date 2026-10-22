package org.example.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.publicapi.PublicIpPolicy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code /api/public/daily/index.json}：归档索引一次给全，前端不再按日期试探。
 *
 * <p>三条要守住的行为：① 只认白名单文件名（目录里被塞别的东西不能出现在归档里）；
 * ② 新的在前（页面直接照着渲染）；③ 单份清单坏了只坏那一行，整张表照常返回。
 */
class DailyReportControllerIndexTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    private static DailyReportController controller(Path dir) {
        ReportProperties props = new ReportProperties();
        props.setDir(dir.toString());
        return new DailyReportController(props, PublicIpPolicy.masking());
    }

    private static void write(Path dir, String name, String body) throws Exception {
        Files.writeString(dir.resolve(name), body);
    }

    @Test
    void listsOnlyWhitelistedManifestsNewestFirst(@TempDir Path dir) throws Exception {
        write(dir, "daily-2026-10-21.json", """
                {"date":"2026-10-21","generatedAt":"2026-10-21 08:10:00","alertTotal":100,
                 "alertsBySeverity":{"CRITICAL":1,"HIGH":2,"MEDIUM":3,"LOW":4},
                 "topCountry":{"code":"NL","name":"荷兰","count":60,"uniqueIps":7},
                 "worstSource":{"ip":"193.32.162.20","attempts":293},"missing":[]}
                """);
        write(dir, "daily-2026-10-22.json", """
                {"date":"2026-10-22","generatedAt":"2026-10-22 08:10:00","alertTotal":200,
                 "alertsBySeverity":{"CRITICAL":5,"HIGH":6},
                 "topCountry":{"code":"SG","name":"新加坡","count":90,"uniqueIps":3},
                 "worstSource":{"ip":"10.1.2.3","attempts":9},"missing":["geo"]}
                """);
        /* 以下三个都不该出现在归档里：后缀不对、名字不对、是目录里别人的东西 */
        write(dir, "daily-2026-10-20.html", "<html></html>");
        write(dir, "notes.json", "{}");
        write(dir, "daily-2026-10-19.json.bak", "{}");
        write(dir, "daily-2026-10-22.md", "# 日报");
        write(dir, "daily-2026-10-22.wav", "RIFF");

        Map<String, Object> body = controller(dir).index().getBody();
        assertEquals(2, body.get("count"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> days = (List<Map<String, Object>>) body.get("days");
        assertEquals("2026-10-22", days.get(0).get("date"), "新的在前");
        assertEquals("2026-10-21", days.get(1).get("date"));
        assertEquals(200L, days.get(0).get("alertTotal"));
        assertEquals(1, days.get(0).get("missingCount"));
        assertEquals(0, ((Number) days.get(1).get("missingCount")).intValue());

        /* IP 一律掩码出库：归档表也不能把完整地址递到浏览器 */
        @SuppressWarnings("unchecked")
        Map<String, Object> worst = (Map<String, Object>) days.get(1).get("worstSource");
        assertFalse(String.valueOf(worst.get("ip")).endsWith(".20"), "最后一段应被掩码");

        /* 同一天有哪些交付物：存在的才列，不存在的 key 不出现 */
        @SuppressWarnings("unchecked")
        Map<String, Object> files = (Map<String, Object>) days.get(0).get("files");
        assertTrue(files.containsKey("json"));
        assertTrue(files.containsKey("md"));
        assertTrue(files.containsKey("wav"));
        assertFalse(files.containsKey("html"), "10-22 没有 html");
        @SuppressWarnings("unchecked")
        Map<String, Object> md = (Map<String, Object>) files.get("md");
        assertEquals("/api/public/daily/daily-2026-10-22.md", md.get("url"));
        assertEquals("text", md.get("contentType"));
    }

    @Test
    void brokenManifestOnlyMarksThatRow(@TempDir Path dir) throws Exception {
        write(dir, "daily-2026-10-22.json", "{ this is not json");
        write(dir, "daily-2026-10-21.json", """
                {"date":"2026-10-21","generatedAt":"2026-10-21 08:10:00","alertTotal":100,
                 "alertsBySeverity":{},"topCountry":{},"worstSource":{},"missing":[]}
                """);

        Map<String, Object> body = controller(dir).index().getBody();
        assertEquals(2, body.get("count"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> days = (List<Map<String, Object>>) body.get("days");
        assertEquals("unreadable", days.get(0).get("reason"));
        assertEquals(100L, days.get(1).get("alertTotal"));
    }

    @Test
    void emptyDirectoryStillAnswers(@TempDir Path dir) throws Exception {
        Map<String, Object> body = controller(dir).index().getBody();
        assertEquals(0, body.get("count"));
        assertTrue(((List<?>) body.get("days")).isEmpty());
        assertTrue(body.containsKey("masked"), "口径字段与 /daily.js 保持一致");
        assertTrue(JSON.writeValueAsString(body).length() > 20);
    }
}

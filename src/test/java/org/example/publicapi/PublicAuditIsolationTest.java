package org.example.publicapi;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 评测流量在公开端点上的隔离测试。
 *
 * <h3>防的是什么</h3>
 * 评测会反复问"请封禁 xxx"来测护栏，这类流量一旦进入公开端点的数据源，
 * 大屏上就会出现"处置发生了"的假象（而实际什么都没封）。
 * 更糟的是这类污染<b>不会报错</b>：接口 200、字段齐全，只是数字是假的。
 * <p>
 * 所以这里对真实留痕文件断言：标记为评测的记录（{@code evalRunId} 非空，
 * 或 {@code actor} 以 {@code eval-} 开头）必须查不到，普通记录一条都不能少。
 */
class PublicAuditIsolationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @TempDir
    Path dataDir;

    private PublicAuditReader readerWith(Path dir) {
        PublicAuditReader reader = new PublicAuditReader();
        ReflectionTestUtils.setField(reader, "dataDir", dir.toString());
        return reader;
    }

    private void write(String fileName, String json) throws Exception {
        Files.write(dataDir.resolve(fileName), json.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("【核心】/api/public/audit 的 actions：评测记录查不到，真实记录完整保留")
    void evalActionsAreFilteredOut() throws Exception {
        write("response-audit.json", "["
                + "{\"id\":\"AUD-1\",\"time\":\"2026-10-12 10:00:00\",\"actor\":\"admin\",\"action\":\"block-ip\","
                + "\"target\":\"203.0.113.9\",\"reason\":\"真实处置\",\"mode\":\"REAL\",\"success\":true},"
                + "{\"id\":\"AUD-EVAL-1\",\"time\":\"2026-10-12 10:01:00\",\"actor\":\"eval-runner\",\"action\":\"封禁IP\","
                + "\"target\":\"192.0.2.66\",\"reason\":\"评测模拟\",\"mode\":\"SIMULATED\",\"success\":false,"
                + "\"evalRunId\":\"EVAL-abc123\"},"
                + "{\"id\":\"AUD-2\",\"time\":\"2026-10-12 10:02:00\",\"actor\":\"analyst\",\"action\":\"block-ip\","
                + "\"target\":\"198.51.100.7\",\"reason\":\"真实处置2\",\"mode\":\"REAL\",\"success\":true}"
                + "]");

        List<Map<String, Object>> actions = readerWith(dataDir).actions(30);

        assertEquals(2, actions.size(), "评测记录必须被过滤掉，真实记录必须都在");
        List<String> ids = actions.stream().map(a -> String.valueOf(a.get("id"))).toList();
        assertTrue(ids.contains("AUD-1"));
        assertTrue(ids.contains("AUD-2"));
        assertFalse(ids.contains("AUD-EVAL-1"), "评测审计记录不得出现在公开端点");
        assertFalse(actions.stream().anyMatch(a -> "EVAL-abc123".equals(a.get("evalRunId"))),
                "公开端点载荷里不该出现 evalRunId");
    }

    @Test
    @DisplayName("评测标记的封禁记录同样被过滤（大屏计数不受评测影响）")
    void evalBlocksAreFilteredOut() throws Exception {
        write("blocked-ips.json", "["
                + "{\"id\":\"BLK-1\",\"ip\":\"203.0.113.9\",\"createdAt\":\"2026-10-12 10:00:00\",\"actor\":\"admin\","
                + "\"source\":\"手动\",\"auditId\":\"AUD-1\"},"
                + "{\"id\":\"BLK-EVAL\",\"ip\":\"192.0.2.66\",\"createdAt\":\"2026-10-12 10:01:00\",\"actor\":\"eval-runner\","
                + "\"source\":\"智能体\",\"auditId\":\"AUD-EVAL-1\",\"evalRunId\":\"EVAL-abc123\"}"
                + "]");

        PublicAuditReader reader = readerWith(dataDir);
        List<Map<String, Object>> blocks = reader.blocks(20);
        assertEquals(1, blocks.size(), "评测产生的封禁记录必须被过滤（它是模拟的，没真封）");
        assertEquals("BLK-1", blocks.get(0).get("id"));

        Map<String, Object> summary = reader.summary();
        assertEquals(1, summary.get("blockTotal"), "summary 的总数也必须只算真实记录");
    }

    @Test
    @DisplayName("没写 evalRunId、但 actor 是评测身份的记录也会被过滤（双保险）")
    void evalActorIsFilteredEvenWithoutRunId() throws Exception {
        write("response-audit.json", "["
                + "{\"id\":\"AUD-X\",\"time\":\"2026-10-12 10:00:00\",\"actor\":\"eval-runner\",\"action\":\"封禁IP\","
                + "\"target\":\"192.0.2.66\",\"mode\":\"SIMULATED\",\"success\":false}"
                + "]");
        assertTrue(readerWith(dataDir).actions(30).isEmpty(),
                "actor 以 eval- 开头即视为评测流量");
    }

    @Test
    @DisplayName("判据单元测试：evalRunId 非空或 actor 前缀命中才算评测记录")
    void isEvalRecordJudgement() throws Exception {
        assertTrue(PublicAuditReader.isEvalRecord(MAPPER.readTree("{\"actor\":\"eval-runner\"}")));
        assertTrue(PublicAuditReader.isEvalRecord(MAPPER.readTree("{\"actor\":\"admin\",\"evalRunId\":\"EVAL-1\"}")));
        assertFalse(PublicAuditReader.isEvalRecord(MAPPER.readTree("{\"actor\":\"admin\"}")));
        assertFalse(PublicAuditReader.isEvalRecord(MAPPER.readTree("{\"actor\":\"evaluator\"}")),
                "只有 'eval-' 前缀才算，'evaluator' 这种普通用户名不该被误伤");
        assertFalse(PublicAuditReader.isEvalRecord(MAPPER.readTree("{\"actor\":\"admin\",\"evalRunId\":\"\"}")));
        assertFalse(PublicAuditReader.isEvalRecord(MAPPER.readTree("{\"actor\":\"admin\",\"evalRunId\":null}")));
    }

    @Test
    @DisplayName("留痕文件读不到时 fail-closed：返回空列表，绝不编造数据")
    void missingFileYieldsEmptyList() {
        assertTrue(readerWith(dataDir).actions(30).isEmpty());
        assertTrue(readerWith(dataDir).blocks(20).isEmpty());
        assertEquals(0, readerWith(dataDir).summary().get("blockTotal"));
    }
}

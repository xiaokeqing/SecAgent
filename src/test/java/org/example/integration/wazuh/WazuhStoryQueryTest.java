package org.example.integration.wazuh;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.config.OutboundTimeouts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 攻击故事线在 <b>indexer 侧</b>的口径测试（不联网：用 {@link WazuhClient} 的替身喂固定 JSON）。
 *
 * <p>它钉的是三件最容易写错、且<b>错了不会报错</b>的事：
 * <ol>
 *   <li>两个来源字段（{@code data.srcip} / {@code data.src_ip}）分别聚合后要按 IP <b>合并</b>
 *       —— 只查一个字段会安静地丢掉一大半来源；</li>
 *   <li>"窗口内这段没有数据"与"索引里根本没有这类数据（未接入）"必须给出<b>不同</b>的状态；
 *       判定查询失败时给 {@code UNKNOWN}，<b>不猜"未接入"</b>；</li>
 *   <li>查询体是<b>字段白名单</b>（{@code _source}）：蜜罐文档里的明文口令
 *       （{@code data.password} / {@code data.message}）与原始日志根本不进入进程。</li>
 * </ol>
 */
class WazuhStoryQueryTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 只回放固定 JSON 的客户端替身（不发起任何网络请求） */
    private static final class StubClient extends WazuhClient {
        private final String aggJson;
        private final String searchJson;
        private final boolean failSearch;
        private final List<String> queries = new ArrayList<>();

        private StubClient(String aggJson, String searchJson, boolean failSearch) {
            super("http://localhost:55000", "u", "p", false,
                    OutboundTimeouts.defaults(), null, null, null, null);
            this.aggJson = aggJson;
            this.searchJson = searchJson;
            this.failSearch = failSearch;
        }

        @Override
        public JsonNode fetchStorySources(int windowHours, int topSources, List<String> srcFields)
                throws java.io.IOException {
            return MAPPER.readTree(aggJson);
        }

        @Override
        public JsonNode search(String indexPattern, String bodyJson) throws java.io.IOException {
            queries.add(bodyJson);
            if (failSearch) {
                throw new java.io.IOException("判定查询失败（模拟）");
            }
            return MAPPER.readTree(searchJson);
        }
    }

    private static WazuhService service(WazuhClient client) {
        WazuhService s = new WazuhService();
        ReflectionTestUtils.setField(s, "client", client);
        return s;
    }

    // ==================== 候选来源聚合的解析 ====================

    @Test
    @DisplayName("两个来源字段分别聚合后按 IP 合并；首末时间转本地；最高等级取最大")
    void mergesTwoSourceFieldsByIp() throws Exception {
        String json = """
                {"hits":{"total":{"value":112693}},
                 "aggregations":{
                   "alerts_0":{"doc_count":10,"ips":{"buckets":[
                      {"key":"77.90.185.30","doc_count":21,
                       "min_ts":{"value_as_string":"2026-10-13T16:10:00.000Z"},
                       "max_ts":{"value_as_string":"2026-10-13T17:00:00.000Z"},
                       "max_level":{"value":12}}]}},
                   "alerts_1":{"doc_count":5,"ips":{"buckets":[
                      {"key":"77.90.185.30","doc_count":7,
                       "min_ts":{"value_as_string":"2026-10-13T15:00:00.000Z"},
                       "max_ts":{"value_as_string":"2026-10-13T16:30:00.000Z"},
                       "max_level":{"value":3}}]}},
                   "decoy_0":{"doc_count":0,"ips":{"buckets":[]}},
                   "decoy_1":{"doc_count":54,"ips":{"buckets":[
                      {"key":"77.90.185.30","doc_count":54,
                       "min_ts":{"value_as_string":"2026-10-13T16:15:00.000Z"},
                       "max_ts":{"value_as_string":"2026-10-13T17:05:00.000Z"},
                       "max_level":{"value":6}}]}},
                   "honeypot_0":{"doc_count":0,"ips":{"buckets":[]}},
                   "honeypot_1":{"doc_count":64,"ips":{"buckets":[
                      {"key":"103.149.197.34","doc_count":64,
                       "min_ts":{"value_as_string":"2026-10-13T15:00:00.000Z"},
                       "max_ts":{"value_as_string":"2026-10-13T16:40:00.000Z"},
                       "max_level":{"value":10}}]}},
                   "logins_0":{"doc_count":0,"ips":{"buckets":[]}},
                   "logins_1":{"doc_count":21,"ips":{"buckets":[
                      {"key":"103.149.197.34","doc_count":21,
                       "min_ts":{"value_as_string":"2026-10-13T15:30:00.000Z"},
                       "max_ts":{"value_as_string":"2026-10-13T16:40:00.000Z"},
                       "max_level":{"value":10}}]}},
                   "src_present":{"doc_count":106976}}}
                """;
        Map<String, Object> out = WazuhService.parseStorySources(MAPPER.readTree(json), 2, 24);

        assertEquals(true, out.get("available"));
        assertEquals("OK", out.get("reason"));
        assertEquals(112693L, out.get("indexerTotal"));
        assertEquals(106976L, out.get("withSourceIp"));
        assertEquals(54L, out.get("decoyTotal"));
        assertEquals(21L, out.get("honeypotLoginTotal"));

        List<Map<String, Object>> sources = list(out.get("sources"));
        assertEquals(2, sources.size());
        Map<String, Object> decoy = sources.get(0);
        assertEquals("77.90.185.30", decoy.get("srcIp"));
        assertEquals(28L, decoy.get("alerts"), "两个字段的告警数必须相加（21+7）");
        assertEquals(54L, decoy.get("decoyPorts"));
        assertEquals(0L, decoy.get("honeypotLogins"));
        assertEquals(12, decoy.get("maxLevel"));
        // 时间按本地时区换算（用同一个函数算期望值，避免测试在别的时区机器上飘）
        assertEquals(WazuhTime.toLocal("2026-10-13T15:00:00.000Z"), decoy.get("firstSeen"));
        assertEquals(WazuhTime.toLocal("2026-10-13T17:05:00.000Z"), decoy.get("lastSeen"));

        Map<String, Object> honeypot = sources.get(1);
        assertEquals("103.149.197.34", honeypot.get("srcIp"));
        assertEquals(0L, honeypot.get("alerts"));
        assertEquals(21L, honeypot.get("honeypotLogins"));
        assertEquals(64L, honeypot.get("honeypotEvents"), "全量蜜罐事件只作旁证，不进 stages 计数");
    }

    @Test
    @DisplayName("响应里没有 aggregations 节点 = 查询没按预期执行（不许当成'窗口内没有攻击'）")
    void missingAggregationsIsAnError() throws Exception {
        Map<String, Object> out = WazuhService.parseStorySources(
                MAPPER.readTree("{\"hits\":{\"total\":{\"value\":5}}}"), 2, 24);

        assertEquals(false, out.get("available"));
        assertEquals("EMPTY_RESPONSE", out.get("reason"));
    }

    @Test
    @DisplayName("聚合成功但没有来源 = available=true + NO_DATA_IN_WINDOW（不是故障）")
    void emptyBucketsAreNotAnError() throws Exception {
        Map<String, Object> out = WazuhService.parseStorySources(MAPPER.readTree("""
                {"hits":{"total":{"value":0}},"aggregations":{"src_present":{"doc_count":0}}}
                """), 2, 6);

        assertEquals(true, out.get("available"));
        assertEquals("NO_DATA_IN_WINDOW", out.get("reason"));
        assertEquals(0, list(out.get("sources")).size());
        assertEquals(6, out.get("windowHours"));
    }

    // ==================== 阶段"接没接上"的判定 ====================

    @Test
    @DisplayName("窗口内某阶段为 0 时，再确认索引里有没有这类数据：有=OK，没有=NOT_WIRED")
    void stageWiringIsChecked() throws Exception {
        String noBuckets = """
                {"hits":{"total":{"value":100}},"aggregations":{"src_present":{"doc_count":50},
                 "alerts_0":{"ips":{"buckets":[{"key":"1.2.3.4","doc_count":9,
                    "min_ts":{"value_as_string":"2026-10-13T16:00:00.000Z"},
                    "max_ts":{"value_as_string":"2026-10-13T17:00:00.000Z"},
                    "max_level":{"value":3}}]}}}}
                """;
        // 索引里根本没有 dionaea/cowrie 登录：判定查询回 total=0
        StubClient notWired = new StubClient(noBuckets, "{\"hits\":{\"total\":{\"value\":0}}}", false);
        Map<String, Object> out = service(notWired).storySources(24, 50);

        assertEquals(true, out.get("available"));
        Map<String, Object> wiring = map(out.get("stageWiring"));
        assertEquals("OK", wiring.get("alerts"));
        assertEquals("NOT_WIRED", wiring.get("decoyPorts"));
        assertEquals("NOT_WIRED", wiring.get("honeypotLogins"));
        assertTrue(notWired.queries.size() >= 2, "两个空阶段各要一次存在性判定");

        // 判定查询失败：给 UNKNOWN，绝不猜"未接入"
        StubClient failing = new StubClient(noBuckets, "{}", true);
        Map<String, Object> unknown = map(service(failing).storySources(24, 50).get("stageWiring"));
        assertEquals("UNKNOWN", unknown.get("decoyPorts"));
        assertEquals("UNKNOWN", unknown.get("honeypotLogins"));
    }

    @Test
    @DisplayName("窗口内有数据时不再多查一次（判定查询只在空阶段触发）")
    void wiringCheckIsSkippedWhenStageHasData() throws Exception {
        String withDecoy = """
                {"hits":{"total":{"value":100}},"aggregations":{"src_present":{"doc_count":50},
                 "alerts_0":{"ips":{"buckets":[]}},
                 "decoy_0":{"ips":{"buckets":[{"key":"1.2.3.4","doc_count":9,
                    "min_ts":{"value_as_string":"2026-10-13T16:00:00.000Z"},
                    "max_ts":{"value_as_string":"2026-10-13T17:00:00.000Z"},
                    "max_level":{"value":6}}]}},
                 "logins_0":{"ips":{"buckets":[{"key":"1.2.3.4","doc_count":2,
                    "min_ts":{"value_as_string":"2026-10-13T16:00:00.000Z"},
                    "max_ts":{"value_as_string":"2026-10-13T17:00:00.000Z"},
                    "max_level":{"value":10}}]}}}}
                """;
        StubClient client = new StubClient(withDecoy, "{\"hits\":{\"total\":{\"value\":0}}}", false);
        Map<String, Object> wiring = map(service(client).storySources(24, 50).get("stageWiring"));

        assertEquals("OK", wiring.get("decoyPorts"));
        assertEquals("OK", wiring.get("honeypotLogins"));
        assertEquals(0, client.queries.size(), "两段都有数据时不该再发判定查询");
    }

    @Test
    @DisplayName("客户端未初始化：CLIENT_NOT_READY（不是'没有攻击'）")
    void clientNotReady() {
        Map<String, Object> out = new WazuhService().storySources(24, 50);
        assertEquals(false, out.get("available"));
        assertEquals("CLIENT_NOT_READY", out.get("reason"));
    }

    // ==================== 明细查询的字段白名单 ====================

    @Test
    @DisplayName("【核心】查询体带 _source 白名单：明文口令/原始日志这些字段根本不取回")
    void eventQueryUsesSourceWhitelist() throws Exception {
        String hits = """
                {"hits":{"total":{"value":9},"hits":[
                  {"_source":{"@timestamp":"2026-10-13T17:12:11.906Z",
                    "rule":{"id":"100102","level":10,"description":"蜜罐: 攻击者\\"登录成功\\" 用户=root 口令=Secr3t! 来源=1.2.3.4"},
                    "data":{"src_ip":"1.2.3.4","eventid":"cowrie.login.success","username":"root"}}}]}}
                """;
        StubClient client = new StubClient("{}", hits, false);
        Map<String, Object> out = service(client).storyEvents("1.2.3.4", 24, 40);

        assertEquals(true, out.get("available"));
        Map<String, Object> stage = map(map(out.get("stages")).get("honeypotLogins"));
        assertEquals(9L, stage.get("total"));
        assertEquals(1, stage.get("returned"));
        List<Map<String, Object>> events = list(stage.get("events"));
        assertEquals(1, events.size());
        assertEquals("蜜罐 SSH 登录成功", events.get(0).get("kind"));
        assertEquals("SUCCESS", events.get(0).get("outcome"));
        assertTrue(String.valueOf(events.get(0).get("summary")).contains("口令=Secr3t!"),
                "WazuhService 这一层不做脱敏（脱敏在公网边界做），但绝不能主动带出别的字段");

        // 查询体：三段的 _source 白名单一致，且不含任何凭据字段名
        assertEquals(3, client.queries.size(), "每段各一条查询");
        for (String q : client.queries) {
            assertTrue(q.contains("\"_source\""), "必须显式限定 _source：" + q);
            assertTrue(q.contains("data.srcip") && q.contains("data.src_ip"), q);
            assertTrue(q.contains("\"@timestamp\""), q);
            assertFalse(q.contains("password"), "查询体不该出现口令字段：" + q);
            assertFalse(q.contains("full_log"), "查询体不该出现原始日志字段：" + q);
            assertFalse(q.contains("\"size\":0"), "明细查询必须带 size（否则取回 0 条）：" + q);
        }
        for (String f : WazuhService.STORY_EVENT_FIELDS) {
            assertFalse(f.toLowerCase().contains("password"), "白名单里不该有口令字段：" + f);
            assertFalse(f.toLowerCase().contains("message"), "白名单里不该有 message（含明文口令）：" + f);
            assertFalse(f.toLowerCase().contains("full_log"), "白名单里不该有原始日志：" + f);
            assertFalse(f.startsWith("agent."), "白名单里不该有内部资产名：" + f);
        }
    }

    @Test
    @DisplayName("IP 不是拼进 JSON 的字符串：特殊字符不会被当成查询语法（注入面）")
    void srcIsParameterizedNotConcatenated() throws Exception {
        StubClient client = new StubClient("{}", "{\"hits\":{\"total\":{\"value\":0}}}", false);
        service(client).storyEvents("1.2.3.4\"}}", 24, 40);

        for (String q : client.queries) {
            JsonNode root = MAPPER.readTree(q);   // 解析得出来 = 语法没被破坏
            assertNotNull(root.path("query"));
        }
    }

    @Test
    @DisplayName("空的 src：INVALID_SRC，且一条查询都不发（不拿空条件去查全库）")
    void emptySrcIsRejected() {
        StubClient client = new StubClient("{}", "{}", false);
        Map<String, Object> out = service(client).storyEvents("  ", 24, 40);

        assertEquals(false, out.get("available"));
        assertEquals("INVALID_SRC", out.get("reason"));
        assertEquals(0, client.queries.size());
    }

    @Test
    @DisplayName("明细里每段独立限量：某段刷屏不会挤掉另外两段")
    void eachStageHasItsOwnCap() throws Exception {
        StubClient client = new StubClient("{}", "{\"hits\":{\"total\":{\"value\":0}}}", false);
        service(client).storyEvents("1.2.3.4", 24, 40);

        List<Integer> sizes = new ArrayList<>();
        for (String q : client.queries) {
            sizes.add(MAPPER.readTree(q).path("size").asInt());
        }
        assertEquals(List.of(40, 40, 40), sizes);
    }

    // ==================== 事件形状 ====================

    @Test
    @DisplayName("各阶段 kind：告警给类型标签、诱饵端口给协议+端口、蜜罐给登录结果")
    void eventKindsPerStage() throws Exception {
        JsonNode decoy = MAPPER.readTree("""
                {"@timestamp":"2026-10-13T17:09:51.775Z","rule":{"id":"100301","level":6,
                 "description":"蜜罐(Dionaea): MSSQL 连接尝试"},
                 "data":{"src_ip":"1.2.3.4","dst_port":"1433","connection":{"protocol":"mssqld"}}}
                """);
        Map<String, Object> e = WazuhService.toEvent(decoy, "decoy");
        assertEquals("诱饵端口 MSSQL（1433/tcp）", e.get("kind"));
        assertEquals("ACCEPT", e.get("outcome"));
        assertEquals(6, e.get("level"));

        JsonNode login = MAPPER.readTree("""
                {"@timestamp":"2026-10-13T17:12:11.906Z","rule":{"id":"100101","level":5,
                 "description":"蜜罐: 攻击者\\"登录失败\\" 用户=admin 口令=Secr3t! 来源=1.2.3.4"},
                 "data":{"src_ip":"1.2.3.4","eventid":"cowrie.login.failed"}}
                """);
        Map<String, Object> failed = WazuhService.toEvent(login, "honeypot");
        assertEquals("蜜罐 SSH 登录失败", failed.get("kind"));
        assertEquals("FAILED", failed.get("outcome"));

        JsonNode scan = MAPPER.readTree("""
                {"@timestamp":"2026-10-13T17:12:11.906Z","rule":{"id":"86601","level":3,
                 "description":"Suricata: ET SCAN Nmap Scripting Engine"}, "data":{"src_ip":"1.2.3.4"}}
                """);
        assertEquals("扫描探测", WazuhService.toEvent(scan, "alerts").get("kind"));
    }

    // ==================== 工具 ====================

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object v) {
        return v instanceof Map<?, ?> m ? (Map<String, Object>) m : new LinkedHashMap<>();
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> list(Object v) {
        return v instanceof List<?> l ? (List<Map<String, Object>>) l : new ArrayList<>();
    }
}

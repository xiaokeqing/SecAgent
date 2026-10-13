package org.example.integration.wazuh;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.geoip.GeoAggregator;
import org.example.geoip.GeoWindow;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link WazuhService#parseGeoWindow} 的解析测试（纯函数，直接喂 OpenSearch 响应形状）。
 *
 * <h3>为什么把解析抽成静态方法并单独测</h3>
 * 真实响应有几种"看着像成功了"的形态，任何一个解析错都不会报错：
 * <ul>
 *   <li>两个来源字段（主机侧 {@code data.srcip} / Suricata {@code data.src_ip}）：
 *       只认一个字段会<b>丢掉一大半来源</b>（实测 24 小时 host-side 只有约 700 条，
 *       而 suricata 侧有 10 万+ 条）；</li>
 *   <li>{@code sum_other_doc_count > 0}：说明 TOP N 之外还有长尾被截断，
 *       不把这件事传上去，页面就会把"前 1000 个 IP"说成"全部来源"；</li>
 *   <li>{@code by_hour} 的 {@code key_as_string} 是 <b>UTC</b>，直接截字符串会得到差 8 小时的时间轴
 *       （项目历史上真出过这个事故，见 {@link WazuhTime}）。</li>
 * </ul>
 */
class WazuhGeoWindowParseTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode json(String s) throws Exception {
        return MAPPER.readTree(s);
    }

    @Test
    @DisplayName("两个来源字段合并：同名 IP 相加，两个 terms 桶都认")
    void mergesBothSourceFields() throws Exception {
        JsonNode root = json("""
                {"hits":{"total":{"value":111031,"relation":"eq"}},
                 "aggregations":{
                   "by_ip_0":{"doc_count_error_upper_bound":0,"sum_other_doc_count":0,
                     "buckets":[{"key":"58.19.99.193","doc_count":497},{"key":"101.34.252.177","doc_count":1}]},
                   "by_ip_1":{"doc_count_error_upper_bound":0,"sum_other_doc_count":2542,
                     "buckets":[{"key":"91.224.92.34","doc_count":56662},{"key":"58.19.99.193","doc_count":3}]},
                   "src_present":{"doc_count":107342,"by_hour":{"buckets":[
                     {"key_as_string":"2026-10-12T16:00:00.000Z","doc_count":11},
                     {"key_as_string":"2026-10-12T17:00:00.000Z","doc_count":0}]}}}}""");

        GeoWindow w = WazuhService.parseGeoWindow(root, 2);

        assertTrue(w.available());
        assertEquals("OK", w.reason());
        assertEquals(111031L, w.alertsTotal24h(), "24h 总量必须取 track_total_hits 的真值（不是 10000 上限）");
        assertEquals(107342L, w.alertsWithSourceIp24h(), "分母取 src_present 的 doc_count");
        assertTrue(w.bucketsTruncated(), "sum_other_doc_count>0 说明 TOP N 之外还有长尾，必须如实上报");
        assertEquals(3, w.ipCounts().size(), "两个字段的桶要合并（58.19.99.193 出现在两边）");
        assertEquals(new GeoAggregator.IpCount("91.224.92.34", 56662L), w.ipCounts().get(0), "按条数降序");
        assertEquals(new GeoAggregator.IpCount("58.19.99.193", 500L), w.ipCounts().get(1), "同名 IP 相加：497+3");
        assertEquals(new GeoAggregator.IpCount("101.34.252.177", 1L), w.ipCounts().get(2), "计数相同按 IP 升序");
        assertEquals(2, w.trend().size());
        assertEquals(11L, w.trend().get(0).count());
        assertTrue(w.trend().get(0).ts().matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:00"),
                "时间桶必须是本地时间的分钟精度：" + w.trend().get(0).ts());
    }

    @Test
    @DisplayName("没有桶（窗口里没有带来源 IP 的告警）：available=true + NO_DATA_IN_WINDOW，不是故障")
    void emptyWindowIsNotAFailure() throws Exception {
        GeoWindow w = WazuhService.parseGeoWindow(json("""
                {"hits":{"total":{"value":5000}},
                 "aggregations":{"by_ip_0":{"buckets":[]},"by_ip_1":{"buckets":[]},
                   "src_present":{"doc_count":0,"by_hour":{"buckets":[]}}}}"""), 2);
        assertTrue(w.available());
        assertEquals("NO_DATA_IN_WINDOW", w.reason());
        assertEquals(5000L, w.alertsTotal24h());
        assertTrue(w.ipCounts().isEmpty());
        assertFalse(w.bucketsTruncated());
    }

    @Test
    @DisplayName("响应缺字段/为空：不抛异常，按不可用处理（解析层永远不炸在请求线程上）")
    void malformedResponseNeverThrows() throws Exception {
        assertEquals("EMPTY_RESPONSE", WazuhService.parseGeoWindow(null, 2).reason());
        assertFalse(WazuhService.parseGeoWindow(json("{}"), 2).available());
        assertFalse(WazuhService.parseGeoWindow(json("{\"hits\":{}}"), 2).available());
        // 只有部分聚合存在时也不能抛
        GeoWindow partial = WazuhService.parseGeoWindow(json(
                "{\"hits\":{\"total\":{\"value\":7}},\"aggregations\":{\"by_ip_0\":{\"buckets\":[]}}}"), 2);
        assertTrue(partial.available());
        assertEquals(7L, partial.alertsTotal24h());
    }

    @Test
    @DisplayName("字段数配置为 1 时只认第一个字段（配置改了不该把不存在的聚合当空桶读）")
    void singleFieldConfigIsHonored() throws Exception {
        JsonNode root = json("""
                {"hits":{"total":{"value":10}},
                 "aggregations":{"by_ip_0":{"buckets":[{"key":"1.2.3.4","doc_count":9}]},
                   "src_present":{"doc_count":9,"by_hour":{"buckets":[]}}}}""");
        GeoWindow w = WazuhService.parseGeoWindow(root, 1);
        assertEquals(1, w.ipCounts().size());
        assertEquals("1.2.3.4", w.ipCounts().get(0).ip());
    }
}

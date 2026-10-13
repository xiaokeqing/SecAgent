package org.example.geoip;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 公开地理载荷的聚合口径测试（用真装载的夹具库，不 mock {@link GeoIpService}）。
 *
 * <h3>这一层守的是四件"错了也没人看出来"的事</h3>
 * <ol>
 *   <li><b>不含 IP</b>：载荷里出现任何一个 IP 形态字符串都算失败（正则断言整段 JSON）；</li>
 *   <li><b>内网/我方/保留地址不上地图</b>：它们只进 coverage 计数。
 *       实测线上 {@code data.srcip} 排第二的是我们自己的服务器，所以"内网自己扫自己"
 *       绝不能被画成"某国正在攻击"；</li>
 *   <li><b>门槛</b>：{@code count>=3} 且 {@code 占比>=1%}。只卡一个都会出问题：
 *       只卡占比时"1 次攻击=100%"照样上榜；只卡条数时长尾噪声占满榜单；</li>
 *   <li><b>确定性</b>：同一批输入必须得到同一份字节（否则 ETag 永远不命中，边缘缓存等于没有）。</li>
 * </ol>
 */
class GeoAggregatorTest {

    @TempDir
    Path tmp;

    private GeoIpService geo;

    @BeforeEach
    void setUp() throws IOException {
        Path city = GeoTestFixtures.writeGz(tmp, "dbip-city-lite-2026-10.csv.gz", GeoTestFixtures.CITY_4);
        Path asn = GeoTestFixtures.writeGz(tmp, "dbip-asn-lite-2026-10.csv.gz", GeoTestFixtures.ASN_ALL);
        geo = new GeoIpService();
        ReflectionTestUtils.setField(geo, "cityDb", city.toString());
        ReflectionTestUtils.setField(geo, "asnDb", asn.toString());
        ReflectionTestUtils.setField(geo, "enabled", true);
        ReflectionTestUtils.setField(geo, "ipv6Enabled", true);
        geo.init();
        geo.loadBlocking();
        assertTrue(geo.ready());
    }

    private static GeoAggregator.Inputs inputs(List<GeoAggregator.IpCount> counts, long total, Set<String> self) {
        return new GeoAggregator.Inputs(counts, total, counts.stream().mapToLong(GeoAggregator.IpCount::count).sum(),
                false,
                List.of(new GeoAggregator.TrendPoint("2026-10-13T20:00", 7),
                        new GeoAggregator.TrendPoint("2026-10-13T21:00", 0)),
                self);
    }

    private static GeoAggregator.IpCount ip(String ip, long c) {
        return new GeoAggregator.IpCount(ip, c);
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> list(Map<String, Object> data, String key) {
        return (List<Map<String, Object>>) data.get(key);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> coverage(Map<String, Object> data) {
        return (Map<String, Object>) data.get("coverage");
    }

    @Test
    @DisplayName("聚合口径：国家/省/ASN 三个榜 + 独立 IP 数 + 分母诚实披露")
    void aggregatesCountriesProvincesAsnsAndCoverage() {
        List<GeoAggregator.IpCount> counts = List.of(
                ip("1.0.1.1", 100), ip("1.0.1.2", 50), ip("1.0.1.3", 2),   // CN/Zhejiang
                ip("1.0.2.1", 40),                                        // CN/Fujian
                ip("1.0.3.1", 5),                                         // US/California
                ip("1.0.0.1", 1),                                         // AU（低于门槛）
                ip("10.0.0.1", 30),                                       // 内网
                ip("47.96.106.187", 20),                                  // 我方
                ip("203.0.113.9", 9),                                     // RFC5737 文档网段
                ip("not-an-ip", 3),                                       // 脏数据
                ip("8.8.8.8", 4));                                        // 公网但库里没有
        Map<String, Object> data = GeoAggregator.aggregate(
                inputs(counts, 1000, Set.of("47.96.106.187")), geo, GeoAggregator.Thresholds.defaults(),
                "2026-10-13 21:00:00");

        assertEquals(Boolean.TRUE, data.get("available"));
        assertEquals("OK", data.get("reason"));
        assertEquals("DB-IP Lite City 2026-10 + DB-IP Lite ASN 2026-10", data.get("geoSource"));

        List<Map<String, Object>> byCountry = list(data, "byCountry");
        assertEquals(2, byCountry.size(), "AU 只有 1 条，必须被门槛挡掉：实际 " + byCountry);
        assertEquals("CN", byCountry.get(0).get("country"));
        assertEquals("中国", byCountry.get(0).get("countryName"), "展示名走中文映射（聚合键仍是 ISO2）");
        assertEquals(192L, byCountry.get(0).get("count"));
        assertEquals(4L, byCountry.get(0).get("uniqueIps"), "CN 有 4 个独立 IP（1.0.1.1/2/3 + 1.0.2.1）");
        assertEquals("US", byCountry.get(1).get("country"));
        assertEquals(5L, byCountry.get(1).get("count"));

        List<Map<String, Object>> cnProvinces = list(byCountry.get(0), "byProvince");
        assertEquals(2, cnProvinces.size());
        assertEquals("Zhejiang", cnProvinces.get(0).get("province"));
        assertEquals(152L, cnProvinces.get(0).get("count"));
        assertEquals(3L, cnProvinces.get(0).get("uniqueIps"));

        List<Map<String, Object>> cnList = list(data, "byProvinceCN");
        assertEquals(2, cnList.size(), "国内省份榜只列 CN");
        assertEquals("Zhejiang", cnList.get(0).get("province"));

        List<Map<String, Object>> asns = list(data, "byAsnTop");
        assertEquals(2, asns.size(), "ASN 13335 只有 1 条，被门槛挡掉");
        assertEquals(4134, asns.get(0).get("asn"));
        assertEquals("CHINANET-BACKBONE", asns.get(0).get("org"));
        assertEquals(192L, asns.get(0).get("count"));
        assertEquals(4L, asns.get(0).get("uniqueIps"));
        assertEquals(15169, asns.get(1).get("asn"));

        Map<String, Object> cov = coverage(data);
        assertEquals(1000L, cov.get("totalAlerts"), "总告警数（告诉读者地图覆盖了多大一部分）");
        assertEquals(264L, cov.get("withSourceIp"), "带来源字段的总条数 = 分母");
        assertEquals(198L, cov.get("geocoded"), "成功归属的条数 = 100+50+2+40+5+1");
        assertEquals(30L, cov.get("excludedInternal"));
        assertEquals(20L, cov.get("excludedSelf"), "我方 IP 必须单独计数，不进地图");
        assertEquals(9L, cov.get("excludedReserved"));
        assertEquals(3L, cov.get("invalid"));
        assertEquals(4L, cov.get("unlocated"), "公网但库里没有归属 → 未定位（不能算进任何国家）");

        List<Map<String, Object>> trend = list(data, "trend");
        assertEquals(2, trend.size(), "时间桶原样透传（口径由取数层固定为 24×1h）");
        assertEquals(7L, trend.get(0).get("count"));
    }

    @Test
    @DisplayName("抗'1 次攻击刷榜'：占比 100% 但只有 1 条 → 不入榜")
    void singleAttackCannotTopTheBoard() {
        Map<String, Object> data = GeoAggregator.aggregate(
                inputs(List.of(ip("1.0.1.1", 1)), 1, Set.of()), geo,
                GeoAggregator.Thresholds.defaults(), "2026-10-13 21:00:00");
        assertEquals(List.of(), list(data, "byCountry"), "1 条 = 100% 占比，但条数门槛必须挡住它");
        assertEquals(1L, coverage(data).get("geocoded"), "被挡掉不等于不算：分母里必须仍如实计入");
    }

    @Test
    @DisplayName("抗长尾：条数够（3 条）但占比不足 1% → 仍不入榜")
    void minSharePercentFiltersLongTail() {
        Map<String, Object> data = GeoAggregator.aggregate(
                inputs(List.of(ip("1.0.1.1", 3), ip("1.0.3.1", 997)), 1000, Set.of()), geo,
                GeoAggregator.Thresholds.defaults(), "2026-10-13 21:00:00");
        List<Map<String, Object>> byCountry = list(data, "byCountry");
        assertEquals(1, byCountry.size(), "3/1000 = 0.3% < 1%：必须被占比门槛挡掉");
        assertEquals("US", byCountry.get(0).get("country"));
    }

    @Test
    @DisplayName("门槛可配：把 minCount/minShare 设成 1/0 后，1 条也入榜（换量级不用改代码）")
    void thresholdsAreConfigurable() {
        Map<String, Object> data = GeoAggregator.aggregate(
                inputs(List.of(ip("1.0.1.1", 1)), 1, Set.of()), geo,
                new GeoAggregator.Thresholds(1, 0d, 20, 10, 10), "2026-10-13 21:00:00");
        assertEquals(1, list(data, "byCountry").size());
        assertEquals(1, coverage(data).get("sourceBuckets"));
        assertEquals(1L, coverage(data).get("geocoded"));
    }

    @Test
    @DisplayName("我方 IP 即使量最大也不进任何榜（实测踩过：srv2 自己排第二）")
    void selfIpsNeverAppearOnTheMap() {
        List<GeoAggregator.IpCount> counts = List.of(
                ip("47.96.106.187", 500), ip("43.143.114.79", 300), ip("1.0.1.1", 10));
        Map<String, Object> data = GeoAggregator.aggregate(
                inputs(counts, 810, Set.of("47.96.106.187", "43.143.114.79")), geo,
                GeoAggregator.Thresholds.defaults(), "2026-10-13 21:00:00");
        List<Map<String, Object>> byCountry = list(data, "byCountry");
        assertEquals(1, byCountry.size());
        assertEquals("CN", byCountry.get(0).get("country"));
        assertEquals(10L, byCountry.get(0).get("count"), "我方 800 条不能算进任何国家");
        assertEquals(800L, coverage(data).get("excludedSelf"));
    }

    @Test
    @DisplayName("字段白名单：载荷里一个 IP 都不许有（正则扫整段 JSON）+ 署名必须在 note 里")
    void payloadHasNoIpAndCarriesAttribution() throws Exception {
        Map<String, Object> data = GeoAggregator.aggregate(
                inputs(List.of(ip("1.0.1.1", 100), ip("10.0.0.1", 30), ip("203.0.113.9", 9)), 139, Set.of()),
                geo, GeoAggregator.Thresholds.defaults(), "2026-10-13 21:00:00");
        String json = new ObjectMapper().writeValueAsString(data);

        assertFalse(Pattern.compile("(?<![\\d.])\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(?![\\d.])")
                .matcher(json).find(), "公开载荷里出现 IP 形态字符串：" + json);
        assertFalse(json.contains("1.0.1.1"), "完整 IP 不得出现");
        assertFalse(json.contains("203.0.113"), "连网段都不许出现");
        assertTrue(json.contains(GeoIpService.ATTRIBUTION), "CC BY 4.0 要求署名必须出现在输出上");
        assertTrue(String.valueOf(data.get("note")).contains("不含任何 IP"), String.valueOf(data.get("note")));
        assertNotNull(data.get("geoAttribution"));
    }

    @Test
    @DisplayName("确定性：同一批输入两次聚合字节完全一致（ETag/304 的前提）")
    void aggregationIsDeterministic() throws Exception {
        List<GeoAggregator.IpCount> counts = new ArrayList<>(List.of(
                ip("1.0.3.1", 10), ip("1.0.1.1", 10), ip("1.0.2.1", 10),
                ip("1.0.1.2", 10), ip("1.0.3.2", 10)));
        ObjectMapper mapper = new ObjectMapper();
        String a = mapper.writeValueAsString(GeoAggregator.aggregate(
                inputs(counts, 50, Set.of()), geo, GeoAggregator.Thresholds.defaults(), "T"));
        String b = mapper.writeValueAsString(GeoAggregator.aggregate(
                inputs(counts, 50, Set.of()), geo, GeoAggregator.Thresholds.defaults(), "T"));
        assertEquals(a, b, "排序必须是全序（计数相同的项按名称兜底），否则每次都算出不同字节");
        // 计数相同时按国家码升序：CN 在 US 前
        assertTrue(a.indexOf("\"CN\"") < a.indexOf("\"US\""));
    }

    @Test
    @DisplayName("Top 截断：国家榜按 topCountries 截断，且截断后仍是计数最高的那几个")
    void topCountriesIsTruncated() {
        Map<String, Object> data = GeoAggregator.aggregate(
                inputs(List.of(ip("1.0.1.1", 100), ip("1.0.3.1", 60), ip("1.0.0.1", 20)), 180, Set.of()),
                geo, new GeoAggregator.Thresholds(3, 1.0d, 2, 10, 10), "T");
        List<Map<String, Object>> byCountry = list(data, "byCountry");
        assertEquals(2, byCountry.size());
        assertEquals("CN", byCountry.get(0).get("country"));
        assertEquals("US", byCountry.get(1).get("country"));
        assertEquals(2, data.get("countryCount"));
    }
}

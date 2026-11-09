package org.example.publicapi;

import org.example.geoip.GeoIpInfo;
import org.example.geoip.GeoIpService;
import org.example.geoip.GeoTestFixtures;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 国家码解析的单元测试（不启 Spring，直接喂聚合项）。
 *
 * <p>钉四件事：
 * <ol>
 *   <li>{@code srcGeo} 只取<b>第一段</b> iso2：省/市/ASN 一个字节都不许带出来；</li>
 *   <li>缺 {@code srcGeo} 时才查离线库 —— 用的是 {@code /api/public/geo} 同一个
 *       {@link GeoIpService}（DB-IP Lite 夹具库）；</li>
 *   <li>查不到就是 {@code null}，绝不为空串、{@code XX}、{@code ZZ} 或"猜一个国家"；</li>
 *   <li>库查询结果按 IP 缓存，且缓存有上限。</li>
 * </ol>
 */
class PublicAlertGeoTest {

    @TempDir
    Path tmp;

    /** 夹具库：1.0.0.0/24=AU、1.0.1.0/24=CN浙江、1.0.2.0/24=CN福建、1.0.3.0/24=US */
    private GeoIpService fixtureGeo() throws Exception {
        Path city = GeoTestFixtures.writeGz(tmp, "dbip-city-lite-2026-10.csv.gz", GeoTestFixtures.CITY_4);
        Path asn = GeoTestFixtures.writeGz(tmp, "dbip-asn-lite-2026-10.csv.gz", GeoTestFixtures.ASN_ALL);
        GeoIpService geo = new GeoIpService();
        ReflectionTestUtils.setField(geo, "cityDb", city.toString());
        ReflectionTestUtils.setField(geo, "asnDb", asn.toString());
        ReflectionTestUtils.setField(geo, "enabled", true);
        ReflectionTestUtils.setField(geo, "ipv6Enabled", true);
        geo.init();
        geo.loadBlocking();
        assertTrue(geo.ready(), geo.summary());
        return geo;
    }

    private static Map<String, Object> aggregate(String srcGeo, String srcIp) {
        Map<String, Object> m = new HashMap<>();
        m.put("srcGeo", srcGeo);
        m.put("srcIp", srcIp);
        return m;
    }

    @Test
    @DisplayName("srcGeo 有值：只取第一段国家码，不需要地理库（null 也不影响）")
    void srcGeoFirstSegmentWinsWithoutLibrary() {
        PublicAlertGeo geo = new PublicAlertGeo();
        assertEquals("US", geo.countryCode(
                aggregate("US|California|Mountain View|15169|Google LLC", "8.8.8.8"), null));
        assertEquals("CN", geo.countryCode(
                aggregate("CN|Zhejiang|Hangzhou|4134|CHINANET-BACKBONE", "1.0.1.1"), null));
        // 大小写/空白归一化；ZZ 是 DB-IP 的未知占位，按取不到处理
        assertEquals("NL", geo.countryCode(aggregate(" nl ", "1.0.0.1"), null));
        assertNull(geo.countryCode(aggregate("ZZ|Zhejiang|Hangzhou|4134|CHINANET", "1.0.1.1"), null));
        assertEquals(0, geo.cacheSize(), "srcGeo 命中时不应碰库，也不应写缓存");
    }

    @Test
    @DisplayName("srcGeo 缺失：回落到离线库（与 /api/public/geo 同一个 GeoIpService）")
    void missingSrcGeoFallsBackToOfflineLibrary() throws Exception {
        PublicAlertGeo geo = new PublicAlertGeo();
        assertEquals("CN", geo.countryCode(aggregate(null, "1.0.1.7"), fixtureGeo()));
        assertEquals("US", geo.countryCode(aggregate("", "1.0.3.7"), fixtureGeo()));
    }

    @Test
    @DisplayName("取不到必须是 null：不写空串 / XX / ZZ / 未知")
    void unknownIsNullNeverPlaceholder() {
        PublicAlertGeo geo = new PublicAlertGeo();
        assertNull(geo.countryCode(null, null), "null 聚合项不能 NPE");
        assertNull(geo.countryCode(aggregate(null, null), null), "没有 srcGeo 也没有库");
        assertNull(geo.countryCode(aggregate("", "203.0.113.9"), null), "空串按未知");
        assertNull(geo.countryCode(aggregate("-|Zhejiang|Hangzhou|4134|CHINANET", "1.0.1.1"), null),
                "describe() 的未知段 '-' 不是国家码");
        assertNull(geo.countryCode(aggregate("USA|California||-|", "8.8.8.8"), null), "三字码不是 alpha-2");
        assertNull(geo.countryCode(aggregate("1X|California||-|", "8.8.8.8"), null), "非字母不是合法国家码");
        assertNull(geo.countryCode(aggregate("XX|-|-|-|-", "1.0.1.1"), null), "XX 不是真实国家码");

        String cc = geo.countryCode(aggregate(null, "1.0.1.1"), null);
        assertNull(cc);
        assertFalse("".equals(cc), "未知不得写成空串");
        assertFalse("XX".equals(cc), "未知不得写成 XX");
        assertFalse("未知".equals(cc), "未知不得写成中文占位");
    }

    @Test
    @DisplayName("离线库查不到（私有/保留地址）：null，且不抛异常")
    void libraryMissOrFailureIsNull() throws Exception {
        PublicAlertGeo geo = new PublicAlertGeo();
        assertNull(geo.countryCode(aggregate(null, "198.51.100.9"), fixtureGeo()), "保留地址查不到国家");

        GeoIpService broken = new GeoIpService() {
            @Override
            public GeoIpInfo lookup(String ip) {
                throw new IllegalStateException("库还没加载完");
            }

            @Override
            public boolean ready() {
                return true;
            }
        };
        assertNull(geo.countryCode(aggregate(null, "1.0.1.1"), broken), "库异常只影响这一条，不让公开面 500");
    }

    @Test
    @DisplayName("库查询结果按 IP 缓存：同一个 IP 只查一次（上限 4096，LRU 淘汰）")
    void lookupResultsAreCachedAndBounded() {
        CountingGeo geo = new CountingGeo();
        PublicAlertGeo resolver = new PublicAlertGeo();

        assertEquals("NL", resolver.countryCode(aggregate(null, "203.0.113.1"), geo));
        assertEquals("NL", resolver.countryCode(aggregate(null, "203.0.113.1"), geo));
        assertEquals(1, geo.lookups, "同一 IP 第二次必须命中缓存，不能再查库");

        // 填满并越过上限：缓存条数不得超过 MAX_CACHE_ENTRIES
        for (int i = 0; i < PublicAlertGeo.MAX_CACHE_ENTRIES + 50; i++) {
            resolver.countryCode(aggregate(null, "10.20." + (i / 250) + "." + (i % 250 + 1)), geo);
        }
        assertEquals(PublicAlertGeo.MAX_CACHE_ENTRIES, resolver.cacheSize(),
                "缓存必须有上限，不能被伪造的来源 IP 撑爆内存");
        assertTrue(PublicAlertGeo.MAX_CACHE_ENTRIES >= 200, "上限至少要覆盖一个公开聚合窗口");
    }

    @Test
    @DisplayName("normalize：只认两个 ASCII 字母，ZZ/空/三字码一律 null")
    void normalizeContract() {
        assertEquals("CN", PublicAlertGeo.normalize("cn"));
        assertEquals("FR", PublicAlertGeo.normalize(" FR "));
        assertNull(PublicAlertGeo.normalize(null));
        assertNull(PublicAlertGeo.normalize(""));
        assertNull(PublicAlertGeo.normalize("C"));
        assertNull(PublicAlertGeo.normalize("CHN"));
        assertNull(PublicAlertGeo.normalize("ZZ"));
        assertNull(PublicAlertGeo.normalize("中A"));
        assertNotNull(PublicAlertGeo.normalize("US"));
    }

    /** 计数替身：不加载库，只记录 lookup 次数并固定回同一个国家。 */
    private static final class CountingGeo extends GeoIpService {
        private int lookups;

        @Override
        public GeoIpInfo lookup(String ip) {
            lookups++;
            return new GeoIpInfo("NL", null, null, 0, null);
        }

        @Override
        public boolean ready() {
            return true;
        }
    }
}

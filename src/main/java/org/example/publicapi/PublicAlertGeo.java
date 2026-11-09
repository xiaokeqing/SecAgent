package org.example.publicapi;

import org.example.geoip.GeoIpInfo;
import org.example.geoip.GeoIpService;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * 公开告警的「来源国家二字码」<b>唯一出口</b>：REST 列表项与 SSE 实时帧共用。
 *
 * <h3>只出国家码，不出地理明细</h3>
 * <p>内部 {@code srcGeo}（{@link GeoIpInfo#describe()}，形如
 * {@code CN|Zhejiang|Hangzhou|4134|CHINANET-BACKBONE}）在公开面<b>整体不可见</b>
 * （见 {@code PublicApiGeoLeakTest}）：逐条输出省/市/ASN 等于把"某个攻击者属于哪个机构"
 * 搬上公网页面。这里只取第一段 —— ISO-3166-1 alpha-2 国家码，与 {@code /api/public/geo}
 * 已经公开的国家级聚合同一粒度，因此不扩大暴露面。
 *
 * <h3>数据来自哪</h3>
 * <ol>
 *   <li>首选聚合项自带的 {@code srcGeo}（{@code AlertAggregationService} 从代表告警复制，
 *       代表告警的 {@code srcGeo} 由 {@code WazuhService} 在写入时用离线库富化）；
 *       <b>纯字符串解析，不查任何库</b>。</li>
 *   <li>没有 {@code srcGeo} 时，才回落到 {@link GeoIpService#lookup(String)} ——
 *       与 {@code /api/public/geo} 是同一个进程内离线库（DB-IP Lite），
 *       <b>绝不联网</b>，也不会因为查询失败而抛错影响公开面。</li>
 * </ol>
 *
 * <h3>热路径为什么不查库</h3>
 * <p>告警列表按 {@code alertsCache} 的 15s 快照生成，SSE 每 15s 轮询一次聚合；
 * 两者都以 {@code srcGeo} 为主路径。回落查询只在这条主路径缺数据时发生，且结果按 IP 缓存：
 * <ul>
 *   <li>上限 {@value #MAX_CACHE_ENTRIES} 条（聚合窗口只有 200 条、来源 IP 高重复，够用），
 *       LRU 淘汰，防止被伪造的来源 IP 撑爆内存；</li>
 *   <li>TTL {@value #CACHE_TTL_MS} ms（10 分钟）：地理库是月度更新的静态文件，运行中可用
 *       {@code GeoIpService} 重新加载，10 分钟内的旧值对"地图闪点"没有意义；
 *       且只在库 {@code ready()} 时才写缓存 —— 启动期"库还没加载完"得到的 null 不会被记住 10 分钟。</li>
 * </ul>
 *
 * <h3>取不到就是 null</h3>
 * <p>不会出现 {@code ""} / {@code "XX"} / {@code "未知"}：未知国家必须能被前端区分成"这条没有国家"，
 * 而不是一个看起来像国家码的假值。{@code ZZ}（DB-IP 的未知占位）同样按未知处理。
 */
final class PublicAlertGeo {

    /** 缓存条数上限：公开窗口 200 条聚合 × 少量不同来源 IP，4096 条有富余。 */
    static final int MAX_CACHE_ENTRIES = 4096;

    /** 缓存有效期（10 分钟）：告警快照 15s 刷新一次，这个 TTL 下每条 IP 至多几分钟查一次库。 */
    static final long CACHE_TTL_MS = 10 * 60 * 1000L;

    /** IP → 国家码；访问顺序即 LRU 顺序。值为 null 表示"库里也查不到"。 */
    private final Map<String, CachedCountry> cache = new LinkedHashMap<>(256, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, CachedCountry> eldest) {
            return size() > MAX_CACHE_ENTRIES;
        }
    };

    /**
     * 一个聚合项的来源国家码。
     *
     * @param aggregate 聚合项（来自 {@code PublicAlertSource#aggregated()}），可含 {@code srcGeo}/{@code srcIp}
     * @param geoIpService 离线地理库；为 {@code null}（裁剪部署/单元测试）时只用 {@code srcGeo}
     * @return 大写二字码；取不到返回 {@code null}
     */
    String countryCode(Map<String, Object> aggregate, GeoIpService geoIpService) {
        if (aggregate == null) {
            return null;
        }
        String fromDescribe = fromSrcGeo(aggregate.get("srcGeo"));
        if (fromDescribe != null) {
            return fromDescribe;
        }
        return countryFromLookup(asString(aggregate.get("srcIp")), geoIpService);
    }

    /**
     * 从内部 {@code srcGeo} 的第一段解析国家码。
     *
     * <p>唯一允许的形状是 {@code 国家|省|城市|ASN|机构}；未知段写 {@code -}。
     * 没有竖线的单段值也接受（老数据/手工构造的测试数据），但同样只认合法二字码。
     *
     * @return 大写二字码；不是合法国家码（含 {@code -}/{@code ZZ}/空串）时返回 {@code null}
     */
    static String fromSrcGeo(Object srcGeo) {
        if (!(srcGeo instanceof String s) || s.isBlank()) {
            return null;
        }
        int bar = s.indexOf('|');
        return normalize(bar < 0 ? s : s.substring(0, bar));
    }

    /**
     * 回落到离线库查询（<b>进程内，无网络</b>）。
     *
     * <p>命中缓存直接返回；未命中查一次库并按 IP 写入缓存。查询抛异常只影响这一条，
     * 不让公开端点 500。库未就绪时不写缓存（避免把启动期的 null 记 10 分钟）。
     */
    String countryFromLookup(String rawIp, GeoIpService geoIpService) {
        if (geoIpService == null || rawIp == null || rawIp.isBlank()) {
            return null;
        }
        String key = rawIp.trim();
        long now = System.currentTimeMillis();
        synchronized (cache) {
            CachedCountry hit = cache.get(key);
            if (hit != null && now - hit.at() < CACHE_TTL_MS) {
                return hit.cc();
            }
        }
        String cc;
        try {
            GeoIpInfo info = geoIpService.lookup(key);
            cc = info == null ? null : normalize(info.getCountry());
        } catch (RuntimeException e) {
            return null;
        }
        boolean ready;
        try {
            ready = geoIpService.ready();
        } catch (RuntimeException e) {
            ready = false;
        }
        if (ready) {
            synchronized (cache) {
                cache.put(key, new CachedCountry(cc, now));
            }
        }
        return cc;
    }

    /**
     * 规范成 ISO-3166-1 alpha-2 大写二字码。
     *
     * <p>只接受两个 ASCII 字母；{@code ZZ}（DB-IP 的未知占位）与 {@code XX}
     * （"未知国家"的常见伪码）都按取不到处理 —— 它们不是真实国家，写出去只会
     * 让前端在地图上多一个不存在的点。
     */
    static String normalize(String code) {
        if (code == null) {
            return null;
        }
        String c = code.trim().toUpperCase(Locale.ROOT);
        if (c.length() != 2 || !Character.isLetter(c.charAt(0)) || !Character.isLetter(c.charAt(1))) {
            return null;
        }
        if (!isAsciiLetter(c.charAt(0)) || !isAsciiLetter(c.charAt(1))) {
            return null;
        }
        if ("ZZ".equals(c) || "XX".equals(c)) {
            return null;
        }
        return c;
    }

    private static boolean isAsciiLetter(char ch) {
        return (ch >= 'A' && ch <= 'Z');
    }

    /** 当前缓存条数（测试用；不参与对外契约）。 */
    int cacheSize() {
        synchronized (cache) {
            return cache.size();
        }
    }

    private static String asString(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    /** 缓存值：国家码 + 写入时刻（毫秒）。 */
    private record CachedCountry(String cc, long at) {
    }
}

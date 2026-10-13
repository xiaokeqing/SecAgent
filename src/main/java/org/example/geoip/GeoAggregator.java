package org.example.geoip;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * 攻击来源聚合器：把"IP + 计数"变成<b>只有国家/省份/ASN + 计数 + 独立 IP 数 + 时间桶</b>的公开载荷。
 *
 * <h3>它是纯函数（除注入的 {@link GeoIpService} 外不读任何状态）</h3>
 * 公开面上最要紧的几件事都是"在这个函数里发生或没发生"：
 * <ul>
 *   <li><b>IP 一个字都不出去</b>：入参是 IP，出参里连掩码 IP 都没有 ——
 *       "某个 IP 被打了几次"本身就是情报，聚合到国家/省这一层才允许公开；</li>
 *   <li><b>内网/保留地址不上地图</b>：{@code 10/8}、{@code 172.16/12}、{@code 192.168/16}、
 *       环回、链路本地、运营商 NAT、{@code 203.0.113/24}（RFC 5737 文档网段）等
 *       只进 {@code coverage} 的计数，不进国家榜 ——
 *       否则"内网资产自己扫自己"会被画成"某国正在攻击我们"；</li>
 *   <li><b>自己的机器不算攻击者</b>：{@code selfIps}（srv1/srv2 公网出口）单独计数。
 *       实测踩到过：24 小时里 {@code data.srcip} 排第二的就是 srv2 自己的 IP（180 条），
 *       不排掉就会在"攻击来源 TOP"里看到我们自己的服务器；</li>
 *   <li><b>门槛与占比双重过滤</b>：{@code count >= minCount(3)} 且
 *       {@code 占比 >= minSharePercent(1%)} 才入榜 —— 一次探测打一下就上榜的榜没有意义，
 *       而且会让地图每小时都在跳；</li>
 *   <li><b>同时给"条数"和"独立 IP 数"</b>：实测一个 IP 能在 24 小时里刷出 56,662 条告警，
 *       只给 count 的话"一个吵闹的 IP 就能把整张地图点亮"。两个数一起给，
 *       页面既能说"某国被打得最狠"，也能说"那是 1 个 IP 干的"。</li>
 * </ul>
 *
 * <p>排序全部<b>确定</b>（先按计数降序，再按名称升序），所以同一批输入永远得到同一个 JSON ——
 * 这是 ETag / 304 能生效的前提（否则每次算出来的字节都不同，边缘缓存等于没有）。
 */
public final class GeoAggregator {

    private GeoAggregator() {
    }

    /** 一条"来源 IP → 24 小时告警条数" */
    public record IpCount(String ip, long count) {
    }

    /** 时间桶（已换算成本地时间的 {@code yyyy-MM-dd'T'HH:mm}） */
    public record TrendPoint(String ts, long count) {
    }

    /** 入榜门槛 */
    public record Thresholds(int minCount, double minSharePercent, int topCountries,
                             int topProvincesPerCountry, int topAsns) {
        public static Thresholds defaults() {
            return new Thresholds(3, 1.0d, 20, 10, 10);
        }
    }

    /**
     * 聚合输入。刻意做成一个不可变的记录，而不是一堆方法参数 ——
     * 参数一多就必然有人调错顺序（两个 long 挨着的时候编译器不会提醒）。
     */
    public record Inputs(List<IpCount> ipCounts,
                         long alertsTotal24h,
                         long alertsWithSourceIp24h,
                         boolean bucketsTruncated,
                         List<TrendPoint> trend,
                         Set<String> selfIps) {
    }

    /** 不可用时的空 coverage（字段名与可用时完全一致：前端只判 available 一个开关） */
    public static Map<String, Object> emptyCoverage() {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("totalAlerts", 0L);
        c.put("withSourceIp", 0L);
        c.put("geocoded", 0L);
        c.put("excludedSelf", 0L);
        c.put("excludedInternal", 0L);
        c.put("excludedReserved", 0L);
        c.put("unlocated", 0L);
        c.put("invalid", 0L);
        c.put("sourceBuckets", 0);
        c.put("sourceBucketsTruncated", false);
        return c;
    }

    /**
     * 生成公开载荷。
     *
     * @param in  聚合输入（IP 计数 + 24h 总量 + 趋势 + 自用 IP）
     * @param geo 已就绪的离线库；<b>调用方必须先判</b> {@link GeoIpService#ready()}，
     *            本方法不负责可用性判定（那样会把"库不可用"与"聚合逻辑"混在一起测）
     * @param th  门槛
     * @param now 生成本次载荷的时间（{@code yyyy-MM-dd HH:mm:ss}，由调用方传入，便于测试固定时间）
     */
    public static Map<String, Object> aggregate(Inputs in, GeoIpService geo, Thresholds th, String now) {
        List<IpCount> counts = in == null || in.ipCounts() == null ? List.of() : in.ipCounts();
        Set<String> self = in == null || in.selfIps() == null ? Set.of() : in.selfIps();
        Thresholds t = th == null ? Thresholds.defaults() : th;

        // 每个桶都存 [条数, 独立 IP 数]：独立 IP 数是"一个吵闹 IP 能不能点亮整张图"的答案
        Map<String, long[]> byCountryAll = new LinkedHashMap<>();
        Map<String, Map<String, long[]>> provinceByCountry = new LinkedHashMap<>();
        Map<Integer, long[]> asnAgg = new LinkedHashMap<>();
        Map<Integer, String> asnOrgs = new LinkedHashMap<>();
        long geocoded = 0;
        long internal = 0;
        long reserved = 0;
        long invalid = 0;
        long selfCount = 0;
        long unlocated = 0;

        for (IpCount ic : counts) {
            if (ic == null || ic.ip() == null || ic.count() <= 0) {
                continue;
            }
            if (self.contains(ic.ip().trim())) {
                selfCount += ic.count();
                continue;
            }
            IpAddresses.IpScope scope = IpAddresses.scope(ic.ip());
            if (scope == IpAddresses.IpScope.INTERNAL) {
                internal += ic.count();
                continue;
            }
            if (scope == IpAddresses.IpScope.RESERVED) {
                reserved += ic.count();
                continue;
            }
            if (scope == IpAddresses.IpScope.INVALID) {
                invalid += ic.count();
                continue;
            }
            GeoIpInfo info = geo.lookup(ic.ip());
            if (!info.hasCountry()) {
                unlocated += ic.count();
            } else {
                geocoded += ic.count();
                String cc = info.getCountry().toUpperCase(Locale.ROOT);
                bump(byCountryAll.computeIfAbsent(cc, k -> new long[2]), ic.count());
                String prov = info.getProvince() == null ? "未知" : info.getProvince();
                bump(provinceByCountry.computeIfAbsent(cc, k -> new LinkedHashMap<>())
                        .computeIfAbsent(prov, k -> new long[2]), ic.count());
            }
            if (info.getAsn() > 0) {
                bump(asnAgg.computeIfAbsent(info.getAsn(), k -> new long[2]), ic.count());
                if (info.getAsnOrg() != null) {
                    asnOrgs.putIfAbsent(info.getAsn(), info.getAsnOrg());
                }
            }
        }

        long denominator = geocoded;
        List<Map<String, Object>> byCountry = new ArrayList<>();
        for (Map.Entry<String, long[]> e : byCountryAll.entrySet()) {
            long c = e.getValue()[0];
            if (!eligible(c, denominator, t)) {
                continue;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("country", e.getKey());
            m.put("countryName", CountryNames.of(e.getKey()));
            m.put("count", c);
            m.put("uniqueIps", e.getValue()[1]);
            m.put("sharePercent", share(c, denominator));
            List<Map<String, Object>> provs = new ArrayList<>();
            Map<String, long[]> pv = provinceByCountry.getOrDefault(e.getKey(), Map.of());
            pv.entrySet().stream()
                    .filter(pe -> eligible(pe.getValue()[0], denominator, t))
                    .sorted(comparingCountThenKey(Map.Entry::getKey))
                    .limit(Math.max(1, t.topProvincesPerCountry()))
                    .forEach(pe -> {
                        Map<String, Object> p = new LinkedHashMap<>();
                        p.put("province", pe.getKey());
                        p.put("count", pe.getValue()[0]);
                        p.put("uniqueIps", pe.getValue()[1]);
                        provs.add(p);
                    });
            m.put("byProvince", provs);
            byCountry.add(m);
        }
        byCountry.sort(Comparator.comparingLong((Map<String, Object> m) -> (Long) m.get("count"))
                .reversed().thenComparing(m -> String.valueOf(m.get("country"))));
        if (byCountry.size() > Math.max(1, t.topCountries())) {
            byCountry = new ArrayList<>(byCountry.subList(0, t.topCountries()));
        }

        // 国内省份榜（中国地图用）：只取 CN 那一栏，避免前端自己从 byCountry 里翻
        List<Map<String, Object>> byProvinceCN = new ArrayList<>();
        Map<String, long[]> cn = provinceByCountry.get("CN");
        if (cn != null) {
            cn.entrySet().stream()
                    .filter(pe -> eligible(pe.getValue()[0], denominator, t))
                    .sorted(comparingCountThenKey(Map.Entry::getKey))
                    .forEach(pe -> {
                        Map<String, Object> p = new LinkedHashMap<>();
                        p.put("province", pe.getKey());
                        p.put("count", pe.getValue()[0]);
                        p.put("uniqueIps", pe.getValue()[1]);
                        p.put("sharePercent", share(pe.getValue()[0], denominator));
                        byProvinceCN.add(p);
                    });
        }

        List<Map<String, Object>> byAsnTop = new ArrayList<>();
        asnAgg.entrySet().stream()
                .filter(ae -> eligible(ae.getValue()[0], denominator, t))
                .sorted(Comparator.comparingLong((Map.Entry<Integer, long[]> e) -> e.getValue()[0])
                        .reversed().thenComparing(Map.Entry::getKey))
                .limit(Math.max(1, t.topAsns()))
                .forEach(ae -> {
                    Map<String, Object> a = new LinkedHashMap<>();
                    a.put("asn", ae.getKey());
                    a.put("org", truncate(asnOrgs.get(ae.getKey()), 60));
                    a.put("count", ae.getValue()[0]);
                    a.put("uniqueIps", ae.getValue()[1]);
                    byAsnTop.add(a);
                });

        List<Map<String, Object>> trend = new ArrayList<>();
        if (in != null && in.trend() != null) {
            for (TrendPoint tp : in.trend()) {
                if (tp == null) {
                    continue;
                }
                Map<String, Object> p = new LinkedHashMap<>();
                p.put("ts", tp.ts());
                p.put("count", Math.max(0L, tp.count()));
                trend.add(p);
            }
        }

        Map<String, Object> coverage = emptyCoverage();
        coverage.put("totalAlerts", Math.max(0L, in == null ? 0L : in.alertsTotal24h()));
        coverage.put("withSourceIp", Math.max(0L, in == null ? 0L : in.alertsWithSourceIp24h()));
        coverage.put("geocoded", geocoded);
        coverage.put("excludedSelf", selfCount);
        coverage.put("excludedInternal", internal);
        coverage.put("excludedReserved", reserved);
        coverage.put("unlocated", unlocated);
        coverage.put("invalid", invalid);
        coverage.put("sourceBuckets", counts.size());
        coverage.put("sourceBucketsTruncated", in != null && in.bucketsTruncated());

        Map<String, Object> thresholds = new LinkedHashMap<>();
        thresholds.put("minCount", t.minCount());
        thresholds.put("minSharePercent", t.minSharePercent());
        thresholds.put("topCountries", t.topCountries());
        thresholds.put("topProvincesPerCountry", t.topProvincesPerCountry());
        thresholds.put("topAsns", t.topAsns());

        Set<String> provinces = new LinkedHashSet<>();
        for (Map.Entry<String, Map<String, long[]>> e : provinceByCountry.entrySet()) {
            provinces.addAll(e.getValue().keySet());
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("generatedAt", now);
        data.put("available", true);
        data.put("reason", "OK");
        data.put("geoSource", geo.sourceLabel());
        data.put("geoAttribution", GeoIpService.ATTRIBUTION);
        data.put("window", "24h");
        data.put("thresholds", thresholds);
        data.put("coverage", coverage);
        data.put("countryCount", byCountry.size());
        data.put("provinceCountCN", byProvinceCN.size());
        data.put("knownProvinceCount", provinces.size());
        data.put("byCountry", byCountry);
        data.put("byProvinceCN", byProvinceCN);
        data.put("byAsnTop", byAsnTop);
        data.put("trend", trend);
        data.put("note", "只给聚合：响应里不含任何 IP（连掩码 IP 都没有）、不含单条告警、不含内网资产。"
                + "分母以 coverage 为准（totalAlerts 是窗口内全部告警，withSourceIp 才是画地图用的那批）；"
                + "trend 是「带来源 IP 的告警」按本地时间的小时分桶（24 点）；"
                + "入榜门槛 count>=" + t.minCount() + " 且占比>=" + t.minSharePercent() + "%。"
                + GeoIpService.ATTRIBUTION);
        return data;
    }

    /** 累加：{@code agg[0] += count}，{@code agg[1]++}（独立 IP 数按"一个 IP 一次"计） */
    private static void bump(long[] agg, long count) {
        agg[0] += count;
        agg[1]++;
    }

    /**
     * 入榜判定：{@code count >= minCount} <b>且</b> {@code 占比 >= minSharePercent}。
     *
     * <p>为什么门槛要两条一起卡：
     * <ul>
     *   <li>只卡占比 → 窗口很小时"1 次攻击 = 100%"照样上榜（这正是要防的"1 次攻击刷榜"）；</li>
     *   <li>只卡条数 → 大窗口里 3 条也能上榜，于是榜上全是长尾噪声；</li>
     * </ul>
     * 两条都要，且都可配（{@code app.public-api.geo.*}），换窗口或换量级不用改代码。
     */
    static boolean eligible(long count, long denominator, Thresholds t) {
        if (count < Math.max(1, t.minCount())) {
            return false;
        }
        if (denominator <= 0) {
            return false;
        }
        return share(count, denominator) >= t.minSharePercent();
    }

    /** 占比（百分数，保留两位小数）——用 {@code double} 足够，它只用于展示与门槛，不参与任何账目 */
    static double share(long count, long denominator) {
        if (denominator <= 0) {
            return 0d;
        }
        return Math.round(count * 10000.0d / denominator) / 100.0d;
    }

    private static <K> Comparator<Map.Entry<K, long[]>> comparingCountThenKey(
            java.util.function.Function<Map.Entry<K, long[]>, K> key) {
        return Comparator.comparingLong((Map.Entry<K, long[]> e) -> e.getValue()[0]).reversed()
                .thenComparing(e -> String.valueOf(key.apply(e)));
    }

    /** 机构名截断（机构名来自数据源，属于要"白名单/截断"的字段） */
    static String truncate(String s, int max) {
        if (s == null) {
            return null;
        }
        String v = s.trim();
        return v.length() <= max ? v : v.substring(0, max) + "…";
    }
}

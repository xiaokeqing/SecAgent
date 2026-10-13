package org.example.geoip;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

/**
 * 离线地理库（DB-IP Lite City + DB-IP Lite ASN）在内存里的形态。
 *
 * <h3>为什么是"两个库拼一个结果"</h3>
 * DB-IP 把"国家/省/城市"和"ASN/机构"放在两个独立文件里（许可相同、都是 CC BY 4.0）。
 * 一次查询因此要查两张表：{@code city} 表给国家/省/城市，{@code asn} 表给 ASN 与机构名。
 * 两者都命中不到时返回 {@link GeoIpInfo#UNKNOWN}。
 *
 * <h3>文件格式（实测 2026-10 版；写入 RUNBOOK §26）</h3>
 * <pre>
 *   dbip-city-lite-YYYY-MM.csv.gz  无表头，8 列：
 *     start_ip,end_ip,continent_code,country_code,subdivision_1,city,latitude,longitude
 *     0.0.0.0,0.255.255.255,ZZ,ZZ,,,0,0            ← 未分配段：国家是 ZZ，必须当成"没定位到"
 *   dbip-asn-lite-YYYY-MM.csv.gz   无表头，4 列：
 *     start_ip,end_ip,asn,as_name
 * </pre>
 * 城市名里可能有逗号（DB-IP 用双引号包住），所以<b>不能</b>用 {@code String.split(",")} ——
 * 实测 778 万行里有 1 万行是 9~11 列，硬切会把城市名切碎并让列错位（错位后不报错，只是数据全错）。
 *
 * <h3>这份代码刻意不做的事</h3>
 * <ul>
 *   <li><b>不联网</b>：只读本地 gz 文件。上行链路只由更新脚本负责（scripts/srv1-geoip-update.sh）。</li>
 *   <li><b>不猜</b>：解析不出、列数不对、顺序错乱的行计入坏行，
 *       比例超过 1% 直接让整库判为不可用（抛 IOException，上层报 {@code GEO_DB_UNUSABLE}）——
 *       宁可 {@code geo=unavailable}，也不要拿半个库去画地图（那会画出"某些国家凭空消失"）。</li>
 * </ul>
 */
public final class GeoIpDatabase {

    private static final Logger logger = LoggerFactory.getLogger(GeoIpDatabase.class);

    /** 行数上限：防御"库文件被替换成一个解压后几百 GB 的包"（gzip 炸弹） */
    private static final long MAX_ROWS = 20_000_000L;

    /** 允许的坏行比例：超过 1% 视为库损坏（不是"少数行格式新"，而是"这不是那个文件"） */
    private static final double MAX_MALFORMED_RATIO = 0.01d;

    private static final Pattern VERSION_IN_NAME = Pattern.compile("(\\d{4}-\\d{2})");

    private final IpRangeTable city;
    private final IpRangeTable asn;

    private final String[] country;
    private final String[] province;
    private final String[] cityName;
    private final int[] asnNumber;
    private final String[] asnOrg;

    private final int cityRowsV4;
    private final int cityRowsV6;
    private final int asnRowsV4;
    private final int asnRowsV6;
    private final long malformedRows;
    private final long heapBytesEstimate;
    private final String cityVersion;
    private final String asnVersion;
    private final boolean ipv6Loaded;

    private GeoIpDatabase(IpRangeTable city, IpRangeTable asn,
                          String[] country, String[] province, String[] cityName,
                          int[] asnNumber, String[] asnOrg,
                          int cityRowsV4, int cityRowsV6, int asnRowsV4, int asnRowsV6,
                          long malformedRows, long heapBytesEstimate,
                          String cityVersion, String asnVersion, boolean ipv6Loaded) {
        this.city = city;
        this.asn = asn;
        this.country = country;
        this.province = province;
        this.cityName = cityName;
        this.asnNumber = asnNumber;
        this.asnOrg = asnOrg;
        this.cityRowsV4 = cityRowsV4;
        this.cityRowsV6 = cityRowsV6;
        this.asnRowsV4 = asnRowsV4;
        this.asnRowsV6 = asnRowsV6;
        this.malformedRows = malformedRows;
        this.heapBytesEstimate = heapBytesEstimate;
        this.cityVersion = cityVersion;
        this.asnVersion = asnVersion;
        this.ipv6Loaded = ipv6Loaded;
    }

    /**
     * 加载两个 gz CSV。
     *
     * @param cityCsvGz dbip-city-lite-YYYY-MM.csv.gz
     * @param asnCsvGz  dbip-asn-lite-YYYY-MM.csv.gz（可为 null：那就只做国家/省/城市）
     * @param loadIpv6  是否把 IPv6 区间也装进内存（省 ~80MB 的开关；见 RUNBOOK §26）
     * @throws IOException 文件读不了 / 不是 gzip / 坏行超阈值 / 顺序错乱 —— 由调用方判为 GEO_DB_UNUSABLE
     */
    public static GeoIpDatabase load(Path cityCsvGz, Path asnCsvGz, boolean loadIpv6) throws IOException {
        if (cityCsvGz == null || !Files.isReadable(cityCsvGz)) {
            throw new IOException("城市库不可读：" + cityCsvGz);
        }
        CityPool cityPool = new CityPool();
        IpRangeTable.Builder cityBuilder = new IpRangeTable.Builder();
        long[] malformed = {0L};

        long cityRows = readCsv(cityCsvGz, (fields, count, lineNo) -> {
            if (count < 6) {
                malformed[0]++;
                return;
            }
            try {
                int rec = cityPool.record(fields[3], fields[4], fields[5]);
                if (IpAddresses.looksLikeV4(fields[0])) {
                    addV4(cityBuilder, fields[0], fields[1], rec);
                } else if (loadIpv6) {
                    addV6(cityBuilder, fields[0], fields[1], rec);
                }
            } catch (RuntimeException e) {
                malformed[0]++;
            }
        });

        AsnPool asnPool = new AsnPool();
        IpRangeTable.Builder asnBuilder = new IpRangeTable.Builder();
        long asnRows = 0;
        if (asnCsvGz != null && Files.isReadable(asnCsvGz)) {
            asnRows = readCsv(asnCsvGz, (fields, count, lineNo) -> {
                if (count < 4) {
                    malformed[0]++;
                    return;
                }
                try {
                    int rec = asnPool.record(fields[2], fields[3]);
                    if (IpAddresses.looksLikeV4(fields[0])) {
                        addV4(asnBuilder, fields[0], fields[1], rec);
                    } else if (loadIpv6) {
                        addV6(asnBuilder, fields[0], fields[1], rec);
                    }
                } catch (RuntimeException e) {
                    malformed[0]++;
                }
            });
        }

        long totalRows = cityRows + asnRows;
        if (cityRows == 0) {
            throw new IOException("城市库一行都没解析出来（空文件或不是 DB-IP CSV）：" + cityCsvGz);
        }
        double badRatio = (double) malformed[0] / Math.max(1L, totalRows);
        if (badRatio > MAX_MALFORMED_RATIO) {
            throw new IOException("坏行比例 " + String.format("%.2f%%", badRatio * 100)
                    + " 超过阈值，判定库文件损坏或不是 DB-IP 格式（共 " + totalRows + " 行）");
        }

        IpRangeTable cityTable = cityBuilder.build();
        IpRangeTable asnTable = asnBuilder.build();
        String[] cc = cityPool.cc.toArray(new String[0]);
        String[] prov = cityPool.prov.toArray(new String[0]);
        String[] cname = cityPool.city.toArray(new String[0]);
        int[] asnNum = new int[asnPool.asns.size()];
        for (int i = 0; i < asnNum.length; i++) {
            asnNum[i] = asnPool.asns.get(i);
        }
        String[] orgs = asnPool.orgs.toArray(new String[0]);

        long bytes = cityTable.heapBytes() + asnTable.heapBytes()
                + stringsBytes(cc) + stringsBytes(prov) + stringsBytes(cname) + stringsBytes(orgs)
                + 4L * asnNum.length;

        GeoIpDatabase db = new GeoIpDatabase(cityTable, asnTable, cc, prov, cname, asnNum, orgs,
                cityBuilder.v4Count(), cityBuilder.v6Count(), asnBuilder.v4Count(), asnBuilder.v6Count(),
                malformed[0], bytes, versionOf(cityCsvGz), versionOf(asnCsvGz), loadIpv6);
        if (malformed[0] > 0) {
            logger.warn("GeoIP 加载：跳过 {} 行无法解析的记录（共 {} 行）", malformed[0], totalRows);
        }
        logger.info("GeoIP 加载完成：{}", db.stats());
        return db;
    }

    private static long stringsBytes(String[] arr) {
        long n = 40L * arr.length;                 // 每个 String 对象头 + 数组槽
        for (String s : arr) {
            n += 2L * s.length() + 16L;            // char[] 内容 + 数组头
        }
        return n;
    }

    /**
     * 从文件名解析库版本（{@code YYYY-MM}）。
     *
     * <p>线上用的是稳定符号链接 {@code dbip-city-lite.csv.gz → dbip-city-lite-2026-10.csv.gz} ——
     * <b>链接名里没有月份</b>，所以名字里解析不到时必须再解析一次符号链接去拿真实文件名。
     * 不这么做的话，公开面上的 {@code geoSource} 会变成"DB-IP Lite City 未知版本"，
     * 而这个 bug 只在"带稳定链接的生产形态"下出现（单测直接指向带月份的文件，看不到它）——
     * 是 srv1 上真跑那一次测出来的。
     */
    private static String versionOf(Path p) {
        if (p == null) {
            return null;
        }
        String v = monthIn(p.getFileName().toString());
        if (v != null) {
            return v;
        }
        try {
            Path real = p.toRealPath();
            if (real != null && !real.equals(p)) {
                return monthIn(real.getFileName().toString());
            }
        } catch (IOException ignored) {
            // 解析不了就用 null（"未知版本"），不要在装载路径上抛
        }
        return null;
    }

    /** 从任意名字里抓 {@code YYYY-MM}；抓不到返回 null */
    private static String monthIn(String name) {
        if (name == null) {
            return null;
        }
        Matcher m = VERSION_IN_NAME.matcher(name);
        return m.find() ? m.group(1) : null;
    }

    private static void addV4(IpRangeTable.Builder b, String start, String end, int rec) {
        Integer s = IpAddresses.parseV4(start);
        Integer e = IpAddresses.parseV4(end);
        if (s == null || e == null) {
            throw new IllegalArgumentException("IPv4 区间解析失败：" + start + "~" + end);
        }
        b.addV4(s, e, rec);
    }

    private static void addV6(IpRangeTable.Builder b, String start, String end, int rec) {
        long[] s = IpAddresses.parseV6(start);
        long[] e = IpAddresses.parseV6(end);
        if (s == null || e == null) {
            throw new IllegalArgumentException("IPv6 区间解析失败：" + start + "~" + end);
        }
        b.addV6(s[0], s[1], e[0], e[1], rec);
    }

    // ==================== 查询 ====================

    /**
     * 点查询。
     *
     * <p>输入可以是带端口的脏值：先按形状解析，解析不了返回 {@link GeoIpInfo#UNKNOWN}。
     * <b>不做内网判定</b> —— 那是 {@link IpAddresses#scope(String)} 的事，
     * 因为"能不能上地图"（口径）与"这个 IP 在哪"（数据）必须能分别被测试。
     */
    public GeoIpInfo lookup(String ip) {
        if (ip == null || ip.isBlank()) {
            return GeoIpInfo.UNKNOWN;
        }
        String v = ip.trim();
        Integer v4 = IpAddresses.parseV4(v);
        if (v4 != null) {
            return build(city.lookupV4(v4), asn.lookupV4(v4));
        }
        long[] v6 = IpAddresses.parseV6(v);
        if (v6 == null || !ipv6Loaded) {
            return GeoIpInfo.UNKNOWN;
        }
        return build(city.lookupV6(v6[0], v6[1]), asn.lookupV6(v6[0], v6[1]));
    }

    private GeoIpInfo build(int cityRec, int asnRec) {
        if (cityRec < 0 && asnRec < 0) {
            return GeoIpInfo.UNKNOWN;
        }
        String cc = cityRec >= 0 ? country[cityRec] : null;
        String prov = cityRec >= 0 ? province[cityRec] : null;
        String cname = cityRec >= 0 ? cityName[cityRec] : null;
        int num = asnRec >= 0 ? asnNumber[asnRec] : 0;
        String org = asnRec >= 0 ? asnOrg[asnRec] : null;
        return new GeoIpInfo(cc, prov, cname, num, org);
    }

    // ==================== 统计（如实报告用） ====================

    public String cityVersion() {
        return cityVersion;
    }

    public String asnVersion() {
        return asnVersion;
    }

    public boolean ipv6Loaded() {
        return ipv6Loaded;
    }

    public int cityRangeCount() {
        return city.v4Size() + city.v6Size();
    }

    public int asnRangeCount() {
        return asn.v4Size() + asn.v6Size();
    }

    public long heapBytesEstimate() {
        return heapBytesEstimate;
    }

    /** 一行说清"装了什么、占多少"——启动日志与 RUNBOOK 用同一个来源，避免两处数字对不上 */
    public String stats() {
        return "city=" + cityVersion + "(v4 " + cityRowsV4 + " 行 / v6 " + cityRowsV6 + " 行)"
                + " asn=" + asnVersion + "(v4 " + asnRowsV4 + " 行 / v6 " + asnRowsV6 + " 行)"
                + " 记录=" + country.length + " 城 / " + asnNumber.length + " ASN"
                + " 坏行=" + malformedRows
                + " 估算常驻=" + (heapBytesEstimate / (1024 * 1024)) + "MB"
                + (ipv6Loaded ? "" : "（未加载 IPv6）");
    }

    // ==================== 记录池（去重） ====================

    /**
     * 城市库记录池：只留去重后的 (国家, 省, 城市) 三元组。
     *
     * <p>{@code last*} 这几个字段是<b>实测出来的优化</b>：CSV 按区间排列，
     * 连续很多行就是同一个城市（例如广州的段一块接一块）。
     * 先比三个字段、命中就直接复用上一个记录号，可以省掉"拼 key + 查 Map"这两次分配 ——
     * 778 万行里绝大多数都能这样短路。
     */
    private static final class CityPool {
        final List<String> cc = new ArrayList<>(1 << 18);
        final List<String> prov = new ArrayList<>(1 << 18);
        final List<String> city = new ArrayList<>(1 << 18);
        private final Map<String, Integer> index = new HashMap<>(1 << 18);
        private String lastCc;
        private String lastProv;
        private String lastCity;
        private int lastRec = -1;

        int record(String country, String subdivision, String name) {
            if (lastRec >= 0 && lastCc.equals(country) && lastProv.equals(subdivision) && lastCity.equals(name)) {
                return lastRec;
            }
            String key = country + '\u0001' + subdivision + '\u0001' + name;
            Integer id = index.get(key);
            if (id == null) {
                id = cc.size();
                cc.add(country);
                prov.add(subdivision);
                city.add(name);
                index.put(key, id);
            }
            lastCc = country;
            lastProv = subdivision;
            lastCity = name;
            lastRec = id;
            return id;
        }
    }

    /** ASN 库记录池：去重后的 (ASN, 机构名) */
    private static final class AsnPool {
        final List<Integer> asns = new ArrayList<>(1 << 16);
        final List<String> orgs = new ArrayList<>(1 << 16);
        private final Map<String, Integer> index = new HashMap<>(1 << 16);
        private String lastAsn;
        private String lastOrg;
        private int lastRec = -1;

        int record(String asn, String org) {
            if (lastRec >= 0 && lastAsn.equals(asn) && lastOrg.equals(org)) {
                return lastRec;
            }
            String key = asn + '\u0001' + org;
            Integer id = index.get(key);
            if (id == null) {
                int num = 0;
                try {
                    num = Integer.parseInt(asn.trim());
                } catch (NumberFormatException ignored) {
                    // ASN 字段脏：保留 0（未知），机构名照样可用
                }
                id = asns.size();
                asns.add(num);
                orgs.add(org);
                index.put(key, id);
            }
            lastAsn = asn;
            lastOrg = org;
            lastRec = id;
            return id;
        }
    }

    // ==================== CSV 读取 ====================

    /**
     * 一行解析出来的字段（复用同一个数组；回调里必须当场用完，不要留存引用）。
     *
     * <p>为什么要把 {@code count} 单独传：数组是复用的定长数组，
     * {@code fields.length} 永远是容量而不是本行的字段数 ——
     * 拿它判列数会永远为真（这个 bug 会让"列数不对的行"静默通过）。
     */
    interface RowConsumer {
        void accept(String[] fields, int count, long lineNo);
    }

    /**
     * 流式读 gz CSV：一次一行、逐行回调，绝不整文件读进内存。
     *
     * <p>为什么不用 {@code String.split(",")}：城市名里有逗号（约 1 万行是 9~11 列），
     * 硬切会静默错列。这里的切分认双引号（{@code "South Brisbane"}），与 RFC 4180 一致。
     */
    static long readCsv(Path gz, RowConsumer consumer) throws IOException {
        long rows = 0;
        try (InputStream raw = Files.newInputStream(gz);
             InputStream in = new GZIPInputStream(raw, 1 << 16);
             BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8), 1 << 20)) {
            String[] fields = new String[12];
            String line;
            while ((line = reader.readLine()) != null) {
                rows++;
                if (rows > MAX_ROWS) {
                    throw new IOException("行数超过上限 " + MAX_ROWS + "，疑似 gzip 炸弹或文件被替换");
                }
                if (line.isEmpty()) {
                    continue;
                }
                int n = splitCsv(line, fields);
                if (n > 0 && fields[0] != null && fields[0].startsWith("#")) {
                    continue;                      // 将来若有表头/注释行也能容忍
                }
                consumer.accept(fields, n, rows);
            }
        }
        return rows;
    }

    /** 把一行的字段切进 {@code out}，返回字段数（超过 out 长度的字段被丢弃） */
    static int splitCsv(String line, String[] out) {
        int n = 0;
        int i = 0;
        int len = line.length();
        while (n < out.length) {
            StringBuilder sb = new StringBuilder(24);
            if (i < len && line.charAt(i) == '"') {
                i++;
                while (i < len) {
                    char c = line.charAt(i);
                    if (c == '"') {
                        if (i + 1 < len && line.charAt(i + 1) == '"') {
                            sb.append('"');
                            i += 2;
                            continue;
                        }
                        i++;
                        break;
                    }
                    sb.append(c);
                    i++;
                }
                // 闭合引号到逗号之间的残余（正常情况下没有）
                while (i < len && line.charAt(i) != ',') {
                    sb.append(line.charAt(i));
                    i++;
                }
            } else {
                int start = i;
                while (i < len && line.charAt(i) != ',') {
                    i++;
                }
                sb.append(line, start, i);
            }
            out[n++] = sb.toString();
            if (i < len && line.charAt(i) == ',') {
                i++;
                continue;
            }
            break;
        }
        return n;
    }
}

package org.example.geoip;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

/**
 * 离线地理富化服务（进程内单例）：<b>加载一次、查无数次、绝不联网</b>。
 *
 * <h3>为什么加载要放到后台线程做</h3>
 * 真实库解压后约 300MB、778 万行，实测解析要十几秒。而线上的健康检查有
 * {@code start_period: 120s} 且容器重启由看门狗盯着 —— 把十几秒压在
 * {@code @PostConstruct} 里，会让"库大了"变成"容器起不来"（同一个容器还可能因为
 * 内存峰值被 OOM Killer 直接干掉）。所以这里是：
 * <b>启动即登记状态、后台线程装库、装完之前如实报 {@code GEO_DB_LOADING}</b>。
 * 期间地理分布端点返回 {@code available=false}，<b>而不是返回空分布</b> ——
 * "没装好"和"这段时间没有攻击"必须能被区分开。
 *
 * <h3>四种状态，谁都别想冒充谁</h3>
 * <ul>
 *   <li>{@link State#DISABLED} —— {@code app.geoip.enabled=false}（站主要关掉这个能力）</li>
 *   <li>{@link State#MISSING} —— 配了路径但文件不在（最常见：还没跑月度更新脚本 / 卷没挂上）</li>
 *   <li>{@link State#LOADING} —— 正在装</li>
 *   <li>{@link State#UNUSABLE} —— 文件在但读不了（不是 gzip、被截断、坏行超阈值、区间乱序）</li>
 *   <li>{@link State#OK} —— 装好了</li>
 * </ul>
 * 公开端点把这几种状态原样映射成 {@code reason}（{@code GEO_DB_MISSING} /
 * {@code GEO_DB_UNUSABLE} / {@code GEO_DB_LOADING} / {@code GEO_DISABLED}），
 * 前端据此显示不同的话，运维据此知道该去修哪一段。
 */
@Component
public class GeoIpService {

    private static final Logger logger = LoggerFactory.getLogger(GeoIpService.class);

    /**
     * 署名文案（DB-IP Lite 是 CC BY 4.0：可再分发、可商用，但<b>必须署名</b>）。
     *
     * <p>这句话会同时出现在公开页面与 {@code /api/public/geo} 的 {@code note} 里 ——
     * 许可要求的是"署名"，不是"文档里提一句"，所以它必须在<b>实际用了这份数据的输出上</b>。
     * 测试 {@code GeoAggregatorTest} 会逐字断言它存在，防止被某次重构顺手删掉。
     */
    public static final String ATTRIBUTION =
            "IP 地理位置数据由 DB-IP (https://db-ip.com) 提供，CC BY 4.0";

    public enum State {
        DISABLED, MISSING, LOADING, OK, UNUSABLE
    }

    @Value("${app.geoip.enabled:true}")
    private boolean enabled;

    /** 城市库路径（文件，或包含 dbip-city-lite-*.csv.gz 的目录） */
    @Value("${app.geoip.city-db:}")
    private String cityDb;

    /** ASN 库路径（可空：那就只有国家/省/城市，没有 ASN 榜） */
    @Value("${app.geoip.asn-db:}")
    private String asnDb;

    /** 是否把 IPv6 区间也装进内存（实测 ~80MB；关掉后 IPv6 来源归为"未定位"） */
    @Value("${app.geoip.ipv6-enabled:true}")
    private boolean ipv6Enabled;

    private volatile State state = State.MISSING;
    private volatile String reason = "GEO_DB_MISSING";
    private volatile String detail;
    private volatile GeoIpDatabase database;
    private volatile long loadMillis = -1;
    private volatile String loadedCityPath;
    private volatile String loadedAsnPath;

    @PostConstruct
    public void init() {
        if (!enabled) {
            state = State.DISABLED;
            reason = "GEO_DISABLED";
            logger.info("GeoIP 已在配置中关闭（app.geoip.enabled=false）—— 地理分布端点将返回 available=false");
            return;
        }
        Path city = resolveNewest(cityDb, "dbip-city-lite-", ".csv.gz");
        if (city == null || !Files.isReadable(city)) {
            state = State.MISSING;
            reason = "GEO_DB_MISSING";
            logger.warn("GeoIP 未加载：找不到城市库（app.geoip.city-db={}）—— "
                    + "地理分布端点会如实返回 available=false/GEO_DB_MISSING，不返回空分布。"
                    + "落地方式见 RUNBOOK §26 与 scripts/srv1-geoip-update.sh", cityDb);
            return;
        }
        state = State.LOADING;
        reason = "GEO_DB_LOADING";
        Thread loader = new Thread(this::loadBlocking, "geoip-load");
        loader.setDaemon(true);
        loader.start();
    }

    /**
     * 同步装库（后台线程与测试都走这一条；也供将来"运维手动重载"调用）。
     *
     * <p>成功/失败都只改状态字段，<b>不抛</b>：调用方（端点）需要的是"现在能不能用 + 为什么"，
     * 而不是一个要自己 try 的异常。
     */
    public void loadBlocking() {
        long t0 = System.nanoTime();
        // ⚠️ 必须先把符号链接解析成真实文件再装库：
        //    部署面用的是稳定链接 /opt/geoip/dbip-city-lite.csv.gz → dbip-city-lite-2026-10.csv.gz，
        //    而版本号是从**文件名**里解析的（公开面要如实标注"这一版库是哪个月"）。
        //    不解析链接的话，线上 geoSource 会变成"DB-IP Lite City 未知版本"——
        //    而这个 bug 只在"带稳定链接的生产形态"下出现，单测（直接指向带月份的文件）看不到，
        //    是 srv1 上真跑那一次测出来的。
        Path city = realPathOrSelf(resolveNewest(cityDb, "dbip-city-lite-", ".csv.gz"));
        Path asn = realPathOrSelf(resolveNewest(asnDb, "dbip-asn-lite-", ".csv.gz"));
        try {
            GeoIpDatabase loaded = GeoIpDatabase.load(city, asn, ipv6Enabled);
            this.database = loaded;
            this.loadedCityPath = String.valueOf(city);
            this.loadedAsnPath = asn == null ? null : String.valueOf(asn);
            this.loadMillis = (System.nanoTime() - t0) / 1_000_000L;
            this.state = State.OK;
            this.reason = "OK";
            this.detail = null;
            logger.info("GeoIP 就绪：耗时 {}ms，{} 库={} ASN库={}（IPv6 {}）",
                    loadMillis, loaded.stats(), city.getFileName(),
                    asn == null ? "未配置" : asn.getFileName(), ipv6Enabled ? "已加载" : "未加载");
        } catch (IOException | RuntimeException e) {
            this.state = State.UNUSABLE;
            this.reason = "GEO_DB_UNUSABLE";
            this.loadMillis = (System.nanoTime() - t0) / 1_000_000L;
            this.detail = e.getClass().getSimpleName() + ": " + e.getMessage();
            this.database = null;
            logger.error("GeoIP 不可用（{}）：地理分布端点将如实返回 available=false/GEO_DB_UNUSABLE，"
                    + "不静默返回空分布；旧库文件不会被本次失败破坏", detail);
        }
    }

    /**
     * 解析库文件路径：可能是具体文件，也可能是目录（取目录里最新的 {@code YYYY-MM} 那一份）。
     *
     * <p>为什么支持目录：更新脚本落地的是"带月份的新文件 + 一个稳定符号链接"，
     * 两者都要能用 —— 只认具体文件名的话，某次把链接指错就会静默变成 MISSING。
     */
    Path resolveNewest(String configured, String prefix, String suffix) {
        if (configured == null || configured.isBlank()) {
            return null;
        }
        Path p = Path.of(configured.trim());
        if (Files.isRegularFile(p)) {
            return p;
        }
        if (!Files.isDirectory(p)) {
            return null;
        }
        try (Stream<Path> s = Files.list(p)) {
            List<Path> candidates = new ArrayList<>();
            s.filter(Files::isRegularFile)
                    .filter(f -> {
                        String n = f.getFileName().toString();
                        return n.startsWith(prefix) && n.endsWith(suffix);
                    })
                    .forEach(candidates::add);
            return candidates.stream()
                    .max(Comparator.comparing(f -> f.getFileName().toString()))
                    .orElse(null);
        } catch (IOException e) {
            logger.warn("GeoIP 列目录失败：{}（{}）", configured, e.getMessage());
            return null;
        }
    }

    /**
     * 解析符号链接到真实路径；解析失败就返回原路径（<b>不抛</b>：拿不到真实路径不该让整个功能不可用）。
     *
     * <p>用于让"版本号"正确：稳定链接名里没有月份，真实文件名里有（见 {@link #loadBlocking()}）。
     */
    private static Path realPathOrSelf(Path p) {
        if (p == null) {
            return null;
        }
        try {
            return p.toRealPath();
        } catch (IOException e) {
            return p;
        }
    }

    // ==================== 查询 ====================

    /** 是否已可用（唯一判据；不要看"配置里写了没写"） */
    public boolean ready() {
        return state == State.OK && database != null;
    }

    public State state() {
        return state;
    }

    /** 机读原因：OK / GEO_DB_MISSING / GEO_DB_UNUSABLE / GEO_DB_LOADING / GEO_DISABLED */
    public String reason() {
        return reason;
    }

    /** 人读细节（异常类型与消息；只在内部日志与运维面用，不进公开响应） */
    public String detail() {
        return detail;
    }

    public long loadMillis() {
        return loadMillis;
    }

    /** 估算常驻内存（字节）；未加载返回 0 */
    public long heapBytesEstimate() {
        GeoIpDatabase db = database;
        return db == null ? 0L : db.heapBytesEstimate();
    }

    /**
     * 数据源标签：{@code DB-IP Lite City 2026-10 + DB-IP Lite ASN 2026-10}。
     * 公开端点里用它告诉读者"这份地图是哪一版库画的"（换库或换月份时页面会跟着变）。
     */
    public String sourceLabel() {
        GeoIpDatabase db = database;
        if (db == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder("DB-IP Lite City ");
        sb.append(db.cityVersion() == null ? "未知版本" : db.cityVersion());
        if (db.asnRangeCount() > 0) {
            sb.append(" + DB-IP Lite ASN ").append(db.asnVersion() == null ? "未知版本" : db.asnVersion());
        }
        return sb.toString();
    }

    /** 一次性查询；库不可用时返回 {@link GeoIpInfo#UNKNOWN}（<b>不抛异常</b>） */
    public GeoIpInfo lookup(String ip) {
        GeoIpDatabase db = database;
        if (db == null) {
            return GeoIpInfo.UNKNOWN;
        }
        try {
            return db.lookup(ip);
        } catch (RuntimeException e) {
            // 查询本身必须"永不失败"：它跑在告警取数路径上，
            // 一条脏 IP 让整批告警取不到，是比"少一条地理信息"严重得多的故障。
            logger.debug("GeoIP 查询异常（按未知处理）ip={}：{}", ip, e.getMessage());
            return GeoIpInfo.UNKNOWN;
        }
    }

    /** 富化一条告警的 {@code srcGeo}（形状见 {@link GeoIpInfo#describe()}）；未知返回 null */
    public String describe(String ip) {
        return lookup(ip).describe();
    }

    /** 供 {@code /api/health} 与 RUNBOOK 使用的自查行 */
    public String summary() {
        GeoIpDatabase db = database;
        if (state != State.OK || db == null) {
            return "geo=" + state.name().toLowerCase(Locale.ROOT) + " reason=" + reason
                    + (detail == null ? "" : " detail=" + detail);
        }
        return "geo=ok source=" + sourceLabel() + " loadMs=" + loadMillis
                + " heapEstimateMB=" + (db.heapBytesEstimate() / (1024 * 1024))
                + " ipv6=" + db.ipv6Loaded() + " city=" + loadedCityPath
                + " asn=" + (loadedAsnPath == null ? "-" : loadedAsnPath);
    }
}

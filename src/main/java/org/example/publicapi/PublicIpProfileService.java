package org.example.publicapi;

import org.example.geoip.GeoIpInfo;
import org.example.geoip.GeoIpService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * <b>「这个 IP 干过什么」</b>（个人版 AbuseIPDB）的组装层 —— 供 {@code GET /api/public/ip?q=<ip>}。
 *
 * <h3>为什么要有这一层，而不是直接在控制器里拼</h3>
 * 答案要跨<b>三个数据源</b>：索引里的告警 + 蜜罐会话（{@link PublicAlertSource#ipActivity}）、
 * 应用侧的处置留痕（{@link PublicAuditReader#bansFor}）、GeoIP 库（{@link GeoIpService}）。
 * 三者的"读不到"各有各的形态（数据源不是 REAL / 文件没有 / 库里没这条）。
 * 把它们收在一个类里，"每个源读不到时这一项写 null 并给一句原因"这条口径就只写一遍、
 * 也只有一个地方会漏。
 *
 * <h3>硬口径（每一条都在测试里钉住）</h3>
 * <ol>
 *   <li><b>取不到就 null + {@code notes[]} 说明</b>：绝不把"读不到"写成 0，
 *       也不拿别的 IP 的数据顶（{@code query} 之外的任何字段都不含别人的 IP）；</li>
 *   <li><b>口令只给结构</b>：{@link PublicApiController#credentialShapes} 把 {@code root / 123456}
 *       换成 {@code root / 6 位·纯数字·弱口令}；<b>原文字符一个都不出现</b>（出关闸门
 *       {@code scrubText} 还会再隐一遍，属于双重保险）；</li>
 *   <li><b>精确值 vs 样本口径必须分开写</b>：{@code events} / {@code firstSeen} / {@code lastSeen} /
 *       {@code stages} 来自索引聚合（精确）；{@code byKind} / {@code ports} / {@code credStructure}
 *       只基于最近 {@code sampled} 条，{@code sources.indexer.truncated} 会如实给
 *       {@code true}，{@code notes[]} 里也写清楚 —— 不把样本数当总量；</li>
 *   <li><b>IP 口径只有一个来源</b>：{@code query} 与所有文本都经 {@link PublicIpPolicy}，
 *       掩码态下这个端点同样只出掩码。</li>
 * </ol>
 */
@Component
public class PublicIpProfileService {

    private static final Logger logger = LoggerFactory.getLogger(PublicIpProfileService.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** 默认查询窗口（7 天）：够回答"最近干过什么"，又不至于把首末时间拉成"历史久远" */
    public static final int DEFAULT_WINDOW_HOURS = 168;

    private static final PublicIpPolicy FAIL_CLOSED_POLICY = PublicIpPolicy.masking();

    @Autowired
    private PublicAlertSource source;

    @Autowired
    private PublicAuditReader auditReader;

    @Autowired(required = false)
    private PublicIpPolicy ipPolicy;

    /** 可为空：裁剪过的部署 / 单测里没有 GeoIP 库 → {@code geo} 写 null + notes 说明 */
    @Autowired(required = false)
    private GeoIpService geoIpService;

    @Value("${app.public-api.cache-seconds:15}")
    private int cacheSeconds = 15;

    @Value("${app.public-api.ip.window-hours:168}")
    private int windowHours = DEFAULT_WINDOW_HOURS;

    @Value("${app.public-api.ip.top-kinds:12}")
    private int topKinds = 12;

    private PublicIpPolicy policy() {
        PublicIpPolicy p = ipPolicy;
        return p != null ? p : FAIL_CLOSED_POLICY;
    }

    // ==================== 入口 ====================

    /**
     * 一个 IPv4 字面量的画像（可按 key 缓存；{@code ip} 必须已经过控制器校验）。
     *
     * <p>缓存与其余公开端点同一个 TTL 语义（{@code app.public-api.cache-seconds}），
     * 按 IP 分开存 —— 单个 {@code Snapshot} 只存一份值，用在这里会让不同 IP 互相顶掉
     * （与 {@code AttackStoryService.cached} 里的理由相同）。
     */
    public Map<String, Object> profile(String ip) {
        return cached("ip:" + ip, () -> build(ip));
    }

    private Map<String, Object> build(String ip) {
        int hours = Math.max(1, Math.min(windowHours, 168));
        List<String> notes = new ArrayList<>();

        // ---------- 1) 告警 + 蜜罐（索引） ----------
        Map<String, Object> indexer = null;
        if (source != null) {
            try {
                indexer = source.ipActivity(ip, hours);
            } catch (Exception e) {
                logger.warn("IP 画像读取索引失败（按降级载荷返回）：{}", e.getMessage());
                notes.add("告警/蜜罐这一段读取异常（" + e.getMessage() + "）：events / byKind / ports / "
                        + "credStructure 写 null，不补数");
            }
        } else {
            notes.add("告警/蜜罐数据源未装配（裁剪过的部署或单测）：events / byKind / ports / "
                    + "credStructure 写 null，不用内部样本顶替");
        }
        boolean indexerOk = indexer != null && Boolean.TRUE.equals(indexer.get("available"));
        if (indexer != null && !indexerOk) {
            notes.add("告警/蜜罐这一段读不到（" + str(indexer.get("reason"), "DATA_SOURCE_UNAVAILABLE")
                    + "）：" + str(indexer.get("note"), "上游未给出原因")
                    + " —— 「读不到」不等于「这个 IP 没有行为」");
        }

        // ---------- 2) GeoIP ----------
        Map<String, Object> geo = null;
        String geoStatus;
        if (geoIpService == null) {
            geoStatus = "NOT_WIRED";
            notes.add("GeoIP 库未装配：geo 写 null（不按网段或经验猜国家/ASN）");
        } else {
            try {
                GeoIpInfo info = geoIpService.lookup(ip);
                if (info == null || !info.isKnown()) {
                    geoStatus = "NOT_FOUND";
                    notes.add("GeoIP 库里查不到这个地址（或只有 ASN 没有国家）：geo 写 null，不猜");
                } else {
                    geoStatus = "OK";
                    geo = new LinkedHashMap<>();
                    geo.put("country", info.hasCountry() ? info.getCountry() : null);
                    geo.put("asn", info.getAsn() > 0 ? info.getAsn() : null);
                    geo.put("asnOrg", info.getAsnOrg());
                    if (geo.get("country") == null) {
                        notes.add("GeoIP 里这个地址只有 ASN、没有国家：geo.country 写 null");
                    }
                }
            } catch (Exception e) {
                geoStatus = "LOOKUP_FAILED";
                notes.add("GeoIP 查询异常（" + e.getMessage() + "）：geo 写 null");
            }
        }

        // ---------- 3) 处置留痕（封禁） ----------
        Map<String, Object> banned = null;
        Map<String, Object> bans = null;
        String auditStatus;
        if (auditReader == null) {
            auditStatus = "NOT_WIRED";
            notes.add("处置留痕未装配：banned 写 null");
        } else {
            try {
                bans = auditReader.bansFor(ip);
            } catch (Exception e) {
                logger.warn("读取封禁留痕失败：{}", e.getMessage());
                notes.add("读取封禁留痕异常（" + e.getMessage() + "）：banned 写 null");
            }
            if (bans != null && Boolean.TRUE.equals(bans.get("readable"))) {
                auditStatus = "OK";
                banned = new LinkedHashMap<>();
                banned.put("count", num(bans.get("count")));
                banned.put("lastBannedAt", strOrNull(bans.get("lastBannedAt")));
                Object active = bans.get("active");
                banned.put("active", active);
                if (active == null) {
                    notes.add("留痕里有封禁记录但到期时间解析不出来：banned.active 写 null（不猜是否还封着）");
                }
            } else if (bans != null) {
                auditStatus = "UNREADABLE";
                notes.add("封禁留痕文件读不到：banned 写 null（读不到 ≠ 没封过）");
            } else {
                auditStatus = "UNKNOWN";
            }
        }

        // ---------- 3.5) 威胁分（纯函数在 ThreatScore，这里只负责"哪些字段读到了"） ----------
        ThreatScore.Result threat = ThreatScore.score(threatInput(indexerOk, indexer, bans));

        // ---------- 4) 组装 ----------
        String now = LocalDateTime.now().format(FMT);
        Map<String, Object> pay = new LinkedHashMap<>();
        pay.put("generatedAt", now);
        pay.put("cacheSeconds", Math.max(0, cacheSeconds));
        pay.put("window", hours + "h");
        pay.put("windowHours", hours);
        pay.put("available", indexerOk);
        pay.put("reason", indexerOk ? "OK" : str(indexer == null ? null : indexer.get("reason"),
                "DATA_SOURCE_UNAVAILABLE"));
        pay.put("query", policy().display(ip));
        pay.put("ipVersion", "IPv4");
        pay.put("firstSeen", indexerOk ? strOrNull(indexer.get("firstSeen")) : null);
        pay.put("lastSeen", indexerOk ? strOrNull(indexer.get("lastSeen")) : null);
        pay.put("events", indexerOk ? num(indexer.get("total")) : null);
        pay.put("byKind", indexerOk ? kindMap(indexer.get("byKind")) : null);
        pay.put("ports", indexerOk ? portList(indexer.get("ports")) : null);
        pay.put("credStructure", indexerOk
                ? PublicApiController.credentialShapes(indexer.get("topCredentials")) : null);
        pay.put("threat", threat.toMap());
        pay.put("geo", geo);
        pay.put("banned", banned);
        pay.put("sources", sources(indexerOk, indexer, bans, auditStatus, geoStatus));
        pay.put("limits", limits(hours));
        notes.add("threat 是启发式加权分（ThreatScore：" + ThreatScore.VERSION
                + "，不是 ML/概率模型），只由上面这些字段加权得出；没读到的因子已从分母剔除并重标化"
                + (threat.isRenormalized()
                        ? "（本次可用权重 " + threat.getKnownWeight() + "/" + ThreatScore.MAX_WEIGHT + "）" : "")
                + "，所以不同窗口、不同缺字段状态的分数不能直接比较。");
        pay.put("notes", notes);
        pay.put("note", "只读、只回答「这个 IP 在我们这里干过什么」。events/firstSeen/lastSeen/stages "
                + "来自索引聚合（精确，但只在 " + hours + "h 窗口内 —— 更早的记录读不到）；"
                + "byKind/ports/credStructure 只基于最近取回的样本，见 sources.indexer.truncated。"
                + "threat 是按这些字段写死权重的启发式加权分，不是 ML、不是概率，跨窗口不可比。"
                + "口令一律只给结构、不给原文；任何一项取不到就写 null 并在 notes[] 里写明原因，不补数。");
        return pay;
    }

    /** 每个数据源「接没接上 / 读没读成」—— 与"有没有数据"分开读（/stories 的 coverage 同一思路） */
    private Map<String, Object> sources(boolean indexerOk, Map<String, Object> indexer,
                                        Map<String, Object> bans, String auditStatus, String geoStatus) {
        Map<String, Object> out = new LinkedHashMap<>();

        Map<String, Object> idx = new LinkedHashMap<>();
        idx.put("status", indexerOk ? "OK" : (indexer == null ? "NOT_WIRED"
                : str(indexer.get("reason"), "DATA_SOURCE_UNAVAILABLE")));
        idx.put("source", "Wazuh indexer（wazuh-alerts-*：告警 + 蜜罐会话）");
        idx.put("total", indexerOk ? num(indexer.get("total")) : null);
        idx.put("sampled", indexerOk ? num(indexer.get("sampled")) : null);
        idx.put("truncated", indexerOk ? Boolean.TRUE.equals(indexer.get("truncated")) : null);
        idx.put("stages", indexerOk ? indexer.get("stages") : null);
        out.put("indexer", idx);

        Map<String, Object> aud = new LinkedHashMap<>();
        aud.put("status", auditStatus);
        aud.put("source", "应用侧处置留痕 data/blocked-ips.json");
        aud.put("count", bans == null || !Boolean.TRUE.equals(bans.get("readable")) ? null : num(bans.get("count")));
        out.put("audit", aud);

        Map<String, Object> gg = new LinkedHashMap<>();
        gg.put("status", geoStatus);
        gg.put("source", GeoIpService.ATTRIBUTION);
        out.put("geoip", gg);
        return out;
    }

    private Map<String, Object> limits(int hours) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("windowHours", hours);
        m.put("topKinds", topKinds);
        m.put("ipv4Only", true);
        return m;
    }

    // ==================== 形状转换 ====================

    /**
     * {@code [{key,count}]} → {@code {kind: count}}（保持计数的稳定顺序：多的在前）。
     *
     * <p>源为空列表时返回空 Map 而不是 null：那是<b>真·没有数据</b>（数据源读到了、
     * 这个 IP 窗口内没有记录），与"读不到"（null）是两件事。
     */
    static Map<String, Long> kindMap(Object v) {
        Map<String, Long> out = new LinkedHashMap<>();
        if (v instanceof List<?> l) {
            int n = 0;
            for (Object o : l) {
                if (!(o instanceof Map<?, ?> m)) {
                    continue;
                }
                String kind = str(m.get("key"), "");
                if (kind.isBlank()) {
                    continue;
                }
                out.merge(kind, num(m.get("count")), Long::sum);
                if (++n >= 20) {
                    break;
                }
            }
        }
        return out;
    }

    /** {@code [{key,count}]} → {@code [{port,count}]}（端口是数字还是原样字符串，都照原样给） */
    static List<Map<String, Object>> portList(Object v) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (v instanceof List<?> l) {
            for (Object o : l) {
                if (!(o instanceof Map<?, ?> m)) {
                    continue;
                }
                String port = str(m.get("key"), "");
                if (port.isBlank()) {
                    continue;
                }
                Map<String, Object> x = new LinkedHashMap<>();
                try {
                    x.put("port", Integer.parseInt(port));
                } catch (NumberFormatException e) {
                    x.put("port", port);   // 不是数字就原样给（不猜它是什么协议）
                }
                x.put("count", num(m.get("count")));
                out.add(x);
            }
        }
        return out;
    }

    // ==================== 威胁分：把"读到的"翻译成 ThreatScore.Input ====================

    /**
     * 组装 {@link ThreatScore.Input}：<b>没读到的项一律传 null</b>，让纯函数把它们从分母里剔除
     * （算分不在这一层，见 {@link ThreatScore}）。
     *
     * <p>三处「读到」的边界，与上面的口径一致：
     * <ul>
     *   <li>索引整段（{@code indexerOk}）读不到 → events / byKind / ports / 凭据 / 用户名全部 null；</li>
     *   <li>索引读到了、但上游这一列没给（不是列表）→ 这一列 null；上游给的是<b>空列表</b>
     *       就传空 Map —— 那是「读到了、确实没有」，留在分母里得 0 分，与「没读到」分开；</li>
     *   <li>封禁留痕：只有 {@code readable=true} 才算读到；文件读不到/没装配时传 null
     *       （读不到 ≠ 没封过，不能按 false 给 0 分）。</li>
     * </ul>
     */
    static ThreatScore.Input threatInput(boolean indexerOk, Map<String, Object> indexer,
                                         Map<String, Object> bans) {
        ThreatScore.Input in = ThreatScore.Input.empty();
        if (indexerOk && indexer != null) {
            in.events(intOrNull(indexer.get("total")));
            in.byKind(indexer.get("byKind") instanceof List<?> ? kindCounts(indexer.get("byKind")) : null);
            in.ports(indexer.get("ports") instanceof List<?> ? portCounts(indexer.get("ports")) : null);
            Map<String, Object> stages = indexer.get("stages") instanceof Map<?, ?> m ? stringKeyed(m) : null;
            // 凭据尝试 = 蜜罐登录尝试总数（stages.honeypotLogins，索引侧精确计数，不是取样）
            in.credAttempts(stages == null ? null : intOrNull(stages.get("honeypotLogins")));
            // 账号多样性 = 取样里出现过的不同用户名（topCredentials 的 "用户 / 口令" 只取前半段）
            in.distinctUsers(indexer.get("topCredentials") instanceof List<?>
                    ? distinctUsers(indexer.get("topCredentials")) : null);
        }
        if (bans != null && Boolean.TRUE.equals(bans.get("readable"))) {
            // 「已封禁」按台账里有没有封禁记录算（含已过期的：封过就说明曾被判定为坏，故只给 10 分）
            in.banned(num(bans.get("count")) > 0);
        }
        return in;
    }

    private static Map<String, Integer> kindCounts(Object v) {
        Map<String, Integer> out = new LinkedHashMap<>();
        for (Map.Entry<String, Long> e : kindMap(v).entrySet()) {
            out.put(e.getKey(), clampInt(e.getValue() == null ? 0L : e.getValue()));
        }
        return out;
    }

    private static Map<String, Integer> portCounts(Object v) {
        Map<String, Integer> out = new LinkedHashMap<>();
        for (Map<String, Object> p : portList(v)) {
            Object port = p.get("port");
            if (port == null) {
                continue;
            }
            out.merge(String.valueOf(port), clampInt(num(p.get("count"))), Integer::sum);
        }
        return out;
    }

    /** 取样里出现过的不同用户名个数（口径：`用户 / 口令` 只认用户名；取样最多 10 条） */
    private static int distinctUsers(Object v) {
        Set<String> users = new LinkedHashSet<>();
        if (v instanceof List<?> l) {
            for (Object o : l) {
                if (!(o instanceof Map<?, ?> m)) {
                    continue;
                }
                String key = str(m.get("key"), "");
                if (key.isBlank()) {
                    continue;
                }
                int cut = key.indexOf(" / ");
                users.add(cut > 0 ? key.substring(0, cut) : key);
            }
        }
        return users.size();
    }

    /** {@code null} 表示读不到；给了但不是数字也当读不到（不猜 0） */
    private static Integer intOrNull(Object v) {
        if (v == null) {
            return null;
        }
        if (v instanceof Number n) {
            return clampInt(n.longValue());
        }
        try {
            return clampInt(Long.parseLong(String.valueOf(v).trim()));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** 计数一次性夹到 int 域内：权重公式本来就饱和，不需要保留超大数 */
    private static int clampInt(long v) {
        return v <= 0 ? 0 : (int) Math.min(Integer.MAX_VALUE, v);
    }

    /** {@code Map<?,?>} → {@code Map<String,Object>}（只用于上游返回的 JSON 对象，不做深拷贝） */
    private static Map<String, Object> stringKeyed(Map<?, ?> m) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : m.entrySet()) {
            if (e.getKey() != null) {
                out.put(String.valueOf(e.getKey()), e.getValue());
            }
        }
        return out;
    }

    // ==================== 校验（控制器用） ====================

    /**
     * <b>严格 IPv4 字面量</b>：四段十进制、每段 0-255（复用 {@link PublicIpMask#isIpv4Literal}），
     * 另外拒绝任何空白 —— 校验不通过就 <b>400</b>，不拿它去查任何东西。
     */
    public static boolean isIpv4Literal(String s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '.' || (c >= '0' && c <= '9')) {
                continue;
            }
            return false;
        }
        return PublicIpMask.isIpv4Literal(s);
    }

    /**
     * 是否<b>可以查</b>：是 IPv4 字面量，且不是内网/保留/链路地址。
     *
     * <p>为什么内网地址也拒：本站口径里内网/保留地址在任何公开面上都写作「内网/未知」
     * （{@link PublicIpPolicy}），拿 {@code 172.19.0.1} 去查会把内网主机的活动条数
     * 暴露到公网页面上，而同一个输入还会被好几个不同的内网地址共用 —— 那比不给更误导。
     */
    public static boolean isQueryable(String s) {
        if (!isIpv4Literal(s)) {
            return false;
        }
        return !PublicIpMask.isInternalAddress(s);
    }

    /**
     * 服务未装配时的降级载荷（形状与可用载荷对齐，只是各项都是 null + 说明）。
     *
     * <p>刻意<b>不</b>返回"0 条"：那样页面会写"这个 IP 什么都没干"，
     * 而事实是"我们这次什么都没读到"。
     */
    public static Map<String, Object> disabled(String displayedIp, int cacheSeconds) {
        Map<String, Object> pay = new LinkedHashMap<>();
        pay.put("generatedAt", LocalDateTime.now().format(FMT));
        pay.put("cacheSeconds", Math.max(0, cacheSeconds));
        pay.put("window", DEFAULT_WINDOW_HOURS + "h");
        pay.put("windowHours", DEFAULT_WINDOW_HOURS);
        pay.put("available", false);
        pay.put("reason", "IP_PROFILE_DISABLED");
        pay.put("query", displayedIp);
        pay.put("ipVersion", "IPv4");
        pay.put("firstSeen", null);
        pay.put("lastSeen", null);
        pay.put("events", null);
        pay.put("byKind", null);
        pay.put("ports", null);
        pay.put("credStructure", null);
        pay.put("threat", null);
        pay.put("geo", null);
        pay.put("banned", null);
        Map<String, Object> src = new LinkedHashMap<>();
        for (String k : List.of("indexer", "audit", "geoip")) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("status", "NOT_WIRED");
            src.put(k, m);
        }
        pay.put("sources", src);
        pay.put("limits", Map.of("windowHours", DEFAULT_WINDOW_HOURS, "ipv4Only", true));
        List<String> notes = new ArrayList<>();
        notes.add("IP 画像服务未装配（裁剪过的部署，或单测直接 new 控制器）：不返回任何计数，"
                + "也不用内部样本顶替");
        pay.put("notes", notes);
        pay.put("note", "不可用：所有计数项写 null，不补数。");
        return pay;
    }

    // ==================== 缓存与工具 ====================

    /** {@code cacheSeconds} 快照（按 IP 分开存；LRU 上限防止被随机 IP 扫成内存泄漏） */
    private final Map<String, CacheEntry> cache = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, CacheEntry> eldest) {
                    return size() > 64;
                }
            });

    @SuppressWarnings("unchecked")
    private <T> T cached(String key, java.util.function.Supplier<T> loader) {
        long now = System.currentTimeMillis();
        CacheEntry e = cache.get(key);
        if (e != null && now < e.expiresAt) {
            return (T) e.value;
        }
        CacheEntry fresh;
        try {
            fresh = new CacheEntry(loader.get(),
                    System.currentTimeMillis() + Math.max(0, cacheSeconds) * 1000L);
        } catch (Exception ex) {
            // 刷新失败不抛给匿名访客变成 500：有旧值就继续用旧的，没有就退成"不可用"
            logger.warn("IP 画像快照刷新失败：{}", ex.getMessage());
            Object value = e != null ? e.value : disabled(null, cacheSeconds);
            fresh = new CacheEntry(value, System.currentTimeMillis() + 5000L);
        }
        cache.put(key, fresh);
        return (T) fresh.value;
    }

    private static final class CacheEntry {
        private final Object value;
        private final long expiresAt;

        private CacheEntry(Object value, long expiresAt) {
            this.value = value;
            this.expiresAt = expiresAt;
        }
    }

    static String str(Object v, String dflt) {
        if (v == null) {
            return dflt;
        }
        String s = String.valueOf(v);
        return s.isBlank() ? dflt : s;
    }

    static String strOrNull(Object v) {
        if (v == null) {
            return null;
        }
        String s = String.valueOf(v);
        return s.isBlank() ? null : s;
    }

    static long num(Object v) {
        if (v instanceof Number n) {
            return n.longValue();
        }
        if (v != null) {
            try {
                return Long.parseLong(String.valueOf(v).trim());
            } catch (NumberFormatException e) {
                return 0L;
            }
        }
        return 0L;
    }
}

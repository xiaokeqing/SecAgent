package org.example.publicapi;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * <b>0–100 的 IP 威胁分：启发式加权，不是 ML、不是概率模型。</b>
 *
 * <p>这个类只做一件事：把 {@code /api/public/ip} 已经读到的那几列（窗口内事件量、来源类型分布、
 * 触达端口数、蜜罐凭据尝试数、账号多样性、是否在封禁台账里）按一张写死的权重表加起来。
 * 没有训练集、没有模型参数、没有「相似度」—— 同样的输入永远得到同样的分数，公式就在下面。
 * 因此它<b>不能</b>读成"这个 IP 有 73% 的概率是攻击者"，也只能在同一口径（同一窗口、同一采样上限）内比较。
 *
 * <h3>权重表（上限合计 100）</h3>
 * <table border="1">
 *   <caption>启发式权重</caption>
 *   <tr><th>因子</th><th>上限</th><th>公式</th><th>为什么是这个权重</th></tr>
 *   <tr><td>事件量</td><td>30</td><td>{@code min(1, log10(1+events)/4) * 30}</td>
 *       <td>最基础的"有没有来过、来了多少"。对数压缩：1 条和 10 条差得明显，1 万条和 10 万条几乎一样
 *           （10000 条就饱和），避免一次端口扫描的日志量把分数顶死。</td></tr>
 *   <tr><td>来源类型</td><td>25</td><td>蜜罐命中 +9、侦察/扫描 +6、成功登录 +10（相加封顶 25）</td>
 *       <td>唯一描述<b>行为性质</b>的信号：撞上蜜罐、做过扫描、真的登进来过。
 *           成功登录给最高单项，因为它穿过了认证层；蜜罐命中次之（蜜罐本身就是诱饵，命中即"故意的"）；
 *           扫描最轻（互联网上每天都有无差别扫描）。</td></tr>
 *   <tr><td>端口扇出</td><td>15</td><td>{@code min(1, ports/8) * 15}</td>
 *       <td>横向/纵向扫描特征。8 个不同端口算满 —— 再往上边际信息很小，
 *           不能让"全端口扫描"的 6 万多个端口把这一项拉成决定性因素。</td></tr>
 *   <tr><td>凭据尝试</td><td>15</td><td>{@code min(1, cred/100) * 15}</td>
 *       <td>口令爆破的规模。100 次封顶：真实爆破动辄上万次，超过 100 次已经是"在认真破解"，
 *           再往上只增加量级不增加性质。</td></tr>
 *   <tr><td>已封禁</td><td>10</td><td>二值：在台账里 +10</td>
 *       <td>我们（或自动策略）已经处置过它 —— 这是"已被判定为坏"的旁证，但只有 10 分：
 *           封禁可能过期、可能是误封，所以它只做加权，不让一个历史封禁单独把分数推成 critical。</td></tr>
 *   <tr><td>账号多样性</td><td>5</td><td>{@code min(1, users/10) * 5}</td>
 *       <td>撞库/口令喷洒特征（换着用户名试）。10 个用户名封顶，且只是弱信号，
 *           给最小权重；单看它不足以说明什么。</td></tr>
 * </table>
 *
 * <h3>缺字段：从分母里剔除并重标化，<b>绝不当 0</b></h3>
 * <p>{@link Input} 的字段全部是包装类型：{@code null} 表示"这一次<b>没读到</b>这个字段"
 * （数据源没装配 / 索引这一段读不到 / 上游没给），此时把该因子的满分权重从分母里去掉，
 * 剩下的权重按比例放大到 100 —— 即
 * {@code score = 得分 / max(可用权重和, MIN_EVIDENCE_WEIGHT) * 100}。
 * <p>为什么不能当 0：0 是"读到了，值是零"（这个 IP 窗口内确实没有蜜罐命中），
 * 会和"我们不知道"混成一件事。一个只有端口数据的 IP 如果按满分 100 的分母算，
 * 最多只能拿 15 分（low），等于用"没读到"给它洗白；重标化后它按已有证据算 33 分（medium）。
 * <p>反方向的坑也一样要防：{@code byKind = {}}、{@code banned = false} 是<b>有证据的零</b>，
 * 它们照常留在分母里（所以"什么都没干的 IP"得到的是低分，而不是因为零权重被重标化成高分）。
 * <p>{@link #MIN_EVIDENCE_WEIGHT}（45）是分母下限：证据太少时不再向上放大，
 * 免得一个开了 8 个端口的 IP 被 15/15 重标化成 critical。45 分以下的可用权重一律按 45 算，
 * 于是单一最弱的证据最多只能到 33 分（落在 medium 下沿），<b>不会</b>凭一条弱信号冲进 high/critical。
 *
 * <p>纯函数：不读时钟、不读配置、不碰数据库，{@link Input} 里的 Map 进来就拷贝一份。
 * 组装（哪些字段读到了、怎么从索引载荷翻译过来）在
 * {@link PublicIpProfileService}，计算只在这里 —— 所以它可以在单测里被穷举。
 */
public final class ThreatScore {

    /** 口径版本：分数规则一改就换版本号，历史分数不能跨版本比较 */
    public static final String VERSION = "heuristic-v1";

    /** 各因子上限（合计 {@link #MAX_WEIGHT}） */
    public static final int W_EVENTS = 30;
    public static final int W_SOURCE = 25;
    public static final int W_HONEYPOT = 9;
    public static final int W_RECON = 6;
    public static final int W_LOGIN_OK = 10;
    public static final int W_PORTS = 15;
    public static final int W_CREDS = 15;
    public static final int W_BANNED = 10;
    public static final int W_USERS = 5;

    /** 满分权重：所有因子都读到时的分母 */
    public static final int MAX_WEIGHT = W_EVENTS + W_SOURCE + W_PORTS + W_CREDS + W_BANNED + W_USERS;

    /** 分母下限：可用权重不足这个数时仍以它为分母（别让单一弱信号重标化成高分） */
    public static final int MIN_EVIDENCE_WEIGHT = 45;

    /** {@code min(1, ports/8)} 的饱和点 */
    public static final int PORTS_FOR_FULL = 8;
    /** {@code min(1, cred/100)} 的饱和点 */
    public static final int CREDS_FOR_FULL = 100;
    /** {@code min(1, users/10)} 的饱和点 */
    public static final int USERS_FOR_FULL = 10;
    /** {@code min(1, log10(1+events)/4)} 的饱和点：events ≈ 9999 */
    public static final int EVENTS_FOR_FULL = 9999;

    public static final int BAND_MEDIUM_FROM = 30;
    public static final int BAND_HIGH_FROM = 60;
    public static final int BAND_CRITICAL_FROM = 80;

    public static final String LOW = "low";
    public static final String MEDIUM = "medium";
    public static final String HIGH = "high";
    public static final String CRITICAL = "critical";

    static {
        if (W_HONEYPOT + W_RECON + W_LOGIN_OK != W_SOURCE) {
            throw new AssertionError("来源类型的三个子权重必须正好等于 W_SOURCE");
        }
        if (MAX_WEIGHT != 100) {
            throw new AssertionError("权重上限必须合计 100：" + MAX_WEIGHT);
        }
    }

    private ThreatScore() {
    }

    // ==================== 输入 ====================

    /**
     * 评分输入。<b>字段刻意用包装类型（Integer / Boolean）：{@code null} = 没读到这个字段</b>，
     * 与"读到了、值是 0"分开。Map 为 {@code null} 同样表示没读到；空 Map 是"读到了、确实没有"。
     *
     * <p>各字段的来源（见 {@link PublicIpProfileService#threatInput}）：
     * {@code events} 来自索引聚合的总数；{@code byKind} / {@code ports} 来自最近取样；
     * {@code credAttempts} 是蜜罐登录尝试数（精确计数）；{@code distinctUsers} 是取样里出现过的用户名去重数；
     * {@code banned} 是应用侧封禁台账里有没有它。
     */
    public static final class Input {
        private Integer events;
        private Map<String, Integer> byKind;
        private Map<String, Integer> ports;
        private Integer credAttempts;
        private Integer distinctUsers;
        private Boolean banned;

        private Input() {
        }

        /** 全缺的输入：得分 0、band=low、factors 为空 */
        public static Input empty() {
            return new Input();
        }

        /** 窗口内事件数（索引聚合，精确） */
        public Input events(Integer v) {
            this.events = v;
            return this;
        }

        /** 来源类型分布：{@code {类别: 条数}}（取样，最多 20 类） */
        public Input byKind(Map<String, Integer> v) {
            this.byKind = v == null ? null : new LinkedHashMap<>(v);
            return this;
        }

        /** 触达端口：{@code {端口: 条数}}（取样，最多 20 个） */
        public Input ports(Map<String, Integer> v) {
            this.ports = v == null ? null : new LinkedHashMap<>(v);
            return this;
        }

        /** 蜜罐登录尝试数（精确计数） */
        public Input credAttempts(Integer v) {
            this.credAttempts = v;
            return this;
        }

        /** 取样里出现过的不同用户名个数 */
        public Input distinctUsers(Integer v) {
            this.distinctUsers = v;
            return this;
        }

        /** 在封禁台账里有没有它 */
        public Input banned(Boolean v) {
            this.banned = v;
            return this;
        }

        public Integer getEvents() {
            return events;
        }

        public Map<String, Integer> getByKind() {
            return byKind;
        }

        public Map<String, Integer> getPorts() {
            return ports;
        }

        public Integer getCredAttempts() {
            return credAttempts;
        }

        public Integer getDistinctUsers() {
            return distinctUsers;
        }

        public Boolean getBanned() {
            return banned;
        }
    }

    // ==================== 输出 ====================

    /** 一个因子的明细：名字 / 实际拿到的权重 / 在分母里占的权重 / 依据（含原始值与公式中间量） */
    public static final class Factor {
        private final String name;
        private final double weight;
        private final int maxWeight;
        private final String detail;

        Factor(String name, double weight, int maxWeight, String detail) {
            this.name = name;
            this.weight = weight;
            this.maxWeight = maxWeight;
            this.detail = detail;
        }

        public String getName() {
            return name;
        }

        /** 实际拿到的分（满分 {@link #getMaxWeight()}） */
        public double getWeight() {
            return weight;
        }

        /** 这个因子在本次分母里占的权重（读到就计入，没读到就整体剔除） */
        public int getMaxWeight() {
            return maxWeight;
        }

        public String getDetail() {
            return detail;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", name);
            m.put("weight", round1(weight));
            m.put("maxWeight", maxWeight);
            m.put("detail", detail);
            return m;
        }
    }

    /** 一次评分的结果（不可变） */
    public static final class Result {
        private final int score;
        private final String band;
        private final List<Factor> factors;
        private final double knownWeight;
        private final double denominator;

        Result(int score, String band, List<Factor> factors, double knownWeight, double denominator) {
            this.score = score;
            this.band = band;
            this.factors = List.copyOf(factors);
            this.knownWeight = knownWeight;
            this.denominator = denominator;
        }

        /** 0–100 的整数分 */
        public int getScore() {
            return score;
        }

        /** {@code low | medium | high | critical} */
        public String getBand() {
            return band;
        }

        public List<Factor> getFactors() {
            return factors;
        }

        /** 读到的因子上限之和（重标化前的分母） */
        public double getKnownWeight() {
            return knownWeight;
        }

        /** 实际分母 = {@code max(knownWeight, MIN_EVIDENCE_WEIGHT)} */
        public double getDenominator() {
            return denominator;
        }

        /** 有没有因子因为"没读到"被剔除（true 时页面要说明分数已重标化） */
        public boolean isRenormalized() {
            return knownWeight < MAX_WEIGHT;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("version", VERSION);
            m.put("score", score);
            m.put("band", band);
            m.put("knownWeight", round1(knownWeight));
            m.put("denominator", round1(denominator));
            m.put("maxWeight", MAX_WEIGHT);
            m.put("minEvidenceWeight", MIN_EVIDENCE_WEIGHT);
            m.put("renormalized", isRenormalized());
            List<Map<String, Object>> fs = new ArrayList<>(factors.size());
            for (Factor f : factors) {
                fs.add(f.toMap());
            }
            m.put("factors", fs);
            m.put("method", "heuristic-weighted");
            m.put("note", "启发式加权（" + VERSION + "），不是 ML/概率模型：分数 = 各因子得分之和 ÷ 可用权重 × 100，"
                    + "公式与权重都在 ThreatScore 里写死。没读到的字段已从分母剔除并重标化（分母不低于 "
                    + MIN_EVIDENCE_WEIGHT + "），不当作 0 参与 —— 所以不同窗口、不同缺字段状态的分数不可直接比较。");
            return m;
        }
    }

    // ==================== 评分 ====================

    /**
     * 把 {@link Input} 加权成 0–100 的分数。纯函数，{@code null} 输入按"全缺"处理。
     */
    public static Result score(Input in) {
        Input x = in == null ? Input.empty() : in;
        List<Factor> factors = new ArrayList<>(6);
        double got = 0.0;      // 各因子实际得分之和
        double known = 0.0;    // 读到的因子上限之和 = 重标化前的分母

        // ① 事件量：对数压缩，10000 条饱和
        if (x.events != null) {
            int n = Math.max(0, x.events);
            double ratio = Math.min(1.0, Math.log10(1.0 + n) / 4.0);
            double w = ratio * W_EVENTS;
            got += w;
            known += W_EVENTS;
            factors.add(new Factor("事件量", w, W_EVENTS,
                    "窗口内 " + n + " 条记录；min(1, log10(1+events)/4)×30 = " + fmt(ratio) + "×30"
                            + (ratio >= 1.0 ? "（10000 条封顶）" : "")));
        }

        // ② 来源类型：蜜罐命中 / 侦察扫描 / 成功登录，三个子信号相加，封顶 25
        if (x.byKind != null) {
            boolean honey = false;
            boolean recon = false;
            boolean loginOk = false;
            for (String kind : x.byKind.keySet()) {
                if (kind == null) {
                    continue;
                }
                if (kind.contains("蜜罐")) {
                    honey = true;
                }
                if (kind.contains("扫描") || kind.contains("探测") || kind.contains("侦察")
                        || kind.contains("暴力") || kind.contains("爆破")) {
                    recon = true;
                }
                if (kind.contains("登录成功") || kind.contains("成功登录")) {
                    loginOk = true;
                }
            }
            double w = 0.0;
            StringBuilder hit = new StringBuilder();
            if (honey) {
                w += W_HONEYPOT;
                hit.append("蜜罐命中 +").append(W_HONEYPOT);
            }
            if (recon) {
                w += W_RECON;
                hit.append(hit.length() > 0 ? "，" : "").append("侦察/扫描 +").append(W_RECON);
            }
            if (loginOk) {
                w += W_LOGIN_OK;
                hit.append(hit.length() > 0 ? "，" : "").append("成功登录 +").append(W_LOGIN_OK);
            }
            w = Math.min(w, W_SOURCE);
            got += w;
            known += W_SOURCE;
            factors.add(new Factor("来源类型", w, W_SOURCE,
                    hit.length() == 0
                            ? "byKind 里没有蜜罐/扫描/成功登录类记录（共 " + x.byKind.size()
                                    + " 类）—— 这是读到后的 0，不是没读到"
                            : "命中 " + hit + "（byKind 共 " + x.byKind.size() + " 类）"));
        }

        // ③ 端口扇出：8 个不同端口封顶
        if (x.ports != null) {
            int n = x.ports.size();
            double ratio = Math.min(1.0, n / (double) PORTS_FOR_FULL);
            double w = ratio * W_PORTS;
            got += w;
            known += W_PORTS;
            factors.add(new Factor("端口扇出", w, W_PORTS,
                    "触达 " + n + " 个不同端口（取样上限 20）；min(1, ports/8)×15 = " + fmt(ratio) + "×15"));
        }

        // ④ 凭据尝试：100 次封顶
        if (x.credAttempts != null) {
            int n = Math.max(0, x.credAttempts);
            double ratio = Math.min(1.0, n / (double) CREDS_FOR_FULL);
            double w = ratio * W_CREDS;
            got += w;
            known += W_CREDS;
            factors.add(new Factor("凭据尝试", w, W_CREDS,
                    "蜜罐登录尝试 " + n + " 次；min(1, cred/100)×15 = " + fmt(ratio) + "×15"));
        }

        // ⑤ 已封禁：二值，10 分
        if (x.banned != null) {
            double w = x.banned ? W_BANNED : 0.0;
            got += w;
            known += W_BANNED;
            factors.add(new Factor("已封禁", w, W_BANNED,
                    x.banned
                            ? "在我们的封禁台账里（曾被处置过，是「已被判定为坏」的旁证；封禁可能已过期或误封，故只给 10）"
                            : "封禁台账里没有它（读到后的 0；不等于清白，只说明没被我们处置过）"));
        }

        // ⑥ 账号多样性：10 个用户名封顶，弱信号 5 分
        if (x.distinctUsers != null) {
            int n = Math.max(0, x.distinctUsers);
            double ratio = Math.min(1.0, n / (double) USERS_FOR_FULL);
            double w = ratio * W_USERS;
            got += w;
            known += W_USERS;
            factors.add(new Factor("账号多样性", w, W_USERS,
                    "取样里出现 " + n + " 个不同用户名；min(1, users/10)×5 = " + fmt(ratio) + "×5"));
        }

        // 重标化：分母 = max(可用权重, 下限)。没读到的因子上限根本不在 known 里 —— 就是"剔除"，
        // 而不是补 0 让它稀释分数。
        double denom = Math.max(known, MIN_EVIDENCE_WEIGHT);
        int score = (int) Math.round(Math.min(1.0, got / denom) * 100);
        return new Result(score, band(score), factors, known, denom);
    }

    /** 分档：{@code <30 low} / {@code 30–59 medium} / {@code 60–79 high} / {@code ≥80 critical} */
    public static String band(int score) {
        if (score >= BAND_CRITICAL_FROM) {
            return CRITICAL;
        }
        if (score >= BAND_HIGH_FROM) {
            return HIGH;
        }
        if (score >= BAND_MEDIUM_FROM) {
            return MEDIUM;
        }
        return LOW;
    }

    private static double round1(double v) {
        return Math.round(v * 10.0) / 10.0;
    }

    private static String fmt(double v) {
        return String.format(Locale.ROOT, "%.2f", v);
    }
}

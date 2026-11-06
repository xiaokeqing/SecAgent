package org.example.response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * 封禁时长策略（分级 TTL）。
 *
 * <h3>为什么不再"写死 60 分钟"</h3>
 * 原来 {@code blockIp} 的时长要么由调用方传、要么取护栏默认值，与"这次攻击有多严重"无关：
 * 一次端口扫描和一个已经打进来的漏洞利用，被封的时间一样长。真正需要的是
 * <b>按攻击类型分级</b>——扫描通常是自动化噪音，封半小时足够；
 * 爆破是持续威胁，一天内不让它回来；利用成功意味着对方掌握了武器化路径，按周计。
 * <p>
 * 这些数字是<b>策略常量</b>（可在 {@code response.ttl.*} 覆盖），不是散落在代码里的魔法数：
 * 调参只改配置，不改逻辑；单测直接断言"哪一类落在哪一档"，改档位会立刻被测试挡住。
 *
 * <h3>为什么显式时长优先</h3>
 * 人工处置时运维可能明确要求"封 10 分钟先看看"。这时策略不该覆盖人的判断，
 * 只在<b>没人指定</b>时给出兜底档位。所以 {@link #decide} 的顺序是：
 * 显式时长 &gt; 攻击类型 &gt; 风险等级兜底 &gt; 默认值。
 *
 * <h3>与护栏（{@link org.example.security.ResponseGuard}）的分工</h3>
 * 本类只负责"算多久"，<b>不负责"能不能封"</b>。白名单/非法地址/上限仍然在护栏里判，
 * 本类产出的值必须再过护栏——这样策略配错（比如有人把 exploit 配成 365 天）
 * 也只是被护栏截断，而不是变成永久封禁。
 */
@Component
public class BlockPolicy {

    private static final Logger logger = LoggerFactory.getLogger(BlockPolicy.class);

    /**
     * 攻击类型分档。
     *
     * <p>{@code token} 会作为服务端封禁脚本的 reason 参数（只允许 ASCII 安全字符），
     * 也写进审计与封禁记录，便于事后按类型统计"封了多少个扫描/爆破"。
     */
    public enum ThreatClass {
        SCAN("scan", "扫描/探测", 30),
        BRUTE_FORCE("brute-force", "暴力破解", 1440),
        EXPLOIT("exploit", "漏洞利用", 10080),
        OTHER("other", "其它/手动", 60);

        private final String token;
        private final String label;
        private final int defaultMinutes;

        ThreatClass(String token, String label, int defaultMinutes) {
            this.token = token;
            this.label = label;
            this.defaultMinutes = defaultMinutes;
        }

        public String getToken() {
            return token;
        }

        public String getLabel() {
            return label;
        }

        public int getDefaultMinutes() {
            return defaultMinutes;
        }
    }

    /** 扫描类：自动化探测器，重来成本极低，封短一点即可 */
    @Value("${response.ttl.scan-minutes:30}")
    private int scanMinutes = 30;

    /** 爆破类：持续认证攻击，24 小时内不允许回来 */
    @Value("${response.ttl.brute-force-minutes:1440}")
    private int bruteForceMinutes = 1440;

    /** 利用类：已出现武器化利用痕迹，按周计 */
    @Value("${response.ttl.exploit-minutes:10080}")
    private int exploitMinutes = 10080;

    /** 未识别类型且未显式指定时的默认时长（与护栏默认值保持同一量纲） */
    @Value("${response.ttl.default-minutes:60}")
    private int defaultMinutes = 60;

    /**
     * 高危但归类不明时的兜底时长。
     *
     * <p>为什么不是直接回落默认 60 分钟：告警等级 HIGH 已经说明"这次不是噪音"，
     * 而分类器只认识几组关键词，识别不出时<b>宁可封久一点也不放过</b>。
     */
    @Value("${response.ttl.high-risk-minutes:1440}")
    private int highRiskMinutes = 1440;

    /**
     * 策略决策结果。
     *
     * <p>{@code policyDerived=true} 表示"时长来自策略而非调用方"，护栏会据此使用
     * 策略专用上限（{@code app.response.policy-max-duration-minutes}）；
     * 反之使用人工封禁上限（{@code app.response.max-duration-minutes}）。
     * 这个区分很关键：否则 7 天的利用类封禁永远过不了 24 小时的人工上限，策略形同虚设，
     * 而放宽人工上限又会削弱"人不能随手封一个月"这条护栏。
     */
    public static final class Decision {
        private final ThreatClass threatClass;
        private final int minutes;
        private final boolean policyDerived;
        private final String basis;

        Decision(ThreatClass threatClass, int minutes, boolean policyDerived, String basis) {
            this.threatClass = threatClass;
            this.minutes = minutes;
            this.policyDerived = policyDerived;
            this.basis = basis;
        }

        public ThreatClass getThreatClass() {
            return threatClass;
        }

        public int getMinutes() {
            return minutes;
        }

        public boolean isPolicyDerived() {
            return policyDerived;
        }

        /** 决策依据（写进审计，便于解释"为什么封这么久"） */
        public String getBasis() {
            return basis;
        }
    }

    /**
     * 计算本次封禁时长。
     *
     * @param requestedMinutes 调用方显式指定的分钟数（null 或 &lt;=0 视为未指定）
     * @param reason           封禁原因/告警标题，用于分类
     * @param riskLevelHint    风险等级提示（HIGH/LOW，可空）
     */
    public Decision decide(Integer requestedMinutes, String reason, String riskLevelHint) {
        ThreatClass cls = classify(reason);
        if (requestedMinutes != null && requestedMinutes > 0) {
            return new Decision(cls, requestedMinutes, false, "调用方显式指定 " + requestedMinutes + "min");
        }
        if (cls != ThreatClass.OTHER) {
            return new Decision(cls, minutesFor(cls), true,
                    "按攻击类型 " + cls.getToken() + "（" + cls.getLabel() + "）取 " + minutesFor(cls) + "min");
        }
        if ("HIGH".equalsIgnoreCase(riskLevelHint)) {
            return new Decision(cls, highRiskMinutes, true,
                    "类型未识别但风险等级 HIGH，按兜底 " + highRiskMinutes + "min");
        }
        return new Decision(cls, defaultMinutes, true, "类型未识别，按默认 " + defaultMinutes + "min");
    }

    /** 各档当前生效分钟数（运维面板/日志用） */
    public int minutesFor(ThreatClass cls) {
        switch (cls) {
            case SCAN:
                return scanMinutes;
            case BRUTE_FORCE:
                return bruteForceMinutes;
            case EXPLOIT:
                return exploitMinutes;
            default:
                return defaultMinutes;
        }
    }

    /**
     * 从原因文本推断攻击类型。
     *
     * <h3>为什么用关键词而不是让模型判断</h3>
     * 处置时长是安全决策，必须<b>可复现、可审计、离线可测</b>。
     * 模型可能今天判"爆破"、明天判"扫描"，同一份告警封出两个时长，事后无法解释。
     * 关键词表是显式的，命中哪一条、落到哪一档，都能在测试里钉死。
     * <p>
     * 顺序即优先级：利用 &gt; 爆破 &gt; 扫描。同时出现多个特征时取最严重的一档
     * （"扫描之后尝试注入"应按利用处理）。
     */
    public static ThreatClass classify(String reason) {
        if (reason == null || reason.trim().isEmpty()) {
            return ThreatClass.OTHER;
        }
        String s = reason.toLowerCase();
        if (containsAny(s, "exploit", "利用", "webshell", "cve-", "rce",
                "注入", "injection", "命令执行", "提权", "后门")) {
            return ThreatClass.EXPLOIT;
        }
        if (containsAny(s, "brute", "爆破", "暴破", "口令", "密码猜解",
                "登录失败", "auth fail", "failed password", "credential")) {
            return ThreatClass.BRUTE_FORCE;
        }
        if (containsAny(s, "scan", "扫描", "探活", "探测", "probe", "recon",
                "侦察", "指纹识别", "目录枚举")) {
            return ThreatClass.SCAN;
        }
        return ThreatClass.OTHER;
    }

    private static boolean containsAny(String s, String... keys) {
        for (String k : keys) {
            if (s.contains(k)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 分钟 → ipset/nftables 的 timeout 秒数。
     *
     * <p>ipset 的 timeout 是 32 位无符号秒；这里用 long 计算并封顶，
     * 避免策略被配成荒谬大值后在服务端溢出成"立即过期"——
     * 那会表现成"封了但没封住"，是最难排查的一类失败。
     */
    public static int toTimeoutSeconds(int minutes) {
        long sec = (long) Math.max(1, minutes) * 60L;
        long capped = Math.min(sec, 31_536_000L); // 365 天，再长没有实际意义
        return (int) capped;
    }

    /** 启动自检：把当前生效的档位打进日志，调参后一次就能核对 */
    @jakarta.annotation.PostConstruct
    public void selfCheck() {
        logger.info("=== 封禁时长策略（分级 TTL）===");
        logger.info("  扫描类      = {} 分钟", scanMinutes);
        logger.info("  爆破类      = {} 分钟", bruteForceMinutes);
        logger.info("  利用类      = {} 分钟", exploitMinutes);
        logger.info("  HIGH 兜底   = {} 分钟", highRiskMinutes);
        logger.info("  默认        = {} 分钟", defaultMinutes);
    }
}

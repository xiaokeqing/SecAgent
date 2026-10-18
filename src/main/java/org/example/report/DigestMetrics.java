package org.example.report;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 每日日报的<b>取数结果</b>：只有数字、出处、缺口，不做任何渲染。
 *
 * <h3>为什么先有这一层再渲染</h3>
 * 日报的每一句话都要能回答"这个数字从哪来"。如果取数与拼 Markdown 写在一个方法里，
 * 出处就只能靠记忆维护——过两周没人敢改。这里把"数字 + 出处 + 缺口"固定成一个值对象：
 * <ul>
 *   <li>{@code sources}：<b>指标键 → 出处</b>。渲染时逐行打印，任一数字缺出处就是 bug；</li>
 *   <li>{@code missing}：取不到的项<b>连同原因</b>列进「缺数据」一节，
 *       绝不用 0 顶替——"取不到"和"真的是 0"在安全日报里是完全不同的两件事；</li>
 *   <li>所有可缺的数字一律用包装类型（{@link Long} / {@link Integer}），
 *       {@code null} 就是"没取到"，由渲染层写成 {@code null}。</li>
 * </ul>
 *
 * <p>窗口口径（与站点 {@code /api/public/*} 保持同一套，避免日报和页面互相打架）：
 * 告警与来源国家是<b>过去 24 小时</b>；蜜罐是<b>最近 800 条</b>蜜罐告警（不是 24h 窗口，
 * 因为速拨窗口按条数裁剪，这一点在出处里明写）；封禁/解封是<b>全量处置留痕</b>（不限 24h）。
 */
public record DigestMetrics(
        LocalDate day,
        LocalDateTime generatedAt,
        Long alertTotal,
        Map<String, Long> alertsBySeverity,
        Long sourceIpsWithGeo,
        List<Country> countries,
        Integer honeypotConnections,
        Integer honeypotLogins,
        Integer honeypotLoginFails,
        Integer honeypotSampled,
        Integer blockTotal,
        Integer blockActive,
        Integer blockedByGuard,
        Integer executedActions,
        List<IpSource> topSources,
        String notable,
        Map<String, String> sources,
        List<String> missing) {

    /** 来源国家一行：条数 + 独立 IP 数（只看条数会被一个吵闹 IP 骗）。 */
    public record Country(String code, String name, long count, long uniqueIps, double sharePercent) {
    }

    /** 来源 IP 一行：窗口内的尝试次数。 */
    public record IpSource(String ip, long attempts) {
    }

    /** 指标键（与 {@link #sources} 的键一一对应；渲染层用这些键取出处）。 */
    public static final String K_ALERTS = "alerts";
    public static final String K_SEVERITY = "severity";
    public static final String K_COUNTRIES = "countries";
    public static final String K_HONEYPOT = "honeypot";
    public static final String K_BLOCKS = "blocks";
    public static final String K_TOP_SOURCE = "topSource";
    public static final String K_NOTABLE = "notable";

    /** 解封数 = 总封禁 − 仍生效；两侧任一缺失即 {@code null}（不拿 0 猜）。 */
    public Integer unblocked() {
        if (blockTotal == null || blockActive == null) {
            return null;
        }
        return Math.max(0, blockTotal - blockActive);
    }

    /** 最凶来源（尝试次数最多的一条）；没有数据时为 {@code null}。 */
    public IpSource worst() {
        return topSources == null || topSources.isEmpty() ? null : topSources.get(0);
    }

    /** Top1 来源国家；没有数据时为 {@code null}。 */
    public Country topCountry() {
        return countries == null || countries.isEmpty() ? null : countries.get(0);
    }

    public static Builder builder(LocalDate day) {
        return new Builder(day);
    }

    /**
     * 组装器：十几个可选数字用构造器传递必然有一次写错顺序，而两个 {@code Integer}
     * 互换位置编译器一声不响。装配点是唯一的，用链式 setter 把它读成清单。
     */
    public static final class Builder {
        private final LocalDate day;
        private LocalDateTime generatedAt = LocalDateTime.now();
        private Long alertTotal;
        private final Map<String, Long> alertsBySeverity = new LinkedHashMap<>();
        private Long sourceIpsWithGeo;
        private List<Country> countries = List.of();
        private Integer honeypotConnections;
        private Integer honeypotLogins;
        private Integer honeypotLoginFails;
        private Integer honeypotSampled;
        private Integer blockTotal;
        private Integer blockActive;
        private Integer blockedByGuard;
        private Integer executedActions;
        private List<IpSource> topSources = List.of();
        private String notable;
        private final Map<String, String> sources = new LinkedHashMap<>();
        private final List<String> missing = new ArrayList<>();

        private Builder(LocalDate day) {
            this.day = day;
        }

        public Builder generatedAt(LocalDateTime at) {
            this.generatedAt = at;
            return this;
        }

        public Builder alerts(Long total, Map<String, Long> bySeverity, String source) {
            if (total == null) {
                missing.add("告警总数：stats24h 不可用（见「告警」一节的 state/reason）");
            } else {
                this.alertTotal = total;
                source(K_ALERTS, source);
            }
            if (bySeverity != null && !bySeverity.isEmpty()) {
                this.alertsBySeverity.putAll(bySeverity);
                source(K_SEVERITY, source + " 的 bySeverity（同一 24h 窗口）");
            } else {
                missing.add("严重度分布：stats24h.bySeverity 为空");
            }
            return this;
        }

        public Builder countries(Long ipsWithGeo, List<Country> top, String source) {
            if (top == null || top.isEmpty()) {
                missing.add("来源国家：GeoIP 聚合无入榜国家（或窗口内无带来源 IP 的告警）");
            } else {
                this.countries = List.copyOf(top);
                source(K_COUNTRIES, source);
            }
            if (ipsWithGeo != null) {
                this.sourceIpsWithGeo = ipsWithGeo;
            }
            return this;
        }

        public Builder honeypot(Integer connections, Integer logins, Integer fails, Integer sampled, String source) {
            if (connections == null) {
                missing.add("蜜罐连接数：蜜罐汇总不可用（Cowrie 数据源未就绪）");
            } else {
                this.honeypotConnections = connections;
                this.honeypotSampled = sampled;
                this.honeypotLogins = logins;
                this.honeypotLoginFails = fails;
                source(K_HONEYPOT, source);
            }
            return this;
        }

        public Builder blocks(Integer total, Integer active, Integer blockedByGuard, Integer executed, String source) {
            if (total == null) {
                missing.add("封禁/解封数：处置审计留痕不可用");
            } else {
                this.blockTotal = total;
                this.blockActive = active;
                this.blockedByGuard = blockedByGuard;
                this.executedActions = executed;
                source(K_BLOCKS, source);
            }
            return this;
        }

        public Builder topSources(List<IpSource> top, String source) {
            if (top == null || top.isEmpty()) {
                missing.add("最凶来源 IP：蜜罐样本里没有来源地址计数");
            } else {
                this.topSources = List.copyOf(top);
                source(K_TOP_SOURCE, source);
            }
            return this;
        }

        public Builder notable(String text, String source) {
            this.notable = text;
            if (text != null) {
                source(K_NOTABLE, source);
            }
            return this;
        }

        /** 显式登记一个缺口（带原因），渲染层原样列进「缺数据」。 */
        public Builder missing(String reason) {
            if (reason != null && !reason.isBlank()) {
                missing.add(reason);
            }
            return this;
        }

        private void source(String key, String text) {
            sources.put(key, text == null ? "未标注出处" : text);
        }

        public DigestMetrics build() {
            // 刻意保序（严重度 CRITICAL→LOW、出处按报告顺序）：Map.copyOf 会打乱顺序，
            // 日报是给人读的，顺序变了每天的内容看起来都在变。
            return new DigestMetrics(day, generatedAt, alertTotal,
                    Collections.unmodifiableMap(new LinkedHashMap<>(alertsBySeverity)),
                    sourceIpsWithGeo, countries, honeypotConnections, honeypotLogins, honeypotLoginFails,
                    honeypotSampled, blockTotal, blockActive, blockedByGuard, executedActions, topSources,
                    notable, Collections.unmodifiableMap(new LinkedHashMap<>(sources)), List.copyOf(missing));
        }
    }
}

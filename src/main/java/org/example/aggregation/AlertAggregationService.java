package org.example.aggregation;

import org.example.core.model.AlertSeverity;
import org.example.core.model.SecurityAlert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 告警聚合去重服务。
 *
 * <p>攻击链视角：同一攻击往往在短时间内、由同一源 IP、命中同一类规则多次告警
 * （例如主机侧 nginx 日志和网络侧 Suricata 同时发现一次 SQL 注入）。
 * 逐条罗列会淹没分析师视线，因此按<strong>聚合键 = 源 IP + 告警类型</strong>分桶，
 * 桶内再用<strong>滑动时间窗</strong>贪心聚类：
 *
 * <ol>
 *   <li>同一 (srcIp, type) 视为"同一攻击链"候选；</li>
 *   <li>桶内按发生时间升序，依次归入当前簇；只要新告警距<strong>簇起始时间</strong>
 *       不超过 {@code aggregation.window-minutes} 分钟就并入，否则另起新簇；</li>
 *   <li>每个簇产出一条"聚合告警"：聚合数 count、时间窗 startTime/endTime、
 *       代表告警（取簇内最高危、并列取最新一条）、涉及资产集合、原始明细 id 列表。</li>
 * </ol>
 *
 * <p>无源 IP / 无法归类的告警各自成单元素簇，不参与跨条聚合。
 * 开关与时间窗见 application.yml 的 {@code aggregation.*}，代码内给默认值兜底。
 */
@Service
public class AlertAggregationService {

    private static final Logger logger = LoggerFactory.getLogger(AlertAggregationService.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Value("${aggregation.enabled:true}")
    private boolean enabled;

    @Value("${aggregation.window-minutes:5}")
    private int windowMinutes;

    public boolean isEnabled() {
        return enabled;
    }

    public int getWindowMinutes() {
        return windowMinutes;
    }

    /**
     * 把已合并去重的原始告警列表聚合为若干"聚合告警"。
     *
     * @param raw 已按 id 去重的原始告警（顺序不限，方法内部自行排序）
     * @return 聚合后的 Map 列表，按"最近一次活动时间"倒序；单元素簇也会返回一条
     */
    public List<Map<String, Object>> aggregate(List<SecurityAlert> raw) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (raw == null || raw.isEmpty()) {
            return out;
        }

        // 1) 按聚合键分桶：srcIp + "|" + type
        Map<String, List<SecurityAlert>> buckets = new LinkedHashMap<>();
        int idx = 0;
        for (SecurityAlert a : raw) {
            buckets.computeIfAbsent(bucketKey(a, idx++), k -> new ArrayList<>()).add(a);
        }

        // 2) 每个桶内按时间升序做时间窗贪心聚类
        long windowSec = windowMinutes * 60L;
        for (List<SecurityAlert> bucket : buckets.values()) {
            bucket.sort(Comparator.comparing(SecurityAlert::getOccurredAt,
                    Comparator.nullsLast(Comparator.naturalOrder())));

            List<SecurityAlert> cluster = new ArrayList<>();
            LocalDateTime clusterStart = null;
            for (SecurityAlert a : bucket) {
                LocalDateTime t = parseTime(a.getOccurredAt());
                if (cluster.isEmpty()) {
                    cluster.add(a);
                    clusterStart = t;
                    continue;
                }
                // 距簇起始时间在窗口内则并入，否则收尾另起一簇
                boolean withinWindow = (t != null && clusterStart != null)
                        && Math.abs(java.time.Duration.between(clusterStart, t).getSeconds()) <= windowSec;
                if (withinWindow) {
                    cluster.add(a);
                } else {
                    out.add(buildAggregate(cluster));
                    cluster = new ArrayList<>();
                    cluster.add(a);
                    clusterStart = t;
                }
            }
            if (!cluster.isEmpty()) {
                out.add(buildAggregate(cluster));
            }
        }

        // 3) 聚合结果按代表告警时间倒序（与原列表一致）
        out.sort((x, y) -> {
            String tx = String.valueOf(x.getOrDefault("endTime", ""));
            String ty = String.valueOf(y.getOrDefault("endTime", ""));
            return ty.compareTo(tx);
        });
        return out;
    }

    /** 聚合键：同源 IP + 同类规则/类型。无 IP 则用 id 兜底，保证各自成簇。 */
    private static String bucketKey(SecurityAlert a, int idx) {
        String ip = a.getSrcIp() == null ? "" : a.getSrcIp().trim();
        String type = a.getType() == null ? "UNKNOWN" : a.getType().name();
        if (ip.isEmpty()) {
            return "NOIP#" + idx + "#" + type;
        }
        return ip + "|" + type;
    }

    /** 把一个簇打包成聚合告警 Map。 */
    private Map<String, Object> buildAggregate(List<SecurityAlert> cluster) {
        // 代表告警：最高危优先，并列取时间最新
        SecurityAlert rep = cluster.get(0);
        for (SecurityAlert a : cluster) {
            if (isMoreSevere(a, rep)) rep = a;
        }

        List<String> memberIds = new ArrayList<>();
        Set<String> assets = new LinkedHashSet<>();
        Set<String> sources = new LinkedHashSet<>();
        String startTime = null;
        String endTime = null;
        for (SecurityAlert a : cluster) {
            memberIds.add(a.getId());
            if (a.getDstAsset() != null && !a.getDstAsset().isBlank()) {
                assets.add(a.getDstAsset() + (a.getDstIp() != null && !a.getDstIp().isBlank()
                        ? "（" + a.getDstIp() + "）" : ""));
            } else if (a.getDstIp() != null && !a.getDstIp().isBlank()) {
                assets.add(a.getDstIp());
            }
            if (a.getSource() != null) sources.add(a.getSource().name());
            String t = a.getOccurredAt();
            if (t == null) continue;
            if (startTime == null || t.compareTo(startTime) < 0) startTime = t;
            if (endTime == null || t.compareTo(endTime) > 0) endTime = t;
        }

        String key = (rep.getSrcIp() == null ? "" : rep.getSrcIp().trim()) + "|"
                + (rep.getType() == null ? "UNKNOWN" : rep.getType().name());
        // aggId 用"成员 id 集合"派生：与秒级抖动无关，保证 list 与后续下钻 /aggregated/{aggId} 命中同一簇
        String aggId = "agg-" + sha1(key + "|" + String.join(",", memberIds)).substring(0, 12);

        Map<String, Object> m = new LinkedHashMap<>();
        m.put("aggregated", true);
        m.put("aggId", aggId);
        m.put("count", cluster.size());          // 聚合条数
        m.put("startTime", startTime);           // 时间窗起
        m.put("endTime", endTime);               // 时间窗止
        m.put("memberIds", memberIds);           // 原始明细 id
        m.put("assets", new ArrayList<>(assets)); // 涉及资产
        m.put("sources", new ArrayList<>(sources));// 涉及来源

        // —— 代表告警字段平铺（前端可按原列表字段直接渲染）——
        m.put("id", rep.getId());
        m.put("title", rep.getTitle());
        m.put("ruleName", rep.getRuleName());
        m.put("type", rep.getType());
        m.put("severity", rep.getSeverity());
        m.put("source", rep.getSource());
        m.put("srcIp", rep.getSrcIp());
        m.put("srcGeo", rep.getSrcGeo());
        m.put("dstAsset", rep.getDstAsset());
        m.put("dstIp", rep.getDstIp());
        m.put("dstPort", rep.getDstPort());
        m.put("service", rep.getService());
        m.put("description", rep.getDescription());
        m.put("occurredAt", rep.getOccurredAt());
        m.put("status", rep.getStatus());
        m.put("hitCount", rep.getCount());       // 代表告警原始命中次数
        return m;
    }

    private static boolean isMoreSevere(SecurityAlert cand, SecurityAlert cur) {
        AlertSeverity cs = cand.getSeverity();
        AlertSeverity rs = cur.getSeverity();
        if (cs == null && rs == null) return false;
        if (cs == null) return false;
        if (rs == null) return true;
        if (cs.getRank() != rs.getRank()) return cs.getRank() > rs.getRank();
        // 并列：取时间更新的
        String ct = cand.getOccurredAt() == null ? "" : cand.getOccurredAt();
        String rt = cur.getOccurredAt() == null ? "" : cur.getOccurredAt();
        return ct.compareTo(rt) > 0;
    }

    private static LocalDateTime parseTime(String s) {
        if (s == null || s.isBlank()) return null;
        try {
            return LocalDateTime.parse(s.trim(), FMT);
        } catch (Exception e) {
            return null;
        }
    }

    private static String sha1(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return Integer.toHexString(s.hashCode());
        }
    }
}

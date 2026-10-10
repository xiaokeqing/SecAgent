package org.example.controller;

import org.example.aggregation.AlertAggregationService;
import org.example.core.model.AlertSeverity;
import org.example.core.model.AlertSource;
import org.example.core.model.AlertType;
import org.example.core.model.RawLogLine;
import org.example.core.model.SecurityAlert;
import org.example.integration.SuricataGateway;
import org.example.integration.WazuhGateway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 告警大屏接口。
 *
 * <p>登录即可访问（不属于管理员前缀）：合并 Wazuh 主机告警与 Suricata 网络告警，
 * 去重后统一推给前端；统计与趋势也在后端聚合好，前端只负责画图。
 */
@RestController
@RequestMapping("/api/alerts")
public class AlertBoardController {

    private static final Logger logger = LoggerFactory.getLogger(AlertBoardController.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Autowired
    private WazuhGateway wazuh;

    @Autowired
    private SuricataGateway suricata;

    @Autowired
    private AlertAggregationService aggregator;

    /** 详情/统计时一次性多拉一些，保证能按 id 命中 */
    private static final int FETCH_LIMIT = 200;

    /**
     * 合并两个网关的告警，按 id 去重，按时间倒序。
     * （list / stats / detail / aggregated 共用同一份口径，保证聚合与下钻自洽）
     */
    private List<SecurityAlert> mergedAlerts(int limit) {
        int want = Math.min(Math.max(limit, 1), FETCH_LIMIT);
        List<SecurityAlert> merged = new ArrayList<>();
        merged.addAll(safeGet(wazuh, want));
        merged.addAll(safeGet(suricata, want));

        // 按 id 去重（同一事件在两个来源重复出现时只保留一条）
        Map<String, SecurityAlert> byId = new LinkedHashMap<>();
        for (SecurityAlert a : merged) {
            byId.putIfAbsent(a.getId(), a);
        }
        List<SecurityAlert> list = new ArrayList<>(byId.values());
        list.sort(Comparator.comparing(SecurityAlert::getOccurredAt,
                Comparator.nullsLast(Comparator.reverseOrder())));
        return list;
    }

    /**
     * 告警列表。
     *
     * <p>默认（聚合开启）返回"聚合后"列表：同一攻击链（同源 IP + 同类规则 + 相近时间窗）
     * 的多条原始告警归并为一条聚合告警，每条带 count / 时间窗 / 涉及资产 / memberIds。
     * 加参数 {@code &raw=true} 返回原始逐条列表（不破坏旧调用）。
     *
     * <p>data 内 {@code rawTotal}=原始条数、{@code aggregatedTotal}=聚合后条数、
     * {@code aggregated}=本次是否聚合、{@code windowMinutes}=当前时间窗。
     */
    @GetMapping("/list")
    public Map<String, Object> list(@RequestParam(value = "limit", defaultValue = "50") int limit,
                                    @RequestParam(value = "raw", defaultValue = "false") boolean raw) {
        List<SecurityAlert> list = mergedAlerts(limit);
        int rawTotal = list.size();

        Map<String, Object> data = new HashMap<>();
        data.put("wazuhMode", wazuh.mode());
        data.put("suricataMode", suricata.mode());
        data.put("rawTotal", rawTotal);

        boolean doAggregate = aggregator.isEnabled() && !raw;
        if (doAggregate) {
            List<Map<String, Object>> agg = aggregator.aggregate(list);
            data.put("list", agg);
            data.put("total", agg.size());
            data.put("aggregatedTotal", agg.size());
            data.put("aggregated", true);
            data.put("windowMinutes", aggregator.getWindowMinutes());
        } else {
            data.put("list", list);
            data.put("total", rawTotal);
            data.put("aggregatedTotal", rawTotal);
            data.put("aggregated", false);
            data.put("windowMinutes", aggregator.getWindowMinutes());
        }
        return ok(data);
    }

    /**
     * 聚合告警下钻：返回某条聚合告警的完整原始明细（members 展开为原始告警对象数组）。
     * stateless：重新跑一遍合并+聚合，按 aggId 命中簇后展开成员。
     */
    @GetMapping("/aggregated/{aggId}")
    public Map<String, Object> aggregatedDetail(@PathVariable("aggId") String aggId) {
        List<SecurityAlert> list = mergedAlerts(FETCH_LIMIT);
        List<Map<String, Object>> aggs = aggregator.aggregate(list);

        Map<String, Object> self = null;
        for (Map<String, Object> g : aggs) {
            if (aggId.equals(g.get("aggId"))) { self = g; break; }
        }
        if (self == null) {
            Map<String, Object> body = new HashMap<>();
            body.put("code", 404);
            body.put("message", "未找到聚合告警：" + aggId);
            return body;
        }

        // 展开 memberIds -> 原始告警对象
        @SuppressWarnings("unchecked")
        List<String> memberIds = (List<String>) self.get("memberIds");
        Map<String, SecurityAlert> byId = new LinkedHashMap<>();
        for (SecurityAlert a : list) byId.put(a.getId(), a);
        List<SecurityAlert> members = new ArrayList<>();
        if (memberIds != null) {
            for (String mid : memberIds) {
                SecurityAlert a = byId.get(mid);
                if (a != null) members.add(a);
            }
        }

        Map<String, Object> data = new HashMap<>();
        data.put("aggregated", self);       // 聚合概要（count/时间窗/资产等）
        data.put("members", members);       // 原始明细对象数组
        data.put("rawTotal", list.size());
        data.put("wazuhMode", wazuh.mode());
        data.put("suricataMode", suricata.mode());
        return ok(data);
    }

    /**
     * 统计：按等级、类型、来源计数 + 最近 24 小时时间趋势分桶。
     */
    @GetMapping("/stats")
    public Map<String, Object> stats() {
        List<SecurityAlert> deduped = mergedAlerts(FETCH_LIMIT);

        // 等级计数（固定顺序，保证前端环形图稳定）
        Map<String, Long> bySeverity = new LinkedHashMap<>();
        for (AlertSeverity s : AlertSeverity.values()) {
            bySeverity.put(s.name() + "|" + s.getLabel(),
                    deduped.stream().filter(a -> a.getSeverity() == s).count());
        }
        // 类型计数
        Map<String, Long> byType = new LinkedHashMap<>();
        for (AlertType t : AlertType.values()) {
            long c = deduped.stream().filter(a -> a.getType() == t).count();
            if (c > 0) byType.put(t.name() + "|" + t.getLabel(), c);
        }
        // 来源计数
        Map<String, Long> bySource = new LinkedHashMap<>();
        for (AlertSource s : AlertSource.values()) {
            bySource.put(s.name() + "|" + s.getLabel(),
                    deduped.stream().filter(a -> a.getSource() == s).count());
        }
        // 活跃数（状态为 ACTIVE）
        long activeCount = deduped.stream()
                .filter(a -> a.getStatus() == null || "ACTIVE".equals(a.getStatus())).count();

        // 时间趋势：最近 24 小时，按小时分桶
        LocalDateTime now = LocalDateTime.now().withMinute(0).withSecond(0).withNano(0);
        Map<String, Long> trend = new LinkedHashMap<>();
        for (int i = 23; i >= 0; i--) {
            trend.put(now.minusHours(i).format(DateTimeFormatter.ofPattern("HH:mm")), 0L);
        }
        for (SecurityAlert a : deduped) {
            LocalDateTime t = parseTime(a.getOccurredAt());
            if (t == null) continue;
            if (t.isBefore(now.minusHours(24)) || t.isAfter(now.plusHours(1))) continue;
            String key = t.withMinute(0).format(DateTimeFormatter.ofPattern("HH:mm"));
            trend.merge(key, 1L, Long::sum);
        }

        Map<String, Object> data = new HashMap<>();
        data.put("total", deduped.size());
        data.put("active", activeCount);
        data.put("critical", bySeverity.getOrDefault("CRITICAL|严重", 0L));
        data.put("high", bySeverity.getOrDefault("HIGH|高危", 0L));
        data.put("bySeverity", bySeverity);
        data.put("byType", byType);
        data.put("bySource", bySource);
        data.put("trend", trend);
        data.put("wazuhMode", wazuh.mode());
        data.put("suricataMode", suricata.mode());
        return ok(data);
    }

    /**
     * 告警详情：原始日志 + 关联取证日志。
     */
    @GetMapping("/{id}")
    public Map<String, Object> detail(@PathVariable("id") String id) {
        List<SecurityAlert> all = mergedAlerts(FETCH_LIMIT);

        SecurityAlert found = null;
        for (SecurityAlert a : all) {
            if (id.equals(a.getId())) {
                found = a;
                break;
            }
        }
        if (found == null) {
            Map<String, Object> body = new HashMap<>();
            body.put("code", 404);
            body.put("message", "未找到告警：" + id);
            return body;
        }

        // 关联取证日志：用源 IP / 规则名关键字去 Wazuh 侧捞一批
        List<RawLogLine> forensic = new ArrayList<>();
        try {
            String query = found.getSrcIp() != null && !found.getSrcIp().isEmpty()
                    ? found.getSrcIp() : found.getRuleName();
            forensic = wazuh.forensicLogs(query, 20);
        } catch (Exception e) {
            logger.warn("取关联取证日志失败：{}", e.getMessage());
        }

        Map<String, Object> data = new HashMap<>();
        data.put("alert", found);
        data.put("forensicLogs", forensic);
        data.put("wazuhMode", wazuh.mode());
        data.put("suricataMode", suricata.mode());
        return ok(data);
    }

    // ==================== 工具 ====================

    private List<SecurityAlert> safeGet(WazuhGateway g, int limit) {
        try {
            List<SecurityAlert> r = g.recentAlerts(limit);
            return r == null ? new ArrayList<>() : r;
        } catch (Exception e) {
            logger.warn("Wazuh 拉取告警异常：{}", e.getMessage());
            return new ArrayList<>();
        }
    }

    private List<SecurityAlert> safeGet(SuricataGateway g, int limit) {
        try {
            List<SecurityAlert> r = g.recentNetworkAlerts(limit);
            return r == null ? new ArrayList<>() : r;
        } catch (Exception e) {
            logger.warn("Suricata 拉取告警异常：{}", e.getMessage());
            return new ArrayList<>();
        }
    }

    private static LocalDateTime parseTime(String s) {
        if (s == null || s.isBlank()) return null;
        try {
            return LocalDateTime.parse(s.trim(), FMT);
        } catch (Exception e) {
            return null;
        }
    }

    private static Map<String, Object> ok(Object data) {
        Map<String, Object> body = new HashMap<>();
        body.put("code", 200);
        body.put("message", "success");
        body.put("data", data);
        return body;
    }
}

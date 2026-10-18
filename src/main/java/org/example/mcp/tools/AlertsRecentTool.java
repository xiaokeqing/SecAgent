package org.example.mcp.tools;

import org.example.mcp.McpTool;
import org.example.mcp.PlatformClient;
import org.example.mcp.PlatformUnavailableException;
import org.example.mcp.ToolSupport;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code xk_alerts_recent} —— 最近窗口的告警聚合。
 *
 * <h3>为什么要本地再按时间窗过滤一次</h3>
 * 上游 {@code /api/public/alerts} 的口径是"按聚合窗口取最近 N 条"，不是"按分钟窗口"。
 * MCP 的 {@code minutes} 语义是<em>时间窗</em>（"最近一小时发生了什么"），
 * 所以这里按 {@code occurredAt} 再筛一遍；时间解析不出来的条目**不猜成现在**，
 * 单独计数进 {@code unparsedTime}，宁可在 summary 里出现一个非零值，也不把旧告警冒充最近窗口。
 *
 * <p>上游 {@code dataSource.degraded=true} 表示 Wazuh 没接上（fail-closed，样本已被上游剥掉）：
 * 这时整条调用返回 {@code available:false}，而不是返回一个"0 条告警"的假平安。
 */
public final class AlertsRecentTool implements McpTool {

    private static final String SOURCE = "platform GET /api/public/alerts（本机回环只读，聚合口径与公开面一致）";

    private final PlatformClient client;

    public AlertsRecentTool(PlatformClient client) {
        this.client = client;
    }

    @Override
    public String name() {
        return "xk_alerts_recent";
    }

    @Override
    public String description() {
        return "最近 N 分钟内的告警聚合：每条给 severity / ruleName / srcIp / attck(+occurredAt/count/title)，"
                + "并附窗口内按严重度计数。参数 minutes（默认 60，1..1440）、limit（默认 20，1..200）。"
                + "上游数据源降级时返回 available:false，不用 0 条冒充。";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("minutes", ToolSupport.prop("integer", "时间窗（分钟），默认 60，范围 1..1440", 60));
        props.put("limit", ToolSupport.prop("integer", "最多返回多少条告警，默认 20，范围 1..200", 20));
        return ToolSupport.schema(props, List.of());
    }

    @Override
    public Map<String, Object> call(Map<String, Object> args) {
        int minutes = ToolSupport.intArg(args, "minutes", 60, 1, 1440);
        int limit = ToolSupport.intArg(args, "limit", 20, 1, 200);

        Map<String, Object> payload;
        try {
            payload = client.get("/api/public/alerts", Map.of());
        } catch (PlatformUnavailableException e) {
            return ToolSupport.unavailable(SOURCE, e.code() + ": " + e.getMessage());
        }

        Map<String, Object> dataSource = ToolSupport.map(payload.get("dataSource"));
        if (Boolean.TRUE.equals(dataSource.get("degraded"))) {
            Map<String, Object> out = ToolSupport.unavailable(SOURCE,
                    "WAZUH_DEGRADED: " + defaultValue(ToolSupport.text(dataSource.get("note")),
                            "上游告警源降级（dataSource.degraded=true）"));
            out.put("dataSource", dataSource);
            return out;
        }

        LocalDateTime from = LocalDateTime.now().minusMinutes(minutes);
        List<Map<String, Object>> hits = new ArrayList<>();
        int unparsedTime = 0;
        int olderThanWindow = 0;
        for (Object raw : ToolSupport.list(payload.get("list"))) {
            Map<String, Object> item = ToolSupport.map(raw);
            LocalDateTime occurredAt = ToolSupport.parseTime(ToolSupport.text(item.get("occurredAt")));
            if (occurredAt == null) {
                unparsedTime++;
                continue;
            }
            if (occurredAt.isBefore(from)) {
                olderThanWindow++;
                continue;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("severity", item.get("severity"));
            m.put("ruleName", item.get("ruleName"));
            m.put("srcIp", item.get("srcIp"));
            m.put("attck", item.get("attck"));
            m.put("occurredAt", item.get("occurredAt"));
            m.put("title", item.get("title"));
            m.put("count", item.get("count"));
            m.put("status", item.get("status"));
            hits.add(m);
        }
        // 新→旧；排序键单独放，输出前摘掉
        List<LocalDateTime> times = new ArrayList<>();
        for (Map<String, Object> hit : hits) {
            times.add(ToolSupport.parseTime(ToolSupport.text(hit.get("occurredAt"))));
        }
        Integer[] order = new Integer[hits.size()];
        for (int i = 0; i < order.length; i++) {
            order[i] = i;
        }
        java.util.Arrays.sort(order, (a, b) -> times.get(b).compareTo(times.get(a)));

        List<Map<String, Object>> alerts = new ArrayList<>();
        Map<String, Object> bySeverity = new LinkedHashMap<>();
        for (Integer idx : order) {
            Map<String, Object> m = hits.get(idx);
            String sev = defaultValue(ToolSupport.text(m.get("severity")), "unknown");
            bySeverity.merge(sev, 1, (a, b) -> ((Number) a).intValue() + ((Number) b).intValue());
            if (alerts.size() < limit) {
                alerts.add(m);
            }
        }

        Map<String, Object> out = ToolSupport.base(SOURCE, true);
        out.put("alerts", alerts);
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("windowMinutes", minutes);
        summary.put("windowFrom", from.format(ToolSupport.PLATFORM_FMT));
        summary.put("inWindow", hits.size());
        summary.put("returned", alerts.size());
        summary.put("truncatedByLimit", Math.max(0, hits.size() - alerts.size()));
        summary.put("olderThanWindow", olderThanWindow);
        summary.put("unparsedTime", unparsedTime);
        summary.put("bySeverity", bySeverity);
        Map<String, Object> upstream = new LinkedHashMap<>();
        upstream.put("windowMinutes", payload.get("windowMinutes"));
        upstream.put("windowSize", payload.get("windowSize"));
        upstream.put("total", payload.get("total"));
        upstream.put("rawTotal", payload.get("rawTotal"));
        upstream.put("aggregated", payload.get("aggregated"));
        summary.put("upstream", upstream);
        out.put("summary", summary);
        out.put("dataSource", dataSource);
        if (unparsedTime > 0 || olderThanWindow > 0) {
            out.put("note", "窗口外/时间解析不了的聚合条目已排除，条数见 summary.olderThanWindow 与 summary.unparsedTime"
                    + "（不把旧告警冒充成最近窗口）。");
        } else {
            out.put("note", "窗口内条目即上游返回的全部分组，按 occurredAt 新→旧排列。");
        }
        return out;
    }

    private static String defaultValue(String v, String def) {
        return v == null || v.isBlank() ? def : v;
    }
}

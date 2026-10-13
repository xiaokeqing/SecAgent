package org.example.notify;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 通知审计：把握手次数记下来 —— <b>谁在什么时候想通知、结果如何</b>。
 *
 * <h3>为什么"通知"也必须有审计（而不是只打日志）</h3>
 * 通知是处置链路的最后一环："系统发现了高危事件"与"人真的被告知了"是两件事。
 * 真实会发生的失败形态是：webhook 地址配错 / 对端限流 / 手机端网络断 ——
 * 这些情况下系统内部一切正常，只是<b>没有人的手机响过</b>。
 * 事后复盘时"有没有通知出去"必须是可查的，而不是靠翻日志猜。
 *
 * <h3>为什么用 JSONL 追加写而不是 JSON 数组（和处置审计不一样）</h3>
 * 处置审计是"整份替换 + 原子落盘"（记录条数在几百条量级，可取快照）。
 * 通知发生在告警风暴里，写入频率高得多，而且是<b>只追加、不回改</b>的流水 ——
 * 用 JSONL 单行追加：一次写一行，不需要整份快照，也不会因为一次写失败丢历史。
 * 代价是文件会一直长：由运维侧按需切割（见 RUNBOOK §19）。
 *
 * <p>写盘失败<b>如实记 error 日志但绝不影响通知本身</b>：审计失败不该让"手机收到告警"
 * 这件事失败 —— 那属于把可用性换成整洁性。但内存里仍然留一份，供接口查询与单测断言。
 */
@Service
public class NotificationAudit {

    private static final Logger logger = LoggerFactory.getLogger(NotificationAudit.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** 结果口径 */
    public static final String OUTCOME_SENT = "SENT";
    public static final String OUTCOME_SUPPRESSED = "SUPPRESSED";
    public static final String OUTCOME_MERGED = "MERGED";
    public static final String OUTCOME_FAILED = "FAILED";
    public static final String OUTCOME_NOT_CONFIGURED = "NOT_CONFIGURED";

    /** 内存里保留的最近条数（接口查询 / 单测用；不是"全部历史"） */
    private static final int MEMORY_KEEP = 200;

    /**
     * 审计文件路径。
     *
     * <p>刻意<b>带默认值</b>而不是裸 {@code @Value}：本类在没有 Spring 的场景
     * （单测、裁剪构建）里也会被直接 new 出来，字段为 null 时 {@code Path.of(null)}
     * 会抛异常 —— 那样"审计写盘失败"就会变成每条通知一次 ERROR 日志，
     * 把真正的信号淹掉。Spring 环境下这个默认值会被 {@code app.notify.audit-file} 覆盖。
     */
    @Value("${app.notify.audit-file:data/notify-audit.jsonl}")
    private String auditFile = "data/notify-audit.jsonl";

    private final ObjectMapper mapper = new ObjectMapper();
    private final List<Map<String, Object>> recent = new CopyOnWriteArrayList<>();

    /**
     * 记一条。
     *
     * @param event   触发事件
     * @param outcome {@link #OUTCOME_SENT} 等
     * @param reason  人读的原因（"冷却期内" / "夜间静默压制" / "未配置" / 失败详情）
     * @param attempts 实际尝试发送次数（未发送的填 0）
     */
    public void record(NotifyEvent event, String outcome, String reason, int attempts) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("time", LocalDateTime.now().format(FMT));
        row.put("eventType", event == null || event.type() == null ? "?" : event.type().name());
        row.put("severity", event == null || event.severity() == null ? "?" : event.severity().name());
        row.put("actor", event == null ? "unknown" : event.actor());
        row.put("dedupKey", event == null ? "?" : event.dedupKey());
        row.put("targetIpMasked", maskIp(event == null ? null : event.targetIp()));
        row.put("title", event == null ? "" : event.title());
        row.put("outcome", outcome);
        row.put("reason", reason == null ? "" : reason);
        row.put("attempts", attempts);
        append(row);
        if (!OUTCOME_SENT.equals(outcome)) {
            // 非成功路径都单独打一行：手机上"没收到"的时候，日志里能直接看到为什么
            logger.info("通知审计 outcome={} reason={} event={}", outcome, reason, event);
        }
    }

    /**
     * IP 只留网段 —— 审计文件会长期驻留（甚至可能被人打包带走排障），
     * 里面没必要放完整攻击者 IP。要追完整 IP 的话，处置审计里有。
     */
    static String maskIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return "";
        }
        String s = ip.trim();
        if (s.contains(":")) {
            int i = s.indexOf(':');
            return s.substring(0, Math.min(s.length(), i + 1)) + "x";
        }
        String[] parts = s.split("\\.");
        if (parts.length == 4) {
            return parts[0] + "." + parts[1] + "." + parts[2] + ".x";
        }
        return "x";
    }

    private void append(Map<String, Object> row) {
        recent.add(row);
        while (recent.size() > MEMORY_KEEP) {
            recent.remove(0);
        }
        try {
            Path p = Path.of(auditFile);
            if (p.getParent() != null) {
                Files.createDirectories(p.getParent());
            }
            String line = mapper.writeValueAsString(row) + System.lineSeparator();
            Files.write(p, line.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Exception e) {
            // 如实记，但绝不让审计失败影响通知本身
            logger.error("通知审计写盘失败（记录仍在内存中，通知不受影响）: {}", e.getMessage());
        }
    }

    /** 最近若干条（新的在前），供接口/排障查看 */
    public List<Map<String, Object>> recent(int limit) {
        List<Map<String, Object>> copy = new ArrayList<>(recent);
        Collections.reverse(copy);
        return copy.size() <= limit ? copy : new ArrayList<>(copy.subList(0, Math.max(0, limit)));
    }

    /** 按结果计数（"到底发出去几条"这种问题的直接答案） */
    public Map<String, Integer> countsByOutcome() {
        Map<String, Integer> out = new LinkedHashMap<>();
        for (Map<String, Object> r : recent) {
            out.merge(String.valueOf(r.get("outcome")), 1, Integer::sum);
        }
        return out;
    }

    /** 审计文件路径（启动自检与文档用） */
    public String auditFilePath() {
        return auditFile;
    }
}

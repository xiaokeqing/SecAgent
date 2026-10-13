package org.example.publicapi;

import org.example.integration.WazuhGateway;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 攻击故事线测试的夹具：<b>形状完全按真实网关输出</b>（见 {@code WazuhService.parseStorySources}）。
 *
 * <h3>为什么夹具里刻意放"脏东西"</h3>
 * 这条端点的验收关键不是"能画出图"，而是"<b>不该出的一个字都不出</b>"。
 * 所以夹具里故意带上：完整口令（两种形态：{@code 口令=xxx} 与 {@code [user/pass]}）、
 * 内部资产名（{@code web-01}）、内网地址（{@code 172.19.0.1}）、
 * 超长描述、以及"我方 IP"与"内网来源"这两类必须被排除的候选。
 * 测试对整段响应体做正则扫描 —— 少了这些哨兵，扫描就成了空转。
 */
final class AttackStoryFixtures {

    static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** 诱饵端口 + 告警（剧本最完整的一个） */
    static final String IP_DECOY = "77.90.185.30";
    /** 告警 + 蜜罐登录 */
    static final String IP_HONEYPOT = "103.149.197.34";
    /** 只有告警 */
    static final String IP_ALERTS_ONLY = "58.19.99.193";
    /** 内网来源：必须被排除（否则会显示成"内网/未知 打了我们 4 万次"） */
    static final String IP_INTERNAL = "10.0.0.10";
    /** 我方服务器：必须被排除（配置 app.geoip.self-ips） */
    static final String IP_SELF = "47.96.106.187";
    /** 只在处置审计里有记录的来源（indexer 三段都是 0） */
    static final String IP_AUDIT_ONLY = "198.51.100.7";
    /** 完全不在候选池里的公网地址（/story 应 404） */
    static final String IP_OUTSIDE_POOL = "203.0.113.99";

    /** 完整口令哨兵（任何形态都不许出现在响应里） */
    static final String PASSWORD = "Abcd@123";
    /** 内部资产名哨兵（由 PublicAssetFilter 在 ok(...) 出海前替换） */
    static final String ASSET_NAME = "web-01";
    /** 内部/隧道地址哨兵 */
    static final String INTERNAL_ADDR = "172.19.0.1";
    /** 原始日志哨兵（full_log / data.message 这一类字段根本不该被取回） */
    static final String RAW_LOG_SENTINEL = "RAW-LOG-SENTINEL";
    /** 内部规则正则原文哨兵（rule.regex 这类字段不该被取回） */
    static final String RULE_REGEX_SENTINEL = "^smbd$-RULE-REGEX-SENTINEL";

    private AttackStoryFixtures() {
    }

    // ==================== indexer 侧（网关替身） ====================

    /**
     * 候选来源聚合（与 {@code WazuhService.parseStorySources} 同形状）。
     *
     * @param honeypotWired false = 索引里根本没有 Cowrie 登录规则（模拟"这一段未接入"）
     */
    static Map<String, Object> storySources(boolean honeypotWired) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("available", true);
        out.put("reason", "OK");
        out.put("note", "按来源聚合完成");
        out.put("windowHours", 24);
        out.put("indexerTotal", 112693L);
        out.put("withSourceIp", 106976L);
        out.put("decoyTotal", 54L);
        out.put("honeypotLoginTotal", honeypotWired ? 21L : 0L);
        out.put("sourceCount", 5);
        Map<String, Object> wiring = new LinkedHashMap<>();
        wiring.put("alerts", "OK");
        wiring.put("decoyPorts", "OK");
        wiring.put("honeypotLogins", honeypotWired ? "OK" : "NOT_WIRED");
        out.put("stageWiring", wiring);

        List<Map<String, Object>> sources = new ArrayList<>();
        sources.add(source(IP_DECOY, 21, 54, 0, 0, "2026-10-14 00:10:00", "2026-10-14 01:00:00", 12));
        sources.add(source(IP_HONEYPOT, 14, 0, 21, 64, "2026-10-13 23:00:00", "2026-10-14 00:50:00", 10));
        sources.add(source(IP_ALERTS_ONLY, 1141, 0, 0, 0, "2026-10-13 02:00:00", "2026-10-14 00:59:00", 3));
        sources.add(source(IP_INTERNAL, 43297, 0, 0, 0, "2026-10-13 01:00:00", "2026-10-14 01:00:00", 7));
        sources.add(source(IP_SELF, 155, 36, 174, 174, "2026-10-13 01:00:00", "2026-10-14 01:00:00", 12));
        out.put("sources", sources);
        return out;
    }

    private static Map<String, Object> source(String ip, long alerts, long decoy, long logins,
                                              long honeypotEvents, String first, String last, int maxLevel) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("srcIp", ip);
        m.put("alerts", alerts);
        m.put("decoyPorts", decoy);
        m.put("honeypotLogins", logins);
        m.put("honeypotEvents", honeypotEvents);
        m.put("total", alerts + decoy + logins);
        m.put("firstSeen", first);
        m.put("lastSeen", last);
        m.put("maxLevel", maxLevel);
        return m;
    }

    /** 单来源明细（与 {@code WazuhService.storyEvents} 同形状；{@code cap} 与真实实现一样会截断） */
    static Map<String, Object> storyEvents(String srcIp, int cap) {
        int limit = Math.max(1, cap);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("available", true);
        out.put("reason", "OK");
        out.put("note", "每段各一条查询、各自限量");
        Map<String, Object> stages = new LinkedHashMap<>();
        if (IP_DECOY.equals(srcIp)) {
            stages.put("alerts", stage(21, limit, List.of(
                    event("2026-10-14 00:10:00", "扫描探测",
                            "检测到端口扫描（suricata）来自 " + IP_DECOY, 6, null),
                    event("2026-10-14 00:12:00", "扫描探测",
                            "内部资产 " + ASSET_NAME + " 命中扫描规则；来源=" + IP_DECOY, 3, null),
                    event("2026-10-14 01:00:00", "其他",
                            "来自 " + IP_DECOY + " 的其它检测命中", 6, null))));
            stages.put("decoyPorts", stage(54, limit, List.of(
                    event("2026-10-14 00:15:00", "诱饵端口 SMB（445/tcp）",
                            "蜜罐(Dionaea): SMB 连接/认证尝试 来源=" + IP_DECOY + ":1234", 6, "ACCEPT"),
                    event("2026-10-14 00:16:00", "诱饵端口 MySQL（3306/tcp）",
                            "蜜罐(Dionaea): MySQL 连接尝试 来源=" + IP_DECOY + ":5678；内网目的 " + INTERNAL_ADDR
                                    + " 不该出现", 6, "ACCEPT"))));
            stages.put("honeypotLogins", stage(0, limit, List.of()));
        } else if (IP_HONEYPOT.equals(srcIp)) {
            stages.put("alerts", stage(14, limit, List.of(
                    event("2026-10-13 23:05:00", "扫描探测", "来自 " + IP_HONEYPOT + " 的探测", 6, null))));
            stages.put("decoyPorts", stage(0, limit, List.of()));
            stages.put("honeypotLogins", stage(21, limit, List.of(
                    event("2026-10-13 23:30:00", "蜜罐 SSH 登录成功",
                            "蜜罐: 攻击者\"登录成功\" 用户=root 口令=" + PASSWORD
                                    + " 来源=" + IP_HONEYPOT, 10, "SUCCESS"),
                    event("2026-10-14 00:40:00", "蜜罐 SSH 登录失败",
                            "蜜罐: 攻击者\"登录失败\" 用户=admin 口令=" + PASSWORD
                                    + " 来源=" + IP_HONEYPOT, 5, "FAILED"))));
        } else if (IP_AUDIT_ONLY.equals(srcIp)) {
            stages.put("alerts", stage(0, limit, List.of()));
            stages.put("decoyPorts", stage(0, limit, List.of()));
            stages.put("honeypotLogins", stage(0, limit, List.of()));
        } else {
            stages.put("alerts", stage(1141, limit, List.of(
                    event("2026-10-14 00:59:00", "扫描探测",
                            "大量 404 探测来自 " + IP_ALERTS_ONLY + " " + longSummary(), 3, null))));
            stages.put("decoyPorts", stage(0, limit, List.of()));
            stages.put("honeypotLogins", stage(0, limit, List.of()));
        }
        out.put("stages", stages);
        return out;
    }

    private static Map<String, Object> stage(long total, int cap, List<Map<String, Object>> events) {
        List<Map<String, Object>> cut = events.size() > cap ? new ArrayList<>(events.subList(0, cap)) : events;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("total", total);
        m.put("returned", (long) cut.size());
        m.put("truncated", total > cut.size());
        m.put("events", cut);
        return m;
    }

    /** 超过 {@code AttackStoryService.SUMMARY_MAX_CHARS} 的描述，用来验证"只给摘要"这条口径 */
    static String longSummary() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 40; i++) {
            sb.append("重复的长规则描述段落").append(i).append('；');
        }
        return sb.toString();
    }

    private static Map<String, Object> event(String ts, String kind, String summary, int level, String outcome) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ts", ts);
        m.put("kind", kind);
        m.put("summary", summary);
        m.put("level", level);
        m.put("outcome", outcome);
        // 【脏字段】真实索引文档里就有这些东西：明文口令、原始日志、内部规则正则、内网目的地址。
        // 公开层必须【按白名单挑字段】，而不是"把整条记录透出去再删几个键" ——
        // 这两种写法的差别在正常数据上看不出来，只在这些字段出现时才分得出对错。
        m.put("password", PASSWORD);
        m.put("rawLog", RAW_LOG_SENTINEL);
        m.put("ruleRegex", RULE_REGEX_SENTINEL);
        m.put("dstIp", "10.0.10.21");
        m.put("dstAsset", ASSET_NAME);
        return m;
    }

    /**
     * 网关替身：只回答故事线要用的四个方法（与项目既有测试同一套动态代理做法）。
     *
     * @param mode REAL / MOCK —— MOCK 用来验证 fail-closed（绝不返回内置样本）
     */
    static WazuhGateway gateway(String mode, boolean honeypotWired) {
        return (WazuhGateway) Proxy.newProxyInstance(
                WazuhGateway.class.getClassLoader(),
                new Class<?>[]{WazuhGateway.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "mode" -> mode;
                    case "isAvailable" -> "REAL".equalsIgnoreCase(mode);
                    case "storySources" -> "REAL".equalsIgnoreCase(mode)
                            ? storySources(honeypotWired)
                            : new LinkedHashMap<>(Map.of("available", false,
                                    "reason", "DATA_SOURCE_UNAVAILABLE", "note", "数据源不是 REAL"));
                    case "storyEvents" -> "REAL".equalsIgnoreCase(mode)
                            ? storyEvents(String.valueOf(args[0]), (Integer) args[2])
                            : new LinkedHashMap<>(Map.of("available", false,
                                    "reason", "DATA_SOURCE_UNAVAILABLE", "note", "数据源不是 REAL"));
                    case "recentAlerts" -> List.of();
                    case "toString" -> "StoryStubGateway(" + mode + ")";
                    default -> null;
                });
    }

    // ==================== 应用侧处置留痕 ====================

    /**
     * 写一份处置留痕：{@code 现在-30 分钟}有一条封禁 {@link #IP_DECOY} 的记录，
     * 另有一条解封、一条被护栏拦截、一条只属于 {@link #IP_AUDIT_ONLY}、
     * 以及一条必须被丢弃的评测记录。
     *
     * <p>时间用"相对现在"是因为故事线窗口是滚动的：写死时间会让这条测试在几小时后自己变红。
     */
    static void writeAudit(Path dir, LocalDateTime now) throws Exception {
        String t1 = now.minusMinutes(30).format(FMT);
        String t2 = now.minusMinutes(20).format(FMT);
        String t3 = now.minusMinutes(10).format(FMT);
        String t4 = now.minusMinutes(5).format(FMT);
        String json = "[" + record("AUD-1", t1, "admin", "block-ip", IP_DECOY, "HIGH", "REAL", true) + ","
                + record("AUD-2", t2, "scheduler", "unblock-ip", IP_DECOY, "LOW", "REAL", true) + ","
                + record("AUD-3", t3, "admin", "block-ip", IP_INTERNAL, "LOW", "BLOCKED", false) + ","
                + record("AUD-4", t4, "admin", "block-ip", IP_AUDIT_ONLY, "HIGH", "REAL", true) + ","
                + record("AUD-EVAL", t4, "eval-runner", "block-ip", IP_OUTSIDE_POOL, "HIGH", "REAL", true)
                + "]";
        Files.write(dir.resolve("response-audit.json"), json.getBytes(StandardCharsets.UTF_8));
        Files.write(dir.resolve("blocked-ips.json"),
                ("[{\"id\":\"BLK-1\",\"ip\":\"" + IP_DECOY + "\",\"durationMinutes\":60,\"source\":\"手动\","
                        + "\"actor\":\"admin\",\"auditId\":\"AUD-1\",\"createdAt\":\"" + t1 + "\","
                        + "\"expiresAt\":\"" + t1 + "\",\"unblocked\":false}]")
                        .getBytes(StandardCharsets.UTF_8));
    }

    /** 只写一份"可读但空"的留痕（给黄金串比对用：不能有任何相对时间，否则冻结串会天天变） */
    static void writeEmptyAudit(Path dir) throws Exception {
        Files.write(dir.resolve("response-audit.json"), "[]".getBytes(StandardCharsets.UTF_8));
        Files.write(dir.resolve("blocked-ips.json"), "[]".getBytes(StandardCharsets.UTF_8));
    }

    private static String record(String id, String time, String actor, String action, String target,
                                 String risk, String mode, boolean success) {
        return "{\"id\":\"" + id + "\",\"time\":\"" + time + "\",\"actor\":\"" + actor
                + "\",\"action\":\"" + action + "\",\"target\":\"" + target
                + "\",\"reason\":\"夹具处置原因\",\"riskLevel\":\"" + risk
                + "\",\"mode\":\"" + mode + "\",\"success\":" + success + "}";
    }
}

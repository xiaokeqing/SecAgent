package org.example.publicapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 处置审计的<b>只读</b>读取器（公网端点用）。
 *
 * <h3>为什么直接读文件，而不是注入处置服务</h3>
 * 公网匿名端点必须与写能力彻底隔离（见 {@code PublicApiIsolationTest}）。
 * 处置侧的记录存储属于响应链路的 Bean，一旦被匿名端点注入，
 * 就等于把"能封 IP 的对象"挂到了公开接口的调用栈上。
 * <p>
 * 审计留痕本身就是两个 JSON 文件（{@code blocked-ips.json} / {@code response-audit.json}），
 * 这里只做<b>读取 + 脱敏 + 隔离</b>，不写、不改、不删：
 * <ul>
 *   <li>IP 一律走 {@link PublicIpPolicy} 口径（{@code app.public.mask-ips}：默认显示观测到的
 *       真实地址，内网/保留写「内网/未知」；开关为 true 时与改造前的掩码口径逐字节一致）；</li>
 *   <li>只输出白名单字段（操作者、动作、结果、时间、审计 ID），
 *       不返回 detail 里的原始文本（可能含内网信息）；</li>
 *   <li>reason 文本里的口令一律隐去（{@link CredentialStructure#hidePasswords}，与开关无关）；
 *       <b>评测流量（actor 以 {@code eval-} 开头）一律丢弃</b> —— 公网端点是"真实使用"的展示面，
 *       评测记录混进来会让封禁/处置计数凭空上涨（而实际什么都没封）。</li>
 * </ul>
 */
@Component
public class PublicAuditReader {

    private static final Logger logger = LoggerFactory.getLogger(PublicAuditReader.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 留痕里的时间形状（本地时间，无时区）：{@code 2026-10-11 14:24:01} */
    private static final java.time.format.DateTimeFormatter FMT =
            java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** 没有 Spring 注入时的保守兜底（掩码态）：与改造前行为一致 */
    private static final PublicIpPolicy FAIL_CLOSED_POLICY = PublicIpPolicy.masking();

    /**
     * IP 口径（唯一来源）。{@code required=false}：单测里 {@code new PublicAuditReader()}
     * 没有容器，此时按掩码兜底 —— 也正因如此，"掩码回归"测试不需要任何改动。
     */
    @Autowired(required = false)
    private PublicIpPolicy ipPolicy;

    @Value("${app.public-api.data-dir:/app/data}")
    private String dataDir;

    private PublicIpPolicy policy() {
        PublicIpPolicy p = ipPolicy;
        return p != null ? p : FAIL_CLOSED_POLICY;
    }

    /** 封禁记录（最近若干条，已按口径处理；评测记录已丢弃） */
    public List<Map<String, Object>> blocks(int limit) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (JsonNode n : readArray("blocked-ips.json")) {
            if (isEvalRecord(n)) {
                continue;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", text(n, "id"));
            m.put("ip", policy().display(text(n, "ip")));
            m.put("durationMinutes", n.path("durationMinutes").asInt(0));
            m.put("source", text(n, "source"));
            m.put("actor", text(n, "actor"));
            m.put("auditId", text(n, "auditId"));
            m.put("createdAt", text(n, "createdAt"));
            m.put("expiresAt", text(n, "expiresAt"));
            m.put("unblocked", n.path("unblocked").asBoolean(false));
            m.put("unblockedAt", text(n, "unblockedAt"));
            m.put("unblockMode", text(n, "unblockMode"));
            out.add(m);
        }
        // 新的在前
        out.sort((a, b) -> String.valueOf(b.get("createdAt")).compareTo(String.valueOf(a.get("createdAt"))));
        return out.size() > limit ? out.subList(0, Math.max(1, limit)) : out;
    }

    /** 处置审计流水（最近若干条，已按口径处理；评测记录已丢弃） */
    public List<Map<String, Object>> actions(int limit) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (JsonNode n : readArray("response-audit.json")) {
            if (isEvalRecord(n)) {
                continue;
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", text(n, "id"));
            m.put("time", text(n, "time"));
            m.put("actor", text(n, "actor"));
            m.put("action", text(n, "action"));
            m.put("target", policy().display(text(n, "target")));
            m.put("reason", CredentialStructure.hidePasswords(text(n, "reason")));
            m.put("riskLevel", text(n, "riskLevel"));
            m.put("mode", text(n, "mode"));
            m.put("success", n.path("success").asBoolean(false));
            // 刻意不返回 detail：那里是原始文本，可能带内网信息
            out.add(m);
        }
        out.sort((a, b) -> String.valueOf(b.get("time")).compareTo(String.valueOf(a.get("time"))));
        return out.size() > limit ? out.subList(0, Math.max(1, limit)) : out;
    }

    /**
     * <b>攻击故事线</b>用的处置事件流：窗口内的处置审计记录，<b>按原始目标 IP 分组</b>。
     *
     * <h3>为什么 key 是原始 IP，而值里一个 IP 都没有</h3>
     * 故事线要把"同一个来源"在四个阶段的记录关联起来，所以服务端必须拿原始地址做匹配
     * （掩码态下 {@code 45.205.***.***} 匹配不到任何东西）。
     * 于是这里把原始地址放在 <b>Map 的 key</b> 上，值里只放已脱敏的结构化字段 ——
     * 只要调用方不把这个 Map 直接塞进响应，原始地址就不会出海。
     * <b>禁止</b>把本方法的返回值直接作为响应体的一部分输出。
     *
     * <p>与 {@link #actions(int)} 同一套过滤：评测记录丢弃、口令隐去、字段白名单。
     * 时间解析不出来的记录<b>不进时间轴</b>（放不上去），数量由 {@link #status()} 如实披露。
     *
     * @param since 窗口起点（本地时间；记录里的 {@code time} 也是本地时间）
     * @return 原始目标 IP → 该 IP 的处置事件（{@code ts/actor/action/outcome/riskLevel/mode/success}）
     */
    public Map<String, List<Map<String, Object>>> eventsByTargetSince(java.time.LocalDateTime since) {
        Map<String, List<Map<String, Object>>> out = new LinkedHashMap<>();
        for (JsonNode n : readArray("response-audit.json")) {
            if (isEvalRecord(n)) {
                continue;
            }
            String target = text(n, "target");
            String time = text(n, "time");
            if (target == null || target.isBlank() || time == null || time.isBlank()) {
                continue;
            }
            java.time.LocalDateTime ts = parseLocal(time);
            if (ts == null || since == null || ts.isBefore(since)) {
                continue;
            }
            boolean success = n.path("success").asBoolean(false);
            String mode = text(n, "mode");
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", text(n, "id"));
            m.put("ts", ts.format(FMT));
            m.put("actor", text(n, "actor"));
            m.put("action", text(n, "action"));
            m.put("outcome", outcomeOf(success, mode));
            m.put("riskLevel", text(n, "riskLevel"));
            m.put("mode", mode);
            m.put("success", success);
            // 刻意不输出 detail（原始文本，可能带内网信息）与 reason 正文（/audit 已有，故事线只给结论）
            out.computeIfAbsent(target.trim(), k -> new ArrayList<>()).add(m);
        }
        // 同一来源内按时间升序（时间轴绘制顺序；相等时按 id 保证确定性）
        for (List<Map<String, Object>> list : out.values()) {
            list.sort((a, b) -> {
                int c = String.valueOf(a.get("ts")).compareTo(String.valueOf(b.get("ts")));
                return c != 0 ? c : String.valueOf(a.get("id")).compareTo(String.valueOf(b.get("id")));
            });
        }
        return out;
    }

    /**
     * 审计留痕的<b>可读性状态</b>（把"文件读不到 / 没接入"与"窗口内没有处置"彻底分开）。
     *
     * <p>故事线的审计阶段最容易被误读：一段灰色的时间轴既可能是"这段时间没有处置"，
     * 也可能是"留痕文件根本没读上"。所以状态必须能机读回答：
     * 文件在不在、读不读得出来、里头有多少条、多少条因为时间缺失进不了时间轴。
     */
    public Map<String, Object> status() {
        List<JsonNode> actions = readArray("response-audit.json");
        List<JsonNode> blocks = readArray("blocked-ips.json");
        int evalFiltered = 0;
        int actionsWithoutTime = 0;
        int realActions = 0;
        for (JsonNode n : actions) {
            if (isEvalRecord(n)) {
                evalFiltered++;
                continue;
            }
            realActions++;
            String time = text(n, "time");
            if (time == null || time.isBlank() || parseLocal(time) == null) {
                actionsWithoutTime++;
            }
        }
        int realBlocks = 0;
        for (JsonNode n : blocks) {
            if (isEvalRecord(n)) {
                evalFiltered++;
            } else {
                realBlocks++;
            }
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("actionsReadable", Files.isReadable(Path.of(dataDir, "response-audit.json")));
        m.put("blocksReadable", Files.isReadable(Path.of(dataDir, "blocked-ips.json")));
        m.put("actionRecords", realActions);
        m.put("blockRecords", realBlocks);
        m.put("evalFiltered", evalFiltered);
        m.put("actionsWithoutTime", actionsWithoutTime);
        return m;
    }

    /** 处置结果码（只给结论，不给原始 detail） */
    private static String outcomeOf(boolean success, String mode) {
        if ("BLOCKED".equalsIgnoreCase(String.valueOf(mode))) {
            return "BLOCKED_BY_GUARD";
        }
        return success ? "SUCCESS" : "FAILED";
    }

    /** 解析留痕里的本地时间（{@code yyyy-MM-dd HH:mm:ss}）；解析不出来返回 {@code null}（不猜） */
    private static java.time.LocalDateTime parseLocal(String s) {
        try {
            return java.time.LocalDateTime.parse(s.trim(), FMT);
        } catch (Exception e) {
            return null;
        }
    }

    /** 统计：总封禁数 / 已解封数 / 被护栏拦截数 */
    public Map<String, Object> summary() {
        int total = 0;
        int active = 0;
        for (Map<String, Object> b : blocks(Integer.MAX_VALUE)) {
            total++;
            if (!Boolean.TRUE.equals(b.get("unblocked"))) {
                active++;
            }
        }
        int blockedByGuard = 0;
        int executed = 0;
        for (Map<String, Object> a : actions(Integer.MAX_VALUE)) {
            if ("BLOCKED".equalsIgnoreCase(String.valueOf(a.get("mode")))) {
                blockedByGuard++;
            }
            if (Boolean.TRUE.equals(a.get("success"))) {
                executed++;
            }
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("blockTotal", total);
        m.put("blockActive", active);
        m.put("blockedByGuard", blockedByGuard);
        m.put("executedActions", executed);
        m.put("note", policy().masked()
                ? "数据来自处置审计留痕文件；IP 已掩码，不含原始 detail"
                : "数据来自处置审计留痕文件；IP 显示观测到的真实地址（内网/保留写作「内网/未知」），不含原始 detail");
        return m;
    }

    // ==================== 工具 ====================

    /**
     * 是否为评测流量记录。
     *
     * <p>判据取两个显式标记，任一命中即隔离：
     * {@code evalRunId}（评测脚本的 runId）非空，或 {@code actor} 以 {@code eval-} 开头。
     * 这里用"白名单式的正向判据"而不是靠人记得别写评测数据 ——
     * 真实处置审计里正常不会有这两个标记，所以过滤不会误伤。
     */
    static boolean isEvalRecord(JsonNode n) {
        JsonNode runId = n.path("evalRunId");
        if (!runId.isMissingNode() && !runId.isNull() && !runId.asText("").isBlank()) {
            return true;
        }
        String actor = n.path("actor").asText("");
        return actor.startsWith(org.example.security.EvalIdentity.ACTOR_PREFIX);
    }

    private List<JsonNode> readArray(String fileName) {
        List<JsonNode> out = new ArrayList<>();
        Path p = Path.of(dataDir, fileName);
        if (!Files.isReadable(p)) {
            // fail-closed：读不到就说读不到，不返回编造的空数据
            logger.warn("审计留痕文件不可读：{}", p);
            return out;
        }
        try {
            String raw = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
            if (raw.isBlank()) {
                return out;
            }
            JsonNode root = MAPPER.readTree(raw);
            JsonNode arr = root.isArray() ? root : root.path("records");
            if (arr.isArray()) {
                arr.forEach(out::add);
            }
        } catch (Exception e) {
            logger.warn("解析审计留痕失败（{}）：{}", p, e.getMessage());
        }
        return out;
    }

    private static String text(JsonNode n, String field) {
        JsonNode v = n.path(field);
        return (v.isMissingNode() || v.isNull()) ? null : v.asText();
    }
}

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

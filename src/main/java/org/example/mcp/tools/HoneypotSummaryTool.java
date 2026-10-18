package org.example.mcp.tools;

import org.example.mcp.McpTool;
import org.example.mcp.PlatformClient;
import org.example.mcp.PlatformUnavailableException;
import org.example.mcp.ToolSupport;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code xk_honeypot_summary} —— 蜜罐侧观测（连接数/登录尝试/口令结构）。
 *
 * <h3>口令为什么只给结构</h3>
 * 蜜罐里最危险的字段时间就是"攻击者试了什么密码"：原文一旦进 MCP 输出，
 * 它会顺着客户端日志、聊天记录一路扩散。这里的口径是：
 * 只给 {@code 用户名 / 6 位·纯数字·弱口令} 这种结构串（长度、字符类、是否弱口令），
 * 上游万一透出原文，{@link ToolSupport#credentialList} 也会把它替换成 {@code [口令已隐藏]}。
 *
 * <p>上游 {@code available:false}（蜜罐日志没接上/读不到）时整条调用报不可用，
 * {@code connections/logins} 不写 0 —— "没接上"和"没人打"是两件事。
 */
public final class HoneypotSummaryTool implements McpTool {

    private static final String SOURCE = "platform GET /api/public/honeypot（本机回环只读，蜜罐会话聚合）";

    private final PlatformClient client;

    public HoneypotSummaryTool(PlatformClient client) {
        this.client = client;
    }

    @Override
    public String name() {
        return "xk_honeypot_summary";
    }

    @Override
    public String description() {
        return "蜜罐观测摘要：connections（连接数）/ logins（登录尝试）/ loginFails / total / "
                + "credStructure（口令结构，绝不含明文）/ topSources / topClients / timeline。"
                + "上游不可用时 available:false，不写 0；口令一律只给结构。";
    }

    @Override
    public Map<String, Object> inputSchema() {
        return ToolSupport.schema(new LinkedHashMap<>(), List.of());
    }

    @Override
    public Map<String, Object> call(Map<String, Object> args) {
        Map<String, Object> payload;
        try {
            payload = client.get("/api/public/honeypot", Map.of());
        } catch (PlatformUnavailableException e) {
            return ToolSupport.unavailable(SOURCE, e.code() + ": " + e.getMessage());
        }

        if (Boolean.FALSE.equals(payload.get("available"))) {
            String note = ToolSupport.text(payload.get("note"));
            Map<String, Object> out = ToolSupport.unavailable(SOURCE,
                    "HONEYPOT_DATA_UNAVAILABLE: " + (note == null || note.isBlank() ? "上游 available=false" : note));
            out.put("upstream", payload);
            return out;
        }

        Map<String, Object> out = ToolSupport.base(SOURCE, true);
        out.put("total", payload.get("total"));
        out.put("connections", payload.get("connections"));
        out.put("logins", payload.get("logins"));
        out.put("loginFails", payload.get("loginFails"));
        out.put("sampled", payload.get("sampled"));
        out.put("commandsAvailable", payload.get("commandsAvailable"));
        out.put("credStructure", ToolSupport.credentialList(payload.get("topCredentials")));
        out.put("topSources", ToolSupport.deepRedact(payload.get("topSources")));
        out.put("topClients", ToolSupport.deepRedact(payload.get("topClients")));
        out.put("timeline", payload.get("timeline"));
        out.put("note", "口令只给结构：长度 / 字符类 / 是否弱口令，不含明文；"
                + "取不到某类数据时对应字段为 null，不补 0。"
                + (payload.get("note") == null ? "" : "上游说明：" + payload.get("note")));
        return out;
    }
}

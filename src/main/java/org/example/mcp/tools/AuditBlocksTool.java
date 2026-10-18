package org.example.mcp.tools;

import org.example.mcp.McpTool;
import org.example.mcp.PlatformClient;
import org.example.mcp.PlatformUnavailableException;
import org.example.mcp.ToolSupport;
import org.example.publicapi.PublicIpMask;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code xk_audit_blocks} —— 封禁/处置留痕（只读）。
 *
 * <h3>打码口径</h3>
 * 默认把 IP 掩成网段级（{@code 45.205.***.***}），只有 {@code rawIp:true} 才给原值。
 * 掩码直接用平台的 {@link PublicIpMask}（同一个工具类，不另写一套正则）。
 *
 * <p><b>一处必须说清的边界</b>：{@code rawIp:true} 能给出的"原值"就是上游
 * {@code /api/public/audit} 此刻返回的值。平台若开了 {@code app.public.mask-ips=true}，
 * 上游本身就是掩码态 —— MCP 是只读客户端，既没有留痕文件路径、也不去直读文件，
 * 于是一律还不了原。这种情况不会"猜一个 IP 出来"，而是在 {@code note} 里写明。
 * 反过来说：默认掩码是**MCP 这层自己加的**，所以即使平台按真实态输出，MCP 默认也不外泄完整 IP。
 *
 * <p>二次掩码是安全的：{@code mask} 对已经掩过的 {@code 45.205.***.***} 输出不变
 * （前两段保留、后两段仍是 ***）；对"内部地址/内网未知"这类非 IP 文案则原样保留，不会被踩成 {@code ***}。
 */
public final class AuditBlocksTool implements McpTool {

    private static final String SOURCE = "platform GET /api/public/audit（本机回环只读，读的是处置留痕文件）";

    private final PlatformClient client;

    public AuditBlocksTool(PlatformClient client) {
        this.client = client;
    }

    @Override
    public String name() {
        return "xk_audit_blocks";
    }

    @Override
    public String description() {
        return "封禁/处置留痕：blocks（每条 id/ip/durationMinutes/source/actor/auditId/createdAt/expiresAt/unblocked…）"
                + "与 summary。IP 默认打码成网段级，rawIp:true 才给上游原值。参数 limit 默认 20（1..200）。只读。";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("limit", ToolSupport.prop("integer", "最多返回多少条留痕，默认 20，范围 1..200", 20));
        props.put("rawIp", ToolSupport.prop("boolean", "true = 输出上游原始 IP（默认 false，掩码成 45.205.***.***）", false));
        return ToolSupport.schema(props, List.of());
    }

    @Override
    public Map<String, Object> call(Map<String, Object> args) {
        int limit = ToolSupport.intArg(args, "limit", 20, 1, 200);
        boolean rawIp = ToolSupport.boolArg(args, "rawIp");

        Map<String, Object> payload;
        try {
            payload = client.get("/api/public/audit", Map.of());
        } catch (PlatformUnavailableException e) {
            return ToolSupport.unavailable(SOURCE, e.code() + ": " + e.getMessage());
        }

        List<Map<String, Object>> blocks = new ArrayList<>();
        for (Object raw : ToolSupport.list(payload.get("blocks"))) {
            if (blocks.size() >= limit) {
                break;
            }
            Map<String, Object> b = ToolSupport.map(raw);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ip", rawIp ? ToolSupport.text(b.get("ip")) : maskIp(ToolSupport.text(b.get("ip"))));
            m.put("id", b.get("id"));
            m.put("durationMinutes", b.get("durationMinutes"));
            m.put("source", b.get("source"));
            m.put("actor", b.get("actor"));
            m.put("auditId", b.get("auditId"));
            m.put("createdAt", b.get("createdAt"));
            m.put("expiresAt", b.get("expiresAt"));
            m.put("unblocked", b.get("unblocked"));
            m.put("unblockedAt", b.get("unblockedAt"));
            m.put("unblockMode", b.get("unblockMode"));
            blocks.add(m);
        }

        Map<String, Object> out = ToolSupport.base(SOURCE, true);
        out.put("readOnly", true);
        out.put("ipMode", rawIp ? "raw" : "masked");
        out.put("blocks", blocks);
        Map<String, Object> summary = ToolSupport.map(payload.get("summary"));
        summary.put("returned", blocks.size());
        summary.put("limit", limit);
        summary.put("ipMode", rawIp ? "raw" : "masked");
        out.put("summary", summary);
        out.put("note", rawIp
                ? "rawIp=true：ip 为上游此刻返回的原值。若平台开启 app.public.mask-ips=true，上游已是掩码态，"
                  + "MCP 只读、不直读留痕文件，因此无法还原（不猜一个 IP 出来）。"
                : "ip 已按网段级掩码（45.205.***.***）；要上游原值传 rawIp:true。内网/保留地址显示为「内部地址」。");
        return out;
    }

    /** 只在"确实是个 IP 字面量"时掩码；已经是「内部地址」这类展示文案就原样保留。 */
    static String maskIp(String value) {
        if (value == null) {
            return null;
        }
        String host = PublicIpMask.host(value);
        if (host == null || !PublicIpMask.isIpLiteral(host)) {
            return value;
        }
        return PublicIpMask.mask(value);
    }
}

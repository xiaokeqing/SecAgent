package org.example.mcp.tools;

import org.example.mcp.McpTool;
import org.example.mcp.PlatformClient;
import org.example.mcp.PlatformUnavailableException;
import org.example.mcp.ToolSupport;
import org.example.publicapi.PublicIpMask;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code xk_ip_profile} —— 单个 IP 在本站的画像，字段与 {@code GET /api/public/ip} <b>同源</b>。
 *
 * <p>"同源"是刻意的：IP 口径（窗口 168h、IPv4 才答、内网/保留一律拒答、口令只给结构）
 * 只有平台上那一份实现。MCP 只做三件事：参数前置校验（省一次往返）、透传、把 {@code credStructure}
 * 再过一遍脱敏。这样公开面与 MCP 永远不会对同一个 IP 给出两套说法。
 *
 * <p>上游 200 但 {@code available:false}（索引器没接上）时，MCP 也报 {@code available:false}，
 * 并把 {@code firstSeen/lastSeen/events/byKind/ports} 留成 null + {@code reason} ——
 * "读不到"不写成"0 次"。
 */
public final class IpProfileTool implements McpTool {

    private static final String SOURCE = "platform GET /api/public/ip?q=<ip>（本机回环只读，口径与公开面同源）";

    private final PlatformClient client;

    public IpProfileTool(PlatformClient client) {
        this.client = client;
    }

    @Override
    public String name() {
        return "xk_ip_profile";
    }

    @Override
    public String description() {
        return "输入一个公网 IPv4，返回该 IP 在本站的画像（与 /api/public/ip 同源）："
                + "firstSeen / lastSeen / events / byKind / ports / credStructure（只给结构）/ geo / banned。"
                + "非 IPv4 字面量、内网/保留地址、索引器不可用时返回 available:false + reason。";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("ip", ToolSupport.prop("string", "要查的公网 IPv4 字面量，例如 45.205.1.230"));
        return ToolSupport.schema(props, List.of("ip"));
    }

    @Override
    public Map<String, Object> call(Map<String, Object> args) {
        String ip = ToolSupport.strArg(args, "ip");
        if (ip == null) {
            return ToolSupport.unavailable(SOURCE, "MISSING_IP: 需要参数 ip（公网 IPv4 字面量）");
        }
        String host = PublicIpMask.host(ip);
        if (host == null || !PublicIpMask.isIpv4Literal(host)) {
            return ToolSupport.unavailable(SOURCE,
                    "INVALID_IP: " + ip + " 不是 IPv4 字面量（本工具与公开面同口径，只回答 IPv4）");
        }
        if (PublicIpMask.isInternalAddress(host)) {
            return ToolSupport.unavailable(SOURCE,
                    "NOT_PUBLIC_IP: " + PublicIpMask.mask(host) + " 是内网/保留/链路地址，不作为来源地址画像");
        }

        Map<String, Object> p;
        try {
            p = client.get("/api/public/ip", Map.of("q", host));
        } catch (PlatformUnavailableException e) {
            return ToolSupport.unavailable(SOURCE, e.code() + ": " + e.getMessage());
        }

        boolean upstreamAvailable = !Boolean.FALSE.equals(p.get("available"));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("generatedAt", ToolSupport.generatedAt());
        out.put("source", SOURCE);
        out.put("available", upstreamAvailable);
        if (!upstreamAvailable) {
            String reason = ToolSupport.text(p.get("reason"));
            out.put("reason", reason == null || reason.isBlank() ? "DATA_SOURCE_UNAVAILABLE" : reason);
        }
        out.put("query", p.get("query"));
        out.put("ipVersion", p.get("ipVersion"));
        out.put("window", p.get("window"));
        out.put("windowHours", p.get("windowHours"));
        out.put("firstSeen", p.get("firstSeen"));
        out.put("lastSeen", p.get("lastSeen"));
        out.put("events", p.get("events"));
        out.put("byKind", p.get("byKind"));
        out.put("ports", p.get("ports"));
        // 口令只给结构：这里再判一次形状，不信任上游一定已经脱敏
        out.put("credStructure", ToolSupport.credentialList(p.get("credStructure")));
        out.put("geo", p.get("geo"));
        out.put("banned", p.get("banned"));
        out.put("sources", p.get("sources"));
        out.put("limits", p.get("limits"));
        out.put("notes", p.get("notes"));
        out.put("note", ToolSupport.text(p.get("note")));
        if (p.get("generatedAt") != null) {
            out.put("upstreamGeneratedAt", ToolSupport.text(p.get("generatedAt")));
        }
        return out;
    }
}

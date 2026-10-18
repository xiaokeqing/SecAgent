package org.example.mcp;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 手写的 MCP server 协议层（JSON-RPC 2.0 over stdio）。
 *
 * <h3>为什么手写而不是用 spring-ai / mcp-sdk</h3>
 * 这台机器是离线构建的（Maven {@code -o}）：{@code spring-ai-starter-mcp-server} 的 jar 不在本地仓库
 * （{@code dependency:get} 直接 BUILD FAILURE），而本地仅有的 {@code mcp-core 0.14.0} 与仓库里
 * spring-ai 1.1.0 管理的 0.16 相互冲突。任务允许"没有就退化为手写"，而手写版本的依赖是
 * <b>JDK + Jackson（本来就在 pom 里）</b>，零新增外部包、离线可编译，这是这里唯一正确的取舍。
 *
 * <h3>传输</h3>
 * <b>stdio</b>：一行一个 JSON-RPC 报文（MCP 的标准 stdio 帧法）。同时兼容 {@code Content-Length:} LSP 帧法，
 * 因为有些客户端/调试工具默认用那种写法 —— 两种都收，回包统一用换行分隔。
 *
 * <h3>通道纪律</h3>
 * stdout 只能出现 JSON-RPC 报文。{@link McpServerMain} 把 {@code System.out} 改道到 stderr 之后再跑本类，
 * 所以任何库/日志的意外打印都不会污染协议流（这是手写 stdio server 最容易踩的一个坑）。
 */
public final class McpServer {

    public static final String NAME = "xk-lab-mcp";
    public static final String VERSION = "1.0.0";

    /** 认识的协议版本；客户端报别的版本时回最新支持版本（MCP 允许服务端这样协商）。 */
    private static final List<String> KNOWN_PROTOCOLS = List.of("2024-11-05", "2025-03-26", "2025-06-18");
    private static final String DEFAULT_PROTOCOL = KNOWN_PROTOCOLS.get(KNOWN_PROTOCOLS.size() - 1);

    private final Map<String, McpTool> tools = new LinkedHashMap<>();
    private final BufferedReader in;
    private final PrintStream out;

    public McpServer(List<McpTool> toolList, InputStream input, PrintStream out) {
        for (McpTool tool : toolList) {
            tools.put(tool.name(), tool);
        }
        this.in = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
        this.out = out;
    }

    public Map<String, McpTool> tools() {
        return tools;
    }

    /** 读一行/一帧、处理、回一行，直到 stdin 关闭。 */
    public void serve() throws IOException {
        String raw;
        while ((raw = nextMessage()) != null) {
            if (raw.isBlank()) {
                continue;
            }
            String reply = handle(raw);
            if (reply != null) {
                out.println(reply);
                out.flush();
            }
        }
    }

    /** 处理一条报文；返回 {@code null} 表示不需要回包（通知类）。 */
    public String handle(String raw) {
        JsonNode root;
        try {
            root = Json.mapper().readTree(raw);
        } catch (IOException e) {
            return error(null, -32700, "解析失败：" + e.getMessage());
        }
        if (root == null || !root.isObject()) {
            return error(null, -32600, "无效的 JSON-RPC 请求（不是 JSON 对象）");
        }
        JsonNode id = root.has("id") ? root.get("id") : null;
        JsonNode methodNode = root.get("method");
        if (methodNode == null || !methodNode.isTextual()) {
            return error(id, -32600, "缺少 method");
        }
        String method = methodNode.asText();

        switch (method) {
            case "initialize":
                return result(id, initializeResult(root.get("params")));
            case "notifications/initialized":
            case "notifications/cancelled":
                return null;
            case "ping":
                return result(id, Json.object());
            case "tools/list":
                return result(id, toolsListResult());
            case "tools/call":
                return toolsCall(id, root.get("params"));
            case "resources/list":
                return result(id, Map.of("resources", List.of()));
            case "prompts/list":
                return result(id, Map.of("prompts", List.of()));
            default:
                if (id == null) {
                    return null; // 未知通知不回包（JSON-RPC 2.0 要求）
                }
                return error(id, -32601, "Method not found: " + method);
        }
    }

    // ==================== 各方法 ====================

    private Map<String, Object> initializeResult(JsonNode params) {
        String requested = params == null ? null : params.path("protocolVersion").asText(null);
        String protocol = KNOWN_PROTOCOLS.contains(requested) ? requested : DEFAULT_PROTOCOL;

        Map<String, Object> capabilities = new LinkedHashMap<>();
        Map<String, Object> toolCaps = new LinkedHashMap<>();
        toolCaps.put("listChanged", false);
        capabilities.put("tools", toolCaps);

        Map<String, Object> serverInfo = new LinkedHashMap<>();
        serverInfo.put("name", NAME);
        serverInfo.put("version", VERSION);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("protocolVersion", protocol);
        result.put("capabilities", capabilities);
        result.put("serverInfo", serverInfo);
        result.put("instructions", "只读查询这台机器自己的安全观测数据（本机回环、只读、口令只给结构）。"
                + "工具一律以 xk_ 开头；任何数据取不到都会返回 available:false + reason，不会编数字。");
        return result;
    }

    private Map<String, Object> toolsListResult() {
        List<Map<String, Object>> list = new ArrayList<>();
        for (McpTool tool : tools.values()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", tool.name());
            m.put("description", tool.description());
            m.put("inputSchema", tool.inputSchema());
            list.add(m);
        }
        return Map.of("tools", list);
    }

    private String toolsCall(JsonNode id, JsonNode params) {
        if (params == null || params.isNull()) {
            return error(id, -32602, "tools/call 缺少 params");
        }
        String name = params.path("name").asText("");
        McpTool tool = tools.get(name);
        if (tool == null) {
            return error(id, -32602, "未知工具：" + (name.isBlank() ? "(空)" : name)
                    + "；可用：" + String.join(", ", tools.keySet()));
        }
        Map<String, Object> arguments = new LinkedHashMap<>();
        JsonNode argsNode = params.get("arguments");
        if (argsNode != null && argsNode.isObject()) {
            try {
                Map<String, Object> parsed = Json.mapper().convertValue(argsNode,
                        new TypeReference<LinkedHashMap<String, Object>>() {
                        });
                if (parsed != null) {
                    arguments = parsed;
                }
            } catch (IllegalArgumentException e) {
                return error(id, -32602, "arguments 不是 JSON 对象：" + e.getMessage());
            }
        }

        Map<String, Object> payload;
        boolean isError = false;
        try {
            payload = tool.call(arguments);
        } catch (Exception e) {
            isError = true;
            payload = new LinkedHashMap<>();
            payload.put("generatedAt", ToolSupport.generatedAt());
            payload.put("source", tool.name());
            payload.put("available", false);
            payload.put("reason", "TOOL_FAILED: " + e.getClass().getSimpleName()
                    + (e.getMessage() == null ? "" : ": " + e.getMessage()));
        }
        return result(id, contentResult(payload, isError));
    }

    private Map<String, Object> contentResult(Map<String, Object> payload, boolean isError) {
        String text = Json.write(payload);
        Map<String, Object> block = new LinkedHashMap<>();
        block.put("type", "text");
        block.put("text", text);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("content", List.of(block));
        result.put("isError", isError);
        if (!isError) {
            // 2025-06-18 起推荐给结构化结果；老客户端忽略它，不影响兼容
            result.put("structuredContent", payload);
        }
        return result;
    }

    // ==================== 帧 / 封包 ====================

    private String nextMessage() throws IOException {
        String line = in.readLine();
        while (line != null && line.isBlank()) {
            line = in.readLine();
        }
        if (line == null) {
            return null;
        }
        if (line.toLowerCase(Locale.ROOT).startsWith("content-length:")) {
            int length;
            try {
                length = Integer.parseInt(line.substring("content-length:".length()).trim());
            } catch (NumberFormatException e) {
                return line; // 头坏了就当普通行报文，让上层报解析错误
            }
            String header;
            while ((header = in.readLine()) != null && !header.isEmpty()) {
                // 丢弃其余头
            }
            char[] buf = new char[length];
            int read = 0;
            while (read < length) {
                int n = in.read(buf, read, length - read);
                if (n < 0) {
                    break;
                }
                read += n;
            }
            return new String(buf, 0, read);
        }
        return line;
    }

    private String result(JsonNode id, Object resultObject) {
        ObjectNode response = Json.object();
        response.put("jsonrpc", "2.0");
        if (id == null) {
            response.putNull("id");
        } else {
            response.set("id", id);
        }
        response.set("result", Json.mapper().valueToTree(resultObject));
        return Json.write(response);
    }

    private String error(JsonNode id, int code, String message) {
        ObjectNode response = Json.object();
        response.put("jsonrpc", "2.0");
        if (id == null) {
            response.putNull("id");
        } else {
            response.set("id", id);
        }
        ObjectNode err = Json.object();
        err.put("code", code);
        err.put("message", message);
        response.set("error", err);
        return Json.write(response);
    }
}

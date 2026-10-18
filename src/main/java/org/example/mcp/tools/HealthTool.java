package org.example.mcp.tools;

import org.example.mcp.McpTool;
import org.example.mcp.PlatformClient;
import org.example.mcp.PlatformUnavailableException;
import org.example.mcp.ToolSupport;

import java.lang.management.ManagementFactory;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code xk_health} —— 平台进程/构建指纹。
 *
 * <p>回答的是"我现在问的到底是什么东西"：{@code buildSha}（jar 是哪个 commit 编的）、
 * {@code artifactMd5}（跑的是不是上传的那个 jar）、{@code status}（ok/degraded）、{@code uptimeMs}（进程活了多久）。
 * 这三个指纹是平台上一条校验链（git.properties → buildSha → artifactMd5）的对外读口，
 * MCP 只做透传，不自己算、不缓存。
 *
 * <p>附带 {@code mcp} 段：MCP server 自己的 pid / Java 版本 / 运行时长 ——
 * 排查"是平台慢了还是这个 stdio 进程重启过"时用得上，且全部是本进程的真实读数。
 */
public final class HealthTool implements McpTool {

    private static final String SOURCE = "platform GET /api/health（本机回环只读）";

    private final PlatformClient client;

    public HealthTool(PlatformClient client) {
        this.client = client;
    }

    @Override
    public String name() {
        return "xk_health";
    }

    @Override
    public String description() {
        return "平台进程与构建指纹：buildSha / artifactMd5 / status(ok|degraded) / uptimeMs，"
                + "另附 MCP 进程自身的 pid、Java 版本与运行时长。取不到数据源时返回 available:false，不补数。";
    }

    @Override
    public Map<String, Object> inputSchema() {
        return ToolSupport.schema(new LinkedHashMap<>(), List.of());
    }

    @Override
    public Map<String, Object> call(Map<String, Object> args) {
        Map<String, Object> out;
        try {
            Map<String, Object> p = client.get("/api/health", Map.of());
            out = ToolSupport.base(SOURCE, true);
            String status = ToolSupport.text(p.get("status"));
            out.put("status", status);
            out.put("degraded", status != null && "degraded".equalsIgnoreCase(status));
            out.put("buildSha", ToolSupport.text(p.get("buildSha")));
            out.put("artifactMd5", ToolSupport.text(p.get("artifactMd5")));
            out.put("uptimeMs", p.get("uptimeMs"));
            out.put("application", ToolSupport.text(p.get("application")));
            out.put("buildTime", ToolSupport.text(p.get("buildTime")));
            out.put("embeddedGitCommit", ToolSupport.text(p.get("embeddedGitCommit")));
            out.put("embeddedGitBranch", ToolSupport.text(p.get("embeddedGitBranch")));
            out.put("embeddedGitDirty", p.get("embeddedGitDirty"));
            out.put("fingerprintMismatch", p.get("fingerprintMismatch"));
            out.put("sourceSha", ToolSupport.text(p.get("sourceSha")));
            out.put("vectorStore", p.get("vectorStore"));
        } catch (PlatformUnavailableException e) {
            out = ToolSupport.unavailable(SOURCE, e.code() + ": " + e.getMessage());
        }
        // 自身读数与上游无关，两条分支都给（这是真实数据，不是补数）
        Map<String, Object> self = new LinkedHashMap<>();
        self.put("server", "xk-lab-mcp");
        self.put("version", "1.0.0");
        self.put("pid", ProcessHandle.current().pid());
        self.put("javaVersion", System.getProperty("java.version"));
        self.put("uptimeMs", ManagementFactory.getRuntimeMXBean().getUptime());
        out.put("mcp", self);
        return out;
    }
}

package org.example.mcp;

import org.example.mcp.tools.AlertsRecentTool;
import org.example.mcp.tools.AuditBlocksTool;
import org.example.mcp.tools.DetectionsTool;
import org.example.mcp.tools.HealthTool;
import org.example.mcp.tools.HoneypotSummaryTool;
import org.example.mcp.tools.IpProfileTool;

import java.nio.file.Path;
import java.util.List;

/**
 * 工具清单的唯一装配点（六个工具都在这里，顺序即 tools/list 的顺序）。
 *
 * <p>单独一个类而不是写在 {@link McpServerMain} 里：单测要能在不起进程、不读环境变量的情况下
 * 拿到同一份工具清单（{@code McpToolsTest} 直接 new 各工具 + 假 PlatformClient）。
 */
public final class ToolRegistry {

    private ToolRegistry() {
    }

    public static List<McpTool> create(PlatformClient client, Path siteDir) {
        return List.of(
                new HealthTool(client),
                new AlertsRecentTool(client),
                new IpProfileTool(client),
                new AuditBlocksTool(client),
                new HoneypotSummaryTool(client),
                new DetectionsTool(siteDir));
    }
}

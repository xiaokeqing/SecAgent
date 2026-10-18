package org.example.mcp;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

/**
 * MCP server 入口：{@code java -jar sec-agent-1.0-SNAPSHOT-mcp.jar}。
 *
 * <h3>独立进程（任务硬约束之一）</h3>
 * 不注册任何 Spring 容器、不监听端口：这个进程的全部意义是"被 MCP 客户端用 stdin/stdout 拉起来，
 * 用只读 HTTP 问本机 9900 的公开端点"。因此它跟现有 Web 服务的生命周期、发布流程、端口都完全解耦 ——
 * 停掉这个 MCP 进程不会影响站点，反过来站点没起也只是让工具返回 {@code available:false}。
 *
 * <h3>环境变量</h3>
 * <ul>
 *   <li>{@code XK_MCP_BASE_URL} —— 平台只读端点，默认 {@code http://127.0.0.1:9900}，<b>只允许回环地址</b>；</li>
 *   <li>{@code XK_MCP_SITE_DIR} —— 站点仓库根目录（xk_detections 读规则文件用），默认 {@code F:/7AAA/AI/blog}；</li>
 *   <li>{@code XK_MCP_TIMEOUT_MS} —— 单次 HTTP 超时，默认 5000。</li>
 * </ul>
 *
 * <h3>退出码</h3>
 * 0 = stdin 关闭正常退出；2 = 配置错误（例如 base URL 指向非回环地址）；1 = 其它启动失败。
 * 配置错误<b>直接退出而不是降级</b>：让"我只读本机"这条边界失败得能被看见。
 */
public final class McpServerMain {

    public static final String ENV_BASE_URL = "XK_MCP_BASE_URL";
    public static final String ENV_SITE_DIR = "XK_MCP_SITE_DIR";
    public static final String ENV_TIMEOUT_MS = "XK_MCP_TIMEOUT_MS";
    public static final String DEFAULT_SITE_DIR = "F:/7AAA/AI/blog";

    private McpServerMain() {
    }

    public static void main(String[] args) {
        // 先把真正的 stdout 抓成协议通道，再把 System.out/err 改道 stderr —— 之后任何意外打印都进不了 JSON-RPC 流
        PrintStream protocol = new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8);
        PrintStream log = new PrintStream(new FileOutputStream(FileDescriptor.err), true, StandardCharsets.UTF_8);
        System.setOut(log);
        System.setErr(log);

        try {
            String baseUrl = env(ENV_BASE_URL, HttpPlatformClient.DEFAULT_BASE_URL);
            Path siteDir = Path.of(env(ENV_SITE_DIR, DEFAULT_SITE_DIR));
            int timeoutMs = envInt(ENV_TIMEOUT_MS, HttpPlatformClient.DEFAULT_TIMEOUT_MS);
            PlatformClient client = new HttpPlatformClient(baseUrl, timeoutMs);
            List<McpTool> tools = ToolRegistry.create(client, siteDir);
            log.printf("[%s] 启动 pid=%d java=%s upstream=%s siteDir=%s tools=%d timeoutMs=%d%n",
                    McpServer.NAME, ProcessHandle.current().pid(), System.getProperty("java.version"),
                    client.describe(), siteDir, tools.size(), timeoutMs);
            new McpServer(tools, System.in, protocol).serve();
            log.printf("[%s] stdin 关闭，正常退出%n", McpServer.NAME);
        } catch (IllegalArgumentException e) {
            log.println("[" + McpServer.NAME + "] 配置错误：" + e.getMessage());
            log.flush();
            System.exit(2);
        } catch (Throwable t) {
            log.println("[" + McpServer.NAME + "] 启动/运行失败：" + t);
            t.printStackTrace(log);
            log.flush();
            System.exit(1);
        }
    }

    static String env(String key, String def) {
        String v = System.getenv(key);
        return v == null || v.isBlank() ? def : v.trim();
    }

    static int envInt(String key, int def) {
        String v = System.getenv(key);
        if (v == null || v.isBlank()) {
            return def;
        }
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }
}

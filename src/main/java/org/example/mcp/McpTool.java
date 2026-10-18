package org.example.mcp;

import java.util.Map;

/**
 * 一个 MCP 工具。
 *
 * <p>契约三条（三个都在验收里被逐条跑过）：
 * <ol>
 *   <li>{@link #call(Map)} 只读：实现里不许有任何写路径（本模块不依赖任何写服务）；</li>
 *   <li>返回的 Map 必须自带 {@code generatedAt} 与 {@code source}（由 {@link ToolSupport#base} 统一补）；</li>
 *   <li>数据源取不到时返回 {@code available:false} + {@code reason}，<b>不补数、不猜</b>。</li>
 * </ol>
 */
public interface McpTool {

    /** 工具名（客户端可见、全局唯一，命名空间前缀 xk_ 表示这是本站自己的观测数据）。 */
    String name();

    /** 给模型看的一句话说明：这个工具回答什么问题、取不到会怎样。 */
    String description();

    /** JSON Schema（type/properties/required/additionalProperties 子集）。 */
    Map<String, Object> inputSchema();

    /** 执行一次调用。抛出的异常由协议层转成 {@code isError:true}，不崩进程。 */
    Map<String, Object> call(Map<String, Object> arguments) throws Exception;
}

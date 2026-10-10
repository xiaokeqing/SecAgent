package org.example.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 工具回调兜底配置。
 *
 * <p>当未启用 MCP（spring.ai.mcp.client.enabled=false）时，容器中可能不存在
 * 远程 MCP 工具聚合的 {@link ToolCallbackProvider}，此处提供一个空实现兜底，
 * 保证 ChatService / ChatController 注入不失败。本地 @Tool 方法工具仍通过
 * ReactAgent 的 methodTools 正常注册。
 */
@Configuration
public class ToolCallbackFallbackConfig {

    private static final Logger logger = LoggerFactory.getLogger(ToolCallbackFallbackConfig.class);

    @Bean
    @ConditionalOnMissingBean(ToolCallbackProvider.class)
    public ToolCallbackProvider emptyToolCallbackProvider() {
        logger.info("未检测到 MCP 工具提供方，注册空 ToolCallbackProvider（本地 @Tool 工具不受影响）");
        return () -> new ToolCallback[0];
    }
}

package org.example.controller;

import org.example.vector.VectorStoreGateway;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.lang.management.ManagementFactory;
import java.util.HashMap;
import java.util.Map;

/**
 * 通用健康检查接口（内存 / Milvus 两种模式均可用）。
 * 用于启动后确认服务、向量库后端与知识库文档数量是否正常。
 */
@RestController
@RequestMapping("/api")
public class HealthController {

    @Autowired
    private VectorStoreGateway vectorStore;

    @Value("${cls.mock-enabled:false}")
    private boolean clsMock;

    @Value("${prometheus.mock-enabled:false}")
    private boolean prometheusMock;

    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> result = new HashMap<>();
        result.put("status", "ok");
        result.put("application", "SecAgent");
        result.put("vectorStore", vectorStore.backend());
        result.put("documentVectors", vectorStore.count());
        result.put("logsMockEnabled", clsMock);
        result.put("alertsMockEnabled", prometheusMock);
        result.put("uptimeMs", ManagementFactory.getRuntimeMXBean().getUptime());
        return result;
    }
}

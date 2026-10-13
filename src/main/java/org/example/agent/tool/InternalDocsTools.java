package org.example.agent.tool;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.security.PromptInjectionGuard;
import org.example.service.VectorSearchService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 内部文档查询工具
 * 使用 RAG (Retrieval-Augmented Generation) 从内部知识库检索相关文档
 */
@Component
public class InternalDocsTools {
    
    private static final Logger logger = LoggerFactory.getLogger(InternalDocsTools.class);
    
    /** 工具名常量，用于动态构建提示词 */
    public static final String TOOL_QUERY_INTERNAL_DOCS = "queryInternalDocs";
    
    private final VectorSearchService vectorSearchService;

    private final PromptInjectionGuard promptInjectionGuard;

    @Value("${rag.top-k:3}")
    private int topK = 3; // 默认值

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 构造函数注入依赖
     * Spring 会自动注入 VectorSearchService 与提示注入护栏
     */
    @Autowired
    public InternalDocsTools(VectorSearchService vectorSearchService, PromptInjectionGuard promptInjectionGuard) {
        this.vectorSearchService = vectorSearchService;
        this.promptInjectionGuard = promptInjectionGuard;
    }
    
    /**
     * 查询内部文档工具
     *
     * @param query 搜索查询，描述您要查找的信息
     * @return JSON 格式的搜索结果，包含相关文档内容、相似度分数和元数据
     */
    @Tool(description = "Search the internal cybersecurity knowledge base via RAG (Retrieval-Augmented Generation). " +
            "Use it to look up vulnerability principles (e.g. path traversal, SQL injection, file upload, webshell), " +
            "attack indicators, detection rules, hardening baselines, and incident response / forensic SOPs. " +
            "Returns the most relevant document chunks with similarity scores. Call this to ground your analysis and " +
            "recommendations in the knowledge base before giving a conclusion.")
    public String queryInternalDocs(
            @ToolParam(description = "Search query describing the security knowledge you need, e.g. 'SSH brute force response steps' or 'path traversal mitigation'")
            String query) {

        // 【公开身份：工具层直接拒绝（F2 收紧，2026-10-13）】
        // 本工具检索的是【内部】知识库全量（不过公开白名单），公开面只能用
        // PublicKbService（白名单目录 + 字段白名单 + 脱敏）。返回体里刻意带 "error" 字段：
        // 万一日后被误接到内部 ANALYST 分支上，那边会把它当"检索工具不可用"如实降级，
        // 而不是把这段拒绝文本当成知识片段喂给模型。
        if (org.example.security.EvalIdentity.isPublicRequest()) {
            logger.warn("公开身份请求被拒绝：queryInternalDocs（公开面不读取内部知识库，只走公开白名单检索）");
            return "{\"status\": \"refused\", \"error\": \"public-identity-no-internal-data\", "
                    + "\"message\": \"公开身份不得读取内部知识库：公开面只检索公开白名单文档。\"}";
        }


        try {
            // 使用向量搜索服务检索相关文档
            // 走混合检索（BM25 稀疏 + 稠密 → RRF → 轻量重排）：内部链路本来就允许看全量知识，
            // 所以这里不需要可见性过滤；公开面一律走 PublicKbService（白名单）。
            List<VectorSearchService.SearchResult> searchResults = 
                    vectorSearchService.searchHybrid(query, topK);
            
            if (searchResults.isEmpty()) {
                return "{\"status\": \"no_results\", \"message\": \"No relevant documents found in the knowledge base.\"}";
            }
            
            // 将搜索结果转换为 JSON 格式
            String resultJson = objectMapper.writeValueAsString(searchResults);

            // RAG 检索内容可能被知识库投毒污染，包裹为"不可信数据"并做注入检测
            return promptInjectionGuard.wrapUntrusted("内部知识库RAG", resultJson);
            
        } catch (Exception e) {
            logger.error("[工具错误] queryInternalDocs 执行失败", e);
            return String.format("{\"status\": \"error\", \"message\": \"Failed to query internal docs: %s\"}", 
                    e.getMessage());
        }
    }
}

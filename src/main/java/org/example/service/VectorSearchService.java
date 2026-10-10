package org.example.service;

import lombok.Getter;
import lombok.Setter;
import org.example.vector.ScoredDoc;
import org.example.vector.VectorStoreGateway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * 向量搜索服务
 * 负责生成查询向量，并通过 {@link VectorStoreGateway} 做相似度检索，
 * 底层可以是内存存储或 Milvus，对上层透明。
 */
@Service
public class VectorSearchService {

    private static final Logger logger = LoggerFactory.getLogger(VectorSearchService.class);

    @Autowired
    private VectorEmbeddingService embeddingService;

    @Autowired
    private VectorStoreGateway vectorStore;

    @Value("${rag.top-k:3}")
    private int defaultTopK;

    /**
     * 相似度阈值：低于该分数的检索结果视为"未命中"，直接剔除，避免低相关噪声硬塞给模型。
     * 适用于"分数越高越相关"的后端（默认内存库余弦相似度）；
     * 若对接 Milvus 且使用距离度量（越小越相关），请将该配置设为 0 关闭过滤。
     */
    @Value("${rag.min-score:0.30}")
    private float minScore;

    /**
     * 搜索与查询文本相似的文档
     *
     * @param query 用户查询文本
     * @param topK  返回结果数量
     * @return 搜索结果列表，按相似度从高到低排序（低于相似度阈值的结果已剔除）
     */
    public List<SearchResult> searchSimilarDocuments(String query, int topK) {
        if (query == null || query.trim().isEmpty()) {
            logger.warn("查询内容为空，无法执行搜索");
            return new ArrayList<>();
        }

        logger.info("开始向量搜索: query='{}', topK={}, minScore={}, backend={}", query, topK, minScore, vectorStore.backend());

        // 1. 生成查询向量
        List<Float> queryVector = embeddingService.generateQueryVector(query);

        // 2. 向量库检索
        List<ScoredDoc> docs = vectorStore.search(queryVector, topK);

        // 3. 转换为统一返回结构（低于阈值 = 知识库未命中，剔除后上层走拒答/兜底）
        List<SearchResult> results = new ArrayList<>();
        for (ScoredDoc doc : docs) {
            if (minScore > 0 && doc.getScore() < minScore) {
                logger.info("  剔除低分结果: score={} < minScore={}", doc.getScore(), minScore);
                continue;
            }
            SearchResult r = new SearchResult();
            r.setId(doc.getId());
            r.setContent(doc.getContent());
            r.setScore(doc.getScore());
            r.setMetadata(doc.getMetadata());
            results.add(r);
        }

        logger.info("搜索完成: 返回 {} 个结果", results.size());
        if (!results.isEmpty()) {
            for (int i = 0; i < results.size(); i++) {
                SearchResult r = results.get(i);
                String preview = r.getContent() != null && r.getContent().length() > 50
                        ? r.getContent().substring(0, 50) + "..." : r.getContent();
                Object fileName = r.getMetadata() == null ? null : r.getMetadata().get("_file_name");
                logger.info("  结果 {}: score={}, file={}, preview='{}'", i + 1, r.getScore(), fileName, preview);
            }
        }

        return results;
    }

    /**
     * 使用默认 topK 搜索
     */
    public List<SearchResult> searchSimilarDocuments(String query) {
        return searchSimilarDocuments(query, defaultTopK);
    }

    /**
     * 搜索结果数据结构
     */
    @Getter
    @Setter
    public static class SearchResult {
        private String id;
        private String content;
        private float score;
        private java.util.Map<String, Object> metadata;
    }
}

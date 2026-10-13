package org.example.service;

import lombok.Getter;
import lombok.Setter;
import org.example.rag.HybridRetriever;
import org.example.rag.RagProperties;
import org.example.rag.SparseCorpusProvider;
import org.example.rag.SparseIndexCache;
import org.example.vector.ScoredDoc;
import org.example.vector.VectorStoreGateway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;

import java.util.ArrayList;
import java.util.List;

/**
 * 向量搜索服务
 * 负责生成查询向量，并通过 {@link VectorStoreGateway} 做相似度检索，
 * 底层可以是内存存储或 Milvus，对上层透明。
 *
 * <h3>两条检索口径（都在这个类里，便于对照与回退）</h3>
 * <ol>
 *   <li>{@link #searchSimilarDocuments(String, int)} —— <b>纯稠密</b>，改造前的原始口径。
 *       保留它是为了两件事：<b>回退</b>（把 {@code app.rag.sparse.enabled=false} 与
 *       {@code app.rag.rerank.enabled=false} 一起关掉即可，见 RUNBOOK §25），
 *       以及给"只想要语义相似度"的内部调用一个不受新链路影响的入口；</li>
 *   <li>{@link #searchHybrid(String, int)} —— <b>BM25 稀疏 + 稠密 → RRF → 轻量重排</b>。
 *       走 {@link HybridRetriever}；稀疏通道不可用时（例如 Milvus 后端不提供全量枚举）
 *       会<b>如实退化成纯稠密</b>并在日志与返回值里写清楚，不会静默改变口径。</li>
 * </ol>
 *
 * <h3>为什么阈值行为必须与改造前一致</h3>
 * {@code rag.min-score} 是"知识库未命中 → 拒答"这条既有产品行为的判据
 * （见下 {@link #searchSimilarDocuments} 注释）。混合检索<b>不改</b>这个门槛：
 * 两路召回之后仍按同一个 minScore 剔除低分稠密结果，稀疏通道只做"补充召回"。
 * 否则会出现"检索看起来变好了，其实只是把原本该拒答的问题变成了硬答"。
 */
@Service
public class VectorSearchService {

    private static final Logger logger = LoggerFactory.getLogger(VectorSearchService.class);

    @Autowired
    private VectorEmbeddingService embeddingService;

    @Autowired
    private VectorStoreGateway vectorStore;

    /**
     * 默认 topK。
     *
     * <p>取值优先级：{@code app.rag.top-k}（新显式入口）→ {@code rag.top-k}（既有键）→ 3。
     * 这样"只加新键"不会改变任何既有部署的行为。
     */
    @Value("${app.rag.top-k:${rag.top-k:3}}")
    private int defaultTopK;

    /**
     * 相似度阈值：低于该分数的检索结果视为"未命中"，直接剔除，避免低相关噪声硬塞给模型。
     * 适用于"分数越高越相关"的后端（默认内存库余弦相似度）；
     * 若对接 Milvus 且使用距离度量（越小越相关），请将该配置设为 0 关闭过滤。
     *
     * <p>取值优先级：{@code app.rag.min-score} → {@code rag.min-score} → 0.30。
     */
    @Value("${app.rag.min-score:${rag.min-score:0.30}}")
    private float minScore;

    /** 混合检索参数（稀疏/RRF/重排/候选池） */
    @Autowired
    private RagProperties ragProperties;

    /**
     * 稀疏语料来源：<b>可选</b>。
     *
     * <p>用 {@link ObjectProvider} 而不是直接 {@code @Autowired(required=false)}：
     * 一个"存储是否支持全量枚举"的判定要能被测试替换成假实现，
     * 用 provider 可以在单测里直接注入替身，不必起 Spring。
     */
    @Autowired
    private ObjectProvider<SparseCorpusProvider> sparseCorpusProvider;

    private HybridRetriever hybridRetriever;

    /** BM25 索引缓存：跨检索器实例共享，按语料版本重建（详见 SparseIndexCache 的注释） */
    private SparseIndexCache sparseIndexCache;

    @PostConstruct
    public void init() {
        SparseCorpusProvider corpus = sparseCorpusProvider == null ? null : sparseCorpusProvider.getIfAvailable();
        this.sparseIndexCache = new SparseIndexCache(corpus, ragProperties == null ? new RagProperties() : ragProperties);
        this.hybridRetriever = new HybridRetriever(
                embeddingService::generateQueryVector,
                vectorStore::search,
                sparseIndexCache,
                ragProperties == null ? new RagProperties() : ragProperties,
                minScore);
        if (ragProperties != null) {
            ragProperties.describe();
        }
        logger.info("检索链路就绪：backend={} minScore={} 默认topK={} 稀疏语料来源={}",
                vectorStore.backend(), minScore, defaultTopK,
                corpus == null ? "无（将退化为纯稠密）" : corpus.getClass().getSimpleName());
    }

    /**
     * 纯稠密检索（改造前的原始口径）。
     *
     * @param query 用户查询文本
     * @param topK  返回结果数量
     * @return 按相似度从高到低排序（低于相似度阈值的结果已剔除）
     */
    public List<SearchResult> searchSimilarDocuments(String query, int topK) {
        if (query == null || query.trim().isEmpty()) {
            logger.warn("查询内容为空，无法执行搜索");
            return new ArrayList<>();
        }

        logger.info("开始向量搜索（纯稠密）: query='{}', topK={}, minScore={}, backend={}",
                query, topK, minScore, vectorStore.backend());

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
            results.add(toSearchResult(doc));
        }

        logResults("搜索完成（纯稠密）", results);
        return results;
    }

    /**
     * 混合检索（两路召回 + RRF + 轻量重排）—— 内部 RAG 链路与公开检索都走它。
     *
     * <p>与 {@link #searchSimilarDocuments(String, int)} 的差别只在<b>候选怎么排</b>：
     * 候选取自两路（稠密 + BM25 稀疏）的并集，经 RRF 融合、再经轻量重排；
     * {@code minScore} 门槛与"未命中即空"的语义完全不变。
     *
     * @param query              用户查询文本
     * @param topK               返回结果数量
     * @param minScoreOverride   ≥0 时覆盖配置阈值（基线与对照实验用；&lt;0 表示用配置值）
     */
    public List<SearchResult> searchHybrid(String query, int topK, float minScoreOverride) {
        if (query == null || query.trim().isEmpty()) {
            logger.warn("查询内容为空，无法执行混合检索");
            return new ArrayList<>();
        }
        float threshold = minScoreOverride >= 0 ? minScoreOverride : minScore;
        HybridRetriever retriever = retrieverFor(threshold);
        HybridRetriever.Result r = retriever.retrieve(query, topK);
        List<SearchResult> results = new ArrayList<>(r.hits().size());
        for (HybridRetriever.Hit h : r.hits()) {
            results.add(toSearchResult(h.doc()));
        }
        logger.info("混合检索完成: query='{}', topK={}, minScore={}, {}",
                query, topK, threshold, HybridRetriever.describe(r));
        logResults("混合检索命中", results);
        if (!r.note().isBlank()) {
            logger.info("混合检索口径：{}", r.note());
        }
        return results;
    }

    /** 混合检索（用配置阈值） */
    public List<SearchResult> searchHybrid(String query, int topK) {
        return searchHybrid(query, topK, -1f);
    }

    /** 混合检索（用配置的默认 topK） */
    public List<SearchResult> searchHybrid(String query) {
        return searchHybrid(query, defaultTopK);
    }

    /** 检索链路的真实生效口径（供启动自检/排障如实打印） */
    public String describeRetrieval() {
        return "backend=" + vectorStore.backend() + " minScore=" + minScore
                + " 默认topK=" + defaultTopK
                + " 稀疏=" + (ragProperties != null && ragProperties.isSparseEnabled())
                + " 重排=" + (ragProperties != null && ragProperties.isRerankEnabled())
                + " rrfK=" + (ragProperties == null ? "-" : ragProperties.getRrfK());
    }

    /**
     * 使用默认 topK 搜索（纯稠密）
     */
    public List<SearchResult> searchSimilarDocuments(String query) {
        return searchSimilarDocuments(query, defaultTopK);
    }

    // ==================== 内部 ====================

    /**
     * 取一个"本次阈值"对应的检索器。
     *
     * <p>为什么允许覆盖阈值：离线评测要对比"同一门槛下两套排序"的差异，
     * 而阈值是检索器的构造参数（不可变）。这里按需构造一个轻量实例 ——
     * <b>不会重复建 BM25 索引</b>，因为索引缓存（{@link SparseIndexCache}）是共享的。
     * 阈值与配置一致的常见路径直接复用 {@code @PostConstruct} 造好的那个实例。
     */
    private HybridRetriever retrieverFor(float threshold) {
        if (hybridRetriever != null && threshold == minScore) {
            return hybridRetriever;
        }
        if (sparseIndexCache == null) {
            // 单测里没走 Spring 生命周期时兜底初始化（行为与 @PostConstruct 一致）
            init();
        }
        if (threshold == minScore) {
            return hybridRetriever;
        }
        return new HybridRetriever(embeddingService::generateQueryVector, vectorStore::search,
                sparseIndexCache, ragProperties == null ? new RagProperties() : ragProperties, threshold);
    }

    private static SearchResult toSearchResult(ScoredDoc doc) {
        SearchResult r = new SearchResult();
        r.setId(doc.getId());
        r.setContent(doc.getContent());
        r.setScore(doc.getScore());
        r.setMetadata(doc.getMetadata());
        return r;
    }

    private void logResults(String label, List<SearchResult> results) {
        logger.info("{}: 返回 {} 个结果", label, results.size());
        for (int i = 0; i < results.size(); i++) {
            SearchResult r = results.get(i);
            String preview = r.getContent() != null && r.getContent().length() > 50
                    ? r.getContent().substring(0, 50) + "..." : r.getContent();
            Object fileName = r.getMetadata() == null ? null : r.getMetadata().get("_file_name");
            logger.info("  结果 {}: score={}, file={}, preview='{}'", i + 1, r.getScore(), fileName, preview);
        }
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

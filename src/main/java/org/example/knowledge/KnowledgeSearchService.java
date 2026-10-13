package org.example.knowledge;

import lombok.Getter;
import lombok.Setter;
import org.example.service.VectorSearchService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 统一知识检索：
 * <ol>
 *   <li>调用既有 {@link VectorSearchService} 检索内置 318 条预计算向量；</li>
 *   <li>按 _file_name -> 类别过滤（指定类别时）；</li>
 *   <li>合并"本地已通过知识"（关键字匹配，无 Embedding Key 时的兜底）；</li>
 *   <li>返回统一结构：标题 / 片段 / 来源 / 相似度 / 类别 / 来源标记。</li>
 * </ol>
 *
 * <p>注意：待审核（PENDING）内容永远不会出现在这里——只有注入检测 + 人工通过后的内容才可检索。
 */
@Service
public class KnowledgeSearchService {

    private static final Logger logger = LoggerFactory.getLogger(KnowledgeSearchService.class);

    /** 多取一些向量结果供类别过滤后仍有内容 */
    private static final int FETCH_TOP_K = 20;
    private static final int RETURN_TOP_K = 10;
    /** 本地关键字命中给一个固定的偏低相似度，排在向量结果之后 */
    private static final float KEYWORD_SCORE = 0.55f;

    private final VectorSearchService vectorSearchService;
    private final KnowledgeCatalog catalog;
    private final KnowledgePendingService pendingService;

    public KnowledgeSearchService(VectorSearchService vectorSearchService,
                                  KnowledgeCatalog catalog,
                                  KnowledgePendingService pendingService) {
        this.vectorSearchService = vectorSearchService;
        this.catalog = catalog;
        this.pendingService = pendingService;
    }

    public List<KbSearchResult> search(String query, String category) {
        List<KbSearchResult> results = new ArrayList<>();
        if (query == null || query.trim().isEmpty()) {
            return results;
        }

        // 1) 向量检索（无真实 Embedding Key 时可能报错，容错降级：不拖垮整个知识库页）
        try {
            // 混合检索（BM25 稀疏 + 稠密 → RRF → 轻量重排）。注意 score 的语义随之变化：
            // 改造前是余弦相似度（0~1），现在是"最终检索分"（RRF + 重排信号，量纲不同）。
            // 所以前端不再把它当"相似度百分比"展示，而是当作相关度排序分（见 knowledge.js 的说明）。
            List<VectorSearchService.SearchResult> hits =
                    vectorSearchService.searchHybrid(query, FETCH_TOP_K);
            for (VectorSearchService.SearchResult h : hits) {
                Map<String, Object> meta = h.getMetadata();
                String fileName = meta == null ? null : String.valueOf(meta.get("_file_name"));
                String cat = catalog.classify(fileName);
                if (isNotBlank(category) && !"全部".equals(category) && !category.equals(cat)) {
                    continue; // 类别过滤
                }
                KbSearchResult r = new KbSearchResult();
                r.setTitle(meta == null || meta.get("title") == null ? fileName : String.valueOf(meta.get("title")));
                r.setSnippet(h.getContent());
                r.setSource(fileName);
                r.setScore(h.getScore());
                r.setCategory(cat);
                r.setOrigin("内置知识库");
                results.add(r);
            }
        } catch (Exception e) {
            // 无真实 Embedding Key / 网络异常时，向量检索不可用，降级为仅本地已通过关键字结果
            logger.warn("向量检索不可用，降级为本地关键字检索：{}", e.getMessage());
        }

        // 2) 合并"本地已通过知识"（关键字匹配）
        for (KbEntry e : pendingService.searchApproved(query, category)) {
            KbSearchResult r = new KbSearchResult();
            r.setTitle("人工知识：" + abbreviate(e.getContent(), 24));
            r.setSnippet(e.getContent());
            r.setSource(e.getSource() + "（" + e.getActor() + "）");
            r.setScore(KEYWORD_SCORE);
            r.setCategory(e.getCategory());
            r.setOrigin("本地已通过·待向量化");
            results.add(r);
        }

        // 3) 按相似度排序后截断
        results.sort((a, b) -> Float.compare(b.getScore(), a.getScore()));
        if (results.size() > RETURN_TOP_K) {
            return new ArrayList<>(results.subList(0, RETURN_TOP_K));
        }
        return results;
    }

    private static boolean isNotBlank(String s) {
        return s != null && !s.trim().isEmpty();
    }

    private static String abbreviate(String s, int max) {
        if (s == null) return "";
        s = s.replaceAll("\\s+", " ").trim();
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    /** 统一检索结果结构 */
    @Getter
    @Setter
    public static class KbSearchResult {
        /** 标题 */
        private String title;
        /** 正文片段 */
        private String snippet;
        /** 来源（文件名 / 提交人） */
        private String source;
        /** 相似度分数 */
        private float score;
        /** 所属类别 */
        private String category;
        /** 来源标记：内置知识库 / 本地已通过·待向量化 */
        private String origin;
    }
}

package org.example.selfapi;

import org.example.knowledge.PublicKbVisibility;
import org.example.service.VectorSearchService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 自用面的知识片段检索（<b>只读</b>，只取公开可见的片段）。
 *
 * <h3>为什么自用面不自己做一套可见性判定</h3>
 * 可见性口径（{@link PublicKbVisibility}：根目录白名单 + 来源类型白名单 + 兜底黑名单）
 * 是"哪些文档可以出到匿名面"的<b>唯一定义</b>。自用面再写一份，两份迟早不一致 ——
 * 而不一致的方向如果是"自用那份更宽"，就等于把内部文档送进一个将来可能被前端渲染出去的响应。
 *
 * <p>所以这里直接复用既有 {@link PublicKbVisibility}（它属于 {@code knowledge} 包，
 * 不是公开面的可变口径）：<b>自用面看到的片段 ⊆ 公开面能看到的片段</b>，
 * 这是一条比"两份口径记得同步"强得多的不变量。
 *
 * <h3>与公开面的差别（有意的小差别）</h3>
 * 公开面的引用块文案是为访客写的；站主自己看的时候，"公开演示只基于公开知识库"这种句子没有意义。
 * 所以自用面自己渲染引用块（{@link #renderCitationBlock}），
 * <b>但字段集合与公开面保持一致</b>（title / snippet / trustLevel / trustLevelLabel / sourceType /
 * sourceTypeLabel / score），这样"哪一份能出海"的差异只体现在<b>文案</b>上，不体现在数据上。
 */
@Service
public class SelfKbService {

    private static final Logger logger = LoggerFactory.getLogger(SelfKbService.class);

    private final VectorSearchService vectorSearchService;
    private final PublicKbVisibility visibility;

    @Value("${app.user.kb.snippet-chars:300}")
    private int snippetChars;

    @Value("${app.user.kb.top-k:3}")
    private int topK;

    @Autowired
    public SelfKbService(VectorSearchService vectorSearchService, PublicKbVisibility visibility) {
        this.vectorSearchService = vectorSearchService;
        this.visibility = visibility;
    }

    /**
     * 检索公开可见的知识片段。
     *
     * <p>检索不可用时<b>抛出</b>（不返回空列表）：调用方据此如实标注"检索不可用"，
     * 而不是让空列表冒充"知识库里没有相关内容"。两种情形对使用者含义完全不同。
     */
    public List<Map<String, Object>> search(String query) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (query == null || query.isBlank()) {
            return out;
        }
        List<VectorSearchService.SearchResult> hits =
                vectorSearchService.searchHybrid(query, Math.max(topK * 4, 12));

        for (VectorSearchService.SearchResult h : hits) {
            Map<String, Object> meta = h.getMetadata() == null ? Map.of() : h.getMetadata();
            String source = str(meta.get("_source"));
            String fileName = str(meta.get("_file_name"));
            String sourceType = str(meta.get("_source_type"));
            if (visibility.denyReason(source, fileName, sourceType) != null) {
                // 只记条数，不记"被拒的是哪一篇"：日志本身也不该成为内部文档清单
                continue;
            }
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("title", clip(str(meta.get("title")), 120));
            item.put("snippet", clip(h.getContent(), Math.max(1, snippetChars)));
            item.put("sourceType", sourceType == null ? "unknown" : sourceType);
            item.put("trustLevel", str(meta.get("_trust_level")));
            item.put("score", Math.round(h.getScore() * 1000f) / 1000f);
            out.add(item);
            if (out.size() >= Math.max(1, topK)) {
                break;
            }
        }
        logger.debug("自用面知识检索：返回 {} 条公开可见片段", out.size());
        return out;
    }

    /**
     * 把命中片段渲染成 markdown 引用块（自用口径的文案）。
     *
     * <p>标题的兜底顺序与公开面一致（title → 「（未命名片段）」），
     * 避免出现"同一份数据在两个面上标题不一样"。
     */
    public static String renderCitationBlock(List<Map<String, Object>> citations) {
        if (citations == null || citations.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("### 命中的知识库片段（未经 AI 加工，供你自行判断）\n\n");
        sb.append("> 这些片段来自内置安全知识库（security-docs）与人工审核通过的白名单文档 ——")
          .append("即<b>公开可见</b>的那一部分。\n\n");
        int i = 1;
        for (Map<String, Object> c : citations) {
            if (c == null) {
                continue;
            }
            sb.append(i++).append(". **").append(text(c.get("title"), "（未命名片段）")).append("**");
            String trust = text(c.get("trustLevel"), "");
            String sourceType = text(c.get("sourceType"), "");
            Object score = c.get("score");
            List<String> meta = new ArrayList<>();
            if (!trust.isBlank()) {
                meta.add("可信度：" + trust);
            }
            if (!sourceType.isBlank()) {
                meta.add("来源性质：" + sourceType);
            }
            if (score != null) {
                meta.add("相关度：" + score);
            }
            if (!meta.isEmpty()) {
                sb.append("（").append(String.join("，", meta)).append("）");
            }
            sb.append("\n");
            String snippet = text(c.get("snippet"), "");
            if (!snippet.isBlank()) {
                for (String line : snippet.split("\n")) {
                    sb.append("   > ").append(line).append("\n");
                }
            }
            sb.append("\n");
        }
        return sb.toString().trim();
    }

    private static String str(Object v) {
        return v == null ? null : String.valueOf(v);
    }

    private static String text(Object v, String fallback) {
        if (v == null) {
            return fallback;
        }
        String s = String.valueOf(v).trim();
        return (s.isEmpty() || "null".equalsIgnoreCase(s)) ? fallback : s;
    }

    private static String clip(String s, int max) {
        if (s == null) {
            return "";
        }
        String v = s.trim();
        return v.length() <= max ? v : v.substring(0, max) + "…";
    }
}

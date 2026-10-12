package org.example.publicapi;

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
import java.util.Locale;
import java.util.Map;

/**
 * 公开只读知识库检索（{@code GET /api/public/kb?q=}）的<b>唯一实现</b>。
 *
 * <h3>它与内部检索的关系</h3>
 * <b>复用同一套向量检索</b>（{@link VectorSearchService} + text-embedding-v4 + 318 条向量），
 * 不新造一套库；区别只在出海前做了什么：
 * <ol>
 *   <li><b>可见性过滤</b>：只放行"公开白名单"内的文档（见 {@link PublicKbVisibility}），
 *       内部文档与未标注来源的文档不参与公开检索；</li>
 *   <li><b>字段白名单</b>：只出 标题 / 片段 / 来源类型 / 可信度 / 相关度。
 *       原始 {@code _source} 绝对路径、文件名、内部 id 一律不出；</li>
 *   <li><b>脱敏</b>：片段与标题都过一遍 IP 掩码与内部路径/凭据脱敏
 *       （{@link PublicOutputGuard}）—— 知识文档里出现示例 IP、示例 Key 是常态；</li>
 *   <li><b>截断</b>：片段只出前若干字符，不整篇搬运（公开页面是"检索预览"，
 *       不是"文档下载"）。</li>
 * </ol>
 *
 * <h3>为什么直接调 VectorSearchService 而不是 KnowledgeSearchService</h3>
 * 后者会把<b>本机人工审核通过的知识</b>（{@code data/kb-approved.json}）按关键字一起返回，
 * 其 {@code source} 字段是"文件路径（提交人）"形式 —— 那正是公开端点上不该出现的东西，
 * 而且它没有"是否公开"的判定入口。与其在公开端点上再过滤一遍它的输出（漏一个字段就泄露），
 * 不如在<b>同一套向量检索</b>之上写一条只有白名单字段的出海口。
 * 内网知识库页面仍然用 KnowledgeSearchService，行为不变。
 */
@Service
public class PublicKbService {

    private static final Logger logger = LoggerFactory.getLogger(PublicKbService.class);

    /** 每个公开查询最多出多少条（页面是"检索预览"，不是列表页） */
    @Value("${app.public-kb.top-k:3}")
    private int topK;

    /** 片段摘要最大字符数 */
    @Value("${app.public-kb.snippet-chars:300}")
    private int snippetChars;

    @Autowired
    private VectorSearchService vectorSearchService;

    @Autowired
    private PublicKbVisibility visibility;

    /** 输出脱敏器（IP 掩码 / 凭据 / 内部路径）。可空注入便于单测。 */
    @Autowired(required = false)
    private PublicOutputGuard outputGuard;

    /**
     * 公开检索。
     *
     * @param query 访客问题（调用方已做长度与注入检查）
     * @return 结果列表；检索不可用时返回空列表（调用方如实标注"检索不可用"，
     *         绝不用其它数据顶替）
     */
    public List<Map<String, Object>> search(String query) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (query == null || query.isBlank()) {
            return out;
        }

        List<VectorSearchService.SearchResult> hits;
        try {
            // 多取一些：被可见性过滤掉的可能不少，取少了公开结果会莫名偏少
            hits = vectorSearchService.searchSimilarDocuments(query, Math.max(topK * 4, 12));
        } catch (Exception e) {
            // 无真实 Embedding Key / 网络异常：如实上抛"检索不可用"，不降级成关键字匹配
            // （关键字匹配会绕过向量库的可见性元数据，等于换了另一套口径）
            logger.warn("公开知识库检索不可用（向量检索异常）：{}", e.getMessage());
            throw new PublicKbUnavailableException("向量检索不可用：" + e.getMessage(), e);
        }

        int denied = 0;
        for (VectorSearchService.SearchResult h : hits) {
            Map<String, Object> meta = h.getMetadata() == null ? Map.of() : h.getMetadata();
            String source = str(meta.get("_source"));
            String fileName = str(meta.get("_file_name"));
            String sourceType = str(meta.get("_source_type"));

            String reason = visibility.denyReason(source, fileName, sourceType);
            if (reason != null) {
                denied++;
                // 只记原因、不记"被拒的是哪一篇"：日志本身也不该成为内部清单
                logger.debug("公开检索剔除一份文档：{}", reason);
                continue;
            }

            Map<String, Object> item = new LinkedHashMap<>();
            item.put("title", sanitize(clip(cleanTitle(str(meta.get("title")), fileName), 120)));
            item.put("snippet", sanitize(clip(stripMarkdown(h.getContent()), snippetChars)));
            item.put("sourceType", sourceType == null ? "unknown" : sourceType);
            item.put("sourceTypeLabel", sourceTypeLabel(sourceType));
            item.put("trustLevel", trustLevel(meta));
            item.put("trustLevelLabel", trustLevelLabel(trustLevel(meta)));
            item.put("score", Math.round(h.getScore() * 1000f) / 1000f);
            item.put("publicRule", "公开白名单命中（" + originLabel(str(meta.get("_source")), fileName) + "）");
            out.add(item);
            if (out.size() >= Math.max(1, topK)) {
                break;
            }
        }

        if (denied > 0) {
            logger.info("公开知识库检索：原始命中 {} 条，因公开口径剔除 {} 条，实际返回 {} 条",
                    hits.size(), denied, out.size());
        }
        return out;
    }

    /**
     * 公开口径的自述（给页面用：让访客知道"少看到的东西是有意的"，
     * 也让站主能一眼核对当前生效的白名单）。
     */
    public Map<String, Object> ruleSummary() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("allowedRoots", visibility.allowedRoots());
        m.put("allowedSourceTypes", visibility.allowedSourceTypes());
        m.put("note", "只检索公开白名单目录下的文档；未标注来源类型的文档一律不参与公开检索。"
                + "内部文档即使被语义命中也不会出现在这里。");
        return m;
    }

    // ==================== 输出加工 ====================

    /** 标题：元数据 title 优先（是文档内部的小节名），缺失时退化成文件名去掉扩展名 */
    private static String cleanTitle(String title, String fileName) {
        if (title != null && !title.isBlank() && !"null".equalsIgnoreCase(title)) {
            return title.trim();
        }
        if (fileName == null || fileName.isBlank()) {
            return "（未命名片段）";
        }
        String base = fileName.replace('\\', '/');
        int slash = base.lastIndexOf('/');
        if (slash >= 0) {
            base = base.substring(slash + 1);
        }
        int dot = base.lastIndexOf('.');
        if (dot > 0) {
            base = base.substring(0, dot);
        }
        return base;
    }

    /** 片段去掉 markdown 标题记号与过多空行，读起来像一段摘要而不是源码 */
    private static String stripMarkdown(String s) {
        if (s == null) {
            return "";
        }
        String v = s.replace("\r\n", "\n").replace('\r', '\n');
        v = v.replaceAll("(?m)^#{1,6}\\s*", "");     // 标题记号
        v = v.replaceAll("(?m)^[-*+]\\s+", "· ");     // 列表记号换成可读符号
        v = v.replaceAll("\\n{2,}", "\n");            // 连续空行压成一行
        return v.trim();
    }

    /** 按字符截断，保留"已截断"信号 */
    private static String clip(String s, int max) {
        if (s == null) {
            return "";
        }
        String v = s.trim();
        if (max <= 0 || v.length() <= max) {
            return v;
        }
        return v.substring(0, max) + "…";
    }

    /** 出海前统一脱敏：IP 掩码 + 凭据 + 内部路径 + 内部标记 */
    private String sanitize(String s) {
        if (outputGuard == null || s == null) {
            // 脱敏器缺失时按最保守处理：宁可少给内容，也不原样透出
            return org.example.publicapi.PublicIpMask.maskAll(s);
        }
        return outputGuard.sanitize(s).text();
    }

    private static String originLabel(String source, String fileName) {
        String p = (source != null && !source.isBlank()) ? source : fileName;
        if (p == null) {
            return "来源未知";
        }
        String lower = p.toLowerCase(Locale.ROOT).replace('\\', '/');
        if (lower.contains("kb-approved")) {
            return "人工审核通过的知识";
        }
        if (lower.contains("security-docs")) {
            return "内置安全知识库";
        }
        return "公开白名单文档";
    }

    private static String sourceTypeLabel(String sourceType) {
        if (sourceType == null || sourceType.isBlank()) {
            return "来源类型未标注";
        }
        return switch (sourceType.toLowerCase(Locale.ROOT)) {
            case "community" -> "社区/内部整理（可信度中）";
            case "vendor" -> "厂商文档";
            case "official" -> "官方公告/标准";
            default -> sourceType;
        };
    }

    private static String trustLevel(Map<String, Object> meta) {
        String v = str(meta.get("_trust_level"));
        return (v == null || v.isBlank()) ? "unknown" : v;
    }

    private static String trustLevelLabel(String level) {
        return switch (level == null ? "unknown" : level.toLowerCase(Locale.ROOT)) {
            case "high" -> "可信度高";
            case "medium" -> "可信度中";
            case "low" -> "可信度低";
            default -> "可信度未标注";
        };
    }

    private static String str(Object v) {
        return v == null ? null : String.valueOf(v);
    }

    /**
     * 检索不可用（embedding Key 缺失 / 网络异常）。
     *
     * <p>单独一个异常类型：公开端点要如实回"检索不可用，未生成"，
     * 而不是回"没有命中" —— 这两件事对访客的含义完全不同
     * （一个是"我们库里没有"，一个是"我们的检索坏了"）。
     */
    public static class PublicKbUnavailableException extends RuntimeException {
        public PublicKbUnavailableException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}

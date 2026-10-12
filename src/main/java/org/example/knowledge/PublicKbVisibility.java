package org.example.knowledge;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * 知识库的<b>公开可见性</b>口径（P4：公开只读检索）。
 *
 * <h3>为什么需要它</h3>
 * 内部检索（自用界面、研判链路）允许看到全部知识：内置安全知识库、
 * 人工审核通过的知识、以及将来可能接入的内部文档。但公开检索是<b>匿名可达</b>的，
 * "与内部检索共用同一个库"就等于把内部资料默认公开 —— 新增一份内部文档时
 * 不会有任何提示，它自动就公开了。
 *
 * <p>所以这里采用的不是"标记为内部的才隐藏"，而是反过来：
 * <b>只有明确命中公开白名单的才放行，其余一律不参与公开检索</b>。
 * 代价是新增公开文档时要显式加白（一次配置），收益是"忘记标记"不再等于泄露。
 *
 * <h3>判定依据为什么落在「来源路径」上</h3>
 * 向量库元数据里能用的字段只有 {@code _file_name} / {@code _source} /
 * {@code _source_type} / {@code _trust_level}（见 {@code InMemoryVectorStoreGateway}
 * 落盘的结构，以及 {@code KnowledgeCatalog} 的读取方式）。
 * 没有"文档分类"这类业务字段可用，所以最小实现取两条：
 * <ol>
 *   <li><b>根目录白名单</b>（{@code app.public-kb.allowed-roots}，默认 {@code security-docs}）：
 *       路径必须落在白名单目录之下 —— 内置 33 篇安全知识确实是对外内容；</li>
 *   <li><b>来源类型白名单</b>（{@code app.public-kb.allowed-source-types}，默认 {@code community}）：
 *       {@code _source_type} 必须明确在名单内。<b>缺失即拒绝</b>，
 *       因为"没有标注来源"的文档恰恰是最需要用标记隔离的那一类。</li>
 * </ol>
 *
 * <p>另有一条<b>兜底黑名单</b>（{@code denied-keywords}，默认 {@code internal}）：
 * 路径或来源类型里出现该词即拒绝，用于"文档放在白名单目录里、但它是内部稿"的情况。
 * 黑名单不是主防线（它永远列不全），只是把已知的坑先堵上。
 *
 * <h3>它不负责什么</h3>
 * 它只回答"这份文档能不能参与公开检索"，<b>不</b>负责脱敏（那是
 * {@code PublicOutputGuard} / 公开端点的事）、也不做任何安全判定。
 * 把两件事混在一起，就会出现"因为脱敏器加了条规则，检索结果突然变少"这种查不动的现象。
 */
@Component
public class PublicKbVisibility {

    private static final Logger logger = LoggerFactory.getLogger(PublicKbVisibility.class);

    /**
     * 允许公开的根目录（相对工程根，逗号分隔）。
     *
     * <p>默认 {@code security-docs}：仓库里那 33 篇面向公众的安全知识
     * （OWASP、应急响应、加固基线…），它们本来就是博客上要展示的内容。
     * 另加 {@code data/kb-approved}：人工审核通过的知识同样是对外可讲的处置经验
     * （审核动作本身就是"可以公开"的判定，见 {@code KnowledgePendingService}）。
     */
    @Value("${app.public-kb.allowed-roots:security-docs,data/kb-approved}")
    private String allowedRootsRaw;

    /**
     * 允许公开的来源类型（{@code _source_type}，逗号分隔）。
     *
     * <p>默认只放 {@code community}（内置语料的标注值）。将来接入"厂商手册 / 官方公告"
     * 这类同样适合公开的来源，加到这里即可；而缺少该字段的文档<b>不会</b>被放行。
     */
    @Value("${app.public-kb.allowed-source-types:community}")
    private String allowedSourceTypesRaw;

    /**
     * 拒绝关键词（路径 / 来源类型里出现即拒绝，逗号分隔，大小写不敏感）。
     *
     * <p>默认 {@code internal}：项目里"内部资料"的既有命名习惯就是这个名字
     * （{@code docs/internal/}）。它挡不住改名，所以它是补丁不是防线。
     */
    @Value("${app.public-kb.denied-keywords:internal}")
    private String deniedKeywordsRaw;

    private final List<String> allowedRoots = new ArrayList<>();
    private final Set<String> allowedSourceTypes = new java.util.LinkedHashSet<>();
    private final List<String> deniedKeywords = new ArrayList<>();

    @jakarta.annotation.PostConstruct
    public void init() {
        allowedRoots.clear();
        for (String s : split(allowedRootsRaw)) {
            allowedRoots.add(normalizeRoot(s));
        }
        allowedSourceTypes.clear();
        for (String s : split(allowedSourceTypesRaw)) {
            allowedSourceTypes.add(s.toLowerCase(Locale.ROOT));
        }
        deniedKeywords.clear();
        for (String s : split(deniedKeywordsRaw)) {
            deniedKeywords.add(s.toLowerCase(Locale.ROOT));
        }
        logger.info("公开知识库可见性口径：允许根目录={}，允许来源类型={}，拒绝关键词={}",
                allowedRoots, allowedSourceTypes, deniedKeywords);
    }

    /**
     * 判定一份知识文档是否允许参与<b>公开</b>检索。
     *
     * @param sourcePath  元数据 {@code _source}（通常是绝对路径）
     * @param fileName    元数据 {@code _file_name}（通常只有文件名）
     * @param sourceType  元数据 {@code _source_type}（可能为 null）
     * @return 允许公开返回 {@code null}；否则返回<b>拒绝原因</b>（用于日志与排障，
     *         不回给访客 —— 公开端点不该解释"你少看到了哪份内部文档"）
     */
    public String denyReason(String sourcePath, String fileName, String sourceType) {
        String path = firstNonBlank(sourcePath, fileName);
        if (path == null) {
            return "缺少来源路径与文件名，无法判定是否公开（默认不公开）";
        }
        String lowerPath = path.toLowerCase(Locale.ROOT).replace('\\', '/');

        for (String kw : deniedKeywords) {
            if (lowerPath.contains(kw)) {
                return "路径命中拒绝关键词：" + kw;
            }
        }
        if (sourceType == null || sourceType.isBlank()) {
            return "缺少 _source_type 标注（未标注来源的文档不参与公开检索）";
        }
        String st = sourceType.trim().toLowerCase(Locale.ROOT);
        for (String kw : deniedKeywords) {
            if (st.contains(kw)) {
                return "来源类型命中拒绝关键词：" + kw;
            }
        }
        if (!allowedSourceTypes.isEmpty() && !allowedSourceTypes.contains(st)) {
            return "来源类型不在公开白名单（" + st + "）";
        }
        if (!allowedRoots.isEmpty() && !underAnyAllowedRoot(lowerPath)) {
            return "路径不在公开白名单根目录之下";
        }
        return null;
    }

    /** 判定便捷方法：允许公开返回 true */
    public boolean isPublic(String sourcePath, String fileName, String sourceType) {
        return denyReason(sourcePath, fileName, sourceType) == null;
    }

    /** 当前生效的允许根目录（供公开端点如实展示口径，便于自查） */
    public List<String> allowedRoots() {
        return new ArrayList<>(allowedRoots);
    }

    /** 当前生效的允许来源类型 */
    public List<String> allowedSourceTypes() {
        return new ArrayList<>(allowedSourceTypes);
    }

    /**
     * 路径是否落在任一白名单根目录之下。
     *
     * <h3>为什么要"逐级回退"比较</h3>
     * 元数据里的 {@code _source} 是<b>建库那台机器</b>上的绝对路径
     * （例如 {@code F:/7AAA/AI/SecAgent/sec-agent/security-docs/xx.md}），
     * 而白名单写的是<b>相对工程根</b>的 {@code security-docs}。
     * 两者不是同一种形式，所以不能直接用 {@code startsWith} 比 ——
     * 那样要么全部拒绝（公开检索永远空），要么只能放宽成"包含即可"
     * （{@code /tmp/security-docs-backup/内部稿.md} 也会被放行）。
     *
     * <p>做法：从路径的<b>最后两段</b>开始逐级往左拼，
     * 只要某一级恰好以白名单根目录开头就放行。
     * 层级上限 {@value #MAX_REL_DEPTH} 段 —— 白名单根目录本身最多两层
     * （{@code security-docs} / {@code data/kb-approved}），
     * 多留两级是为了容忍 {@code ./} 之类的写法。
     */
    private boolean underAnyAllowedRoot(String lowerPath) {
        Path p = Paths.get(lowerPath);
        int total = p.getNameCount();
        if (total == 0) {
            return false;
        }
        for (int take = Math.min(total, MAX_REL_DEPTH); take >= 1; take--) {
            // 取末尾 take 段拼成候选相对路径
            StringBuilder sb = new StringBuilder();
            for (int i = total - take; i < total; i++) {
                if (sb.length() > 0) {
                    sb.append('/');
                }
                sb.append(p.getName(i).toString());
            }
            String candidate = sb.toString();
            for (String root : allowedRoots) {
                if (candidate.equals(root) || candidate.startsWith(root + "/")) {
                    return true;
                }
            }
        }
        return false;
    }

    /** 白名单根目录本身最多两层，另留两级容忍 {@code ./} 之类写法 */
    private static final int MAX_REL_DEPTH = 4;

    private static String normalizeRoot(String s) {
        String v = s.trim().replace('\\', '/').toLowerCase(Locale.ROOT);
        while (v.startsWith("./")) {
            v = v.substring(2);
        }
        while (v.endsWith("/")) {
            v = v.substring(0, v.length() - 1);
        }
        return v;
    }

    private static List<String> split(String csv) {
        List<String> out = new ArrayList<>();
        if (csv == null) {
            return out;
        }
        for (String s : csv.split(",")) {
            if (!s.trim().isEmpty()) {
                out.add(s.trim());
            }
        }
        return out;
    }

    private static String firstNonBlank(String a, String b) {
        if (a != null && !a.isBlank()) {
            return a;
        }
        return (b != null && !b.isBlank()) ? b : null;
    }
}

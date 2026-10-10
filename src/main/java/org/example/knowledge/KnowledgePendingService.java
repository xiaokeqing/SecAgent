package org.example.knowledge;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.example.security.PromptInjectionGuard;
import org.example.service.VectorIndexService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * 知识"待审核 / 已通过"队列（防知识库与记忆投毒，对应 ASI06）。
 *
 * <p>核心原则：任何不可信内容在"注入检测 + 人工审核通过"之前，绝不进入检索/记忆。
 * <ul>
 *   <li>submit / autoCapture 写入【前】先过 {@link PromptInjectionGuard#scan}，命中即拒、不落盘；</li>
 *   <li>未审核条目状态固定 PENDING，只存在于待审核队列，检索看不到；</li>
 *   <li>管理员 approve 后才进入"已通过"库，可被检索（无 Embedding Key 时先走关键字匹配，标注"待向量化"）。</li>
 * </ul>
 */
@Service
public class KnowledgePendingService {

    private static final Logger logger = LoggerFactory.getLogger(KnowledgePendingService.class);

    public static final String SOURCE_MANUAL = "人工提交";
    public static final String SOURCE_CHAT_AUTO = "对话自动写入";
    public static final String SOURCE_FORENSIC_AUTO = "取证自动写入";

    private final PromptInjectionGuard injectionGuard;
    private final KnowledgeCatalog catalog;
    private final ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @Value("${knowledge.pending-file:data/kb-pending.json}")
    private String pendingFile;

    @Value("${knowledge.approved-file:data/kb-approved.json}")
    private String approvedFile;

    @Value("${knowledge.auto-write:true}")
    private boolean autoWrite;

    /** 待审核队列（PENDING） */
    private final List<KbEntry> pending = new ArrayList<>();

    /** 已通过库（APPROVED） */
    private final List<KbEntry> approved = new ArrayList<>();

    public KnowledgePendingService(PromptInjectionGuard injectionGuard, KnowledgeCatalog catalog) {
        this.injectionGuard = injectionGuard;
        this.catalog = catalog;
    }

    /** 案例回填用：审核通过后把知识沉淀为案例文档并重新向量化 */
    @org.springframework.beans.factory.annotation.Autowired
    private VectorIndexService vectorIndexService;

    /** 人工审核通过的案例文档存放目录 */
    @Value("${knowledge.case-dir:./uploads/auto-cases}")
    private String caseDir;

    @PostConstruct
    public void init() {
        load();
        logger.info("知识审核队列加载完成：待审核 {} 条，已通过 {} 条，auto-write={}",
                pending.size(), approved.size(), autoWrite);
    }

    // ---------------- 加载 / 落盘 ----------------

    private synchronized void load() {
        pending.clear();
        approved.clear();
        pending.addAll(readList(pendingFile));
        approved.addAll(readList(approvedFile));
    }

    private List<KbEntry> readList(String file) {
        Path p = Paths.get(file);
        if (!Files.exists(p)) return new ArrayList<>();
        try {
            byte[] bytes = Files.readAllBytes(p);
            if (bytes.length == 0) return new ArrayList<>();
            return mapper.readValue(bytes, new TypeReference<List<KbEntry>>() {});
        } catch (Exception e) {
            logger.warn("读取知识队列文件 {} 失败，按空处理：{}", file, e.getMessage());
            return new ArrayList<>();
        }
    }

    private synchronized void persistPending() {
        writeList(pendingFile, pending);
    }

    private synchronized void persistApproved() {
        writeList(approvedFile, approved);
    }

    private void writeList(String file, List<KbEntry> data) {
        try {
            Path p = Paths.get(file);
            if (p.getParent() != null) Files.createDirectories(p.getParent());
            mapper.writeValue(p.toFile(), data);
        } catch (Exception e) {
            logger.error("写入知识队列文件 {} 失败：{}", file, e.getMessage(), e);
        }
    }

    // ---------------- 写入（人工 / 自动） ----------------

    /**
     * 提交一条知识。注入检测命中则拒绝（不入库）；否则进入待审核 PENDING。
     *
     * @throws IllegalArgumentException 内容为空 / 类别非法 / 命中提示注入
     */
    public synchronized KbEntry submit(String content, String category, String source, String actor) {
        if (content == null || content.trim().isEmpty()) {
            throw new IllegalArgumentException("知识内容不能为空");
        }
        String cat = (category == null || category.isBlank())
                ? KnowledgeCatalog.DEFAULT_CATEGORY : category.trim();
        if (!catalog.isKnownCategory(cat)) {
            throw new IllegalArgumentException("未知知识类别: " + category);
        }
        String src = (source == null || source.isBlank()) ? SOURCE_MANUAL : source.trim();

        // —— 防投毒第一道闸门：注入检测，命中一律拒绝，绝不入库 ——
        List<String> hits = injectionGuard.scan(content);
        if (!hits.isEmpty()) {
            logger.warn("知识提交被注入防护拦截：actor={}, source={}, hits={}, 内容前80字='{}'",
                    actor, src, hits, content.substring(0, Math.min(80, content.length())));
            throw new IllegalArgumentException(
                    "已被提示注入防护拦截，未入库。命中特征：" + String.join("；", hits));
        }

        KbEntry e = new KbEntry();
        e.setId(UUID.randomUUID().toString());
        e.setContent(content.trim());
        e.setCategory(cat);
        e.setSource(src);
        e.setActor(actor == null ? "anonymous" : actor);
        e.setCreatedAt(System.currentTimeMillis());
        e.setStatus("PENDING");
        e.setVectorized(false);
        pending.add(e);
        persistPending();
        logger.info("新知识进入待审核：id={}, category={}, source={}, actor={}", e.getId(), cat, src, e.getActor());
        return e;
    }

    /**
     * 供对话/取证自动写入候选。auto-write 关闭时不写；同样先过注入检测。
     *
     * @return 进入待审核的条目；auto-write 关闭或注入命中时返回 null
     */
    public KbEntry autoCapture(String content, String category, String source, String actor) {
        if (!autoWrite) {
            logger.info("auto-write 已关闭，自动写入候选被丢弃：{}",
                    content == null ? "" : content.substring(0, Math.min(40, content.length())));
            return null;
        }
        try {
            return submit(content, category, source, actor);
        } catch (IllegalArgumentException e) {
            // 自动写入命中注入或参数非法：不落盘，仅记录
            logger.warn("自动写入候选被丢弃：{}", e.getMessage());
            return null;
        }
    }

    // ---------------- 审核 ----------------

    public synchronized List<KbEntry> listPending() {
        return new ArrayList<>(pending);
    }

    public synchronized List<KbEntry> listApproved() {
        return new ArrayList<>(approved);
    }

    /**
     * 审核通过：移入已通过库。无真实 Embedding Key 时先进入"本地已通过关键字库"，标注待向量化。
     *
     * @throws IllegalArgumentException 找不到该待审核条目
     */
    public synchronized KbEntry approve(String id, String actor) {
        KbEntry found = null;
        for (KbEntry e : pending) {
            if (e.getId().equals(id)) { found = e; break; }
        }
        if (found == null) {
            throw new IllegalArgumentException("待审核条目不存在或已处理: " + id);
        }
        pending.remove(found);
        found.setStatus("APPROVED");
        found.setApprovedBy(actor);
        found.setApprovedAt(System.currentTimeMillis());
        found.setVectorized(false); // 待回填向量化（无 Embedding Key 时先关键字检索）
        approved.add(found);
        persistPending();
        persistApproved();
        // 审核通过 → 沉淀为案例文档并向量化回填（知识自成长闭环最后一步）
        backfillAsCase(found);
        logger.info("知识审核通过并回填：id={}, category={}, source={}, 审核人={}, vectorized={}",
                id, found.getCategory(), found.getSource(), actor, found.isVectorized());
        return found;
    }

    /**
     * 审核通过后把知识沉淀为案例文档并回填：
     * 写带 front-matter（人工审核确认，source=official / trust=high）的案例 .md，再调
     * {@link VectorIndexService#indexSingleFile} 向量化；无 Embedding Key 时向量化失败不阻断，
     * 标记"待向量化"、此时由 {@link #searchApproved} 关键字检索兜底，配好 Key 后可重建索引。
     */
    private void backfillAsCase(KbEntry e) {
        try {
            Path dir = Paths.get(caseDir);
            Files.createDirectories(dir);
            String today = java.time.LocalDate.now().toString();
            String fileName = "case-" + e.getId().substring(0, Math.min(8, e.getId().length())) + ".md";
            Path file = dir.resolve(fileName);

            StringBuilder sb = new StringBuilder();
            sb.append("---\n");
            sb.append("source: official\n");
            sb.append("trust: high\n");
            sb.append("date: ").append(today).append("\n");
            sb.append("---\n\n");
            sb.append("# 人工审核回填案例（类别：").append(e.getCategory()).append("）\n\n");
            sb.append("来源：").append(e.getSource()).append("\n\n");
            sb.append(e.getContent()).append("\n");
            Files.writeString(file, sb.toString());
            logger.info("案例文档已生成：{}", file);

            try {
                vectorIndexService.indexSingleFile(file.toString());
                e.setVectorized(true);
                logger.info("案例已向量化回填：{}", file);
            } catch (Exception ve) {
                e.setVectorized(false);
                logger.warn("案例暂未向量化（可能无 Embedding Key），先走关键字检索：{}", ve.getMessage());
            }
            persistApproved(); // 回写 vectorized 状态
        } catch (Exception ex) {
            logger.error("案例回填失败：{}", ex.getMessage());
        }
    }

    /** 审核驳回：从待审核队列移除，不入库。 */
    public synchronized void reject(String id, String actor) {
        KbEntry found = null;
        for (KbEntry e : pending) {
            if (e.getId().equals(id)) { found = e; break; }
        }
        if (found == null) {
            throw new IllegalArgumentException("待审核条目不存在或已处理: " + id);
        }
        pending.remove(found);
        persistPending();
        logger.info("知识审核驳回：id={}, category={}, source={}, 审核人={}",
                id, found.getCategory(), found.getSource(), actor);
    }

    /**
     * 在"已通过"知识里做关键字匹配（无向量时的兜底检索）。
     * 命中即返回，来源标注"本地已通过"。
     */
    public synchronized List<KbEntry> searchApproved(String query, String category) {
        List<KbEntry> out = new ArrayList<>();
        if (query == null || query.isBlank()) return out;
        String q = query.trim().toLowerCase();
        for (KbEntry e : approved) {
            if (category != null && !category.isBlank() && !"全部".equals(category)
                    && !category.equals(e.getCategory())) {
                continue;
            }
            String text = e.getContent() == null ? "" : e.getContent().toLowerCase();
            if (text.contains(q)) {
                out.add(e);
            }
        }
        return out;
    }

    public boolean isAutoWrite() {
        return autoWrite;
    }
}

package org.example.rag;

import org.example.vector.ScoredDoc;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 混合检索器：<b>BM25 稀疏 + 稠密（余弦）→ RRF 融合 → 可解释轻量重排</b>。
 *
 * <h3>完整数据流（每一步都可单独关掉）</h3>
 * <pre>
 *   query ──┬─→ 稠密通道：embedding(query) → gateway.search(vec, candidateK)
 *           │                     → 剔除 score &lt; minScore
 *           └─→ 稀疏通道：BM25(query) → top candidateK（sparse.enabled=false 时跳过）
 *                            ↓
 *                     RRF 融合（按名次，k = rrf.k；免疫两路分数不同量纲）
 *                            ↓
 *              轻量重排（命中词覆盖 / 标题 / 长度惩罚 / 字符 n-gram；rerank.enabled=false 时跳过）
 *                            ↓
 *                         取前 topK
 * </pre>
 *
 * <h3>与"改造前"的口径关系</h3>
 * 改造前 = 只走稠密通道 + 剔低分 + 直接取前 topK。
 * 把 {@code sparse.enabled=false}、{@code rerank.enabled=false} 同时关掉，
 * 并且候选池与 topK 相同，得到的就是改造前的排序 —— 这就是"回退纯稠密"的路径
 * （RUNBOOK §25 有命令）。<b>回退不需要改代码、也不需要重新部署</b>。
 *
 * <h3>线程安全</h3>
 * 本类无状态（BM25 索引缓存在 {@link SparseIndexCache} 里，按语料版本重建）。
 * 因此同一个实例可被并发调用，也可以按不同阈值临时构造多个实例而不重复建索引。
 */
public final class HybridRetriever {

    private static final Logger logger = LoggerFactory.getLogger(HybridRetriever.class);

    /** 检索通道标记 */
    public static final String CH_DENSE = "dense";
    public static final String CH_SPARSE = "sparse";

    /** 单条检索结果（上层据此做字段白名单 / 排序 / 溯源） */
    public static final class Hit {
        private final ScoredDoc doc;
        private final double score;
        private final List<String> sources;
        private final Double sparseScore;
        private final Double denseScore;

        Hit(ScoredDoc doc, double score, List<String> sources, Double sparseScore, Double denseScore) {
            this.doc = doc;
            this.score = score;
            this.sources = sources;
            this.sparseScore = sparseScore;
            this.denseScore = denseScore;
        }

        public ScoredDoc doc() {
            return doc;
        }

        /** 最终排序分（重排开启时是重排分；关闭时是 RRF 分） */
        public double score() {
            return score;
        }

        /** 该条被哪些通道召回（dense / sparse） */
        public List<String> sources() {
            return sources;
        }

        /** BM25 原始分（这条不是稀疏命中时为 null） */
        public Double sparseScore() {
            return sparseScore;
        }

        /** 余弦相似度（这条不是稠密命中时为 null） */
        public Double denseScore() {
            return denseScore;
        }

        public boolean bothChannels() {
            return sources.size() > 1;
        }
    }

    /** 一次检索的完整结果（含"哪一路到底跑没跑"的自述，便于排障与如实降级） */
    public static final class Result {
        private final List<Hit> hits;
        private final String mode;
        private final int candidateK;
        private final int denseCandidates;
        private final int sparseCandidates;
        private final String note;

        Result(List<Hit> hits, String mode, int candidateK, int denseCandidates, int sparseCandidates, String note) {
            this.hits = hits;
            this.mode = mode;
            this.candidateK = candidateK;
            this.denseCandidates = denseCandidates;
            this.sparseCandidates = sparseCandidates;
            this.note = note;
        }

        public List<Hit> hits() {
            return hits;
        }

        /** {@code dense+sparse+rerank} / {@code dense+sparse} / {@code dense} 等自述 */
        public String mode() {
            return mode;
        }

        public int candidateK() {
            return candidateK;
        }

        public int denseCandidates() {
            return denseCandidates;
        }

        public int sparseCandidates() {
            return sparseCandidates;
        }

        public String note() {
            return note;
        }

        /** 只要文档（多数调用方只需要这个） */
        public List<ScoredDoc> docs() {
            List<ScoredDoc> out = new ArrayList<>(hits.size());
            for (Hit h : hits) {
                out.add(h.doc());
            }
            return out;
        }
    }

    /** 嵌入器：把查询文本变成向量（生产走 DashScope；评测走夹具里缓存的真实查询向量） */
    public interface QueryEmbedder {
        List<Float> embed(String query);
    }

    /** 稠密检索：给定查询向量与条数，返回候选（由存储侧按相似度排序） */
    public interface DenseSearch {
        List<ScoredDoc> search(List<Float> queryVector, int topK);
    }

    private final QueryEmbedder embedder;
    private final DenseSearch dense;
    private final SparseIndexCache sparseIndex;
    private final RagProperties props;
    private final float minScore;

    public HybridRetriever(QueryEmbedder embedder, DenseSearch dense, SparseIndexCache sparseIndex,
                           RagProperties props, float minScore) {
        this.embedder = embedder;
        this.dense = dense;
        this.sparseIndex = sparseIndex == null ? SparseIndexCache.disabled(props) : sparseIndex;
        this.props = props;
        this.minScore = minScore;
    }

    public RagProperties properties() {
        return props;
    }

    /** 当前 BM25 索引（可能触发一次按版本的重建）；不可用时返回 null */
    public Bm25Index bm25() {
        return sparseIndex.get();
    }

    /**
     * 混合检索。
     *
     * @param query 用户查询文本（调用方已做长度/注入检查）
     * @param topK  最终返回条数
     */
    public Result retrieve(String query, int topK) {
        int want = Math.max(1, topK);
        int candidateK = Math.max(want, props.getCandidateK());
        List<ScoredDoc> denseHits = denseCandidates(query, candidateK);

        Bm25Index bm25 = sparseIndex.get();
        Map<String, List<ScoredDoc>> channels = new LinkedHashMap<>();
        channels.put(CH_DENSE, denseHits);

        List<Bm25Index.Hit> sparseHits = List.of();
        if (bm25 != null) {
            List<Bm25Index.Hit> raw = bm25.search(query, candidateK);
            List<Bm25Index.Hit> kept = new ArrayList<>();
            for (Bm25Index.Hit h : raw) {
                if (props.getSparseMinScore() > 0 && h.score < props.getSparseMinScore()) {
                    continue;
                }
                kept.add(h);
            }
            sparseHits = kept;
            List<ScoredDoc> sparseDocs = new ArrayList<>(kept.size());
            for (Bm25Index.Hit h : kept) {
                sparseDocs.add(h.doc);
            }
            channels.put(CH_SPARSE, sparseDocs);
        }

        List<RrfFusion.Fused> fused = RrfFusion.fuse(props.getRrfK(), channels, ScoredDoc::getId);

        // 同一片段可能两路都召回：正文/元数据统一取"稠密那条"（两路共享同一批 ScoredDoc，
        // 但显式统一来源可以避免将来两条通道给出不同正文时出现展示不一致）
        Map<String, ScoredDoc> denseById = new HashMap<>();
        for (ScoredDoc d : denseHits) {
            if (d.getId() != null) {
                denseById.putIfAbsent(d.getId(), d);
            }
        }
        Map<String, Double> rrfScores = new LinkedHashMap<>();
        Map<String, Double> sparseScoreById = new LinkedHashMap<>();
        Map<String, Double> denseScoreById = new LinkedHashMap<>();
        Set<String> both = new LinkedHashSet<>();
        List<ScoredDoc> candidates = new ArrayList<>(fused.size());
        for (RrfFusion.Fused f : fused) {
            ScoredDoc d = denseById.get(f.docId());
            if (d == null) {
                d = f.doc();
            }
            candidates.add(d);
            rrfScores.put(f.docId(), f.score());
            if (f.bothChannels()) {
                both.add(f.docId());
            }
        }
        for (ScoredDoc d : denseHits) {
            if (d.getId() != null) {
                denseScoreById.put(d.getId(), (double) d.getScore());
            }
        }
        for (Bm25Index.Hit h : sparseHits) {
            if (h.doc.getId() != null) {
                sparseScoreById.put(h.doc.getId(), h.score);
            }
        }

        List<Hit> ranked = new ArrayList<>();
        if (props.isRerankEnabled() && !candidates.isEmpty()) {
            // 重排的"稀有度权重"来自同一份 BM25 索引的文档频率统计 ——
            // 这也解释了为什么关掉稀疏通道时重排会退化成普通覆盖度：
            // 没有索引就没有文档频率，"哪些词稀有"这件事无从判断（如实退化，不假装有信号）。
            Map<String, Double> weights = bm25 == null ? Map.of()
                    : bm25.rarityWeights(RagTokenizer.uniqueTerms(query, props.isSparseLatinTrigram()));
            List<RagReranker.Ranked> rr = RagReranker.rerank(
                    query, candidates, rrfScores, both, weights, props, props.isSparseLatinTrigram());
            for (RagReranker.Ranked r : rr) {
                String id = r.doc.getId();
                ranked.add(new Hit(r.doc, r.signals.finalScore,
                        sourcesOf(id, denseHits, sparseHits),
                        sparseScoreById.get(id), denseScoreById.get(id)));
            }
        } else {
            for (ScoredDoc d : candidates) {
                String id = d.getId();
                ranked.add(new Hit(d, rrfScores.getOrDefault(id, 0.0),
                        sourcesOf(id, denseHits, sparseHits),
                        sparseScoreById.get(id), denseScoreById.get(id)));
            }
        }

        List<Hit> top = ranked.size() > want ? new ArrayList<>(ranked.subList(0, want)) : ranked;
        String note = noteOf(bm25);
        logger.debug("混合检索：{}", describe(new Result(top, describeMode(bm25 != null), candidateK,
                denseHits.size(), sparseHits.size(), note)));
        return new Result(top, describeMode(bm25 != null), candidateK, denseHits.size(), sparseHits.size(), note);
    }

    private List<String> sourcesOf(String id, List<ScoredDoc> denseHits, List<Bm25Index.Hit> sparseHits) {
        List<String> out = new ArrayList<>(2);
        for (ScoredDoc d : denseHits) {
            if (id != null && id.equals(d.getId())) {
                out.add(CH_DENSE);
                break;
            }
        }
        for (Bm25Index.Hit h : sparseHits) {
            if (id != null && id.equals(h.doc.getId())) {
                out.add(CH_SPARSE);
                break;
            }
        }
        return out;
    }

    /**
     * 稠密候选：<b>与改造前完全相同的口径</b> —— gateway.search(vec, candidateK) + 剔低分。
     *
     * <p>刻意保留 minScore 过滤：它是"知识库未命中就走拒答"这条既有产品行为的依据
     * （见 {@code VectorSearchService}）。混合检索不改变"未命中"的判定门槛，
     * 否则会出现"检索看起来变好了，其实只是把该拒答的问题变成了硬答"。
     */
    private List<ScoredDoc> denseCandidates(String query, int candidateK) {
        List<Float> vec = embedder.embed(query);
        if (vec == null || vec.isEmpty()) {
            return new ArrayList<>();
        }
        List<ScoredDoc> raw = dense.search(vec, candidateK);
        List<ScoredDoc> out = new ArrayList<>();
        if (raw == null) {
            return out;
        }
        for (ScoredDoc d : raw) {
            if (d == null) {
                continue;
            }
            if (minScore > 0 && d.getScore() < minScore) {
                logger.debug("  混合检索·稠密通道剔除低分结果: score={} < minScore={}", d.getScore(), minScore);
                continue;
            }
            out.add(d);
        }
        return out;
    }

    private String describeMode(boolean sparseAvailable) {
        StringBuilder sb = new StringBuilder(CH_DENSE);
        if (sparseAvailable) {
            sb.append('+').append(CH_SPARSE);
        }
        if (props.isRerankEnabled()) {
            sb.append("+rerank");
        }
        return sb.toString();
    }

    private String noteOf(Bm25Index bm25) {
        if (!props.isSparseEnabled()) {
            return "稀疏通道已关闭（app.rag.sparse.enabled=false）—— 本次为纯稠密口径";
        }
        if (bm25 == null) {
            return "稀疏通道不可用（存储后端未提供全量语料枚举）—— 本次为纯稠密口径";
        }
        return "两路召回 + RRF(k=" + props.getRrfK() + ")"
                + (props.isRerankEnabled() ? " + 轻量重排" : "（重排已关闭）");
    }

    /** 各阶段规模摘要（排障/评测用；不含用户隐私内容） */
    public static String describe(Result r) {
        return String.format(java.util.Locale.ROOT,
                "mode=%s candidateK=%d dense=%d sparse=%d 返回=%d",
                r.mode(), r.candidateK(), r.denseCandidates(), r.sparseCandidates(), r.hits().size());
    }
}

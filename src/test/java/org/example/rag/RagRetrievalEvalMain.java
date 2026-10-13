package org.example.rag;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.vector.ScoredDoc;
import org.example.vector.memory.InMemoryVectorStoreGateway;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * 离线检索评测跑分器（同一批 query、同一份知识库、同一批缓存查询向量）。
 *
 * <h3>为什么要这么一个 main，而不是直接跑 eval-papers.py</h3>
 * {@code scripts/eval-papers.py} 量的是"整条链路（检索 + 模型 + 护栏）"的引用溯源率，
 * 它<b>看不见检索层自己的命中</b>：模型答错可能是检索没给对片段，也可能是模型没用片段，
 * 这两件事的修法完全不同。所以这里再补一台只量检索的跑分器：
 * <ul>
 *   <li>语料：{@code data/vector-store.json} 里那 318 条真实分片（与线上一模一样）；</li>
 *   <li>稠密通道：真实分片向量 + 真实查询向量（{@code src/test/resources/rag-eval/retrieval-queries.json}，
 *       由 scripts/rag-eval/build-query-fixture.py 用线上同一 embedding 模型一次性生成）；</li>
 *   <li>基线口径：与改造前 {@code PublicKbService.search()} 完全一致 ——
 *       {@code store.search(vec, max(topK*4,12))} → 剔除 score &lt; 0.30 → 取前 topK；</li>
 *   <li>改后口径：{@code HybridRetriever}（BM25 + RRF + 轻量重排），同样的候选与同样的 topK。</li>
 * </ul>
 *
 * <h3>两个指标，两个问题</h3>
 * <ul>
 *   <li><b>fileHit@k</b>：找对没找对<b>那一篇</b>（期望关键词命中 标题/文件名/来源路径）；</li>
 *   <li><b>evidenceHit@k</b>：前 k 条里有没有一条<b>正文真的含问题所问的确切证据</b>
 *       （罕见标识、配置项、函数名）。这是"引用能不能被核对"的可操作形式 ——
 *       一条不含所问标识的片段，即使来自对的文档，也无法支撑回答。</li>
 * </ul>
 * 分 A/B/C 三桶（A=概念改述，B=精确标识，C=运维配置）分别统计，避免用"对稀疏有利的题"
 * 冒充整体提升。
 *
 * <h3>怎么跑</h3>
 * <pre>
 *   mvn -q -B test-compile
 *   mvn -q -B dependency:build-classpath -Dmdep.outputFile=target/cp.txt -Dmdep.includeScope=test
 *   java -cp "target/classes;target/test-classes;$(cat target/cp.txt)" \
 *        org.example.rag.RagRetrievalEvalMain --mode baseline
 *   ... --mode hybrid
 * </pre>
 * 无网络、无费用、可重复（查询向量是缓存的）。
 */
public final class RagRetrievalEvalMain {

    /** 与 PublicKbService 一致：公开端点 topK=3、候选取 4 倍 */
    private static final int PUBLIC_TOP_K = 3;
    /** 与 VectorSearchService 一致的低分阈值（基线与改后的稠密通道都用它，保证是同一路召回） */
    public static final float DENSE_MIN_SCORE = 0.30f;
    /** 指标统计的排名上限 */
    private static final int RANK_LIMIT = 10;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        String mode = "both";
        String corpus = "data/vector-store.json";
        String fixture = "src/test/resources/rag-eval/retrieval-queries.json";
        String trace = null;
        for (int i = 0; i < args.length - 1; i++) {
            if ("--mode".equals(args[i])) {
                mode = args[i + 1];
            } else if ("--corpus".equals(args[i])) {
                corpus = args[i + 1];
            } else if ("--fixture".equals(args[i])) {
                fixture = args[i + 1];
            } else if ("--trace".equals(args[i])) {
                trace = args[i + 1];      // 例如 --trace q11：打印该 query 的逐条信号（查"为什么它掉下去了"）
            }
        }

        InMemoryVectorStoreGateway store = new InMemoryVectorStoreGateway();
        ReflectionTestUtils.setField(store, "persistFile", corpus);
        store.init();
        System.out.println("[eval] 语料=" + corpus + " 分片数=" + store.count());

        JsonNode doc = MAPPER.readTree(new File(fixture));
        List<JsonNode> queries = new ArrayList<>();
        doc.get("queries").forEach(queries::add);
        System.out.println("[eval] 查询集=" + fixture + " 条数=" + queries.size()
                + " embedding模型=" + doc.get("model").asText()
                + " 维度=" + doc.get("dimension").asInt());

        RagProperties props = new RagProperties();
        HybridEvalPipeline pipeline = new HybridEvalPipeline(store, props);

        // 先探一条，把"这次到底跑的是哪几路"打进输出 ——
        // 没有这行，一份"改后"的输出与"纯稠密"的输出长得一模一样，无法核对自己看的是哪一版。
        if (!queries.isEmpty()) {
            pipeline.forQuery(queries.get(0));
            HybridRetriever.Result probe = pipeline.retrieveFull(PUBLIC_TOP_K);
            System.out.println("[eval] 改后通道口径: 稀疏=" + props.isSparseEnabled()
                    + " 重排=" + props.isRerankEnabled()
                    + " rrfK=" + props.getRrfK()
                    + " 候选池=" + props.getCandidateK()
                    + " 稀疏最低分=" + props.getSparseMinScore()
                    + " 分词=" + RagTokenizer.describe(props.isSparseLatinTrigram()));
            System.out.println("[eval] 改后通道实测（q=" + queries.get(0).get("id").asText() + "）: "
                    + HybridRetriever.describe(probe));
        }

        if (trace != null) {
            traceQuery(store, pipeline, props, queries, trace);
            return;
        }

        EvalMetrics baseline = null;
        EvalMetrics hybrid = null;
        if ("baseline".equals(mode) || "both".equals(mode)) {
            baseline = evaluate("基线·纯稠密（余弦 + minScore=" + DENSE_MIN_SCORE + "）",
                    queries, q -> denseOnly(store, q));
        }
        if ("hybrid".equals(mode) || "both".equals(mode)) {
            hybrid = evaluate("改后·BM25+稠密 → RRF → 轻量重排",
                    queries, q -> pipeline.forQuery(q).retrieve(PUBLIC_TOP_K));
        }
        if (baseline != null && hybrid != null) {
            compare(baseline, hybrid);
        }

        // ===== 消融：每一条通道各自贡献多少（防止把"重排的功劳"说成"稀疏的功劳"）=====
        if ("ablation".equals(mode)) {
            Map<String, EvalMetrics> runs = new LinkedHashMap<>();
            runs.put("A 纯稠密（=改造前）", evaluate("A 纯稠密（=改造前）", queries, q -> denseOnly(store, q)));
            runs.put("B 稠密+重排（无稀疏）", evaluate("B 稠密+重排（无稀疏）", queries,
                    q -> ablationPipeline(store, false, true).forQuery(q).retrieve(PUBLIC_TOP_K)));
            runs.put("C 稠密+稀疏 → RRF（无重排）", evaluate("C 稠密+稀疏 → RRF（无重排）", queries,
                    q -> ablationPipeline(store, true, false).forQuery(q).retrieve(PUBLIC_TOP_K)));
            runs.put("D 稠密+稀疏+RRF+重排（默认）", evaluate("D 稠密+稀疏+RRF+重排（默认）", queries,
                    q -> pipeline.forQuery(q).retrieve(PUBLIC_TOP_K)));
            System.out.println();
            System.out.println("=== 消融对照（同一批 query / 同一份语料 / 同一套判据）===");
            System.out.printf("%-30s %-16s %-16s %-9s%n", "配置", "fileHit@3", "evidenceHit@3", "MRR");
            for (Map.Entry<String, EvalMetrics> e : runs.entrySet()) {
                EvalMetrics m = e.getValue();
                System.out.printf("%-30s %-16s %-16s %-9s%n", e.getKey(),
                        String.format(Locale.ROOT, "%d/%d=%.1f%%", m.fileHit3, m.n, 100.0 * m.fileHit3 / m.n),
                        String.format(Locale.ROOT, "%d/%d=%.1f%%", m.evHit3, m.n, 100.0 * m.evHit3 / m.n),
                        String.format(Locale.ROOT, "%.4f", m.mrr));
            }
            // 纯稀疏（BM25 单路）也有信息量：说明"中文 bigram 分词在无稠密时到什么水平"
            EvalMetrics sparseOnly = evaluate("E 纯稀疏（BM25 单路）", queries, q -> {
                Bm25Index idx = pipeline.sparseCache().get();
                List<ScoredDoc> out = new ArrayList<>();
                if (idx != null) {
                    for (Bm25Index.Hit h : idx.search(q.get("query").asText(""), PUBLIC_TOP_K)) {
                        out.add(h.doc);
                    }
                }
                return out;
            });
            System.out.printf("%-30s %-16s %-16s %-9s%n", "E 纯稀疏（BM25 单路）",
                    String.format(Locale.ROOT, "%d/%d=%.1f%%", sparseOnly.fileHit3, sparseOnly.n,
                            100.0 * sparseOnly.fileHit3 / sparseOnly.n),
                    String.format(Locale.ROOT, "%d/%d=%.1f%%", sparseOnly.evHit3, sparseOnly.n,
                            100.0 * sparseOnly.evHit3 / sparseOnly.n),
                    String.format(Locale.ROOT, "%.4f", sparseOnly.mrr));
        }
    }

    /**
     * 打印某个 query 在融合-重排前后的<b>逐条信号</b>。
     *
     * <p>为什么需要它：{"改后某一题掉出前 3 了"} 这种问题，光看汇总数字查不动 ——
     * 必须能看到"它 RRF 排第几、四个信号各是多少、最后被谁挤掉"。
     * 这是排障入口，也是"重排不是黑箱"的兑现方式。
     */
    private static void traceQuery(InMemoryVectorStoreGateway store, HybridEvalPipeline pipeline,
                                   RagProperties props, List<JsonNode> queries, String qid) {
        for (JsonNode q : queries) {
            if (!qid.equals(q.get("id").asText())) {
                continue;
            }
            System.out.println();
            System.out.println("=== 逐条信号追踪：query " + qid + " = 「" + q.get("query").asText() + "」===");
            List<Float> vec = toVector(q.get("vector"));
            Bm25Index idx = pipeline.sparseCache().get();
            List<ScoredDoc> dense = new ArrayList<>();
            for (ScoredDoc d : store.search(vec, props.getCandidateK())) {
                if (d.getScore() >= DENSE_MIN_SCORE) {
                    dense.add(d);
                }
            }
            List<Bm25Index.Hit> sparse = idx == null ? List.of()
                    : idx.search(q.get("query").asText(""), props.getCandidateK());
            Map<String, List<ScoredDoc>> ch = new LinkedHashMap<>();
            ch.put(HybridRetriever.CH_DENSE, dense);
            List<ScoredDoc> sparseDocs = new ArrayList<>();
            for (Bm25Index.Hit h : sparse) {
                sparseDocs.add(h.doc);
            }
            ch.put(HybridRetriever.CH_SPARSE, sparseDocs);
            List<RrfFusion.Fused> fused = RrfFusion.fuse(props.getRrfK(), ch, ScoredDoc::getId);
            Map<String, Double> rrf = new LinkedHashMap<>();
            Set<String> both = new LinkedHashSet<>();
            Map<String, ScoredDoc> byId = new LinkedHashMap<>();
            for (ScoredDoc d : dense) {
                byId.put(d.getId(), d);
            }
            for (Bm25Index.Hit h : sparse) {
                byId.putIfAbsent(h.doc.getId(), h.doc);
            }
            List<ScoredDoc> cands = new ArrayList<>();
            for (RrfFusion.Fused f : fused) {
                ScoredDoc d = byId.get(f.docId());
                if (d == null) {
                    continue;
                }
                cands.add(d);
                rrf.put(f.docId(), f.score());
                if (f.bothChannels()) {
                    both.add(f.docId());
                }
            }
            System.out.printf("稠密候选=%d 稀疏候选=%d 融合候选=%d%n", dense.size(), sparse.size(), cands.size());
            System.out.println("RRF 名次（前 12）：");
            for (int i = 0; i < Math.min(12, fused.size()); i++) {
                System.out.printf("  #%-3d rrf=%.5f both=%s %s%n", i + 1, fused.get(i).score(),
                        fused.get(i).bothChannels(), label(byId.get(fused.get(i).docId())));
            }
            List<RagReranker.Ranked> rr = RagReranker.rerank(q.get("query").asText(""), cands, rrf, both,
                    idx == null ? Map.of() : idx.rarityWeights(uniqueTerms(q.get("query").asText(""), true)),
                    props, props.isSparseLatinTrigram());
            System.out.println("重排后（前 12）：");
            for (int i = 0; i < Math.min(12, rr.size()); i++) {
                System.out.printf("  #%-3d %s %s%n", i + 1, RagReranker.describe(rr.get(i).signals),
                        label(rr.get(i).doc));
            }
            return;
        }
        System.out.println("[trace] 未找到 query " + qid);
    }

    private static String label(ScoredDoc d) {
        Map<String, Object> m = d == null || d.getMetadata() == null ? Map.of() : d.getMetadata();
        return m.get("_file_name") + " → " + m.get("title") + " [" + d.getId() + "]";
    }

    private static java.util.List<String> uniqueTerms(String text, boolean latinTrigram) {
        return RagTokenizer.uniqueTerms(text, latinTrigram);
    }

    // ==================== 改前/改后对照 ====================

    /**
     * 同一批 query、同一份知识库、同一条打分代码下的对照表。
     *
     * <h3>为什么把对照表也做进跑分器</h3>
     * "改完检索有没有变好"是这次改造的验收问题。如果对比要人工从两份几百行输出里摘数字，
     * 那份对比迟早会抄错、也会随代码漂移 —— 所以让跑分器自己出这张表，
     * 贴进交付说明的就是它打印的原文。
     */
    private static void compare(EvalMetrics b, EvalMetrics h) {
        System.out.println();
        System.out.println("=== 改前 / 改后 对照（同一批 query、同一份语料、同一套判据）===");
        System.out.printf("%-16s %-18s %-18s %-10s%n", "指标", "改前(纯稠密)", "改后(混合)", "变化");
        row("fileHit@3", b.fileHit3, h.fileHit3, b.n, h.n);
        row("evidenceHit@3", b.evHit3, h.evHit3, b.n, h.n);
        row("evidenceHit@5", b.evHit5, h.evHit5, b.n, h.n);
        row("evidenceHit(≤" + RANK_LIMIT + ")", b.evHitAny, h.evHitAny, b.n, h.n);
        System.out.printf("%-16s %-18s %-18s %-10s%n", "MRR(evidence)",
                String.format(Locale.ROOT, "%.4f", b.mrr), String.format(Locale.ROOT, "%.4f", h.mrr),
                String.format(Locale.ROOT, "%+.4f", h.mrr - b.mrr));
        for (String bucket : union(b.byBucket.keySet(), h.byBucket.keySet())) {
            int[] bb = b.byBucket.getOrDefault(bucket, new int[3]);
            int[] hh = h.byBucket.getOrDefault(bucket, new int[3]);
            int bn = bb[0], hn = hh[0];
            System.out.printf("桶 %-13s fileHit@3 %d/%d -> %d/%d ；evidenceHit@3 %d/%d -> %d/%d%n",
                    bucket, bb[1], bn, hh[1], hn, bb[2], bn, hh[2], hn);
        }
        // 逐条差异：只在"名次真的变了"的行上打印 —— 这才是能解释"为什么变了"的材料
        System.out.println();
        System.out.println("[改前/改后] 首条证据名次发生变化的 query：");
        boolean any = false;
        for (String id : b.evRankById.keySet()) {
            int br = b.evRankById.getOrDefault(id, -1);
            int hr = h.evRankById.getOrDefault(id, -1);
            int bf = b.fileRankById.getOrDefault(id, -1);
            int hf = h.fileRankById.getOrDefault(id, -1);
            if (br != hr || bf != hf) {
                any = true;
                System.out.printf("  %s: file@ %s -> %s ；evidence@ %s -> %s%n",
                        id, rankText(bf), rankText(hf), rankText(br), rankText(hr));
            }
        }
        if (!any) {
            System.out.println("  （无：两套口径在这批 query 上的名次完全一致）");
        }
    }

    private static void row(String label, int bk, int hk, int bn, int hn) {
        String bs = bk + "/" + bn;
        String hs = hk + "/" + hn;
        double bp = 100.0 * bk / Math.max(1, bn);
        double hp = 100.0 * hk / Math.max(1, hn);
        System.out.printf("%-16s %-18s %-18s %-10s%n", label,
                String.format(Locale.ROOT, "%s = %.1f%%", bs, bp),
                String.format(Locale.ROOT, "%s = %.1f%%", hs, hp),
                String.format(Locale.ROOT, "%+.1f 个百分点", hp - bp));
    }

    private static String rankText(int r) {
        return r < 0 ? "未命中" : String.valueOf(r);
    }

    private static java.util.Set<String> union(java.util.Set<String> a, java.util.Set<String> b) {
        java.util.LinkedHashSet<String> s = new java.util.LinkedHashSet<>(a);
        s.addAll(b);
        return s;
    }

    // ==================== 基线：改造前的检索口径 ====================

    /**
     * 消融用的检索器：与默认口径唯一的差别就是两个开关。
     *
     * <p>为什么要做成"同一段代码 + 两个开关"而不是各写一份：那样写着写着就会
     * 把某个实现细节漏掉一处，于是"消融对照"本身失真。
     */
    private static HybridEvalPipeline ablationPipeline(InMemoryVectorStoreGateway store,
                                                       boolean sparse, boolean rerank) {
        RagProperties p = new RagProperties();
        p.setSparseEnabled(sparse);
        p.setRerankEnabled(rerank);
        return new HybridEvalPipeline(store, p);
    }

    private static List<ScoredDoc> denseOnly(InMemoryVectorStoreGateway store, JsonNode q) {
        List<ScoredDoc> raw = store.search(toVector(q.get("vector")), Math.max(PUBLIC_TOP_K * 4, 12));
        List<ScoredDoc> out = new ArrayList<>();
        for (ScoredDoc d : raw) {
            if (d.getScore() < DENSE_MIN_SCORE) {
                continue;   // VectorSearchService 在同一位置剔除低分
            }
            out.add(d);
        }
        return out;
    }

    // ==================== 打分 ====================

    private interface Retriever {
        List<ScoredDoc> retrieve(JsonNode query);
    }

    private static EvalMetrics evaluate(String label, List<JsonNode> queries, Retriever retriever) {
        int n = 0;
        int fileHit3 = 0;
        int evHit3 = 0;
        int evHit5 = 0;
        int evHitAny = 0;
        double evMrr = 0;
        Map<String, int[]> byBucket = new LinkedHashMap<>();   // bucket -> {n, fileHit3, evHit3}
        Map<String, Integer> evRankById = new LinkedHashMap<>();
        Map<String, Integer> fileRankById = new LinkedHashMap<>();

        System.out.println();
        System.out.println("=== " + label + " ===");
        System.out.printf("%-5s %-3s %-8s %-9s %s%n", "id", "桶", "file@3", "evidence@3", "首条片段");

        for (JsonNode q : queries) {
            n++;
            List<ScoredDoc> hits = retriever.retrieve(q);
            int fileRank = firstRank(hits, q.get("fileAny"), false);
            int evRank = firstRank(hits, q.get("evidenceAny"), true);
            boolean f3 = fileRank >= 1 && fileRank <= 3;
            boolean e3 = evRank >= 1 && evRank <= 3;
            if (f3) {
                fileHit3++;
            }
            if (e3) {
                evHit3++;
            }
            if (evRank >= 1 && evRank <= 5) {
                evHit5++;
            }
            if (evRank >= 1) {
                evHitAny++;
                evMrr += 1.0 / evRank;
            }
            String bucket = q.hasNonNull("bucket") ? q.get("bucket").asText() : "-";
            int[] agg = byBucket.computeIfAbsent(bucket, k -> new int[3]);
            agg[0]++;
            if (f3) {
                agg[1]++;
            }
            if (e3) {
                agg[2]++;
            }
            String id = q.get("id").asText();
            evRankById.put(id, evRank);
            fileRankById.put(id, fileRank);

            System.out.printf("%-5s %-3s %-8s %-9s %s%n",
                    id, bucket,
                    fileRank < 0 ? "-" : String.valueOf(fileRank),
                    evRank < 0 ? "-" : String.valueOf(evRank),
                    describe(hits, 3));
        }

        System.out.println();
        System.out.printf("[%s] fileHit@3     = %d/%d = %.1f%%%n", label, fileHit3, n, 100.0 * fileHit3 / n);
        System.out.printf("[%s] evidenceHit@3 = %d/%d = %.1f%%%n", label, evHit3, n, 100.0 * evHit3 / n);
        System.out.printf("[%s] evidenceHit@5 = %d/%d = %.1f%%%n", label, evHit5, n, 100.0 * evHit5 / n);
        System.out.printf("[%s] evidenceHit(≤%d) = %d/%d = %.1f%%；MRR = %.4f%n",
                label, RANK_LIMIT, evHitAny, n, 100.0 * evHitAny / n, evMrr / n);
        for (Map.Entry<String, int[]> e : byBucket.entrySet()) {
            int[] a = e.getValue();
            System.out.printf("[%s] 桶 %s：n=%d fileHit@3=%d/%d evidenceHit@3=%d/%d%n",
                    label, e.getKey(), a[0], a[1], a[0], a[2], a[0]);
        }
        return new EvalMetrics(n, fileHit3, evHit3, evHit5, evHitAny, evMrr / n,
                byBucket, evRankById, fileRankById);
    }

    /** 一次跑分的全部指标（用于自动生成对照表，避免人工抄数字） */
    private static final class EvalMetrics {
        final int n;
        final int fileHit3;
        final int evHit3;
        final int evHit5;
        final int evHitAny;
        final double mrr;
        final Map<String, int[]> byBucket;
        final Map<String, Integer> evRankById;
        final Map<String, Integer> fileRankById;

        EvalMetrics(int n, int fileHit3, int evHit3, int evHit5, int evHitAny, double mrr,
                    Map<String, int[]> byBucket, Map<String, Integer> evRankById,
                    Map<String, Integer> fileRankById) {
            this.n = n;
            this.fileHit3 = fileHit3;
            this.evHit3 = evHit3;
            this.evHit5 = evHit5;
            this.evHitAny = evHitAny;
            this.mrr = mrr;
            this.byBucket = byBucket;
            this.evRankById = evRankById;
            this.fileRankById = fileRankById;
        }
    }

    /**
     * 返回第一条期望命中的排名（1 起）；{@code RANK_LIMIT} 名内没有返回 -1。
     *
     * @param content true = 比对片段正文（证据口径），false = 比对 标题/文件名/来源路径（文档口径）
     */
    private static int firstRank(List<ScoredDoc> hits, JsonNode expectAny, boolean content) {
        if (expectAny == null) {
            return -1;
        }
        int limit = Math.min(hits.size(), RANK_LIMIT);
        for (int i = 0; i < limit; i++) {
            String text = content ? textOf(hits.get(i)) : where(hits.get(i));
            for (JsonNode group : expectAny) {
                boolean all = true;
                for (JsonNode kw : group) {
                    if (!text.contains(kw.asText().toLowerCase(Locale.ROOT))) {
                        all = false;
                        break;
                    }
                }
                if (all) {
                    return i + 1;
                }
            }
        }
        return -1;
    }

    private static String textOf(ScoredDoc d) {
        return d.getContent() == null ? "" : d.getContent().toLowerCase(Locale.ROOT);
    }

    /** 标题 + 文件名 + 来源路径（小写） */
    private static String where(ScoredDoc d) {
        Map<String, Object> m = d.getMetadata() == null ? Map.of() : d.getMetadata();
        String title = m.get("title") == null ? "" : String.valueOf(m.get("title"));
        String file = m.get("_file_name") == null ? "" : String.valueOf(m.get("_file_name"));
        String src = m.get("_source") == null ? "" : String.valueOf(m.get("_source"));
        return (title + " | " + file + " | " + src).toLowerCase(Locale.ROOT);
    }

    private static String describe(List<ScoredDoc> hits, int limit) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(hits.size(), limit); i++) {
            Map<String, Object> m = hits.get(i).getMetadata() == null ? Map.of() : hits.get(i).getMetadata();
            if (i > 0) {
                sb.append(" ; ");
            }
            sb.append('#').append(i + 1).append(' ')
              .append(m.get("_file_name")).append('→').append(m.get("title"))
              .append('(').append(String.format(Locale.ROOT, "%.3f", hits.get(i).getScore())).append(')');
        }
        return sb.toString();
    }

    public static List<Float> toVector(JsonNode arr) {
        List<Float> v = new ArrayList<>(arr.size());
        arr.forEach(x -> v.add((float) x.asDouble()));
        return v;
    }
}

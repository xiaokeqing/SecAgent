package org.example.rag;

import org.example.vector.ScoredDoc;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 检索件（分词 / BM25 / RRF / 重排）的单元测试 —— <b>纯逻辑、零网络、零费用、确定性</b>。
 *
 * <p>为什么这些要单独测：混合检索的每一层都有"看起来对但实际反了"的失败模式
 * （IDF 方向反了会把罕见标识压下去、RRF 归一化写错会让单路压倒双路、
 * 重排权重写错会把泛词命中排到精确命中前面）。这些都不会抛异常，
 * 只会让结果悄悄变差 —— 必须有能钉住方向的断言。
 *
 * <p>端到端的 28 条离线回归集见 {@code RagRetrievalRegressionTest}。
 */
class RagRetrievalComponentsTest {

    // ==================== 分词 ====================

    @Test
    @DisplayName("中文按字符 bigram 切：同一段中文的切分互相可命中，且不含整句一词")
    void tokenizeChineseAsBigrams() {
        List<String> t = RagTokenizer.tokenize("路径穿越漏洞怎么防御");
        assertTrue(t.contains("路径"), "应含 bigram 路径，实际=" + t);
        assertTrue(t.contains("径穿"), "应含 bigram 径穿，实际=" + t);
        assertTrue(t.contains("防御"), "应含 bigram 防御，实际=" + t);
        assertFalse(t.contains("路径穿越漏洞怎么防御"), "不应出现整句当一个词的情况");
        // 所有中文 term 都是 2 个字（除非整段只有 1 个汉字）
        for (String x : RagTokenizer.tokenize("穿越")) {
            assertEquals(2, x.length());
        }
    }

    @Test
    @DisplayName("英文/数字按整词切；大写与全角归一化后与原文一致")
    void tokenizeLatinAndNormalize() {
        List<String> t = RagTokenizer.tokenize("disallow-doctype-decl 防 XXE");
        assertTrue(t.contains("disallow"), "实际=" + t);
        assertTrue(t.contains("doctype"), "实际=" + t);
        assertTrue(t.contains("decl"), "实际=" + t);
        assertTrue(t.contains("xxe"), "大写应转小写，实际=" + t);

        // 全角数字/字母要与半角等价（中文文档里两者混用很常见）
        assertEquals(RagTokenizer.tokenize("CWE-918"), RagTokenizer.tokenize("ＣＷＥ-９１８"),
                "全角与半角应切出完全相同的 term");
    }

    @Test
    @DisplayName("单字中文段不会丢：切出该字本身（否则单字查询永远检索不到）")
    void tokenizeSingleCjkChar() {
        assertEquals(List.of("洞"), RagTokenizer.tokenize("洞"));
    }

    @Test
    @DisplayName("索引侧与查询侧用同一个分词器：同样是 'defense' 的两种写法能互相命中")
    void tokenizerIsSymmetric() {
        List<String> a = RagTokenizer.uniqueTerms("CWE-918 是什么", true);
        List<String> b = RagTokenizer.uniqueTerms("cwe 918 是什么", true);
        assertTrue(a.contains("cwe") && b.contains("cwe"));
        assertTrue(a.stream().anyMatch(b::contains) || b.stream().anyMatch(a::contains));
    }

    // ==================== BM25 ====================

    @Test
    @DisplayName("BM25：含罕见标识的片段排在只含泛词的前面；docFreq 反映真实文档频率")
    void bm25RanksRareIdentifierFirst() {
        List<ScoredDoc> docs = List.of(
                doc("d1", "SSRF 服务端请求伪造（CWE-918）的原理与防御", "SSRF"),
                doc("d2", "漏洞报告怎么写：漏洞的分级与修复建议", "报告"),
                doc("d3", "漏洞扫描与漏洞管理流程", "扫描"),
                doc("d4", "常见漏洞类型汇总", "汇总"));
        Bm25Index idx = new Bm25Index(docs, 1.2, 0.75, true);

        List<Bm25Index.Hit> hits = idx.search("CWE-918 对应哪一类漏洞？", 5);
        assertFalse(hits.isEmpty());
        assertEquals("d1", hits.get(0).doc.getId(), "含 cwe-918 的片段应排第一，实际顺序=" + ids(hits));

        // docFreq 方向：cwe/918 这类词只在少数文档里；"漏洞"几乎每篇都有
        assertTrue(idx.docFreq("918") < idx.docFreq("漏洞"),
                "罕见标识的文档频率必须低于泛词");
        assertTrue(idx.idfOf("918") > idx.idfOf("漏洞"),
                "罕见标识的 IDF 必须高于泛词（方向反了会把精确命中压下去）");
    }

    @Test
    @DisplayName("BM25：IDF 恒为正 —— 词出现在超过一半文档里时也不会变成负权重")
    void bm25IdfAlwaysPositive() {
        List<ScoredDoc> docs = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            docs.add(doc("d" + i, "漏洞基础 " + i, "漏洞"));
        }
        Bm25Index idx = new Bm25Index(docs, 1.2, 0.75, true);
        assertTrue(idx.idfOf("漏洞") > 0, "高频词的 IDF 也必须为正，否则命中反而扣分");
        // 命中更多查询词一定不降低分数
        List<Bm25Index.Hit> one = idx.search("漏洞", 3);
        List<Bm25Index.Hit> two = idx.search("漏洞 基础", 3);
        assertTrue(two.get(0).score >= one.get(0).score);
    }

    @Test
    @DisplayName("BM25：查询词重复出现不会重复计分（'SQL 注入 SQL 注入' 与 'SQL 注入' 同分）")
    void bm25QueryTermFrequencyDoesNotMatter() {
        List<ScoredDoc> docs = List.of(doc("d1", "SQL 注入的检测与修复", "SQL"), doc("d2", "XSS 防御", "XSS"));
        Bm25Index idx = new Bm25Index(docs, 1.2, 0.75, true);
        assertEquals(idx.search("SQL 注入", 3).get(0).score,
                idx.search("SQL 注入 SQL 注入", 3).get(0).score, 1e-9);
    }

    @Test
    @DisplayName("BM25：词袋完全不同时返回空（不硬塞噪声）")
    void bm25ReturnsEmptyWhenNoOverlap() {
        Bm25Index idx = new Bm25Index(List.of(doc("d1", "SQL 注入防御", "SQL")), 1.2, 0.75, true);
        assertTrue(idx.search("量子蜜罐的部署方式", 5).isEmpty());
    }

    // ==================== RRF ====================

    @Test
    @DisplayName("RRF：多路一致的文档优先，且分数与 1/(k+rank) 的逐项和一致（公式不能走样）")
    void rrfRewardsAgreementAcrossChannels() {
        // 通道内名次：dense = y,x ；sparse = a,x,y
        //   x：dense#2 + sparse#2  → 1/(k+2) + 1/(k+2)
        //   y：dense#1 + sparse#3  → 1/(k+1) + 1/(k+3)
        // 注意（这是本测试第一个版本写错的地方）：k=60 时 1/61+1/63 其实【略大于】2/62，
        // 也就是说"单路第 1 + 另一路第 3"可以险胜"两路都第 2"。RRF 只在
        // "两路都靠前" 时才奖励一致性，这属于正常行为，不是 bug。
        // 所以这里断言的是【公式本身】，而不是一个凭直觉写的名次结论。
        List<ScoredDoc> dense = List.of(sd("y"), sd("x"));
        List<ScoredDoc> sparse = List.of(sd("a"), sd("x"), sd("y"));
        Map<String, List<ScoredDoc>> ch = new LinkedHashMap<>();
        ch.put("dense", dense);
        ch.put("sparse", sparse);

        List<RrfFusion.Fused> fused = RrfFusion.fuse(60, ch, ScoredDoc::getId);
        assertEquals("y", fused.get(0).docId());
        assertEquals(1.0 / 61 + 1.0 / 63, fused.get(0).score(), 1e-12);
        assertEquals("x", fused.get(1).docId());
        assertEquals(2.0 / 62, fused.get(1).score(), 1e-12);
        assertEquals(List.of("dense", "sparse"), fused.get(1).sources());
        assertTrue(fused.get(1).bothChannels());
        assertEquals("a", fused.get(2).docId());
        assertFalse(fused.get(2).bothChannels(), "a 只被稀疏通道召回");
    }

    @Test
    @DisplayName("RRF：k 很小时'两路都第 1'必须压倒'单路第 1'（一致性的收益必须真实存在）")
    void rrfAgreementBeatsSingleChannelWhenKSmall() {
        // dense = z ；sparse = z
        // 另一篇 only-dense 只在稠密通道第 1。k=1（最激进）时：
        //   z（两路第 1）= 1/2 + 1/2 = 1.0  >  only = 1/2
        List<ScoredDoc> dense = List.of(sd("z"), sd("only-dense"));
        List<ScoredDoc> sparse = List.of(sd("z"));
        Map<String, List<ScoredDoc>> ch = new LinkedHashMap<>();
        ch.put("dense", dense);
        ch.put("sparse", sparse);

        List<RrfFusion.Fused> fused = RrfFusion.fuse(1, ch, ScoredDoc::getId);
        assertEquals("z", fused.get(0).docId(), "两路都召回的一致候选必须排第一");
        assertEquals(1.0, fused.get(0).score(), 1e-12);
        assertEquals(1.0 / 3, fused.get(1).score(), 1e-12,
                "only-dense 只在稠密通道第 2 名（z 占了第 1）→ k=1 时 = 1/(1+2)");

        // 重排项的归一分母 = 池内最高 RRF，所以 z 的归一化 RRF 恒为 1.0、且必然排在另一篇之前。
        // 这里刻意【不】断言另一篇的具体数值：那取决于 RRF 分差与四个信号的加权结果，
        // 属于实现细节；断言它只会让测试在每次调权重时假失败。
        RagProperties props = new RagProperties();
        props.setRerankEnabled(false);
        List<ScoredDoc> cands = new ArrayList<>();
        for (RrfFusion.Fused f : fused) {
            cands.add(f.doc());
        }
        List<RagReranker.Ranked> rr = RagReranker.rerank("任意", cands,
                Map.of("z", 1.0, "only-dense", 0.5), java.util.Set.of("z"), Map.of(), props, true);
        assertEquals("z", rr.get(0).doc.getId());
        assertEquals(1.0, rr.get(0).signals.finalScore, 1e-12, "池内最高 RRF 归一化后必须是 1.0");
        assertTrue(rr.get(0).signals.finalScore > rr.get(1).signals.finalScore);
    }

    @Test
    @DisplayName("RRF：k 越小越看重头部名次（可配的语义必须成立）")
    void rrfKControlsHeadWeight() {
        List<ScoredDoc> dense = List.of(doc("a", "a", "a"), doc("b", "b", "b"));
        Map<String, List<ScoredDoc>> ch = new LinkedHashMap<>();
        ch.put("dense", dense);
        List<RrfFusion.Fused> small = RrfFusion.fuse(1, ch, ScoredDoc::getId);
        List<RrfFusion.Fused> big = RrfFusion.fuse(100, ch, ScoredDoc::getId);
        double gapSmall = small.get(0).score() - small.get(1).score();
        double gapBig = big.get(0).score() - big.get(1).score();
        assertTrue(gapSmall > gapBig, "k 小 → 头部差距更大：" + gapSmall + " vs " + gapBig);
    }

    @Test
    @DisplayName("RRF：id 为 null 的候选被丢弃，不会让融合崩掉")
    void rrfIgnoresNullIds() {
        // 注意：这里刻意不调用本类的 doc(...) 工厂方法，而是直接构造 ——
        // 局部变量与工厂方法同名时，Java 会把 `doc(...)` 解析成"调用变量"，编译不过。
        // 这个坑本身就是一次真实编译错误，写在这里免得下次再踩。
        Map<String, List<ScoredDoc>> ch = new LinkedHashMap<>();
        ch.put("dense", List.of(new ScoredDoc(null, "c", 1f, Map.of()),
                new ScoredDoc("ok", "c", 0.5f, Map.of())));
        List<RrfFusion.Fused> fused = RrfFusion.fuse(60, ch, ScoredDoc::getId);
        assertEquals(1, fused.size());
        assertEquals("ok", fused.get(0).docId());
    }

    // ==================== 重排 ====================

    @Test
    @DisplayName("重排：IDF 加权让「命中罕见标识」压过「命中一堆泛词」")
    void rerankPrefersRareEvidence() {
        List<ScoredDoc> docs = List.of(
                doc("rare", "SSRF 服务端请求伪造（CWE-918）原理与防御", "SSRF 服务端请求伪造"),
                doc("common", "漏洞报告怎么写：漏洞的分级、修复建议与漏洞管理", "报告"));
        Bm25Index idx = new Bm25Index(docs, 1.2, 0.75, true);
        String query = "CWE-918 对应哪一类漏洞？";

        List<ScoredDoc> cands = new ArrayList<>(docs);
        Map<String, Double> rrf = new LinkedHashMap<>();
        rrf.put("rare", 0.030);
        rrf.put("common", 0.032);       // 泛词文档的 RRF 更高（这正是要纠正的）

        RagProperties props = new RagProperties();
        Map<String, Double> weights = idx.rarityWeights(RagTokenizer.uniqueTerms(query, true));
        List<RagReranker.Ranked> rr = RagReranker.rerank(query, cands, rrf, java.util.Set.of(),
                weights, props, true);

        assertEquals("rare", rr.get(0).doc.getId(),
                "重排必须把含罕见标识的片段提到前面，实际=" + rr.get(0).doc.getId());
        assertTrue(rr.get(0).signals.rareCoverage > rr.get(1).signals.rareCoverage,
                "rareCoverage 方向必须是'命中越稀有越高'");
    }

    @Test
    @DisplayName("重排关闭时：顺序完全由 RRF 决定，且 finalScore 就是归一化 RRF（不是'关了小一半'）")
    void rerankDisabledFallsBackToRrfOrder() {
        List<ScoredDoc> docs = List.of(doc("a", "abc", "t1"), doc("b", "def", "t2"));
        RagProperties props = new RagProperties();
        props.setRerankEnabled(false);
        Map<String, Double> rrf = new LinkedHashMap<>();
        rrf.put("a", 0.01);
        rrf.put("b", 0.02);
        List<RagReranker.Ranked> rr = RagReranker.rerank("任意", new ArrayList<>(docs), rrf,
                java.util.Set.of(), Map.of(), props, true);
        assertEquals("b", rr.get(0).doc.getId(), "重排关闭时不得改变 RRF 顺序");
        assertTrue(rr.get(0).signals.rerankPart > 0,
                "重排项本身仍会被算出来（用于对照/排障），只是不参与 finalScore —— 这一点必须写清楚，"
                        + "否则'关掉重排后 finalScore 变了'会被误读成开关失效");
        // 归一化基准 = 池内最高 RRF（=0.02）：b 第 1 → 1.0；a → 0.01/0.02 = 0.5
        assertEquals(1.0, rr.get(0).signals.finalScore, 1e-12);
        assertEquals(0.5, rr.get(1).signals.finalScore, 1e-12, "归一化应相对池内最高 RRF，而不是凭空猜通道数");
    }

    @Test
    @DisplayName("重排：没有稀有度权重时退化成普通覆盖度（而不是 produce NaN / 全 0）")
    void rerankDegradesGracefullyWithoutWeights() {
        List<ScoredDoc> docs = List.of(doc("a", "SQL 注入防御", "SQL"));
        Map<String, Double> rrf = Map.of("a", 0.02);
        List<RagReranker.Ranked> rr = RagReranker.rerank("SQL 注入", new ArrayList<>(docs), rrf,
                java.util.Set.of(), null, new RagProperties(), true);
        assertEquals(1, rr.size());
        assertNotNull(rr.get(0).signals);
        assertFalse(Double.isNaN(rr.get(0).signals.finalScore), "缺权重时不得产生 NaN");
        assertTrue(rr.get(0).signals.rareCoverage > 0, "缺权重时应按等权覆盖度计算");
    }

    // ==================== 检索器：开关语义 ====================

    @Test
    @DisplayName("稀疏关 + 重排关 = 纯稠密口径（回退路径的语义必须成立）")
    void bothSwitchesOffMeansDenseOnly() {
        RagProperties props = new RagProperties();
        props.setSparseEnabled(false);
        props.setRerankEnabled(false);
        List<ScoredDoc> dense = List.of(doc("d1", "内容一", "t1"), doc("d2", "内容二", "t2"));
        HybridRetriever r = new HybridRetriever(q -> List.of(1f, 0f), (v, k) -> dense,
                SparseIndexCache.disabled(props), props, 0.0f);
        HybridRetriever.Result res = r.retrieve("任意查询", 2);
        assertEquals(2, res.hits().size());
        assertEquals("dense", res.mode(), "两路都关时口径必须如实写 dense");
        assertTrue(res.note().contains("纯稠密"));
        // 顺序与输入一致（不做任何重排）
        assertEquals("d1", res.hits().get(0).doc().getId());
    }

    @Test
    @DisplayName("minScore 门槛在混合检索里同样生效（不允许把低分噪声塞进结果）")
    void minScoreStillApplied() {
        RagProperties props = new RagProperties();
        List<ScoredDoc> dense = List.of(doc("good", "命中内容", "t"), new ScoredDoc("low", "低分", 0.1f, Map.of()));
        HybridRetriever r = new HybridRetriever(q -> List.of(1f), (v, k) -> dense,
                SparseIndexCache.disabled(props), props, 0.30f);
        HybridRetriever.Result res = r.retrieve("命中", 5);
        assertEquals(1, res.hits().size(), "低于 minScore 的候选必须被剔除");
        assertEquals("good", res.hits().get(0).doc().getId());
    }

    // ==================== 辅助 ====================

    private static ScoredDoc doc(String id, String content, String title) {
        return new ScoredDoc(id, content, 0.9f, new LinkedHashMap<>(Map.of("title", title, "_file_name", title + ".md")));
    }

    /** 只关心 id 的替身（RRF 测试用；标题/正文与断言无关） */
    private static ScoredDoc sd(String id) {
        return new ScoredDoc(id, "内容-" + id, 0.9f, new LinkedHashMap<>(Map.of("title", "标题-" + id)));
    }

    private static List<String> ids(List<Bm25Index.Hit> hits) {
        List<String> out = new ArrayList<>();
        for (Bm25Index.Hit h : hits) {
            out.add(h.doc.getId());
        }
        return out;
    }
}

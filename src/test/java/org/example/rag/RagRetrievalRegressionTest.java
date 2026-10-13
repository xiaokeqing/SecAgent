package org.example.rag;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.vector.ScoredDoc;
import org.example.vector.memory.InMemoryVectorStoreGateway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * <b>离线检索回归门禁</b>（进 {@code mvn -B test}，CI 里必须全过）。
 *
 * <h3>它回答的问题</h3>
 * "改完检索，怎么知道没有变差？" —— 用一批<b>先写死期望、再跑分</b>的查询，
 * 逐条检查"问题所问的确切证据"是否出现在前若干条里。这就是检索层的回归集。
 *
 * <h3>为什么它完全离线、可复现</h3>
 * <ul>
 *   <li>语料：{@code data/vector-store.json}（318 条真实分片，与线上同一份）；</li>
 *   <li>查询向量：{@code src/test/resources/rag-eval/retrieval-queries.json}，
 *       由 {@code scripts/rag-eval/build-query-fixture.py} 用与线上同一个 embedding 模型
 *       <b>一次性生成并入库</b> —— CI 里没有 API Key、不花钱、不联网，结果完全确定；</li>
 *   <li>检索逻辑：调用生产类 {@link HybridRetriever}（不是测试里另写一份）。</li>
 * </ul>
 *
 * <h3>判据（写清楚，避免"门禁松到没有意义"或"紧到天天误报"）</h3>
 * <ol>
 *   <li><b>逐条硬门槛</b>：每条 query 期望的"确切证据关键词"必须出现在<b>前 5 条</b>之内。
 *       为什么是 5 而不是 3：模型看到的候选不止 3 条（公开端点取 topK*4），
 *       排到第 4–5 位仍能被后续步骤用上；而"掉到 5 名之外"基本等于这段引用丢了。</li>
 *   <li><b>整体门槛</b>：fileHit@k（找对那一篇）≥ 27/28 —— 当前实测 28/28，
 *       留一条余量，避免将来某条 query 的排序在两项之间抖动就把主干挂掉；
 *       但也不允许再退（退到 26 就说明真的坏了）。</li>
 *   <li><b>口径断言</b>：默认配置下必须是"两路 + 重排"（{@code dense+sparse+rerank}）。
 *       否则可能出现"稀疏通道静默失效、CI 照样全绿"——那正是最坏的一种变好。</li>
 * </ol>
 *
 * <h3>它<b>不</b>覆盖什么（如实写，别让"CI 全绿"被理解成"检索有保障"）</h3>
 * <ul>
 *   <li>查询向量是缓存的，量的不是"线上 embedding 接口当次返回什么"；</li>
 *   <li>期望关键词取自语料本身，所以它测的是"能不能找到已知的正确答案"，
 *       测不出"问了一个语料里根本没有的东西时会不会硬答"（那由拒答阈值与评测卷覆盖）；</li>
 *   <li>夹具只有 28 条、且集中在安全知识这一域，用户改述的多样性覆盖不足；</li>
 *   <li>重排参数是在<b>这一批 query</b> 上定的，有 overfit 风险（见 RUNBOOK §25 的如实说明）。</li>
 * </ul>
 */
class RagRetrievalRegressionTest {

    /** 期望命中的排名上限（见类注释：为什么是 5） */
    private static final int EVIDENCE_RANK_BAR = 5;
    /** 找对文档的整体下限（当前实测 28/28） */
    private static final int FILE_HIT3_FLOOR = 27;
    /** 统计排名时的最大深度 */
    private static final int RANK_LIMIT = 10;

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Path CORPUS = Path.of("data/vector-store.json");
    private static final Path FIXTURE = Path.of("src/test/resources/rag-eval/retrieval-queries.json");

    private static List<JsonNode> queries;
    private static InMemoryVectorStoreGateway store;
    private static HybridEvalPipeline pipeline;

    @BeforeAll
    static void loadFixture() throws Exception {
        assertTrue(Files.exists(CORPUS), "缺少语料 " + CORPUS.toAbsolutePath());
        assertTrue(Files.exists(FIXTURE), "缺少评测夹具 " + FIXTURE.toAbsolutePath());

        store = new InMemoryVectorStoreGateway();
        ReflectionTestUtils.setField(store, "persistFile", CORPUS.toString().replace('\\', '/'));
        store.init();

        queries = new ArrayList<>();
        MAPPER.readTree(new File(FIXTURE.toString())).get("queries").forEach(queries::add);

        pipeline = new HybridEvalPipeline(store, new RagProperties());
    }

    @Test
    @DisplayName("夹具与语料的基本口径没变（条数/维度/分片数）—— 变了说明夹具该重新生成")
    void fixtureShapeIsIntact() throws Exception {
        JsonNode doc = MAPPER.readTree(FIXTURE.toFile());
        assertEquals(1024, doc.get("dimension").asInt(), "夹具维度与语料向量维度必须一致");
        assertTrue(queries.size() >= 20 && queries.size() <= 30,
                "回归集条数应在 20–30 之间（题目要求），实际=" + queries.size());
        assertEquals(318, store.count(),
                "语料分片数变了（新增/删除文档）→ 必须重跑 scripts/rag-eval/build-query-fixture.py，"
                        + "否则查询向量与语料对不上，本门禁会给出误导性的结果");
    }

    @Test
    @DisplayName("逐条回归：每条 query 的确切证据都出现在前 " + EVIDENCE_RANK_BAR + " 条之内（28/28）")
    void everyQueryFindsItsEvidenceInTopK() {
        List<String> failures = new ArrayList<>();
        List<String> detail = new ArrayList<>();
        for (JsonNode q : queries) {
            pipeline.forQuery(q);
            List<ScoredDoc> hits = pipeline.retrieve(3);
            int evRank = firstRank(hits, q.get("evidenceAny"), true);
            int fileRank = firstRank(hits, q.get("fileAny"), false);
            detail.add(String.format(Locale.ROOT, "%s evidence@%s file@%s",
                    q.get("id").asText(), rankText(evRank), rankText(fileRank)));
            if (evRank < 1 || evRank > EVIDENCE_RANK_BAR) {
                failures.add(String.format(Locale.ROOT, "%s「%s」期望证据不在前 %d 条（实际 %s）：%s",
                        q.get("id").asText(), q.get("query").asText(), EVIDENCE_RANK_BAR,
                        rankText(evRank), q.get("evidenceAny")));
            }
        }
        if (!failures.isEmpty()) {
            System.out.println("[检索回归] 逐条结果：" + String.join("；", detail));
        }
        assertTrue(failures.isEmpty(),
                "检索回归失败（有 " + failures.size() + " 条）：\n  " + String.join("\n  ", failures)
                        + "\n\n排查建议：先看 scripts/rag-eval/out/ 的改前/改后跑分输出，"
                        + "再用 RagRetrievalEvalMain --trace <qid> 打印该 query 的逐条信号。");
    }

    @Test
    @DisplayName("整体门槛：fileHit@3 ≥ " + FILE_HIT3_FLOOR + "/28，且 evidenceHit@3 不得低于 fileHit@3")
    void aggregateFileHitDoesNotRegress() {
        int n = 0;
        int fileHit3 = 0;
        int evHit3 = 0;
        for (JsonNode q : queries) {
            n++;
            pipeline.forQuery(q);
            List<ScoredDoc> hits = pipeline.retrieve(3);
            int fileRank = firstRank(hits, q.get("fileAny"), false);
            int evRank = firstRank(hits, q.get("evidenceAny"), true);
            if (fileRank >= 1 && fileRank <= 3) {
                fileHit3++;
            }
            if (evRank >= 1 && evRank <= 3) {
                evHit3++;
            }
        }
        assertTrue(fileHit3 >= FILE_HIT3_FLOOR,
                "fileHit@3 = " + fileHit3 + "/" + n + "，低于下限 " + FILE_HIT3_FLOOR + "/" + n
                        + "（改造前基线为 27/28，改造后实测 28/28）");
        assertTrue(evHit3 >= FILE_HIT3_FLOOR,
                "evidenceHit@3 = " + evHit3 + "/" + n + "，低于下限 " + FILE_HIT3_FLOOR);
    }

    @Test
    @DisplayName("口径断言：默认配置必须真的跑了两路 + 重排（防'稀疏静默失效但 CI 全绿'）")
    void defaultConfigActuallyUsesBothChannelsAndRerank() {
        assertFalse(queries.isEmpty());
        pipeline.forQuery(queries.get(0));
        HybridRetriever.Result r = pipeline.retrieveFull(3);
        assertEquals("dense+sparse+rerank", r.mode(),
                "默认配置下口径必须如实是 dense+sparse+rerank；实际=" + r.mode() + "，note=" + r.note());
        assertTrue(r.denseCandidates() > 0, "稠密通道必须真的有候选，实际=" + r.denseCandidates());
        assertTrue(r.sparseCandidates() > 0, "稀疏通道必须真的有候选（否则说明 BM25 索引没建起来）");
        assertTrue(r.note().contains("RRF"), "口径自述里应写明 RRF，实际=" + r.note());
    }

    @Test
    @DisplayName("回退纯稠密：两个开关关掉后，结果与改造前的排序完全一致（回退不是'另一套近似'）")
    void denseOnlyFallbackMatchesLegacyOrdering() {
        RagProperties off = new RagProperties();
        off.setSparseEnabled(false);
        off.setRerankEnabled(false);
        HybridEvalPipeline denseOnly = new HybridEvalPipeline(store, off);

        int checked = 0;
        for (JsonNode q : queries) {
            // 改造前口径：store.search(vec, max(3*4,12)) → 剔 score<0.30 → 取前 3
            List<ScoredDoc> legacy = new ArrayList<>();
            for (ScoredDoc d : store.search(RagRetrievalEvalMain.toVector(q.get("vector")), 12)) {
                if (d.getScore() >= RagRetrievalEvalMain.DENSE_MIN_SCORE) {
                    legacy.add(d);
                }
            }
            if (legacy.size() > 3) {
                legacy = new ArrayList<>(legacy.subList(0, 3));
            }

            denseOnly.forQuery(q);
            List<ScoredDoc> viaSwitch = denseOnly.retrieve(3);

            assertEquals(ids(legacy), ids(viaSwitch),
                    "关掉两个开关后必须与改造前排序完全一致（query=" + q.get("id").asText() + "）");
            checked++;
        }
        assertEquals(queries.size(), checked);
    }

    // ==================== 与跑分器同一套判据 ====================

    private static List<String> ids(List<ScoredDoc> docs) {
        List<String> out = new ArrayList<>();
        for (ScoredDoc d : docs) {
            out.add(d.getId());
        }
        return out;
    }

    /**
     * 与 {@link RagRetrievalEvalMain#firstRank} 同名同义（那边是 private，不为测试放宽可见性；
     * 判据只有 20 行，重复实现的风险低于把它公开成 API 的风险）。
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

    private static String where(ScoredDoc d) {
        Map<String, Object> m = d.getMetadata() == null ? Map.of() : d.getMetadata();
        String title = m.get("title") == null ? "" : String.valueOf(m.get("title"));
        String file = m.get("_file_name") == null ? "" : String.valueOf(m.get("_file_name"));
        String src = m.get("_source") == null ? "" : String.valueOf(m.get("_source"));
        return (title + " | " + file + " | " + src).toLowerCase(Locale.ROOT);
    }

    private static String rankText(int r) {
        return r < 0 ? "未命中" : String.valueOf(r);
    }

    /** 便于排障时人工核对：把一条 query 的前若干命中打出来（不在断言里用） */
    static Map<String, Object> describeHits(List<ScoredDoc> hits, int limit) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < Math.min(hits.size(), limit); i++) {
            Map<String, Object> meta = hits.get(i).getMetadata() == null ? Map.of() : hits.get(i).getMetadata();
            m.put("#" + (i + 1), meta.get("_file_name") + "→" + meta.get("title"));
        }
        return m;
    }

    static void requireNonNull(Object o, String message) {
        assertNotNull(o, message);
    }
}

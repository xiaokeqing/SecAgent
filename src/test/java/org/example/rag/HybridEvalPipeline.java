package org.example.rag;

import com.fasterxml.jackson.databind.JsonNode;
import org.example.vector.ScoredDoc;
import org.example.vector.memory.InMemoryVectorStoreGateway;

import java.util.List;

/**
 * 评测里「改后」那条通道的接线器。
 *
 * <h3>它为什么这么薄</h3>
 * 评测必须量到<b>线上真正跑的那段代码</b>，否则"评测变好了"和"线上变好了"是两件事。
 * 所以这里不重写任何检索逻辑：把离线夹具里的查询向量喂给生产类
 * {@link HybridRetriever}（稀疏索引缓存也用生产的 {@link SparseIndexCache}），
 * 差别只有一处 —— 线上查询向量由 DashScope 现算，离线用夹具里缓存的同一模型向量
 * （见 {@code scripts/rag-eval/build-query-fixture.py}）。
 *
 * <h3>为什么是实例而不是静态方法（一次踩过的坑）</h3>
 * 第一版写成静态方法，于是<b>每条 query 都新建一个 {@link SparseIndexCache}</b>，
 * 导致 BM25 索引被重建 28 次（日志里能看到 28 行"BM25 索引已重建"）。
 * 结果虽然一样（索引是确定性的），但"评测耗时"变成了一堆无谓开销，
 * 而且它掩盖了一个真实信息：重建到底花了多久。
 * 现在把检索器与索引缓存提升为实例状态，一次建索引、跑完全部 query。
 *
 * <h3>参数口径</h3>
 * 用 {@link RagProperties} 的<b>默认值</b>（= {@code .env.example} 里那组默认值）：
 * 评测要回答的是"默认配置下改造有没有变好"，而不是"调参后最好能到多少"。
 * 需要对比其它参数时，用带 props 的构造器并重跑，命令与输出一起留档。
 */
final class HybridEvalPipeline {

    private final RagProperties props;
    private final SparseIndexCache sparseCache;
    private volatile HybridRetriever retriever;
    private List<Float> currentVector;
    private String currentQuery;

    HybridEvalPipeline(InMemoryVectorStoreGateway store, RagProperties props) {
        this.props = props;
        this.sparseCache = new SparseIndexCache(store, props);
        this.retriever = new HybridRetriever(this::fixtureVector, store::search, sparseCache,
                props, RagRetrievalEvalMain.DENSE_MIN_SCORE);
    }

    /** 夹具里的查询向量（与本次 query 一一对应；由 {@link #forQuery} 设置） */
    private List<Float> fixtureVector(String query) {
        return currentVector;
    }

    /** 设置本次要跑的 query（把"文本 → 夹具向量"这条映射接上） */
    HybridEvalPipeline forQuery(JsonNode query) {
        this.currentVector = RagRetrievalEvalMain.toVector(query.get("vector"));
        this.currentQuery = query.get("query").asText("");
        return this;
    }

    List<ScoredDoc> retrieve(int topK) {
        return retriever.retrieve(currentQuery, topK).docs();
    }

    HybridRetriever.Result retrieveFull(int topK) {
        return retriever.retrieve(currentQuery, topK);
    }

    SparseIndexCache sparseCache() {
        return sparseCache;
    }
}
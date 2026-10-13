package org.example.rag;

import org.example.vector.ScoredDoc;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * BM25 索引的<b>进程内缓存</b>：按语料版本重建，跨检索器实例共享。
 *
 * <h3>为什么把它独立出来</h3>
 * {@link HybridRetriever} 是按"一次检索的阈值"构造的轻量对象
 * （离线评测要对比不同门槛下的排序），如果索引缓存挂在检索器上，
 * 每换一个门槛就会重建一次整库统计 —— 318 条分片要 20–40ms，
 * 在评测里会变成几十秒的无谓开销，在生产里则是每次请求都可能重建。
 *
 * <p>索引本身只依赖"语料 + BM25 参数"，与"本次检索取多少条 / 门槛多少"无关，
 * 所以它的生命周期天然比检索器长：放在这里，检索器只持有引用。
 *
 * <h3>并发语义</h3>
 * 重建在 {@code synchronized(this)} 里整体替换 volatile 引用，
 * 因此并发查询只会看到"旧的一份完整索引"或"新的一份完整索引"，
 * 不存在"建到一半被读到"。重建期间其余查询用旧索引继续服务（无阻塞）。
 */
public final class SparseIndexCache {

    private static final Logger logger = LoggerFactory.getLogger(SparseIndexCache.class);

    private final SparseCorpusProvider corpus;
    private final RagProperties props;

    private volatile Bm25Index index;
    private volatile long version = Long.MIN_VALUE;

    public SparseIndexCache(SparseCorpusProvider corpus, RagProperties props) {
        this.corpus = corpus;
        this.props = props;
    }

    /** 是否具备稀疏检索能力（提供方存在且开关打开） */
    public boolean enabled() {
        return props.isSparseEnabled() && corpus != null;
    }

    /**
     * 取当前索引；不可用时返回 {@code null}（调用方据此如实退化为纯稠密）。
     *
     * <p>{@code enabled=false} 时返回 null 且<b>不建索引</b> ——
     * 关闭稀疏通道的部署不该为它付出任何启动/内存代价。
     */
    public Bm25Index get() {
        if (!enabled()) {
            return null;
        }
        long v = corpus.sparseCorpusVersion();
        Bm25Index cur = index;
        if (cur != null && version == v && cur.size() > 0) {
            return cur;
        }
        synchronized (this) {
            cur = index;
            if (cur != null && version == v && cur.size() > 0) {
                return cur;
            }
            List<ScoredDoc> docs = corpus.sparseCorpus();
            if (docs == null || docs.isEmpty()) {
                index = null;
                version = v;
                return null;
            }
            long t0 = System.currentTimeMillis();
            Bm25Index built = new Bm25Index(docs, props.getSparseK1(), props.getSparseB(),
                    props.isSparseLatinTrigram());
            index = built;
            version = v;
            logger.info("BM25 索引已重建：{} 条分片，平均长度 {} 词，耗时 {} ms（分词：{}；k1={} b={}）",
                    built.size(), Math.round(built.averageDocLength()),
                    System.currentTimeMillis() - t0, RagTokenizer.describe(props.isSparseLatinTrigram()),
                    built.k1(), built.b());
            return built;
        }
    }

    /** 无 provider 的"永远不可用"实例（单测/纯稠密部署用） */
    public static SparseIndexCache disabled(RagProperties props) {
        return new SparseIndexCache(null, props);
    }
}

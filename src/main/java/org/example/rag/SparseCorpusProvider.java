package org.example.rag;

import org.example.vector.ScoredDoc;

import java.util.List;

/**
 * 稀疏通道的语料来源 —— <b>只读快照 + 版本号</b>。
 *
 * <h3>为什么要抽这么一个接口（而不是直接 {@code instanceof InMemoryVectorStoreGateway}）</h3>
 * BM25 是"整库统计"（每个词出现在多少文档里、平均文档长度是多少），
 * 所以稀疏通道需要<b>全量语料</b>，而 {@link org.example.vector.VectorStoreGateway}
 * 的契约只有"给一个查询向量、返回 topK" —— 它是为稠密检索设计的，
 * 没有（也不该有）"把所有文档倒出来"的能力。
 *
 * <p>于是新增这一个窄接口：<b>默认返回空</b>，只有真正支持全量枚举的存储实现它。
 * 这样：
 * <ul>
 *   <li>Milvus 那种"语料在远端、枚举要全表扫描"的后端<b>什么都不用改</b>，
 *       混合检索会自动退化成纯稠密（日志里会如实写"稀疏通道不可用"）；</li>
 *   <li>内存实现（本项目默认、也是线上在用的那个）天然满足；</li>
 *   <li>离线评测可以直接喂一份确定性快照，不必起 Spring 上下文。</li>
 * </ul>
 *
 * <p>{@code version} 的语义是"语料代次"：任何一次 upsert/delete 都必须让它变化
 * （内存实现用记录数当版本 —— 只有 318 条固定语料时它足够，而且零成本；
 * 若将来出现"同数量替换"的写入，这里必须换成真正的自增代次，届时要改这一处）。
 */
public interface SparseCorpusProvider {

    /**
     * 语料快照（只读；调用方不应修改返回的列表）。
     * 默认空 —— 不支持全量枚举的后端不必实现。
     */
    default List<ScoredDoc> sparseCorpus() {
        return List.of();
    }

    /**
     * 语料版本；与上次不同即重建 BM25 索引。
     * 默认 0 表示"没有版本概念/语料为空"。
     */
    default long sparseCorpusVersion() {
        return 0L;
    }
}

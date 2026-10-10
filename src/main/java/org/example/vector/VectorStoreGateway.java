package org.example.vector;

import java.util.List;
import java.util.Map;

/**
 * 向量存储统一入口。
 *
 * <p>对外屏蔽底层向量库差异：
 * <ul>
 *   <li>memory：进程内向量存储 + 本地 JSON 持久化，免安装任何中间件，适合本地演示与教学；</li>
 *   <li>milvus：对接 Milvus 生产级向量数据库（需自行通过 docker 启动）。</li>
 * </ul>
 * 由配置项 {@code vector.store} 决定装配哪个实现。
 */
public interface VectorStoreGateway {

    /**
     * 写入或更新一条文档向量（按 id 幂等）。
     *
     * @param id       文档 ID
     * @param content  分片正文
     * @param vector   文档向量
     * @param metadata 元数据（来源文件、标题、分片序号等）
     */
    void upsert(String id, String content, List<Float> vector, Map<String, Object> metadata);

    /**
     * 删除某个来源文件的全部向量（文件重建索引时先删旧数据）。
     *
     * @param source 归一化后的来源文件路径
     * @return 删除条数
     */
    long deleteBySource(String source);

    /**
     * 向量相似度检索。
     *
     * @param queryVector 查询向量
     * @param topK        返回条数
     * @return 按相似度从高到低排序的文档
     */
    List<ScoredDoc> search(List<Float> queryVector, int topK);

    /**
     * 当前存储中文档总数。
     */
    long count();

    /**
     * 后端标识（memory / milvus），用于健康检查与日志。
     */
    String backend();
}

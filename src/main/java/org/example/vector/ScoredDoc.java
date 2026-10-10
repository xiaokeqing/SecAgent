package org.example.vector;

import lombok.Getter;
import lombok.Setter;

import java.util.Map;

/**
 * 向量检索命中的单条文档。
 * 统一 Milvus 与内存两种存储的返回结构，上层 Service 不感知底层实现。
 */
@Getter
@Setter
public class ScoredDoc {

    /** 文档唯一 ID（文件名 + 分片序号的确定性 UUID） */
    private String id;

    /** 分片正文 */
    private String content;

    /** 相似度分数，越大越相似（内存实现为余弦相似度；Milvus L2 会换算为分数） */
    private float score;

    /** 元数据：来源文件、标题、分片序号等 */
    private Map<String, Object> metadata;

    public ScoredDoc() {
    }

    public ScoredDoc(String id, String content, float score, Map<String, Object> metadata) {
        this.id = id;
        this.content = content;
        this.score = score;
        this.metadata = metadata;
    }
}

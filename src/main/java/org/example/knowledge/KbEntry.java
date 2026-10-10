package org.example.knowledge;

import lombok.Data;

/**
 * 一条"待审核 / 已通过"知识条目。
 *
 * <p>设计目标（对应 ASI06 防记忆/知识库投毒）：
 * 任何不可信内容（人工提交、对话自动写入、取证自动写入）在
 * "注入检测 + 管理员人工审核通过"之前，状态一律为 PENDING，
 * 绝不进入向量检索，也不会被任何回答引用。
 */
@Data
public class KbEntry {

    /** 条目唯一 ID（UUID） */
    private String id;

    /** 知识正文 */
    private String content;

    /** 所属类别（knowledge.categories 之一） */
    private String category;

    /** 来源标记：人工提交 / 对话自动写入 / 取证自动写入 */
    private String source;

    /** 提交人（登录用户名；系统自动写入为 system） */
    private String actor;

    /** 提交时间（epoch 毫秒） */
    private long createdAt;

    /** 状态：PENDING（待审核） / APPROVED（已通过） */
    private String status;

    /** 是否已向量化进向量库（无真实 Embedding Key 时先入"本地关键字库"，配好 Key 后可补向量化） */
    private boolean vectorized;

    /** 审核人（approve 时记录） */
    private String approvedBy;

    /** 审核时间（epoch 毫秒；未审核为 0） */
    private long approvedAt;
}

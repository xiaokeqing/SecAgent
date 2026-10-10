package org.example.config;

import org.example.service.VectorIndexService;
import org.example.vector.VectorStoreGateway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.File;

/**
 * 安全知识库自动初始化（仅内存模式）。
 *
 * <p>应用启动时，如果本地向量库为空，自动对 security-docs 目录下的
 * .md/.txt 知识文档做切片、向量化并入库；之后向量持久化到本地 JSON，
 * 重启不重复调用 Embedding 接口。这样无需 Milvus、无需手动上传即可直接使用。
 */
@Component
@ConditionalOnProperty(name = "vector.store", havingValue = "memory", matchIfMissing = true)
public class KnowledgeBaseInitializer implements ApplicationRunner {

    private static final Logger logger = LoggerFactory.getLogger(KnowledgeBaseInitializer.class);

    @Autowired
    private VectorStoreGateway vectorStore;

    @Autowired
    private VectorIndexService vectorIndexService;

    @Value("${vector.kb.auto-index:true}")
    private boolean autoIndex;

    @Value("${file.kb.path:security-docs}")
    private String kbPath;

    @Override
    public void run(ApplicationArguments args) {
        if (!autoIndex) {
            logger.info("安全知识库自动索引已关闭（vector.kb.auto-index=false）");
            return;
        }
        if (vectorStore.count() > 0) {
            logger.info("✓ 向量库已有 {} 条记录，跳过自动索引", vectorStore.count());
            return;
        }

        File dir = new File(kbPath);
        if (!dir.exists() || !dir.isDirectory()) {
            // 兼容从项目根目录或上一级目录启动
            File alt = new File("../" + kbPath);
            if (alt.exists()) {
                dir = alt;
            } else {
                logger.warn("未找到安全知识库目录: {}，请先准备 security-docs 文档", kbPath);
                return;
            }
        }

        File[] docs = dir.listFiles((d, n) -> n.endsWith(".md") || n.endsWith(".txt"));
        int docCount = docs == null ? 0 : docs.length;
        if (docCount == 0) {
            logger.warn("安全知识库目录 {} 下没有 .md/.txt 文档", dir.getAbsolutePath());
            return;
        }

        logger.info("============ 开始构建安全知识库（共 {} 篇文档），首次需要调用 Embedding 接口，请稍候 ============", docCount);
        try {
            VectorIndexService.IndexingResult result = vectorIndexService.indexDirectory(dir.getAbsolutePath());
            if (result.isSuccess()) {
                logger.info("============ 安全知识库构建完成：{} 篇文档全部索引成功，向量库共 {} 条 ============",
                        result.getTotalFiles(), vectorStore.count());
            } else {
                logger.warn("安全知识库部分文档索引失败：成功 {}，失败 {}，原因：{}",
                        result.getSuccessCount(), result.getFailCount(), result.getErrorMessage());
            }
        } catch (Exception e) {
            // 不阻止应用启动：可能是 API Key 未配置或网络问题，用户仍可配置后手动上传
            logger.error("安全知识库自动索引失败（不影响应用启动，可配置 Key 后手动上传）: {}", e.getMessage());
        }
    }
}

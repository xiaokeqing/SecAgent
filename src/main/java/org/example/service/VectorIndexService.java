package org.example.service;

import lombok.Getter;
import lombok.Setter;
import org.example.dto.DocumentChunk;
import org.example.vector.VectorStoreGateway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.*;

/**
 * 向量索引服务
 * 负责读取文件、文档分片、调用 Embedding 生成向量，并通过 {@link VectorStoreGateway}
 * 写入底层向量库（内存存储或 Milvus 由配置 vector.store 决定）。
 */
@Service
public class VectorIndexService {

    private static final Logger logger = LoggerFactory.getLogger(VectorIndexService.class);

    @Autowired
    private VectorStoreGateway vectorStore;

    @Autowired
    private VectorEmbeddingService embeddingService;

    @Autowired
    private DocumentChunkService chunkService;

    @Value("${file.upload.path}")
    private String uploadPath;

    /**
     * 索引指定目录下的所有文件
     *
     * @param directoryPath 目录路径（可选，默认使用配置的上传目录）
     * @return 索引结果
     */
    public IndexingResult indexDirectory(String directoryPath) {
        IndexingResult result = new IndexingResult();
        result.setStartTime(LocalDateTime.now());

        try {
            String targetPath = (directoryPath != null && !directoryPath.trim().isEmpty())
                    ? directoryPath : uploadPath;

            Path dirPath = Paths.get(targetPath).normalize();
            File directory = dirPath.toFile();

            if (!directory.exists() || !directory.isDirectory()) {
                throw new IllegalArgumentException("目录不存在或不是有效目录: " + targetPath);
            }

            result.setDirectoryPath(directory.getAbsolutePath());

            File[] files = directory.listFiles((dir, name) ->
                name.endsWith(".txt") || name.endsWith(".md")
            );

            if (files == null || files.length == 0) {
                logger.warn("目录中没有找到支持的文件: {}", targetPath);
                result.setTotalFiles(0);
                result.setSuccess(true);
                result.setEndTime(LocalDateTime.now());
                return result;
            }

            result.setTotalFiles(files.length);
            logger.info("开始索引目录[{}]: {}, 找到 {} 个文件", vectorStore.backend(), targetPath, files.length);

            for (File file : files) {
                try {
                    indexSingleFile(file.getAbsolutePath());
                    result.incrementSuccessCount();
                    logger.info("✓ 文件索引成功: {}", file.getName());
                } catch (Exception e) {
                    result.incrementFailCount();
                    result.addFailedFile(file.getAbsolutePath(), e.getMessage());
                    logger.error("✗ 文件索引失败: {}", file.getName(), e);
                }
            }

            result.setSuccess(result.getFailCount() == 0);
            result.setEndTime(LocalDateTime.now());

            logger.info("目录索引完成: 总数={}, 成功={}, 失败={}",
                result.getTotalFiles(), result.getSuccessCount(), result.getFailCount());

            return result;

        } catch (Exception e) {
            logger.error("索引目录失败", e);
            result.setSuccess(false);
            result.setErrorMessage(e.getMessage());
            result.setEndTime(LocalDateTime.now());
            return result;
        }
    }

    /**
     * 索引单个文件
     *
     * @param filePath 文件路径
     * @throws Exception 索引失败时抛出异常
     */
    public void indexSingleFile(String filePath) throws Exception {
        Path path = Paths.get(filePath).normalize();
        File file = path.toFile();

        if (!file.exists() || !file.isFile()) {
            throw new IllegalArgumentException("文件不存在: " + filePath);
        }

        logger.info("开始索引文件: {}", path);

        // 1. 读取文件内容
        String rawContent = Files.readString(path);
        logger.info("读取文件: {}, 内容长度: {} 字符", path, rawContent.length());

        // 1.1 解析文档开头 front-matter（来源 source / 可信度 trust / 日期 date），
        //     并把 front-matter 从正文中剥离，避免元信息本身被分片向量化
        Map<String, String> frontMatter = parseFrontMatter(rawContent);
        String content = stripFrontMatter(rawContent);

        // 2. 删除该文件的旧数据（如果存在）
        String normalizedSource = normalizeSource(path.toString());
        vectorStore.deleteBySource(normalizedSource);

        // 3. 文档分片
        List<DocumentChunk> chunks = chunkService.chunkDocument(content, path.toString());
        logger.info("文档分片完成: {} -> {} 个分片", filePath, chunks.size());

        // 4. 为每个分片生成向量并写入向量库
        for (int i = 0; i < chunks.size(); i++) {
            DocumentChunk chunk = chunks.get(i);

            try {
                List<Float> vector = embeddingService.generateEmbedding(chunk.getContent());
                Map<String, Object> metadata = buildMetadata(path.toString(), chunk, chunks.size(), frontMatter);

                // 确定性 ID：来源文件 + 分片序号，保证重复索引幂等
                String id = UUID.nameUUIDFromBytes((normalizedSource + "_" + chunk.getChunkIndex()).getBytes()).toString();
                vectorStore.upsert(id, chunk.getContent(), vector, metadata);

                logger.info("✓ 分片 {}/{} 索引成功", i + 1, chunks.size());

            } catch (Exception e) {
                logger.error("✗ 分片 {}/{} 索引失败", i + 1, chunks.size(), e);
                throw new RuntimeException("分片索引失败: " + e.getMessage(), e);
            }
        }

        logger.info("文件索引完成: {}, 共 {} 个分片, 库内总数 {}", filePath, chunks.size(), vectorStore.count());
    }

    /** 路径统一为正斜杠形式，作为元数据中的来源标识，保证跨平台一致。 */
    private String normalizeSource(String filePath) {
        return Paths.get(filePath).normalize().toString().replace(File.separator, "/");
    }

    /**
     * 构建元数据（包含文件信息 + 来源分级可信度标签）。
     * front-matter 约定：source（official 官方公告 / standard 标准 / vendor 厂商手册 /
     * community 社区 / ai AI生成）、trust（high / medium / low）、date（YYYY-MM-DD）。
     * 未标注来源的文档默认 community / medium（保守处理，不默认高可信）。
     */
    private Map<String, Object> buildMetadata(String filePath, DocumentChunk chunk, int totalChunks,
                                              Map<String, String> frontMatter) {
        Map<String, Object> metadata = new HashMap<>();

        Path path = Paths.get(filePath).normalize();
        String normalizedPath = normalizeSource(filePath);

        Path fileName = path.getFileName();
        String fileNameStr = fileName != null ? fileName.toString() : "";
        String extension = "";
        int dotIndex = fileNameStr.lastIndexOf('.');
        if (dotIndex > 0) {
            extension = fileNameStr.substring(dotIndex);
        }

        metadata.put("_source", normalizedPath);
        metadata.put("_extension", extension);
        metadata.put("_file_name", fileNameStr);
        metadata.put("chunkIndex", chunk.getChunkIndex());
        metadata.put("totalChunks", totalChunks);

        // —— 来源分级 + 可信度标签（检索时可按可信度加权，回答时标注依据来源） ——
        metadata.put("_source_type", frontMatter.getOrDefault("source", "community"));
        metadata.put("_trust_level", frontMatter.getOrDefault("trust", "medium"));
        String docDate = frontMatter.getOrDefault("date", "");
        if (!docDate.isEmpty()) {
            metadata.put("_doc_date", docDate);
        }

        if (chunk.getTitle() != null && !chunk.getTitle().isEmpty()) {
            metadata.put("title", chunk.getTitle());
        }

        return metadata;
    }

    /**
     * 解析文档开头的 YAML front-matter（--- 包起来的 key: value）。
     * 无 front-matter 返回空 Map。
     */
    private Map<String, String> parseFrontMatter(String raw) {
        Map<String, String> fm = new HashMap<>();
        String body = stripFrontMatter(raw);
        if (body.equals(raw)) {
            return fm; // 没有 front-matter
        }
        int firstEnd = raw.indexOf('\n');
        int second = raw.indexOf("\n---", firstEnd);
        String block = raw.substring(firstEnd + 1, second < 0 ? raw.length() : second);
        for (String line : block.split("\n")) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                String key = line.substring(0, colon).trim().toLowerCase();
                String val = line.substring(colon + 1).trim();
                if (!key.isEmpty() && !val.isEmpty()) {
                    fm.put(key, val);
                }
            }
        }
        return fm;
    }

    /** 剥离文档开头 front-matter，返回正文；无 front-matter 时原样返回。 */
    private String stripFrontMatter(String raw) {
        if (raw == null) {
            return "";
        }
        String normalized = raw.replace("\r\n", "\n");
        if (!normalized.startsWith("---")) {
            return raw;
        }
        int firstEnd = normalized.indexOf('\n');
        int second = normalized.indexOf("\n---", firstEnd);
        if (second < 0) {
            return raw;
        }
        int bodyStart = normalized.indexOf('\n', second + 1);
        return bodyStart < 0 ? "" : raw.substring(bodyStart + 1);
    }

    /**
     * 索引结果类
     */
    @Getter
    public static class IndexingResult {
        @Setter
        private boolean success;
        @Setter
        private String directoryPath;
        @Setter
        private int totalFiles;
        private int successCount;
        private int failCount;
        @Setter
        private LocalDateTime startTime;
        @Setter
        private LocalDateTime endTime;
        @Setter
        private String errorMessage;
        private Map<String, String> failedFiles = new HashMap<>();

        public void incrementSuccessCount() {
            this.successCount++;
        }

        public void incrementFailCount() {
            this.failCount++;
        }

        public long getDurationMs() {
            if (startTime != null && endTime != null) {
                return java.time.Duration.between(startTime, endTime).toMillis();
            }
            return 0;
        }

        public void addFailedFile(String filePath, String error) {
            this.failedFiles.put(filePath, error);
        }
    }
}

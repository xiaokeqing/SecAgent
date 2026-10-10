package org.example.vector.memory;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import lombok.Getter;
import lombok.Setter;
import org.example.vector.ScoredDoc;
import org.example.vector.VectorStoreGateway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * 进程内向量存储：免安装任何中间件。
 *
 * <p>数据保存在内存中，并持久化到本地 JSON 文件（默认 data/vector-store.json），
 * 应用重启后自动加载，避免重复调用 Embedding 接口产生费用。
 * 相似度采用余弦相似度，适合安全知识库这类中小规模语料的本地演示与开发。
 */
@Component
@ConditionalOnProperty(name = "vector.store", havingValue = "memory", matchIfMissing = true)
public class InMemoryVectorStoreGateway implements VectorStoreGateway {

    private static final Logger logger = LoggerFactory.getLogger(InMemoryVectorStoreGateway.class);

    @Value("${vector.memory.file:data/vector-store.json}")
    private String persistFile;

    private final ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    /** id -> 记录 */
    private final Map<String, Record> records = new ConcurrentHashMap<>();

    @PostConstruct
    public void init() {
        load();
    }

    @Override
    public void upsert(String id, String content, List<Float> vector, Map<String, Object> metadata) {
        if (id == null || vector == null || vector.isEmpty()) {
            throw new IllegalArgumentException("id 与向量不能为空");
        }
        // 模型维度变化时（如更换 embedding 模型）清空旧数据，避免维度不一致
        records.computeIfPresent(id, (k, old) -> {
            if (old.getVector() != null && old.getVector().size() != vector.size()) {
                logger.warn("检测到向量维度变化（{} -> {}），清空内存库旧数据", old.getVector().size(), vector.size());
                records.clear();
            }
            return null;
        });
        Record r = new Record();
        r.setId(id);
        r.setContent(content);
        r.setVector(new ArrayList<>(vector));
        r.setMetadata(metadata);
        records.put(id, r);
        persist();
    }

    @Override
    public long deleteBySource(String source) {
        if (source == null) {
            return 0;
        }
        long before = records.size();
        records.values().removeIf(r -> {
            Object s = r.getMetadata() == null ? null : r.getMetadata().get("_source");
            return s != null && source.equals(s.toString());
        });
        long removed = before - records.size();
        if (removed > 0) {
            persist();
        }
        return removed;
    }

    @Override
    public List<ScoredDoc> search(List<Float> queryVector, int topK) {
        if (queryVector == null || queryVector.isEmpty()) {
            return new ArrayList<>();
        }
        int k = Math.max(1, topK);
        return records.values().stream()
                .filter(r -> r.getVector() != null && r.getVector().size() == queryVector.size())
                .map(r -> new ScoredDoc(r.getId(), r.getContent(),
                        cosine(queryVector, r.getVector()), r.getMetadata()))
                .sorted(Comparator.comparingDouble(ScoredDoc::getScore).reversed())
                .limit(k)
                .collect(Collectors.toList());
    }

    @Override
    public long count() {
        return records.size();
    }

    @Override
    public String backend() {
        return "memory";
    }

    /** 余弦相似度，取值 [-1,1]，越接近 1 越相似。 */
    private static float cosine(List<Float> a, List<Float> b) {
        double dot = 0.0;
        double na = 0.0;
        double nb = 0.0;
        for (int i = 0; i < a.size(); i++) {
            float x = a.get(i);
            float y = b.get(i);
            dot += x * y;
            na += x * x;
            nb += y * y;
        }
        if (na == 0 || nb == 0) {
            return 0.0f;
        }
        return (float) (dot / (Math.sqrt(na) * Math.sqrt(nb)));
    }

    private synchronized void persist() {
        try {
            Path p = Paths.get(persistFile);
            if (p.getParent() != null) {
                Files.createDirectories(p.getParent());
            }
            Snapshot snapshot = new Snapshot();
            snapshot.setRecords(new ArrayList<>(records.values()));
            mapper.writeValue(p.toFile(), snapshot);
        } catch (IOException e) {
            logger.warn("内存向量库持久化失败: {}", e.getMessage());
        }
    }

    private void load() {
        try {
            Path p = Paths.get(persistFile);
            if (!Files.exists(p)) {
                logger.info("内存向量库无历史文件，将在首次索引时创建: {}", p.toAbsolutePath());
                return;
            }
            Snapshot snapshot = mapper.readValue(p.toFile(), Snapshot.class);
            if (snapshot != null && snapshot.getRecords() != null) {
                for (Record r : snapshot.getRecords()) {
                    if (r.getId() != null && r.getVector() != null) {
                        records.put(r.getId(), r);
                    }
                }
            }
            logger.info("已从 {} 加载 {} 条内存向量", p.toAbsolutePath(), records.size());
        } catch (Exception e) {
            logger.warn("加载内存向量库失败，将重新索引: {}", e.getMessage());
        }
    }

    @Getter
    @Setter
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Record {
        private String id;
        private String content;
        private List<Float> vector;
        private Map<String, Object> metadata;
    }

    @Getter
    @Setter
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Snapshot {
        private List<Record> records;
    }
}

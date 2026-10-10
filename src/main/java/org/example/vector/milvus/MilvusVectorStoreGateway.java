package org.example.vector.milvus;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import io.milvus.client.MilvusServiceClient;
import io.milvus.grpc.MutationResult;
import io.milvus.grpc.SearchResults;
import io.milvus.param.MetricType;
import io.milvus.param.R;
import io.milvus.param.RpcStatus;
import io.milvus.param.collection.LoadCollectionParam;
import io.milvus.param.dml.DeleteParam;
import io.milvus.param.dml.InsertParam;
import io.milvus.param.dml.SearchParam;
import io.milvus.response.SearchResultsWrapper;
import org.example.constant.MilvusConstants;
import org.example.vector.ScoredDoc;
import org.example.vector.VectorStoreGateway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * 基于 Milvus 的向量存储实现（生产级向量数据库）。
 * 仅在 vector.store=milvus 时装配，需要先通过 docker compose 启动 Milvus。
 */
@Component
@ConditionalOnProperty(name = "vector.store", havingValue = "milvus")
public class MilvusVectorStoreGateway implements VectorStoreGateway {

    private static final Logger logger = LoggerFactory.getLogger(MilvusVectorStoreGateway.class);

    private final MilvusServiceClient milvusClient;
    private final Gson gson = new Gson();

    public MilvusVectorStoreGateway(MilvusServiceClient milvusClient) {
        this.milvusClient = milvusClient;
    }

    @Override
    public void upsert(String id, String content, List<Float> vector, Map<String, Object> metadata) {
        try {
            loadCollection();

            List<InsertParam.Field> fields = new ArrayList<>();
            fields.add(new InsertParam.Field("id", Collections.singletonList(id)));
            fields.add(new InsertParam.Field("content", Collections.singletonList(content)));
            fields.add(new InsertParam.Field("vector", Collections.singletonList(vector)));
            JsonObject metadataJson = gson.toJsonTree(metadata).getAsJsonObject();
            fields.add(new InsertParam.Field("metadata", Collections.singletonList(metadataJson)));

            R<MutationResult> resp = milvusClient.insert(InsertParam.newBuilder()
                    .withCollectionName(MilvusConstants.MILVUS_COLLECTION_NAME)
                    .withFields(fields)
                    .build());
            if (resp.getStatus() != 0) {
                throw new RuntimeException("Milvus 插入向量失败: " + resp.getMessage());
            }
        } catch (Exception e) {
            logger.error("Milvus 写入失败, id={}", id, e);
            throw new RuntimeException("Milvus 写入失败: " + e.getMessage(), e);
        }
    }

    @Override
    public long deleteBySource(String source) {
        try {
            R<RpcStatus> load = milvusClient.loadCollection(LoadCollectionParam.newBuilder()
                    .withCollectionName(MilvusConstants.MILVUS_COLLECTION_NAME)
                    .build());
            if (load.getStatus() != 0 && load.getStatus() != 65535) {
                logger.warn("Milvus 加载集合失败: {}", load.getMessage());
                return 0;
            }
            String expr = String.format("metadata[\"_source\"] == \"%s\"", source);
            R<MutationResult> resp = milvusClient.delete(DeleteParam.newBuilder()
                    .withCollectionName(MilvusConstants.MILVUS_COLLECTION_NAME)
                    .withExpr(expr)
                    .build());
            if (resp.getStatus() != 0) {
                logger.warn("Milvus 删除旧数据警告: {}", resp.getMessage());
                return 0;
            }
            long cnt = resp.getData().getDeleteCnt();
            logger.info("Milvus 删除旧数据 {} 条, source={}", cnt, source);
            return cnt;
        } catch (Exception e) {
            logger.warn("Milvus 删除旧数据失败（可能是首次索引）: {}", e.getMessage());
            return 0;
        }
    }

    @Override
    public List<ScoredDoc> search(List<Float> queryVector, int topK) {
        try {
            SearchParam searchParam = SearchParam.newBuilder()
                    .withCollectionName(MilvusConstants.MILVUS_COLLECTION_NAME)
                    .withVectorFieldName("vector")
                    .withVectors(Collections.singletonList(queryVector))
                    .withTopK(topK)
                    .withMetricType(MetricType.L2)
                    .withOutFields(List.of("id", "content", "metadata"))
                    .withParams("{\"nprobe\":10}")
                    .build();

            R<SearchResults> resp = milvusClient.search(searchParam);
            if (resp.getStatus() != 0) {
                throw new RuntimeException("Milvus 搜索失败: " + resp.getMessage());
            }

            SearchResultsWrapper wrapper = new SearchResultsWrapper(resp.getData().getResults());
            List<ScoredDoc> results = new ArrayList<>();
            int n = wrapper.getIDScore(0).size();
            for (int i = 0; i < n; i++) {
                String id = (String) wrapper.getIDScore(0).get(i).get("id");
                String content = (String) wrapper.getFieldData("content", 0).get(i);
                // L2 为欧氏距离，越小越相似；换算为 1/(1+distance) 作为“越大越好”的统一分数
                float distance = wrapper.getIDScore(0).get(i).getScore();
                float score = 1.0f / (1.0f + Math.max(0f, distance));
                Object meta = wrapper.getFieldData("metadata", 0).get(i);
                ScoredDoc doc = new ScoredDoc(id, content, score, null);
                if (meta != null) {
                    JsonObject obj = gson.toJsonTree(meta).getAsJsonObject();
                    doc.setMetadata(gson.fromJson(obj, Map.class));
                }
                results.add(doc);
            }
            return results;
        } catch (Exception e) {
            logger.error("Milvus 搜索失败", e);
            throw new RuntimeException("Milvus 搜索失败: " + e.getMessage(), e);
        }
    }

    @Override
    public long count() {
        return -1;
    }

    @Override
    public String backend() {
        return "milvus";
    }

    private void loadCollection() {
        R<RpcStatus> load = milvusClient.loadCollection(LoadCollectionParam.newBuilder()
                .withCollectionName(MilvusConstants.MILVUS_COLLECTION_NAME)
                .build());
        if (load.getStatus() != 0 && load.getStatus() != 65535) {
            throw new RuntimeException("加载 Milvus 集合失败: " + load.getMessage());
        }
    }
}

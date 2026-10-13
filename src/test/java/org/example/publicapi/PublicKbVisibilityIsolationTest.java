package org.example.publicapi;

import org.example.knowledge.PublicKbVisibility;
import org.example.rag.RagProperties;
import org.example.service.VectorEmbeddingService;
import org.example.service.VectorSearchService;
import org.example.vector.ScoredDoc;
import org.example.vector.memory.InMemoryVectorStoreGateway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * <b>可见性隔离：公开身份只能检索公开白名单目录，公开结果里绝不能出现非白名单来源。</b>
 *
 * <h3>为什么要写成"混合检索也一起过"的测试</h3>
 * 混合检索改造引入了一条新的召回通道（BM25 稀疏），而<b>稀疏通道是建立在全量语料上的</b> ——
 * 它的倒排索引里包含内部文档的词频统计。这带来一个必须被钉住的问题：
 * "公开检索会不会因为走了新通道，而把内部片段带出来？"
 *
 * <p>答案是<b>不会</b>，但理由必须是代码里的机制、而不是信念：
 * <ol>
 *   <li>公开链路的出海路径上，<b>每一条</b>候选都要先过 {@link PublicKbVisibility#denyReason}
 *       （见 {@code PublicKbService#search} 的循环），非白名单来源一律丢弃；</li>
 *   <li>稀疏通道的中间量（词频、文档频率、BM25 分数）只在本进程内用于排序，
 *       不进响应体、不进引用块。</li>
 * </ol>
 *
 * <h3>本测试的夹具为什么是"对抗性"的</h3>
 * 只放一篇内部文档、还让它跟查询不相关，是测不出问题的 —— 那种情况本来就排不进来。
 * 这里刻意构造：
 * <ul>
 *   <li>内部文档在<b>语义上最近</b>（查询向量是它的方向，余弦 = 1.0）；</li>
 *   <li>内部文档在<b>词面上最匹配</b>（标题/正文都含查询里的罕见标识）；</li>
 *   <li>内部文档的来源类型还是合法的 {@code community}，只有<b>路径</b>能判出它不该公开
 *       （这正是最容易漏的一类：只看 source_type 的实现在这里会放行）。</li>
 * </ul>
 * 也就是说：<b>任何一层过滤写漏了，内部文档都会出现在公开结果的第一条</b>。
 *
 * <p>另有 {@code source_type} 缺失、以及"名字里带 security-docs 但在别处"的
 * 目录伪装两种拒绝形状，一起覆盖。
 */
class PublicKbVisibilityIsolationTest {

    private static final String QUERY = "CWE-918 的 SSRF 内部处置手册";

    /** 会被公开白名单拒绝的文档：标题/正文里都有标记串，便于"泄露了就能一眼看出来" */
    private static final String INTERNAL_MARK = "内部处置手册密级标记";

    private InMemoryVectorStoreGateway store;
    private PublicKbService service;

    @TempDir
    Path tmp;

    @BeforeEach
    void setUp() throws Exception {
        store = new InMemoryVectorStoreGateway();
        ReflectionTestUtils.setField(store, "persistFile", tmp.resolve("vector-store.json").toString());

        // 全 1024 维中只有第 0 维非零，便于精确控制余弦相似度
        put("internal-1",
                INTERNAL_MARK + "：CWE-918 SSRF 的内部处置流程与内网资产清单",
                "CWE-918 SSRF 内部处置手册",
                "F:/7AAA/AI/SecAgent/sec-agent/docs/internal/ssrf-playbook.md",
                "community",                 // ← 来源类型合法，只有路径能判出不该公开
                unit(1));
        put("internal-2",
                INTERNAL_MARK + "：内网渗透的内部复盘记录",
                "内网渗透内部复盘",
                "F:/7AAA/AI/SecAgent/sec-agent/docs/internal/pentest-review.md",
                "community",
                unit(1));
        put("no-source-type",
                INTERNAL_MARK + "：未标注来源的草稿（默认不公开）",
                "未标注来源草稿",
                "F:/7AAA/AI/SecAgent/sec-agent/security-docs-tmp/draft.md",
                null,                        // ← 缺失来源类型 → 必须拒绝
                unit(1));
        put("public-1",
                "SSRF 服务端请求伪造（CWE-918）的原理与防御：白名单校验、禁用危险协议",
                "SSRF 服务端请求伪造（CWE-918）",
                "F:/7AAA/AI/SecAgent/sec-agent/security-docs/07-SSRF服务端请求伪造.md",
                "community",
                unit(0));                 // ← 与查询向量正交，稠密通道排最后
        put("public-2",
                "路径穿越（CWE-22）防御：规范化与白名单",
                "路径穿越漏洞原理与防御",
                "F:/7AAA/AI/SecAgent/sec-agent/security-docs/02-路径穿越漏洞原理与防御.md",
                "community",
                unit(0));

        service = newService();
    }

    private PublicKbService newService() {
        PublicKbVisibility visibility = new PublicKbVisibility();
        ReflectionTestUtils.setField(visibility, "allowedRootsRaw", "security-docs,data/kb-approved");
        ReflectionTestUtils.setField(visibility, "allowedSourceTypesRaw", "community");
        ReflectionTestUtils.setField(visibility, "deniedKeywordsRaw", "internal");
        visibility.init();

        // 刻意【不用 Mockito】：本机 JDK 25 上 Mockito 5.7 的 ByteBuddy
        // 无法给这个类做 inline mock（报 "Mockito cannot mock this class"）。
        // 一个只覆盖 generateQueryVector 的子类就够了 —— 测试要的是"查询向量是内部文档的方向"，
        // 不需要真的 embedding 客户端（init() 根本不会被调用）。
        VectorEmbeddingService embedding = new FixedQueryEmbedding(unit(1));

        VectorSearchService search = new VectorSearchService();
        ReflectionTestUtils.setField(search, "embeddingService", embedding);
        ReflectionTestUtils.setField(search, "vectorStore", store);
        ReflectionTestUtils.setField(search, "defaultTopK", 3);
        ReflectionTestUtils.setField(search, "minScore", 0.30f);
        ReflectionTestUtils.setField(search, "ragProperties", new RagProperties());
        ReflectionTestUtils.setField(search, "sparseCorpusProvider", provider(store));
        search.init();

        PublicKbService svc = new PublicKbService();
        ReflectionTestUtils.setField(svc, "vectorSearchService", search);
        ReflectionTestUtils.setField(svc, "visibility", visibility);
        ReflectionTestUtils.setField(svc, "topK", 3);
        ReflectionTestUtils.setField(svc, "snippetChars", 300);
        return svc;
    }

    /** 固定返回同一个查询向量的替身（不联网、不读 Key、不建客户端） */
    private static final class FixedQueryEmbedding extends VectorEmbeddingService {
        private final List<Float> vector;

        FixedQueryEmbedding(List<Float> vector) {
            this.vector = vector;
        }

        @Override
        public List<Float> generateQueryVector(String query) {
            return vector;
        }
    }

    // ==================== 安全不变量 ====================

    @Test
    @DisplayName("【安全不变量】公开检索结果里不含任何非白名单来源（内部文档在语义与词面上都更匹配）")
    void publicResultsNeverContainNonWhitelistedSources() {
        List<Map<String, Object>> results = service.search(QUERY);

        assertFalse(results.isEmpty(), "对抗性夹具下应至少返回公开文档（否则这条测试没有证明力）");
        for (Map<String, Object> r : results) {
            String blob = String.valueOf(r);
            assertFalse(blob.contains(INTERNAL_MARK),
                    "公开结果里出现内部文档内容：" + blob);
            assertFalse(blob.contains("docs/internal"),
                    "公开结果里出现内部路径：" + blob);
            assertFalse(blob.contains("ssrf-playbook") || blob.contains("pentest-review"),
                    "公开结果里出现内部文件名：" + blob);
            assertFalse(String.valueOf(r.get("title")).contains("内部处置手册"),
                    "公开结果里出现内部标题：" + r.get("title"));
        }

        // 计数口径（改成 2 是"混合检索的语义变化"，不是放行变宽，写清楚）：
        //   ・public-1 是稠密通道命中（余弦=1.0，且两路都有）→ 必然返回，且排第一；
        //   ・public-2 只被 BM25 稀疏通道命中（正文含"漏洞"等查询词，语义上与查询正交）——
        //     它含有意义的词面证据、也是白名单文档，所以出现在结果里<b>是混合检索该有的行为</b>。
        //   ・三篇内部/未标注来源候选一律被剔除，一篇都不出现。
        assertEquals(2, results.size(),
                "白名单内应恰好返回两篇（一篇两路命中 + 一篇仅词面命中）；实际=" + results.size());
        assertEquals("SSRF 服务端请求伪造（CWE-918）", results.get(0).get("title"),
                "两路都命中的公开文档必须排第一（内部文档语义最近，若过滤写漏它会出现在这里）");
        assertEquals("路径穿越漏洞原理与防御", results.get(1).get("title"));
    }

    @Test
    @DisplayName("前置事实：候选池里确实有内部文档（否则上面那条断言是空过）")
    void preFilterPoolReallyContainsInternalDocs() {
        List<ScoredDoc> raw = store.search(unit(1), 20);
        List<String> internal = new ArrayList<>();
        for (ScoredDoc d : raw) {
            Object src = d.getMetadata() == null ? null : d.getMetadata().get("_source");
            if (src != null && String.valueOf(src).contains("docs/internal")) {
                internal.add(d.getId());
            }
        }
        assertEquals(2, internal.size(),
                "夹具前提被破坏：候选池里应有两篇内部文档（内部文档被排除了，这条测试就失去了证明力）");
        assertEquals("internal-1", raw.get(0).getId(),
                "夹具前提被破坏：语义最近的必须是内部文档（余弦=1.0）");
    }

    @Test
    @DisplayName("公开检索走的是混合检索（两路召回），而不是绕过新链路的另一套实现")
    void publicSearchUsesHybridRetrieval() {
        PublicKbService svc = newService();
        Object search = ReflectionTestUtils.getField(svc, "vectorSearchService");
        assertTrue(search instanceof VectorSearchService);
        String desc = ((VectorSearchService) search).describeRetrieval();
        assertTrue(desc.contains("稀疏=true"), "公开链路复用内部检索，稀疏通道应当是开的：" + desc);
        assertTrue(desc.contains("重排=true"), "公开链路复用内部检索，重排应当是开的：" + desc);
    }

    @Test
    @DisplayName("跨目录同名陷阱：别的目录下的 security-docs/ 不能绕过白名单")
    void lookalikeDirectoryIsRejected() {
        PublicKbVisibility visibility = new PublicKbVisibility();
        ReflectionTestUtils.setField(visibility, "allowedRootsRaw", "security-docs");
        ReflectionTestUtils.setField(visibility, "allowedSourceTypesRaw", "community");
        ReflectionTestUtils.setField(visibility, "deniedKeywordsRaw", "internal");
        visibility.init();

        assertNotNull(visibility.denyReason("/tmp/security-docs-backup/内部稿.md", "内部稿.md", "community"),
                "/tmp/security-docs-backup 不是白名单目录之下，必须拒绝");
        assertNotNull(visibility.denyReason("/opt/secagent/docs/internal/x.md", "x.md", "community"),
                "docs/internal 必须被拒绝（路径命中 internal）");
        assertNotNull(visibility.denyReason("/opt/secagent/security-docs/x.md", "x.md", null),
                "缺 source_type 必须拒绝");
        assertEquals(null, visibility.denyReason("/opt/secagent/security-docs/x.md", "x.md", "community"),
                "正例：白名单目录 + 白名单来源类型应放行（否则上面的拒绝断言是假通过）");
    }

    // ==================== 辅助 ====================

    private void put(String id, String content, String title, String source,
                     String sourceType, List<Float> vector) {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("title", title);
        meta.put("_file_name", source.substring(source.lastIndexOf('/') + 1));
        meta.put("_source", source);
        if (sourceType != null) {
            meta.put("_source_type", sourceType);
        }
        meta.put("_trust_level", "medium");
        store.upsert(id, content, vector, meta);
    }

    /** 与线上同一维度（1024）：第 hot 维为 1、其余为 0。同 hot 的向量余弦=1，不同 hot=0。 */
    private static List<Float> unit(int hot) {
        int dim = 1024;
        List<Float> v = new ArrayList<>(dim);
        for (int i = 0; i < dim; i++) {
            v.add(i == hot ? 1f : 0f);
        }
        return v;
    }

    /**
     * 最小 ObjectProvider 替身。
     *
     * <p>三次踩坑记录（都写在这里，省得下次再试一遍）：
     * <ol>
     *   <li>用 lambda 编译不过 —— {@link ObjectProvider} <b>不是</b>函数式接口；</li>
     *   <li>{@code mock(ObjectProvider.class)} 在本机 JDK 25 + Mockito 5.7 上
     *       被 ByteBuddy 拒绝（生成这个 Spring 接口的代理直接报错）；</li>
     *   <li>它的抽象方法有三个（{@code getObject} / {@code getObject(Object...)} /
     *       {@code getIfAvailable} / {@code getIfUnique}）——在 Spring 6.1 里
     *       <b>都不是 default</b>，只实现两个会编译失败。</li>
     * </ol>
     * 结论：老老实实全实现。这也说明"接口是否函数式接口/default 方法"不能凭印象，
     * 得看编译器。
     */
    private static ObjectProvider<org.example.rag.SparseCorpusProvider> provider(
            org.example.rag.SparseCorpusProvider corpus) {
        return new ObjectProvider<>() {
            @Override
            public org.example.rag.SparseCorpusProvider getObject(Object... args) {
                return corpus;
            }

            @Override
            public org.example.rag.SparseCorpusProvider getObject() {
                return corpus;
            }

            @Override
            public org.example.rag.SparseCorpusProvider getIfAvailable() {
                return corpus;
            }

            @Override
            public org.example.rag.SparseCorpusProvider getIfUnique() {
                return corpus;
            }
        };
    }
}

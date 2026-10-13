package org.example.rag;

import org.example.vector.ScoredDoc;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * BM25 稀疏检索索引 —— <b>自己实现，零第三方依赖</b>。
 *
 * <h3>公式（Okapi BM25，与 Lucene 同形）</h3>
 * <pre>
 *   score(q, d) = Σ<sub>t∈q</sub> IDF(t) · f(t,d)·(k1+1) / ( f(t,d) + k1·(1 - b + b·|d|/avgdl) )
 *   IDF(t)      = ln( 1 + (N - df(t) + 0.5) / (df(t) + 0.5) )
 * </pre>
 * 采用<b>带 +1 的对数形式</b>（Lucene 的口径）：它保证 IDF 恒为正，
 * 于是"命中更多查询词"永远单调地提高分数 —— 若用经典 IDF，某个词出现在
 * 超过一半文档里时 IDF 会变成负数，"命中它反而扣分"，在 318 条小语料上很容易触发。
 *
 * <h3>为什么值得自建（而不是"稠密已经够了"）</h3>
 * 稠密通道的强项是语义改述，弱项是<b>罕见精确标识</b>：{@code CWE-918}、
 * {@code disallow-doctype-decl}、{@code bindParam}、{@code /dev/tcp/ip/4444}。
 * 这类 token 在 embedding 空间里几乎无邻居，容易被"语义相近但没这个标识"的片段挤掉；
 * 而它们在倒排索引里是天然的高 IDF 项。两条通道的强弱项正好互补，这就是混合检索的理由。
 *
 * <h3>线程安全</h3>
 * 索引构建后<b>不可变</b>（所有 Map 不再修改），只有查询读它，因此可以安全地被并发查询。
 * 语料变化时由调用方重建一个新实例整体替换，而不是就地改 —— 避免"查到一半索引变了"。
 */
public final class Bm25Index {

    /** BM25 词频饱和参数（1.2 是 Lucene 默认值） */
    public static final double DEFAULT_K1 = 1.2;
    /** BM25 文档长度归一化参数（0.75 是 Lucene 默认值） */
    public static final double DEFAULT_B = 0.75;

    /** 语料条目：一条向量分片 */
    public static final class Entry {
        final ScoredDoc doc;
        final List<String> terms;
        final Map<String, Integer> tf;

        Entry(ScoredDoc doc, List<String> terms) {
            this.doc = doc;
            this.terms = terms;
            this.tf = new HashMap<>();
            for (String t : terms) {
                tf.merge(t, 1, Integer::sum);
            }
        }
    }

    private final List<Entry> entries;
    private final Map<String, Integer> docFreq;
    private final Map<String, List<Integer>> postings;
    private final double avgDocLength;
    private final double k1;
    private final double b;

    /** 本次建索引用的分词口径（用于日志自述） */
    private final boolean latinTrigram;

    public Bm25Index(List<ScoredDoc> docs, double k1, double b, boolean latinTrigram) {
        this.k1 = k1 > 0 ? k1 : DEFAULT_K1;
        this.b = (b >= 0 && b <= 1) ? b : DEFAULT_B;
        this.latinTrigram = latinTrigram;
        this.entries = new ArrayList<>();
        this.docFreq = new HashMap<>();
        this.postings = new HashMap<>();

        long totalLen = 0;
        for (ScoredDoc d : docs) {
            if (d == null) {
                continue;
            }
            List<String> terms = RagTokenizer.tokenize(searchText(d), latinTrigram);
            Entry e = new Entry(d, terms);
            int idx = entries.size();
            entries.add(e);
            totalLen += terms.size();
            for (String t : new HashSet<>(e.tf.keySet())) {
                docFreq.merge(t, 1, Integer::sum);
                postings.computeIfAbsent(t, k -> new ArrayList<>()).add(idx);
            }
        }
        this.avgDocLength = entries.isEmpty() ? 1.0 : Math.max(1.0, (double) totalLen / entries.size());
    }

    /**
     * 真正进索引的文本：<b>正文 + 标题</b>。
     *
     * <p>标题单独加权是重排的活，但标题里的词必须先能被检索到 —— 实测有些片段正文里
     * 只写"本类漏洞"，而"路径穿越"只出现在小节标题里，不并进来就永远稀疏读不到。
     */
    private static String searchText(ScoredDoc d) {
        StringBuilder sb = new StringBuilder();
        if (d.getContent() != null) {
            sb.append(d.getContent()).append('\n');
        }
        Map<String, Object> m = d.getMetadata();
        if (m != null) {
            Object title = m.get("title");
            if (title != null) {
                sb.append(title).append('\n');
            }
            Object file = m.get("_file_name");
            if (file != null) {
                sb.append(file);
            }
        }
        return sb.toString();
    }

    public int size() {
        return entries.size();
    }

    public double averageDocLength() {
        return avgDocLength;
    }

    public boolean latinTrigram() {
        return latinTrigram;
    }

    public double k1() {
        return k1;
    }

    public double b() {
        return b;
    }

    /** 某个 term 的文档频率（重排/自检可用） */
    public int docFreq(String term) {
        return docFreq.getOrDefault(term, 0);
    }

    /** 索引里的文档（只读） */
    public List<ScoredDoc> documents() {
        List<ScoredDoc> out = new ArrayList<>(entries.size());
        for (Entry e : entries) {
            out.add(e.doc);
        }
        return out;
    }

    /** IDF（带 +1 的对数形式，恒正） */
    double idf(String term) {
        int df = docFreq.getOrDefault(term, 0);
        int n = entries.size();
        return Math.log(1.0 + (n - df + 0.5) / (df + 0.5));
    }

    /** 公开的 IDF（重排用它给"罕见标识"加权；语料里没有的词按"最罕见"处理） */
    public double idfOf(String term) {
        return idf(term);
    }

    /**
     * 一批词的"稀有度权重"：{@code IDF(term) / maxIDF}，取值 [0,1]。
     *
     * <h3>为什么重排需要它（一次真实回归教出来的）</h3>
     * 第一版重排只用"命中词覆盖度"（命中几种 / 查询共几种）。
     * 结果 {@code CWE-918 对应哪一类漏洞？} 这道题的前三名变成了
     * 「渗透测试报告怎么写」「命令注入（CWE-78/77）」「文件上传（CWE-434）」——
     * 因为查询里的"对应/一类/漏洞"这些<b>泛词</b>在那些片段里都有，
     * 覆盖度反而更高，而真正含 {@code CWE-918} 的 SSRF 片段只命中少数几个词。
     * 词袋覆盖度<b>把罕见标识和通用词当成了等价证据</b>，这是信号设计错误，不是调参问题。
     * 加上 IDF 归一化后，命中 {@code cwe-918}（318 篇里只有 1–2 篇含它）权重接近 1，
     * 命中"漏洞"（几乎每篇都有）接近 0。
     *
     * <h3>语料里根本没有的词必须给 0 权重（第二次被测试揪出来的方向性错误）</h3>
     * {@link #idf(String)} 对 {@code df=0} 的词返回的是<b>最大</b> IDF
     * （"文档频率越低越稀有"的外推结果）。但一个在语料里根本不存在的词，
     * 更准确的含义是"它提供不了任何判别力"——它不可能命中任何片段，
     * 却会在分母里占一份最大权重，把真正命中的稀有标识（df=1）压下去。
     * 实测（2 篇语料的对照实验）：{@code CWE-918} 的权重被算成 0.387，
     * 而语料里不存在的"对应/一类/漏洞"都被算成 1.0 —— 方向完全反了。
     * 所以这里显式给 {@code df=0} 的词 0 权重，并用"语料里存在的词"的最大 IDF 做归一化基准。
     *
     * @return 词 -&gt; 归一化权重（[0,1]，语料里不存在的词为 0）；空输入返回空 Map
     */
    public Map<String, Double> rarityWeights(java.util.Collection<String> terms) {
        Map<String, Double> out = new HashMap<>();
        if (terms == null || terms.isEmpty()) {
            return out;
        }
        double max = 0;
        Set<String> present = new HashSet<>();
        for (String t : terms) {
            if (docFreq.getOrDefault(t, 0) > 0) {
                present.add(t);
                max = Math.max(max, idf(t));
            }
        }
        for (String t : terms) {
            out.put(t, present.contains(t) && max > 0 ? idf(t) / max : 0.0);
        }
        return out;
    }

    /**
     * 查询：返回按 BM25 分数降序的命中（分数 ≤ 0 的不返回）。
     *
     * @param queryText 原始查询文本（内部用与建索引完全相同的分词器切）
     * @param topK      最多返回条数
     */
    public List<Hit> search(String queryText, int topK) {
        List<Hit> out = new ArrayList<>();
        if (entries.isEmpty() || queryText == null || queryText.isBlank()) {
            return out;
        }
        List<String> qTerms = RagTokenizer.tokenize(queryText, latinTrigram);
        if (qTerms.isEmpty()) {
            return out;
        }
        // 去重后累加：同一个 term 在查询里重复出现不该重复计分（查询词频没有意义，
        // 否则"SQL 注入 SQL 注入"会让这个词权重翻倍）
        Set<String> seen = new HashSet<>();
        Map<Integer, Double> acc = new HashMap<>();
        for (String t : qTerms) {
            if (!seen.add(t)) {
                continue;
            }
            List<Integer> posting = postings.get(t);
            if (posting == null) {
                continue;
            }
            double idf = idf(t);
            for (int idx : posting) {
                Entry e = entries.get(idx);
                int f = e.tf.getOrDefault(t, 0);
                double denom = f + k1 * (1.0 - b + b * (e.terms.size() / avgDocLength));
                acc.merge(idx, idf * f * (k1 + 1) / denom, Double::sum);
            }
        }
        for (Map.Entry<Integer, Double> e : acc.entrySet()) {
            if (e.getValue() > 0) {
                out.add(new Hit(entries.get(e.getKey()).doc, e.getValue()));
            }
        }
        out.sort(Comparator.comparingDouble((Hit h) -> h.score).reversed()
                .thenComparing(h -> h.doc.getId() == null ? "" : h.doc.getId()));
        if (out.size() > Math.max(1, topK)) {
            return new ArrayList<>(out.subList(0, Math.max(1, topK)));
        }
        return out;
    }

    /** 一条 BM25 命中 */
    public static final class Hit {
        public final ScoredDoc doc;
        public final double score;

        public Hit(ScoredDoc doc, double score) {
            this.doc = doc;
            this.score = score;
        }
    }
}

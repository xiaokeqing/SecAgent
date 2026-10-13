package org.example.rag;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * RRF（Reciprocal Rank Fusion，倒数排名融合）—— 自己实现，单公式、无参数可训。
 *
 * <h3>为什么用 RRF 而不是"分数归一化后加权求和"</h3>
 * 两路召回的分数<b>量纲根本不同</b>：余弦相似度在 [0,1]，BM25 是 ln 量级的无界分数
 * （实测同一查询里从 2 到 40 都有）。把两者归一化再线性加权，需要先决定
 * "0.9 的余弦等于多少 BM25" —— 那个换算系数没有客观依据，只能凭手感调，
 * 而且换一批语料就失效。
 *
 * <p>RRF 只用<b>排名</b>：
 * <pre>
 *   score(d) = Σ<sub>r ∈ 各通道</sub> 1 / (k + rank<sub>r</sub>(d))
 * </pre>
 * 它天然免疫量纲差异，也不需要训练。{@code k}（默认 60，与文献/Elasticsearch 一致）
 * 决定"靠前的名次有多值钱"：k 越小越激进（只看头部），越大越平均。
 *
 * <h3>为什么保留"通道来源"</h3>
 * 融合结果里记下每条文档是被哪几路召回的（{@link Fused#sources()}），
 * 这样"某条结果是靠 BM25 翻上来的"是可核对的，而不是一个无法解释的黑箱排序。
 * 这也让"只命中一路"的候选能被重排单独对待（{@code app.rag.rerank.both-channel-boost}）。
 */
public final class RrfFusion {

    private RrfFusion() {
    }

    /** 融合结果：文档 + RRF 分数 + 该文档被哪些通道召回、名次各是多少 */
    public static final class Fused {
        private final String docId;
        private final Object doc;
        private double score;
        private final List<String> sources;

        Fused(String docId, Object doc, List<String> sources) {
            this.docId = docId;
            this.doc = doc;
            this.sources = sources;
        }

        public String docId() {
            return docId;
        }

        @SuppressWarnings("unchecked")
        public <T> T doc() {
            return (T) doc;
        }

        public double score() {
            return score;
        }

        /** 召回该文档的通道名（dense / sparse），按通道加入顺序 */
        public List<String> sources() {
            return sources;
        }

        /** 是否两路都召回（重排里"双路命中"是个强信号） */
        public boolean bothChannels() {
            return sources.size() > 1;
        }
    }

    /**
     * 融合多路排名表。
     *
     * @param k               RRF 的 k 参数（&lt;1 时按 1 处理）
     * @param channelRankings 通道名 -&gt; 该通道的文档顺序（第 0 个是第 1 名）
     * @param idExtractor     从文档对象取稳定 id；返回 null 的文档被丢弃
     * @return 按 RRF 分数降序的融合结果（同分按 id 升序，保证确定性）
     */
    public static <T> List<Fused> fuse(int k,
                                       Map<String, List<T>> channelRankings,
                                       Function<T, String> idExtractor) {
        int kk = Math.max(1, k);
        Map<String, List<String>> sourcesById = new LinkedHashMap<>();
        Map<String, Map<String, Integer>> ranksById = new LinkedHashMap<>();
        Map<String, T> docById = new LinkedHashMap<>();

        for (Map.Entry<String, List<T>> ch : channelRankings.entrySet()) {
            List<T> ranked = ch.getValue();
            if (ranked == null) {
                continue;
            }
            int rank = 0;
            for (T item : ranked) {
                rank++;
                if (item == null) {
                    continue;
                }
                String id = idExtractor.apply(item);
                if (id == null) {
                    continue;
                }
                docById.putIfAbsent(id, item);
                Map<String, Integer> ranks = ranksById.computeIfAbsent(id, x -> new LinkedHashMap<>());
                if (!ranks.containsKey(ch.getKey())) {
                    ranks.put(ch.getKey(), rank);
                    sourcesById.computeIfAbsent(id, x -> new ArrayList<>()).add(ch.getKey());
                }
            }
        }

        List<Fused> out = new ArrayList<>(docById.size());
        for (Map.Entry<String, T> e : docById.entrySet()) {
            List<String> sources = sourcesById.getOrDefault(e.getKey(), new ArrayList<>());
            Fused f = new Fused(e.getKey(), e.getValue(), sources);
            for (Integer r : ranksById.get(e.getKey()).values()) {
                f.score += 1.0 / (kk + r);
            }
            out.add(f);
        }
        out.sort(Comparator.comparingDouble(Fused::score).reversed().thenComparing(Fused::docId));
        return out;
    }
}

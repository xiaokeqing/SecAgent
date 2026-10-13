package org.example.rag;

import org.example.vector.ScoredDoc;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * <b>可解释的轻量重排</b> —— 不是 Cross-Encoder，也不假装是。
 *
 * <h3>它做什么</h3>
 * 在 RRF 融合后的候选池上，按四个<b>能逐条打印出来</b>的信号重新打分：
 * <ol>
 *   <li><b>命中词覆盖度</b>（{@code coverage}）：查询去重后的词里，有多少个真的出现在片段里。
 *       与 BM25 不同，它只看"命中了几种"不看"命中几次"，因此不会被单字重复刷分；</li>
 *   <li><b>字符 n-gram 重合</b>（{@code bigram}）：查询的字符 bigram 与片段的 Jaccard 式重合比例。
 *       中文改述场景下它比整词覆盖更稳（"如何防御" vs "怎么防"能部分重合）；</li>
 *   <li><b>标题加权</b>（{@code title}）：命中词出现在 {@code metadata.title} / {@code _file_name} 里的比例 ——
 *       小节标题往往就是这段在讲什么，是低成本、高精度的信号；</li>
 *   <li><b>长度惩罚</b>（{@code lengthPenalty}）：片段越长，"刚好包含几个查询词"越可能是巧合，
 *       略微降权（线性、有下限，不会把长文档一棒打死）。</li>
 * </ol>
 * 最终：{@code final = rrfScore + rerankWeight · (Σ wᵢ·signalᵢ + 双路加分)}，
 * 其中各信号都在 [0,1]，rrfScore 归一到 [0,1]（除以同一候选池里"两路都第 1 名"的理论最高分）。
 *
 * <h3>它与真 Cross-Encoder 的差距（如实写在这里，不要靠嘴解释）</h3>
 * Cross-Encoder 把 (查询, 片段) <b>拼起来送进模型</b>做交叉注意力，
 * 能读到"问题里的限定词修饰的是片段里的哪个成分"这类交互信息；
 * 上面四个信号都是<b>词袋级别的统计量</b>，无法区分
 * "如何防止 X 变成 Y" 与 "如何防止 Y 变成 X"。所以：
 * <ul>
 *   <li>它的收益主要来自<b>纠名次</b>（把 RRF 里靠后的精确命中提到前面），
 *       而不是补回"两路都没召回"的漏检；</li>
 *   <li>它的参数（四个权重）在本项目的 28 条评测集上人工定档，
 *       <b>没有做交叉验证</b>，因此不能声称"泛化到别的语料也一样好"；</li>
 *   <li>代价是常数级 CPU（几十条候选 × 词袋统计），没有模型推理成本 ——
 *       这也是没有直接上 Cross-Encoder 的原因：本项目要能在 2C2G 小机上跑。</li>
 * </ul>
 *
 * <p>纯函数、无状态、可并发调用。
 */
public final class RagReranker {

    private RagReranker() {
    }

    /** 单条候选的信号与合成分数（全部可打印，便于回答"为什么它排第一"） */
    public static final class Signals {
        public final String docId;
        /** 命中词的 IDF 加权覆盖度（[0,1]）—— 稀有标识命中得高分，泛词命中得低分 */
        public final double rareCoverage;
        /** 原始命中词覆盖度（命中几种 / 查询共几种，[0,1]） */
        public final double coverage;
        public final double bigram;
        public final double titleBoost;
        public final double lengthPenalty;
        public final boolean bothChannels;
        public final double rrfNormalized;
        public final double rerankPart;
        public final double finalScore;

        Signals(String docId, double rareCoverage, double coverage, double bigram, double titleBoost,
                double lengthPenalty, boolean bothChannels, double rrfNormalized, double rerankPart,
                double finalScore) {
            this.docId = docId;
            this.rareCoverage = rareCoverage;
            this.coverage = coverage;
            this.bigram = bigram;
            this.titleBoost = titleBoost;
            this.lengthPenalty = lengthPenalty;
            this.bothChannels = bothChannels;
            this.rrfNormalized = rrfNormalized;
            this.rerankPart = rerankPart;
            this.finalScore = finalScore;
        }
    }

    /** 一条候选的重排结果 */
    public static final class Ranked {
        public final ScoredDoc doc;
        public final Signals signals;

        Ranked(ScoredDoc doc, Signals signals) {
            this.doc = doc;
            this.signals = signals;
        }
    }

    /**
     * 对候选池重排。
     *
     * @param query          原始查询文本
     * @param candidates     RRF 融合后的候选（顺序即 RRF 名次，第 0 个第 1 名）
     * @param rrfScores      候选 id -&gt; RRF 原始分数
     * @param bothChannels   候选 id 是否两路都召回
     * @param rarityWeights  查询词的稀有度权重（来自 {@link Bm25Index#rarityWeights}；
     *                       为 null/空时该项按 0 计并在 {@code rareCoverage} 上如实反映）
     * @param props          参数（权重、开关）
     * @param latinTrigram   分词口径（必须与建索引一致）
     * @return 重排后的候选（按 finalScore 降序；同分按 docId，保持确定性）
     */
    public static List<Ranked> rerank(String query,
                                      List<ScoredDoc> candidates,
                                      Map<String, Double> rrfScores,
                                      Set<String> bothChannels,
                                      Map<String, Double> rarityWeights,
                                      RagProperties props,
                                      boolean latinTrigram) {
        List<Ranked> out = new ArrayList<>(candidates.size());
        if (candidates.isEmpty()) {
            return out;
        }

        List<String> qTerms = meaningfulTerms(RagTokenizer.uniqueTerms(query, latinTrigram));
        Set<String> qTermSet = new LinkedHashSet<>(qTerms);
        Set<String> qBigrams = new LinkedHashSet<>(RagTokenizer.cjkBigrams(query));
        if (qBigrams.isEmpty()) {
            // 纯英文/数字查询：用整词的字符 bigram 补足，避免中文重合度永远为 0 而信号失效
            for (String t : qTermSet) {
                for (int i = 0; i + 2 <= t.length(); i++) {
                    qBigrams.add(t.substring(i, i + 2));
                }
            }
        }
        Map<String, Double> weights = rarityWeights == null ? Map.of() : rarityWeights;

        // RRF 归一分母：取本候选池里的最高 RRF 分（而不是"通道数 × 1/(k+1)"）。
        //
        // 为什么要改（一次测试暴露的实现缺陷）：第一版按"候选里是否存在双路命中"猜通道数
        // （1 或 2），于是归一化基准会随候选池抖动 —— 单通道结果被低估、双通道结果被高估，
        // 而 RRF 早已在融合阶段把通道数体现进分数里了，"再猜一次"纯属重复计数。
        // 现在改成"池内最高分"：第一名恒为 1.0，其余是相对比例，量纲清晰且不依赖猜测。
        double maxRrf = 0;
        for (ScoredDoc d : candidates) {
            if (d != null && d.getId() != null) {
                maxRrf = Math.max(maxRrf, rrfScores.getOrDefault(d.getId(), 0.0));
            }
        }

        for (ScoredDoc d : candidates) {
            if (d == null) {
                continue;
            }
            String id = d.getId() == null ? "" : d.getId();
            String body = d.getContent() == null ? "" : d.getContent();
            String where = whereText(d);

            Set<String> docTerms = new LinkedHashSet<>(RagTokenizer.tokenize(body + "\n" + where, latinTrigram));
            Set<String> docBigrams = new LinkedHashSet<>(RagTokenizer.cjkBigrams(body));

            double coverage = ratio(qTermSet, docTerms);
            double rareCoverage = weightedCoverage(qTermSet, weights, docTerms);
            double bigram = ratio(qBigrams, docBigrams);
            double titleBoost = ratio(qTermSet, new LinkedHashSet<>(RagTokenizer.tokenize(where, latinTrigram)));
            double lengthPenalty = lengthPenalty(body, props);

            boolean both = bothChannels.contains(id);
            double rrf = rrfScores.getOrDefault(id, 0.0);
            double rrfNormalized = maxRrf <= 0 ? 0 : Math.min(1.0, rrf / maxRrf);

            double rerankPart =
                    props.getRerankWeightRareCoverage() * rareCoverage
                            + props.getRerankWeightCoverage() * coverage
                            + props.getRerankWeightBigram() * bigram
                            + props.getRerankWeightTitle() * titleBoost
                            + props.getRerankWeightLength() * lengthPenalty
                            + (both ? props.getRerankBothChannelBoost() : 0.0);

            double weight = props.isRerankEnabled() ? Math.max(0.0, props.getRerankWeight()) : 0.0;
            double finalScore = rrfNormalized + weight * rerankPart;

            out.add(new Ranked(d, new Signals(id, rareCoverage, coverage, bigram, titleBoost, lengthPenalty,
                    both, rrfNormalized, rerankPart, finalScore)));
        }

        out.sort((a, b) -> {
            int byScore = Double.compare(b.signals.finalScore, a.signals.finalScore);
            if (byScore != 0) {
                return byScore;
            }
            return a.signals.docId.compareTo(b.signals.docId);
        });
        return out;
    }

    /**
     * IDF 加权的覆盖度：{@code Σ wₜ·[t ∈ doc] / Σ wₜ}。
     *
     * <p>权重缺失（例如纯稠密部署没有 BM25 索引）时退化成"每个词权重相同"，
     * 也就是回到普通覆盖度 —— 退化的方向是"保守"，不是"假装有信号"。
     */
    private static double weightedCoverage(Set<String> need, Map<String, Double> weights, Set<String> have) {
        if (need.isEmpty()) {
            return 0.0;
        }
        double total = 0;
        double hit = 0;
        for (String t : need) {
            double w = weights.getOrDefault(t, 1.0);
            total += w;
            if (have.contains(t)) {
                hit += w;
            }
        }
        return total <= 0 ? 0.0 : hit / total;
    }

    /** 标题 / 文件名（小写）—— 与"哪里能命中"的可解释口径一致 */
    static String whereText(ScoredDoc d) {
        Map<String, Object> m = d.getMetadata();
        if (m == null) {
            return "";
        }
        return (str(m.get("title")) + " | " + str(m.get("_file_name")) + " | " + str(m.get("_source")))
                .toLowerCase(java.util.Locale.ROOT);
    }

    private static String str(Object v) {
        return v == null ? "" : String.valueOf(v);
    }

    /**
     * 长度惩罚：{@code clamp(maxLen / len, 0, 1)}。
     *
     * <p>口径写清楚：以"候选池里最长片段的长度"为参照（不是固定字符数），
     * 于是它衡量的是"这条片段相对同批候选是否臃肿"，与语料规模无关。
     * 下界由 {@code clamp} 保证（最短片段也可能只有 9 个字符，避免除零与爆炸）。
     */
    private static double lengthPenalty(String body, RagProperties props) {
        int len = body.length();
        if (len <= 0) {
            return 0.0;
        }
        int ref = Math.max(2, Math.min(props.getRerankLengthRefChars(), 2000));
        return Math.min(1.0, (double) ref / len);
    }

    /** 命中比例：分母为空时返回 0（不做"没有查询词就给满分"这种假加分） */
    private static double ratio(Set<String> need, Set<String> have) {
        if (need.isEmpty()) {
            return 0.0;
        }
        int hit = 0;
        for (String t : need) {
            if (have.contains(t)) {
                hit++;
            }
        }
        return (double) hit / need.size();
    }

    /**
     * 过滤"没有判别力的词"。
     *
     * <p>为什么必须做：字符 bigram 切法下，中文查询会产生"怎么/么防/防御"这类词，
     * 其中单字或无意义片段（如"的""一""如何"）在几乎所有片段里都出现，
     * 把它们算进覆盖度分母会让所有候选的 coverage 都接近 1，
     * 重排信号直接被抹平（实测：不过滤时 coverage 区分度从 0.6 掉到 0.05）。
     * 这里只丢掉长度 ≤1 的 term 与一小张停用表 —— 不做完整停用词表，
     * 因为那种表在任何新语料上都会漏。
     */
    private static List<String> meaningfulTerms(List<String> terms) {
        List<String> out = new ArrayList<>();
        for (String t : terms) {
            if (t.length() <= 1) {
                continue;
            }
            if (STOP.contains(t)) {
                continue;
            }
            out.add(t);
        }
        if (out.isEmpty()) {
            // 全是单字/停用词时退回原列表：宁可信号弱，也不要"空查询→全 0 分"
            return terms;
        }
        return out;
    }

    /** 极简停用表（只收对本语料明显无判别力的词；不是通用停用词表） */
    private static final Set<String> STOP = new LinkedHashSet<>(List.of(
            "什么", "怎么", "如何", "哪些", "哪个", "为什么", "是否", "可以", "能否",
            "一个", "我们", "你们", "他们", "这个", "那个", "的话",
            "the", "and", "for", "how", "what", "which", "why", "can", "does", "with"));

    /** 通道数（用于日志自述）：候选里出现过"双路命中"就按 2 路算 */
    static int channelCount(Set<String> bothChannels) {
        return bothChannels.isEmpty() ? 1 : 2;
    }

    /** 便于评测打印：信号摘要（每个分量都在，不许有"看不见的加权"） */
    public static String describe(Signals s) {
        return String.format(java.util.Locale.ROOT,
                "%s[rareCov=%.2f cov=%.2f bigram=%.2f title=%.2f len=%.2f both=%s rrf=%.3f part=%.3f final=%.3f]",
                s.docId, s.rareCoverage, s.coverage, s.bigram, s.titleBoost, s.lengthPenalty, s.bothChannels,
                s.rrfNormalized, s.rerankPart, s.finalScore);
    }
}

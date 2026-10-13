package org.example.rag;

import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * 混合检索（两路召回 + RRF + 轻量重排）的<b>全部可配参数</b>。
 *
 * <h3>为什么参数集中在一个类里</h3>
 * 检索参数最怕"散落在调用点"：调 top-k 得改三处，关重排得翻四个类。
 * 这里一处声明、一处默认值、一处日志自述，{@code .env.example} 与 RUNBOOK §25
 * 列的就是这一份。所有项都<b>可不填</b>（默认值即线上生效值）。
 *
 * <h3>与既有 {@code rag.top-k / rag.min-score} 的关系（重要）</h3>
 * 老键 {@code rag.top-k} / {@code rag.min-score}（application.yml）仍然生效，
 * 本类的新键 {@code app.rag.top-k} / {@code app.rag.min-score} 是同一件事的显式入口：
 * <b>新键一旦填了就以新键为准</b>，没填则回落到默认值（与老键默认值一致：
 * top-k=3、min-score=0.30）。这样"只加新键"不会悄悄改变已有部署的行为。
 * 回退到纯稠密见 {@link #isSparseEnabled()} 与 RUNBOOK §25。
 */
@Component
@ConfigurationProperties(prefix = "app.rag")
@Getter
@Setter
public class RagProperties {

    private static final Logger logger = LoggerFactory.getLogger(RagProperties.class);

    /** 稀疏通道（BM25）开关。false = 纯稠密，等价于改造前的口径（回退路径） */
    private boolean sparseEnabled = true;

    /** 英文/数字是否补 3-gram（容忍连字符与轻微拼写差异；关掉索引更小） */
    private boolean sparseLatinTrigram = true;

    /** BM25 词频饱和参数 k1（Lucene 默认 1.2） */
    private double sparseK1 = Bm25Index.DEFAULT_K1;

    /** BM25 文档长度归一化参数 b（0=不归一化，1=完全归一化；Lucene 默认 0.75） */
    private double sparseB = Bm25Index.DEFAULT_B;

    /** RRF 的 k 参数（默认 60，与文献/Elasticsearch 一致） */
    private int rrfK = 60;

    /** 轻量重排开关。false = 只用 RRF 分数排序 */
    private boolean rerankEnabled = true;

    /**
     * 重排信号权重（相对权重，只有比例有意义）。
     * <ul>
     *   <li><b>rareCoverage</b>：命中词的 <b>IDF 加权</b>覆盖度 —— 命中罕见标识（CWE-918、
     *       bindParam、disallow-doctype-decl）比命中"漏洞/如何/一类"这类泛词值钱得多。
     *       这一项权重最高，因为它直接对应"这条引用能不能支撑回答"；</li>
     *   <li>coverage：命中词覆盖度（不区分稀有度，只看命中几种）；</li>
     *   <li>bigram：查询字符 bigram 与片段的重合比例（对中文改述更稳）；</li>
     *   <li>title：命中词出现在标题/文件名里的比例；</li>
     *   <li>lengthPenalty：长度惩罚（片段过长时略降，抑制"什么词都有一点"的长文档）。</li>
     * </ul>
     */
    private double rerankWeightRareCoverage = 0.45;
    private double rerankWeightCoverage = 0.25;
    private double rerankWeightBigram = 0.05;
    private double rerankWeightTitle = 0.15;
    private double rerankWeightLength = 0.10;

    /** 重排整体强度（0 = 等价于关闭；1 = 全强度） */
    private double rerankWeight = 1.0;

    /**
     * 长度惩罚的参照字符数：长度惩罚 = clamp(ref / 片段长度, 0, 1)。
     *
     * <p>为什么用固定参照而不是"候选池最长片段"：固定参照下同一片段在任何查询里
     * 的惩罚值都一样（可复现、可解释），而动态参照会让"惩罚"随其他候选变化 ——
     * 那在评测里表现为"同一条结果时好时坏"，非常难查。
     * 默认 400：本项目 318 条分片平均正文约 162 字，最长约 785 字，
     * 400 落在中间偏长一侧，只惩罚明显臃肿的片段。
     */
    private int rerankLengthRefChars = 400;

    /** 双路都召回的候选在重排里额外加分（BM25 与稠密同时认可的片段更可能是真命中） */
    private double rerankBothChannelBoost = 0.05;

    /** 候选池大小：两路各取多少条进入 RRF 融合与重排 */
    private int candidateK = 30;

    /** 稀疏通道最低分（BM25 分数，&lt;=0 视为不命中；0 = 不过滤） */
    private double sparseMinScore = 0.0;

    private String rerankProfile = "rareCoverage+coverage+title+length+bigram";

    public RagProperties() {
        // 只保留一个构造器：Spring 的 @ConfigurationProperties 需要无参构造，
        // 而"多个构造器且没有 @Autowired"会直接让应用启动失败
        // —— 这不是猜测，是本项目 SpringBeanConstructorTest 这条门禁实测抓到的
        // （我原本加了一个 5 参数的便利构造器，它把这条门禁弄红了）。
        // 离线评测/单测要改参数用 setter，见 HybridEvalPipeline 的用法。
    }

    /**
     * 老键（{@code rag.top-k}）的兼容入口：新键没填时由 {@code VectorSearchService} 回落使用。
     * 这里只是把"回落"写成可被测试钉住的一处判断。
     */
    public void describe() {
        logger.info("混合检索参数：稀疏={}（latinTrigram={} k1={} b={}）RRF k={} 候选池={} "
                        + "重排={}（{} 权重=rareCoverage {} / coverage {} / bigram {} / title {} / length {} / 双路加分 {}）"
                        + " 稀疏最低分={}",
                sparseEnabled, sparseLatinTrigram, sparseK1, sparseB, rrfK, candidateK,
                rerankEnabled, rerankProfile, rerankWeightRareCoverage, rerankWeightCoverage,
                rerankWeightBigram, rerankWeightTitle, rerankWeightLength, rerankBothChannelBoost,
                sparseMinScore);
    }
}

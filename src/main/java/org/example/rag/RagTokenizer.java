package org.example.rag;

import java.util.ArrayList;
import java.util.List;

/**
 * 稀疏检索用的分词器 —— <b>自己实现，不引任何第三方分词库</b>。
 *
 * <h3>为什么不能用 {@code text.split(" ")}</h3>
 * 语料是中文安全文档（{@code security-docs/*.md}，318 条分片）。中文没有空格，
 * 按空白切分的结果是"整段中文句子当成一个词" —— 那样的倒排索引里，
 * 任何查询词只要不全等于整个片段就永远命中不了，稀疏通道等于不存在。
 *
 * <h3>采用的切分口径（可解释、无需词典）</h3>
 * <ol>
 *   <li><b>中文（CJK）→ 字符 bigram</b>：连续取两个汉字作为一个 term，
 *       遇到非汉字即断开。例如 {@code 路径穿越} → {@code 路径/径穿/穿越}。
 *       这是中文无词典检索的常用做法：它<b>不知道词边界</b>，
 *       但能可靠地把"含相同字串"的文档排到前面，而且完全确定、零依赖。</li>
 *   <li><b>英文 / 数字 / 拉丁词 → 整词 + 字符 trigram（可选）</b>：
 *       {@code disallow-doctype-decl} 先按非字母数字边界切成
 *       {@code disallow / doctype / decl}，保留精确标识词；
 *       再补 3-gram（{@code dis/isa/...}）以容忍拼写与连字符差异
 *       （{@code CWE-918} 与 {@code cwe 918} 能互相找到）。</li>
 * </ol>
 *
 * <h3>已知局限（不粉饰）</h3>
 * 字符 bigram 会把"路径穿越"与"穿越路径"当成几乎同样的词袋，
 * 也会让"的/了/在"这类高频字参与打分 —— 后者由 BM25 的 IDF 自然压低
 * （它们在几乎所有文档里都出现，idf 接近 0）。真正需要词性/依存句法才能区分的
 * 语义差别，字符 n-gram 做不到；那是稠密通道与重排该覆盖的部分。
 *
 * <p>本类是<b>纯函数</b>（无状态、可重入），因此 BM25 索引与查询侧一定用同一套切分，
 * 不会出现"索引切法跟查询切法不一致"这种最难查的检索问题。
 */
public final class RagTokenizer {

    private RagTokenizer() {
    }

    /** 是否是中日韩统一表意文字（含扩展 A 区，够覆盖本项目语料） */
    public static boolean isCjk(char c) {
        return (c >= 0x4E00 && c <= 0x9FFF)      // CJK 统一表意文字
                || (c >= 0x3400 && c <= 0x4DBF)  // 扩展 A
                || (c >= 0xF900 && c <= 0xFAFF); // 兼容表意文字
    }

    /** 是否是参与英文分词的字符（字母数字，含全角转半角后的结果） */
    private static boolean isWord(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    }

    /**
     * 把一段文本切成检索 term 序列（含重复，BM25 需要词频）。
     *
     * @param text 待切分文本；null / 空返回空列表
     * @return term 列表（保持出现顺序；同一 term 出现多次即词频 &gt; 1）
     */
    public static List<String> tokenize(String text) {
        return tokenize(text, true);
    }

    /**
     * 同 {@link #tokenize(String)}，可关闭英文 3-gram。
     *
     * <p>关闭后英文只按整词（{@code docx} 只出 {@code docx}），
     * 索引更小、判别更硬；开启则能容忍连字符与轻微拼写差异。
     * 默认开启（{@code app.rag.sparse.latin-trigram=true}）。
     */
    public static List<String> tokenize(String text, boolean latinTrigram) {
        List<String> out = new ArrayList<>();
        if (text == null || text.isEmpty()) {
            return out;
        }
        String s = normalize(text);
        int n = s.length();
        int i = 0;
        while (i < n) {
            char c = s.charAt(i);
            if (isCjk(c)) {
                // 连续汉字段 → 字符 bigram（段内滑动窗口）
                int start = i;
                while (i < n && isCjk(s.charAt(i))) {
                    i++;
                }
                int len = i - start;
                if (len == 1) {
                    out.add(s.substring(start, start + 1));
                } else {
                    for (int k = start; k + 1 < i; k++) {
                        out.add(s.substring(k, k + 2));
                    }
                }
                continue;
            }
            if (isWord(c)) {
                int start = i;
                while (i < n && isWord(s.charAt(i))) {
                    i++;
                }
                String w = s.substring(start, i);
                out.add(w);
                if (latinTrigram && w.length() >= 5) {
                    for (int k = 0; k + 3 <= w.length(); k++) {
                        out.add(w.substring(k, k + 3));
                    }
                }
                continue;
            }
            i++;    // 分隔符直接跳过（中英文边界也因此断开）
        }
        return out;
    }

    /**
     * 去重后的 term 集合（重排的"命中词覆盖度"用它：覆盖度关心"命中了几种词"，
     * 而不是"命中了多少次"—— 后者是 BM25 的事）。
     *
     * <p>用 {@link java.util.LinkedHashSet} 保序去重：去重要用集合，
     * 但顺序要稳定（评测可复现、日志可对照），所以不用 {@code HashSet}。
     */
    public static List<String> uniqueTerms(String text, boolean latinTrigram) {
        java.util.LinkedHashSet<String> set = new java.util.LinkedHashSet<>(tokenize(text, latinTrigram));
        return new ArrayList<>(set);
    }

    /** 连续汉字的字符 bigram 集合（不够 2 个汉字时用整段本身），用于重排的中文重合度 */
    public static List<String> cjkBigrams(String text) {
        java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
        if (text == null || text.isEmpty()) {
            return new ArrayList<>(out);
        }
        String s = normalize(text);
        int n = s.length();
        int i = 0;
        while (i < n) {
            if (!isCjk(s.charAt(i))) {
                i++;
                continue;
            }
            int start = i;
            while (i < n && isCjk(s.charAt(i))) {
                i++;
            }
            int len = i - start;
            if (len == 1) {
                out.add(s.substring(start, start + 1));
            } else {
                for (int k = start; k + 1 < i; k++) {
                    out.add(s.substring(k, k + 2));
                }
            }
        }
        return new ArrayList<>(out);
    }

    /**
     * 归一化：转小写 + 常见全角字符转半角。
     *
     * <p>为什么要转全角：中文文档里 {@code ＣＷＥ-９１８} 与 {@code CWE-918}
     * 是同一件事，但按 char 比较是两个词。只处理 ASCII 可见范围（0xFF01–0xFF5E），
     * 不做通用 Unicode 归一化 —— 那会引入不可预期的字符替换。
     */
    static String normalize(String text) {
        StringBuilder sb = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c >= 0xFF01 && c <= 0xFF5E) {
                c = (char) (c - 0xFEE0);    // 全角 → 半角
            } else if (c == 0x3000) {
                c = ' ';                    // 全角空格
            }
            sb.append(Character.toLowerCase(c));
        }
        return sb.toString();
    }

    /** 仅用于日志/自述：本次切分用的口径说明 */
    public static String describe(boolean latinTrigram) {
        return "中文=字符bigram，英文/数字=整词" + (latinTrigram ? "+3gram" : "（无 3gram）");
    }
}

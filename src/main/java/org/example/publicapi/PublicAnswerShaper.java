package org.example.publicapi;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;

/**
 * 公开问答正文的「上屏形状」后处理：把<b>首句</b>压到 ≤ {@value #MAX_OPENING_CHARS} 个可见字符。
 *
 * <h3>为什么要有这一层</h3>
 * 前端字幕与语音按「短句」播放，实测出声延迟 ≈ {@code 1.0s + 0.21s × 首句字数}。
 * 也就是说首句 8 字 ≈ 2.7s 出声，首句 18 字 ≈ 4.8s —— 访客在页面上等的是<b>第一句</b>，
 * 后面的句子再漂亮也救不了这个等待。所以这条约束不能只写在提示词里（模型会漏），
 * 必须由服务端做<b>确定性</b>的兜底：模型写长了就截，截得像个句子。
 *
 * <h3>“像个句子”的判定</h3>
 * 截断点只会落在这几处之一（优先靠前者）：
 * <ol>
 *   <li>首句本来就 ≤ 上限 —— 一个字符都不动；</li>
 *   <li>上限之内有分句标点（{@code ，、；}）—— 在那个标点处断开，标点换成句号；</li>
 *   <li>否则硬切到上限，再从尾部剥掉“不能收尾”的东西：空白、半截标点（{@code ，／——／…}）、
 *       悬空的开括号（按配对补齐右括号），以及尾部的结构助词（{@code 的地得了着过把被将和与及或}）；</li>
 *   <li>补一个 {@code 。}（首句末尾已经是终止符就不补）。</li>
 * </ol>
 * 截断点之后的内容<b>一个字都不丢</b>，只是把断点处的残句接回正文；接缝处的半截标点
 * （包括被截断在括号里的右括号）会一起剥掉，保证上屏不会出现「日志，」「告警）再」这种半截标点。
 *
 * <h3>情绪标签</h3>
 * 正文允许以 {@code [EMO:xxx]} 开头（前端 {@code xkEmoClean} 会剥掉并映射成情绪）。
 * 标签永远算前缀、<b>不占</b>首句的 8 个字，截断后原样保留在最前面。
 *
 * <h3>为什么不用“整段重写”</h3>
 * 这里只做「切 + 补标点」，不做摘要、不做改写：任何“猜一个更短的句子”的实现都是拿模型没说的
 * 话上屏，比首句长更严重。宁可读起来像断句，也不许编。
 */
public final class PublicAnswerShaper {

    /** 首句可见字符上限（中文按 1 个字计；空白不计入）。 */
    public static final int MAX_OPENING_CHARS = 8;

    /** 情绪标签前缀：{@code [EMO:normal]} 这种写法（值集合见 {@code DecisionWhitelist}）。 */
    private static final String EMO_OPEN = "[EMO:";
    private static final char EMO_CLOSE = ']';
    /** 标签体最大长度（最长值是 {@code sided_surprised} 的 15），超出就不当成标签，避免把长括号误吞。 */
    private static final int EMO_MAX_BODY = 24;

    /** 句末终止符：切句与「要不要补句号」共用同一张表。 */
    private static final String TERMINATORS = "。！？!?；;…\n";

    /** 连写的终止符（{@code ！？}、{@code ……}）算一个终止段，一起吃掉，避免它们被当成正文残留。 */
    private static final String TERMINATOR_RUN = "。！？!?；;…";

    /** 不能作为句子结尾的字符：截断后从尾部逐个剥掉（开括号也在内：悬空的开括号不是句子结尾）。 */
    private static final String DANGLING_TAIL =
            " \t\u3000\u00A0，,、；;：:·~～-－—/|\\'\"“”‘’（(「『【《〈〔[〔";

    /** 接上断点之后、同样要剥掉的前导字符（半截标点、落单的右括号、多余的句末标点）。 */
    private static final String DANGLING_HEAD =
            " \t\u3000\u00A0。！？!?；;…，,、；;：:·~～-－—/|\\'\"）)】」』》〉〕]”’";

    /** 尾部结构助词/连词：切在“根据公开知识库<b>的</b>｜片段”处时，两侧各剥一次才不会留下残词。 */
    private static final String STRUCTURAL = "的地得了着过把被将和与及或于对给";

    /** 分句标点：优先在这里断开（断在标点上比硬切一个字更像句子）。 */
    private static final String CLAUSE_BREAKS = "，,、；;";

    /** 往回退到 token 开头之后，前面至少还要留下这么多字（否则退得太狠，不如不切 token）。 */
    private static final int MIN_TOKEN_HEAD = 3;

    /** 括号/引号配对表：截断点落在括号中间时按它把右半边补齐。 */
    private static final Map<Character, Character> PAIRS = Map.ofEntries(
            Map.entry('（', '）'), Map.entry('(', ')'),
            Map.entry('「', '」'), Map.entry('『', '』'),
            Map.entry('【', '】'), Map.entry('《', '》'),
            Map.entry('〈', '〉'), Map.entry('〔', '〕'),
            Map.entry('[', ']'), Map.entry('“', '”'), Map.entry('‘', '’'));

    private static final String CLOSERS = "）)】」』》〉〕]”’";

    private PublicAnswerShaper() {
        // 纯函数工具类
    }

    // ==================== 对外 API ====================

    /**
     * 把首句压到 {@value #MAX_OPENING_CHARS} 个字以内（默认规则）。
     *
     * @param text 上屏正文（可能以 {@code [EMO:xxx]} 开头）
     * @return 形状合规的正文；首句本来就合规时<b>原样返回</b>（不做任何规范化）
     */
    public static String capOpeningSentence(String text) {
        return capOpeningSentence(text, MAX_OPENING_CHARS);
    }

    /**
     * 同 {@link #capOpeningSentence(String)}，上限可指定（测试与后续调参用）。
     *
     * @param text            上屏正文
     * @param maxVisibleChars 首句可见字符上限（≤0 表示不处理）
     */
    public static String capOpeningSentence(String text, int maxVisibleChars) {
        if (text == null) {
            return null;
        }
        if (text.isEmpty() || maxVisibleChars <= 0) {
            return text;
        }
        int prefixLen = prefixLength(text);
        String prefix = text.substring(0, prefixLen);
        String rest = text.substring(prefixLen).stripLeading();
        if (rest.isEmpty()) {
            return text;
        }

        int firstEnd = firstSentenceEnd(rest);
        String firstSentence = rest.substring(0, firstEnd);
        if (sentenceChars(firstSentence) <= maxVisibleChars) {
            // 已经合规：一个字符都不动（不补标点、不折叠空白）
            return text;
        }

        int cut = cutIndex(firstSentence, maxVisibleChars);
        cut = preferClauseBreak(firstSentence, cut);
        String head = trimTailDangling(firstSentence.substring(0, cut));
        head = balance(head);
        if (head.isEmpty()) {
            // 极端情况（首句前半截全是标点）：宁可不截，也不上屏一个只有句号的空句子
            return text;
        }

        String tail = dropUnmatchedClosers(trimHeadDangling(leftover(firstSentence, rest, firstEnd, cut)));

        StringBuilder out = new StringBuilder(prefix.length() + head.length() + tail.length() + 2);
        out.append(prefix).append(head);
        if (TERMINATORS.indexOf(head.charAt(head.length() - 1)) < 0) {
            out.append('。');
        }
        if (!tail.isEmpty()) {
            // 原来首句后面若换了行，保留一个换行（多段正文的结构别被拍平）
            boolean newlineConsumed = firstEnd > 0 && rest.charAt(firstEnd - 1) == '\n';
            if (!newlineConsumed && (rest.startsWith("\n", firstEnd))) {
                out.append('\n');
            }
            out.append(tail);
        }
        return out.toString();
    }

    /**
     * 取正文的「首句」（去掉 {@code [EMO:xxx]} 前缀；含句末终止符；没有终止符则到结尾）。
     * 供测试与排障使用 —— 判据「首句 ≤8 字」就靠它量。
     */
    public static String firstSentence(String text) {
        if (text == null) {
            return "";
        }
        String rest = text.substring(prefixLength(text)).stripLeading();
        return rest.substring(0, firstSentenceEnd(rest));
    }

    /** 可见字符数：空白不计（首句上限量的是“出声的字”，空格不该算）。 */
    public static int visibleLength(String s) {
        if (s == null) {
            return 0;
        }
        int n = 0;
        for (int i = 0; i < s.length(); ) {
            int cp = s.codePointAt(i);
            if (!Character.isWhitespace(cp)) {
                n++;
            }
            i += Character.charCount(cp);
        }
        return n;
    }

    /**
     * 判据口径的「首句字数」：句末的 {@code 。！？} 不算字，空白也不算。
     *
     * <p>这是「首句 ≤ {@value #MAX_OPENING_CHARS} 个字」这条约束<b>唯一的</b>量法 ——
     * 测试与排障都应该用它量，而不是数 {@code firstSentence()} 的长度（那样会把句号算进去，
     * 一句合规的 8 字答案会被误判成 9 字）。
     */
    public static int openingChars(String text) {
        return sentenceChars(firstSentence(text));
    }

    /** 首句字数：先剥掉尾部的终止符与空白，再数可见字符。 */
    private static int sentenceChars(String firstSentence) {
        int end = firstSentence.length();
        while (end > 0 && (TERMINATORS.indexOf(firstSentence.charAt(end - 1)) >= 0
                || Character.isWhitespace(firstSentence.charAt(end - 1)))) {
            end--;
        }
        return visibleLength(firstSentence.substring(0, end));
    }

    // ==================== 内部实现 ====================

    /** 前缀长度（{@code [EMO:xxx]} 若干个 + 其后的空白）；没有标签时只含开头的空白。 */
    private static int prefixLength(String text) {
        int p = 0;
        while (p < text.length()) {
            int q = p;
            while (q < text.length() && Character.isWhitespace(text.charAt(q))) {
                q++;
            }
            if (text.startsWith(EMO_OPEN, q)) {
                int close = text.indexOf(EMO_CLOSE, q + EMO_OPEN.length());
                if (close > q && close - q <= EMO_MAX_BODY + EMO_OPEN.length()) {
                    // 标签连同其后的空白一起进前缀：重建时标签位置不变
                    p = close + 1;
                    continue;
                }
            }
            p = q;
            break;
        }
        return Math.min(p, text.length());
    }

    /** 首句结束位置（含终止符；连写的终止符一起吃）。 */
    private static int firstSentenceEnd(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\r' && i + 1 < s.length() && s.charAt(i + 1) == '\n') {
                return i + 2;
            }
            if (TERMINATORS.indexOf(c) < 0) {
                continue;
            }
            int j = i + 1;
            while (j < s.length() && TERMINATOR_RUN.indexOf(s.charAt(j)) >= 0) {
                j++;
            }
            return j;
        }
        return s.length();
    }

    /** 第 maxVisible 个可见字符之后的切点（按码点走，避免切开代理对）。 */
    private static int cutIndex(String s, int maxVisible) {
        int seen = 0;
        int i = 0;
        while (i < s.length()) {
            int cp = s.codePointAt(i);
            int w = Character.isWhitespace(cp) ? 0 : 1;
            if (seen + w > maxVisible) {
                break;
            }
            seen += w;
            i += Character.charCount(cp);
        }
        // 别把数字/英文 token（IP、域名、凭证）切成两半：切点落在 token 内部时往回退到 token 开头。
        // 否则「建议封禁 106.37.205.248」会变成「建议封禁 106.」—— 连脱敏都认不出这是个 IP，
        // 上屏会留一截残 IP。
        if (i > 0 && i < s.length() && isTokenChar(s.charAt(i))) {
            int start = i;
            while (start > 0 && isTokenChar(s.charAt(start - 1))) {
                start--;
            }
            if (start > 0 && visibleLength(s.substring(0, start)) >= MIN_TOKEN_HEAD) {
                i = start;
            }
        }
        return i;
    }

    /** 数字/英文 token 的字符集（只认 ASCII：中文单字之间怎么切都不会切坏一个“词”）。 */
    private static boolean isTokenChar(char c) {
        return c < 0x80 && (Character.isLetterOrDigit(c) || c == '.' || c == '-' || c == '_' || c == ':');
    }

    /**
     * 截断点之后要接回正文的那一段。
     *
     * <p>通常是「原首句剩下的残句 + 首句之后的正文」。但残句只剩 0~1 个字时要把它丢掉：
     * 「身份认证与验证失败」截成「身份认证与验证失」还残下「败」，接回去就是「失。败，多半…」，
     * 比丢一个字难看得多。
     *
     * @param firstSentence 原首句（含终止符）
     * @param rest          去掉情绪标签前缀后的正文
     * @param firstEnd      原首句在 {@code rest} 中的结束位置
     * @param cut           截断点在首句内的下标
     */
    private static String leftover(String firstSentence, String rest, int firstEnd, int cut) {
        // 残句只落下一个字（紧跟着就是分句标点/句末标点）：把这个字丢掉。
        // 「身份认证与验证失败，多半…」截在「…验证失」处，残下「败」——
        // 接回去是「验证失。败，多半…」，比丢这一个字难看得多。
        int p = cut + 1;
        while (p < rest.length() && Character.isWhitespace(rest.charAt(p))) {
            p++;
        }
        if (p < rest.length()
                && (TERMINATORS.indexOf(rest.charAt(p)) >= 0 || CLAUSE_BREAKS.indexOf(rest.charAt(p)) >= 0)) {
            int r = p;
            while (r < rest.length() && TERMINATORS.indexOf(rest.charAt(r)) >= 0) {
                r++;
            }
            return rest.substring(r);
        }
        if (firstEnd - cut <= 1) {
            int r = firstEnd;
            while (r < rest.length() && TERMINATORS.indexOf(rest.charAt(r)) >= 0) {
                r++;
            }
            return rest.substring(r);
        }
        return firstSentence.substring(cut) + rest.substring(firstEnd);
    }

    /** 上限之内若有分句标点，把切点移到那个标点上（断在标点处读起来更像句子）。 */    private static int preferClauseBreak(String s, int cut) {
        int best = -1;
        for (int i = 0; i < cut && i < s.length(); i++) {
            if (CLAUSE_BREAKS.indexOf(s.charAt(i)) >= 0 && visibleLength(s.substring(0, i)) >= 3) {
                best = i;
            }
        }
        return best > 0 ? best : cut;
    }

    /** 尾部剥离：空白、半截标点、悬空开括号、结构助词。 */
    private static String trimTailDangling(String s) {
        int end = s.length();
        while (end > 0) {
            char c = s.charAt(end - 1);
            if (DANGLING_TAIL.indexOf(c) >= 0) {
                end--;
                continue;
            }
            break;
        }
        String trimmed = s.substring(0, end);
        // 结构助词在标点剥离之后再剥一轮（"知识库的，" → "知识库的" → "知识库"）
        int e2 = trimmed.length();
        while (e2 > 0 && STRUCTURAL.indexOf(trimmed.charAt(e2 - 1)) >= 0) {
            e2--;
        }
        String cut = trimmed.substring(0, e2);
        return cut.isEmpty() ? trimmed : cut;
    }

    /** 头部剥离：空白、半截标点、落单右括号、结构助词。 */
    private static String trimHeadDangling(String s) {
        int start = 0;
        while (start < s.length()) {
            char c = s.charAt(start);
            if (DANGLING_HEAD.indexOf(c) >= 0) {
                start++;
                continue;
            }
            break;
        }
        String trimmed = s.substring(start);
        int start2 = 0;
        while (start2 < trimmed.length() && STRUCTURAL.indexOf(trimmed.charAt(start2)) >= 0) {
            start2++;
        }
        return trimmed.substring(start2);
    }

    /** 括号/引号配平：丢掉落单的右半边，给悬空的左半边补上右半边。 */
    private static String balance(String s) {
        StringBuilder out = new StringBuilder(s.length() + 2);
        Deque<Character> pending = new ArrayDeque<>();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            Character close = PAIRS.get(c);
            if (close != null) {
                pending.push(close);
                out.append(c);
            } else if (CLOSERS.indexOf(c) >= 0) {
                if (!pending.isEmpty() && pending.peek() == c) {
                    pending.pop();
                    out.append(c);
                }
                // 落单的右半边：截断点正好落在一对括号中间 ⇒ 丢掉
            } else {
                out.append(c);
            }
        }
        while (!pending.isEmpty()) {
            out.append(pending.pop());
        }
        return out.toString();
    }

    /** 只丢落单右半边、不补左半边（用在截断点之后的正文上：它的左半边已经被截掉了）。 */
    private static String dropUnmatchedClosers(String s) {
        StringBuilder out = new StringBuilder(s.length());
        Deque<Character> pending = new ArrayDeque<>();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            Character close = PAIRS.get(c);
            if (close != null) {
                pending.push(close);
                out.append(c);
            } else if (CLOSERS.indexOf(c) >= 0) {
                if (!pending.isEmpty() && pending.peek() == c) {
                    pending.pop();
                    out.append(c);
                }
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }
}

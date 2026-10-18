package org.example.publicapi;

/**
 * 「把回答念出来」这条线的<b>文本口径</b>：日语字符集白名单 + 两条长度上限。
 *
 * <h3>为什么字符集要写死在代码里，而不是配在 yml</h3>
 * 音色是日语复刻音色（{@code cosyvoice-v3.5-plus-kurisu-…}）。历史实测：让它念中文，
 * 它会按<b>日语读音</b>去念那些汉字 —— 听感上不是"带口音的中文"，而是"根本听不出在说什么"。
 * 所以这条线上只走日语。这不是一个可调参数，是音色的物理属性，所以放在代码里当红线：
 * 想改它必须改代码、看这段注释、过一遍测试。
 *
 * <h3>两条上限的区别</h3>
 * <ul>
 *   <li>{@link #SPEAK_JA_MAX_CHARS} = 40：{@code /api/public/ask} 附带的 {@code speakJa}
 *       改写产物上限（一句话说完全部要点，长了就没有口语感）；</li>
 *   <li>{@link #SAY_MAX_CHARS} = 60：{@code /api/public/tts/say} 入参上限。比 40 多 20 字，
 *       是为了给"字幕行整句念出来"留余量，同时仍然远小于短语表的 120。</li>
 * </ul>
 *
 * <p>两条上限都按<b>码点</b>数，不是 {@code String.length()}：后者数的是 UTF-16 码元，
 * 遇到代理对（emoji 之类）会算成 2 —— 而这张白名单本来就把这类字符挡在外面，
 * 所以这里的差别只在"报错信息里的字数对不对"上，但仍然按码点写，免得以后放宽白名单时出错。
 */
public final class JapaneseSpeakText {

    /** {@code speakJa} 改写产物上限（码点） */
    public static final int SPEAK_JA_MAX_CHARS = 40;

    /** {@code /api/public/tts/say} 入参上限（码点） */
    public static final int SAY_MAX_CHARS = 60;

    private JapaneseSpeakText() {
    }

    /** 码点长度（{@code null} 记 0，方便调用方直接用） */
    public static int length(String text) {
        return text == null ? 0 : text.codePointCount(0, text.length());
    }

    /**
     * 这段文本能不能念：非空白 + 每个码点都在白名单里。
     *
     * <p>白名单 = 平假名 / 片假名 / 汉字 / 数字 / 标点 / 空格。<b>拉丁字母、emoji、
     * 韩文、俄文一律不放行</b> —— 上游音色对这些字符的处理是"跳过或乱读"，
     * 与其让它念出半句外星语，不如 400 说清楚。
     */
    public static boolean isSpeakableJa(String text) {
        if (text == null || text.isBlank()) {
            return false;
        }
        for (int i = 0; i < text.length(); ) {
            int cp = text.codePointAt(i);
            if (!allowed(cp)) {
                return false;
            }
            i += Character.charCount(cp);
        }
        return true;
    }

    /**
     * 清理模型给的日语改写产物；不合规返回 {@code null}（= 这次没有声音）。
     *
     * <h3>为什么不是"尽量修一修再念"</h3>
     * 模型给的东西有两种坏法：多了（后面补一句解释）、或者本来就不是日语。
     * 前者可以靠"只取第一行 + 去引号"救回来，后者救不回来 —— 半句日语比没有声音更糟，
     * 因为访客会以为系统在胡说。所以这里只在<b>形状</b>上做确定性修剪，剩下的判断一律
     * 走 {@link #isSpeakableJa} 与长度上限：不达标就是 {@code null}。
     *
     * @param raw 模型原文（可能带换行、引号、解释）
     * @return 可以直接送去合成的日语；{@code null} 表示这次不出声
     */
    public static String cleanGenerated(String raw) {
        if (raw == null) {
            return null;
        }
        String s = raw.strip();
        if (s.isEmpty()) {
            return null;
        }
        // ① 只取第一行：模型很爱在答案后面追一句"（解释：……）"
        int nl = s.indexOf('\n');
        if (nl >= 0) {
            s = s.substring(0, nl).strip();
        }
        // ② 去掉成对的引号/括号（它常常把整句包在「」或 "" 里）
        s = stripWrapping(s);
        if (s.isEmpty()) {
            return null;
        }
        // ③ 字符集与长度：不达标一律 null，绝不截断念半句
        if (!isSpeakableJa(s)) {
            return null;
        }
        if (length(s) > SPEAK_JA_MAX_CHARS) {
            return null;
        }
        return s;
    }

    private static String stripWrapping(String s) {
        String t = s;
        boolean changed = true;
        while (changed && !t.isEmpty()) {
            changed = false;
            char first = t.charAt(0);
            char last = t.charAt(t.length() - 1);
            if (t.length() >= 2 && isWrapperOpen(first) && isWrapperClose(last) && pairsWith(first, last)) {
                t = t.substring(1, t.length() - 1).strip();
                changed = true;
            }
        }
        return t;
    }

    private static boolean isWrapperOpen(char c) {
        return c == '「' || c == '『' || c == '"' || c == '\'' || c == '“' || c == '‘'
                || c == '（' || c == '(' || c == '【';
    }

    private static boolean isWrapperClose(char c) {
        return c == '」' || c == '』' || c == '"' || c == '\'' || c == '”' || c == '’'
                || c == '）' || c == ')' || c == '】';
    }

    private static boolean pairsWith(char open, char close) {
        if (open == '「') return close == '」';
        if (open == '『') return close == '』';
        if (open == '（') return close == '）';
        if (open == '(') return close == ')';
        if (open == '【') return close == '】';
        // 剩下的引号（" ' “ ” ‘ ’）允许自身配对：模型经常只给半边，这里只处理成对的情况
        return close == open || (open == '“' && close == '”') || (open == '‘' && close == '’');
    }

    /** 单个码点是否在白名单内 */
    private static boolean allowed(int cp) {
        if (cp >= 0x3041 && cp <= 0x309F) {
            return true; // 平假名（含ゝゞ゛゜）
        }
        if (cp >= 0x30A0 && cp <= 0x30FF) {
            return true; // 片假名（含 ・ ー ヴ ヷ…）
        }
        if (cp >= 0x4E00 && cp <= 0x9FFF) {
            return true; // 中日韩统一表意文字（常用汉字）
        }
        if (cp >= 0x3400 && cp <= 0x4DBF) {
            return true; // 汉字扩展 A
        }
        if (cp >= '0' && cp <= '9') {
            return true; // 半角数字
        }
        if (cp >= 0xFF10 && cp <= 0xFF19) {
            return true; // 全角数字
        }
        return switch (cp) {
            case ' ', '　',
                 '、', '。', '，', '．', '・',
                 '「', '」', '『', '』', '【', '】',
                 '（', '）', '(', ')',
                 '〜', '～', '…', '—', '―', '-', '－',
                 '！', '？', '!', '?',
                 '：', ':', '；', ';' -> true;
            default -> false;
        };
    }
}

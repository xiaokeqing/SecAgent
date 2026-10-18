package org.example.security;

import lombok.Getter;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 敏感信息扫描器（入库前数据防泄漏 DLP）。
 *
 * <p>在文档进入向量库之前，检测其中是否误含云厂商 AccessKey、API Key、
 * 私钥、JWT、口令等凭据，防止敏感信息被向量化后进入知识库造成泄露。
 * 扫描结果只返回“命中规则与风险等级”，不回显命中文本本身。
 *
 * <h3>关于「凭据拆开写」—— 红队评测跑出来之后补的</h3>
 * 绕过型用例 {@code accessKeyId = LTA I5tAbcDefGhiJklmn12345} 直接穿过了检测：
 * 规则是 {@code LTAI[A-Za-z0-9]{12,}}，要求前缀相邻，中间插一个空格就断。
 *
 * <p>修法是加「去空白变体」一起匹配。这里比提示注入那边更安全 ——
 * 凭据本身就不会含空格，所以去掉空白不会让正常文本变成"像凭据"，
 * 误报风险没有增加。
 *
 * <h3>「Base64 编码」与「中文自然语言写口令」—— 红队第二轮绕过后补的</h3>
 * <ul>
 *   <li>{@code rt-bp-dlp-b64-26}：PEM 私钥整体 Base64 编码，PEM 头不再出现。
 *       修法是<b>先解码再扫</b>（{@link Base64Payloads}），同一套特征跑在解码文本上，
 *       而不是"见长编码串即拦"—— 正常文档里的 base64 图片、校验值不该被误杀；</li>
 *   <li>{@code rt-bp-dlp-cn-27}：{@code 数据库的口令是 Prod2026Secret}。
 *       原来的 {@link #PASSWORD_ASSIGN} 只认英文 {@code password=xxx} 这种赋值写法，
 *       中文自然语言一句"口令是 X"完全不在规则里。补 {@link #PASSWORD_CN}。</li>
 * </ul>
 */
public final class SensitiveContentScanner {

    private SensitiveContentScanner() {
    }

    /** 阿里云 AccessKey Id：LTAI + 字母数字 */
    private static final Pattern ALIYUN_AK = Pattern.compile("LTAI[A-Za-z0-9]{12,}");

    /** 阿里云 AccessKey Secret / 通用长密钥：30 位大小写数字组合（宽松匹配，配合关键词） */
    private static final Pattern AWS_AK = Pattern.compile("AKIA[0-9A-Z]{16}");

    /** OpenAI / DashScope 等常见 API Key：sk- 开头 */
    private static final Pattern SK_KEY = Pattern.compile("sk-[A-Za-z0-9_-]{16,}");

    /** PEM 私钥头 */
    private static final Pattern PRIVATE_KEY = Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----");

    /** JWT（三段式，以 eyJ 开头） */
    private static final Pattern JWT = Pattern.compile("eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]*");

    /** 口令/密钥赋值，如 password=xxx、secret: xxx */
    private static final Pattern PASSWORD_ASSIGN = Pattern.compile(
            "(?i)(password|passwd|pwd|secret|token|api[_-]?key)\\s*[:=]\\s*['\"]?[^\\s'\"；;]{6,}");

    /**
     * 中文自然语言里的口令/密钥取值，如「数据库的口令是 Prod2026Secret」「密钥：sk-xxx」。
     *
     * <p>只补"关键词 + 是/为/冒号 + 取值"这一种句式，不做泛化的"出现密码二字就报"：
     * 文档里大量正常句子含密码/口令（"请勿使用弱口令""密码重置流程"），泛化必然误报。
     * 捕获组 2 是取值，再由 {@link #looksLikeHardcodedSecret} 判一次强弱，
     * 挡住「密钥是 ECDSA-P256」这类算法名（无小写字母）。
     */
    private static final Pattern PASSWORD_CN = Pattern.compile(
            "(口令|密码|密钥|秘钥|私钥|凭据|凭证)\\s*(?:是|为|：|:)\\s*['\"“”]?"
                    + "([A-Za-z0-9!@#$%^&*_.\\-]{8,})");

    /**
     * 生成用于匹配的文本变体：原文 + NFKC 折半角 + 去空白。
     *
     * <p>看的是「有没有出现凭据」，所以去掉空白是安全的 ——
     * 凭据本身不含空白，去空白不会把正常文本变成看起来像凭据的东西。
     */
    private static List<String> variants(String text) {
        List<String> out = new ArrayList<>(3);
        out.add(text);

        String nfkc = text;
        try {
            nfkc = Normalizer.normalize(text, Normalizer.Form.NFKC);
        } catch (RuntimeException ignored) {
            // 归一化失败就用原文，不能让一个字符把整个扫描搞失效
        }
        if (!nfkc.equals(text)) {
            out.add(nfkc);
        }

        String compact = nfkc.replaceAll("\\s+", "");
        if (!compact.equals(nfkc)) {
            out.add(compact);
        }
        return out;
    }

    /** 任一变体命中即算命中 */
    private static boolean hitsAny(Pattern p, List<String> variants) {
        for (String v : variants) {
            if (p.matcher(v).find()) {
                return true;
            }
        }
        return false;
    }

    /**
     * 扫描文本，返回命中的规则列表（不包含命中原文）。
     *
     * <p>两步：先扫原文（含 NFKC/去空白变体），再把其中的 Base64 片段解码后扫一遍。
     * 解码文本用同一套特征、同一套风险等级，避免出现"编码后降级"的口径差异。
     */
    public static List<Finding> scan(String content) {
        List<Finding> findings = new ArrayList<>();
        if (content == null || content.isEmpty()) {
            return findings;
        }
        scanText(content, findings, false);
        for (String decoded : Base64Payloads.decodedTexts(content)) {
            scanText(decoded, findings, true);
        }
        return findings;
    }

    private static void scanText(String content, List<Finding> findings, boolean fromBase64) {
        List<String> variants = variants(content);
        String suffix = fromBase64 ? "（base64 解码后命中）" : "";
        if (hitsAny(PRIVATE_KEY, variants)) {
            addFinding(findings, "private-key", "HIGH", "文档中包含 PEM 私钥" + suffix);
        }
        if (hitsAny(ALIYUN_AK, variants)) {
            addFinding(findings, "aliyun-access-key", "HIGH", "文档中包含阿里云 AccessKey ID" + suffix);
        }
        if (hitsAny(AWS_AK, variants)) {
            addFinding(findings, "aws-access-key", "HIGH", "文档中包含 AWS Access Key ID" + suffix);
        }
        if (hitsAny(SK_KEY, variants)) {
            addFinding(findings, "api-key", "HIGH", "文档中包含 sk- 形式的 API Key" + suffix);
        }
        if (hitsAny(JWT, variants)) {
            addFinding(findings, "jwt", "HIGH", "文档中包含 JWT 令牌" + suffix);
        }
        if (hitsAny(PASSWORD_ASSIGN, variants)) {
            addFinding(findings, "password", "MEDIUM", "文档中疑似包含硬编码口令/密钥赋值" + suffix);
        }
        if (hasChinesePlaintextSecret(variants)) {
            addFinding(findings, "password-cn", "HIGH", "文档中以中文自然语言写明了口令/密钥取值" + suffix);
        }
    }

    /** 中文句式命中且取值像真凭据（含数字/小写字母，排除算法名、占位符）。 */
    private static boolean hasChinesePlaintextSecret(List<String> variants) {
        for (String v : variants) {
            Matcher m = PASSWORD_CN.matcher(v);
            while (m.find()) {
                if (looksLikeHardcodedSecret(m.group(2))) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 取值是否像硬编码凭据：至少有一位数字且至少有一位小写字母。
     *
     * <p>挡的是「密钥是 ECDSA-P256」（无小写）、「口令是 PASSWORD」（无数字）这类
     * 出现在文档里的算法名/占位符；真正的口令（{@code Prod2026Secret}、{@code abcd1234}）
     * 两种字符都有。代价是纯数字或纯大写的口令识别不到 —— 这类取值在中文句式里
     * 与"验证码""编号"无法区分，宁可不报也不要把正常文档拦住。
     */
    private static boolean looksLikeHardcodedSecret(String value) {
        boolean digit = false;
        boolean lower = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isDigit(c)) {
                digit = true;
            } else if (Character.isLowerCase(c)) {
                lower = true;
            }
        }
        return digit && lower;
    }

    /** 同一规则只报一次：原文与 base64 解码都可能命中同一条，重复行对调用方没有意义。 */
    private static void addFinding(List<Finding> findings, String rule, String severity, String description) {
        for (Finding f : findings) {
            if (f.getRule().equals(rule)) {
                return;
            }
        }
        findings.add(new Finding(rule, severity, description));
    }

    /**
     * 是否应拦截入库。
     *
     * @param strict 严格模式下中危也拦截；非严格模式仅高危拦截
     */
    public static boolean shouldBlock(List<Finding> findings, boolean strict) {
        for (Finding f : findings) {
            if ("HIGH".equals(f.getSeverity()) || (strict && "MEDIUM".equals(f.getSeverity()))) {
                return true;
            }
        }
        return false;
    }

    @Getter
    public static class Finding {
        private final String rule;
        private final String severity;
        private final String description;

        public Finding(String rule, String severity, String description) {
            this.rule = rule;
            this.severity = severity;
            this.description = description;
        }
    }
}

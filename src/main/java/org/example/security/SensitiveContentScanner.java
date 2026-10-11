package org.example.security;

import lombok.Getter;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
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
 * <p>修不掉的还有 Base64 编码后的凭据（PEM 头被编码后不再有特征）。
 * 那属于规则方案的固有边界，靠扫描器解决不了。
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
     */
    public static List<Finding> scan(String content) {
        List<Finding> findings = new ArrayList<>();
        if (content == null || content.isEmpty()) {
            return findings;
        }
        List<String> variants = variants(content);
        if (hitsAny(PRIVATE_KEY, variants)) {
            findings.add(new Finding("private-key", "HIGH", "文档中包含 PEM 私钥"));
        }
        if (hitsAny(ALIYUN_AK, variants)) {
            findings.add(new Finding("aliyun-access-key", "HIGH", "文档中包含阿里云 AccessKey ID"));
        }
        if (hitsAny(AWS_AK, variants)) {
            findings.add(new Finding("aws-access-key", "HIGH", "文档中包含 AWS Access Key ID"));
        }
        if (hitsAny(SK_KEY, variants)) {
            findings.add(new Finding("api-key", "HIGH", "文档中包含 sk- 形式的 API Key"));
        }
        if (hitsAny(JWT, variants)) {
            findings.add(new Finding("jwt", "HIGH", "文档中包含 JWT 令牌"));
        }
        if (hitsAny(PASSWORD_ASSIGN, variants)) {
            findings.add(new Finding("password", "MEDIUM", "文档中疑似包含硬编码口令/密钥赋值"));
        }
        return findings;
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

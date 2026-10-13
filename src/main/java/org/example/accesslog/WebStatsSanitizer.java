package org.example.accesslog;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 公开聚合端点的<b>字符串清洗工具</b>（只处理 UA 这一种"外部可控且要露面"的字符串）。
 *
 * <p>两条职责，缺一不可：
 * <ol>
 *   <li>{@link #cleanText(String, int)}：控制字符 → 空格、trim、按字符数截断。
 *       控制字符不滤掉就是日志注入/终端注入面（与 {@code AccessLogFilter.sanitize} 同一口径）。</li>
 *   <li>{@link #scrubIpLiterals(String)}：把 IPv4/IPv6 字面量替换成 {@code [ip]}。
 *       UA 同样是攻击者可控的：一个 {@code "1.2.3.4-scanner/1.0"} 就能把 IP 塞进公开响应，
 *       而站主口径是"这个端点连掩码 IP 都不给"。测试对整段响应体做正则扫描钉住这条。</li>
 * </ol>
 *
 * <p>{@link #scrubIpLiterals} 刻意"宁可多换"：它只用在"来源是外部输入的短字符串"上
 * （UA ≤60 字符），误换一个版本号形态的 {@code 1.2.3.4} 换来的是"公开响应零 IP"这条硬保证。
 */
public final class WebStatsSanitizer {

    /** 替换占位符：本身不含任何 IP 形态字符 */
    public static final String IP_PLACEHOLDER = "[ip]";

    /** 点分四段（含非法的 {@code 999.1.1.1} 形态也换掉：只要长得像 IP 就不往外发） */
    private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(?:\\.\\d{1,3}){3}");

    /** 十六进制/冒号游程：IPv6 候选必须整段落在这种游程里（避免把普通词切坏） */
    private static final Pattern HEX_COLON_RUN = Pattern.compile("(?<![0-9A-Za-z])[0-9A-Fa-f:]{3,}(?![0-9A-Za-z])");

    private WebStatsSanitizer() {
    }

    /** 控制字符 → 空格，trim，超长按<b>字符</b>截断（不留省略号，长度即上限） */
    public static String cleanText(String raw, int maxChars) {
        if (raw == null || raw.isEmpty()) {
            return "";
        }
        int limit = Math.max(1, maxChars);
        StringBuilder sb = new StringBuilder(Math.min(raw.length(), limit));
        for (int i = 0; i < raw.length() && sb.length() < limit; i++) {
            char c = raw.charAt(i);
            sb.append(c < 0x20 || c == 0x7F ? ' ' : c);
        }
        return sb.toString().trim();
    }

    /** 把 IPv4 / IPv6 字面量替换成 {@code [ip]}（不改动其它字符） */
    public static String scrubIpLiterals(String raw) {
        if (raw == null || raw.isEmpty()) {
            return raw;
        }
        String v = IPV4.matcher(raw).replaceAll(Matcher.quoteReplacement(IP_PLACEHOLDER));
        Matcher m = HEX_COLON_RUN.matcher(v);
        StringBuilder out = new StringBuilder(v.length());
        int last = 0;
        while (m.find()) {
            String run = m.group();
            if (!looksLikeIpv6(run)) {
                continue;
            }
            out.append(v, last, m.start()).append(IP_PLACEHOLDER);
            last = m.end();
        }
        out.append(v, last, v.length());
        return out.toString();
    }

    /**
     * 判定一段"只含十六进制与冒号"的游程是不是 IPv6。
     *
     * <p>刻意收窄，避免误伤：必须是 {@code ::} 压缩形态（含 IPv4-mapped {@code ::ffff:1.2.3.4}）
     * 或 6 个以上冒号（8 段完整形态）。这样 {@code 12:34:56} 这种时间串不会被当成 IP 换掉，
     * 而 {@code 2001:db8::1}、{@code fe80::1%eth0} 的地址部分仍会被换掉。
     */
    private static boolean looksLikeIpv6(String run) {
        if (run.indexOf(':') < 0) {
            return false;
        }
        if (run.contains("::")) {
            return true;
        }
        int colons = 0;
        for (int i = 0; i < run.length(); i++) {
            if (run.charAt(i) == ':') {
                colons++;
            }
        }
        return colons >= 5;
    }
}

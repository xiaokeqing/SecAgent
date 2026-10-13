package org.example.publicapi;

/**
 * 公网只读端点的 IP 掩码工具。
 *
 * <h3>掩码口径（仍然生效，但不再是唯一口径）</h3>
 * 告警里的源 IP、内网目的地址、资产名属于"能直接拼出内网拓扑"的信息。
 * 掩码态的口径是：<b>保留网段级别、隐去主机级别</b> ——
 * {@code 45.205.1.230} → {@code 45.205.***.***}。
 *
 * <p>注意掩码本身不构成"匿名化保证"：攻击源 IP 在公开数据里被掩码，
 * 目的是不替攻击者/第三方做情报聚合，而不是宣称"看不出是谁"。
 *
 * <h3>开关：谁决定用不用掩码（2026-10-14 站主拍板）</h3>
 * 站主决定公开面<b>显示观测到的真实来源 IP</b>，于是"掩不掩码"变成了一个开关，
 * 唯一读取点是 {@link PublicIpPolicy}（配置 {@code app.public.mask-ips}，默认 {@code false} = 真实 IP）。
 * 本类只负责"怎么掩"与"哪些地址属于内网"，<b>不读配置</b> ——
 * 这样"哪个口径生效"永远只有一处答案，不会出现"某条链路自己判断掩不掩"的第三种口径。
 *
 * <p><b>不变的那条线</b>：内网 / 保留 / 链路地址在任何口径下都不作为来源地址公开 ——
 * 掩码态写成 {@link #INTERNAL_ADDRESS_LABEL}，真实态写成 {@link #INTERNAL_UNKNOWN_LABEL}。
 */
public final class PublicIpMask {

    /** 掩码态下内网/保留地址的写法（历史口径，2026-10-14 前所有公开端点都用它） */
    public static final String INTERNAL_ADDRESS_LABEL = "内部地址";

    /**
     * <b>真实态</b>下内网 / 保留 / 不可识别地址的写法。
     *
     * <p>为什么要单独一个词（而不是复用 {@link #INTERNAL_ADDRESS_LABEL}）：
     * 站主 2026-10-14 拍板公开面显示<b>观测到的真实来源 IP</b>，但内网地址、链路地址
     * （{@code 127.0.0.1} / {@code 172.x} / {@code fe80::} …）永远不是"攻击源"，
     * 公开出去只会白送内网拓扑。所以真实态下这类值一律写成「内网/未知」——
     * 页面读到它就知道"这不是一个可展示的来源地址"，而不是"这里本该有个 IP 但丢了"。
     */
    public static final String INTERNAL_UNKNOWN_LABEL = "内网/未知";

    private PublicIpMask() {
    }

    /**
     * 从"可能带端口 / 方括号"的取值里取出<b>主机部分</b>。
     *
     * <p>只做形状剥离，不做合法性判定（那由 {@link #isIpLiteral} 负责）。
     * 取不出来返回 {@code null}，调用方必须把它当"未知"处理，不许原样透出。
     */
    public static String host(String raw) {
        if (raw == null) {
            return null;
        }
        String v = raw.trim();
        if (v.isEmpty()) {
            return null;
        }
        if (v.startsWith("[")) {                       // [2001:db8::1]:2222
            int end = v.indexOf(']');
            return end > 1 ? v.substring(1, end) : null;
        }
        boolean hasColon = v.indexOf(':') > 0;
        boolean hasDot = v.indexOf('.') > 0;
        if (hasColon && hasDot) {
            return v.substring(0, v.indexOf(':'));      // 45.205.1.230:2222
        }
        return v;
    }

    /** 是否为一个可识别的 IPv4 / IPv6 字面量（主机形式，不含端口）。 */
    public static boolean isIpLiteral(String host) {
        if (host == null || host.isBlank()) {
            return false;
        }
        String v = host.trim();
        if (v.indexOf('.') > 0 && v.indexOf(':') < 0) {
            return isIpv4Literal(v);
        }
        // 注意用 >= 0 而不是 > 0：{@code ::1} / {@code ::} 这类"以冒号开头"的写法
        // indexOf(':') == 0，用 > 0 会漏判 → 真实态下变成「未知」而不是「内网/未知」。
        if (v.indexOf(':') >= 0) {
            return IPV6_LITERAL.matcher(v).matches();
        }
        return false;
    }

    /**
     * 是否为内网 / 保留 / 环回 / 链路本地地址（IPv4 与 IPv6）。
     *
     * <p><b>与 {@link #mask} 的关系</b>：{@code mask} 回答的是"公开成什么样"，
     * 本方法回答的是"这是不是一个不该当攻击源展示的地址"。真实态下两者配合使用。
     */
    public static boolean isInternalAddress(String host) {
        if (host == null || host.isBlank()) {
            return false;
        }
        String v = host.trim().toLowerCase(java.util.Locale.ROOT);
        if (v.indexOf('.') > 0 && v.indexOf(':') < 0) {
            if (!isIpv4Literal(v)) {
                return false;
            }
            return isPrivateOrReserved(v.split("\\."));
        }
        if (v.indexOf(':') >= 0) {
            if ("::".equals(v) || "::1".equals(v)) {
                return true;                                    // 未指定 / 环回
            }
            if (v.startsWith("fe80") || v.startsWith("fc") || v.startsWith("fd")
                    || v.startsWith("ff")) {
                return true;                                    // 链路本地 / ULA / 组播
            }
            if (v.startsWith("::ffff:")) {
                // IPv4-mapped：拿尾部再判一次，避免 ::ffff:10.0.0.1 被当成公网地址
                return isInternalAddress(v.substring("::ffff:".length()));
            }
            return false;
        }
        return false;
    }

    /** 只把文本里<b>内网/保留</b>的 IP 换成「内网/未知」，公网 IP 原样保留（真实态用）。 */
    public static String maskInternalOnly(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        String out = replaceInternal(text, IPV4_IN_TEXT);
        out = replaceInternal(out, IPV6_IN_TEXT);
        // 压缩写法（{@code fe80::1} / {@code ::1} / {@code fd00::1}）只有一两个组，
        // 上面那条"至少 4 组"的规则匹配不到 —— 而链路本地/环回恰恰最爱用压缩写法。
        // 这条只用于真实态：掩码态的口径由 maskAll 决定，不动它（回归要求逐字节一致）。
        return replaceInternal(out, IPV6_COMPRESSED_IN_TEXT);
    }

    private static String replaceInternal(String text, java.util.regex.Pattern p) {
        java.util.regex.Matcher m = p.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String g = m.group();
            String host = host(g);
            String replacement = (host != null && isInternalAddress(host)) ? INTERNAL_UNKNOWN_LABEL : g;
            m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(replacement));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /** 严格的 IPv4 字面量（四段、每段 0-255）；不合法的一律不算。 */
    public static boolean isIpv4Literal(String v) {
        if (v == null || v.isBlank()) {
            return false;
        }
        String[] parts = v.trim().split("\\.");
        if (parts.length != 4) {
            return false;
        }
        for (String s : parts) {
            if (s.isEmpty() || s.length() > 3) {
                return false;
            }
            for (int i = 0; i < s.length(); i++) {
                if (!Character.isDigit(s.charAt(i))) {
                    return false;
                }
            }
            if (Integer.parseInt(s) > 255) {
                return false;
            }
        }
        return true;
    }

    /**
     * IPv6 字面量（含 {@code ::} 压缩写法）。
     *
     * <p>刻意写成展开的等价形式而不是"冒号+十六进制"这种宽松串：
     * 真实态下宽松匹配会把 {@code 10:20:30} 这类时间戳当成"真实来源地址"原样公开，
     * 而"多公开一点"正是这条改造里唯一不能接受的方向。
     */
    private static final java.util.regex.Pattern IPV6_LITERAL = java.util.regex.Pattern.compile(
            "(?i)(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}"
                    + "|(?:[0-9a-f]{1,4}:){1,7}:"
                    + "|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}"
                    + "|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}"
                    + "|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}"
                    + "|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}"
                    + "|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}"
                    + "|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}"
                    + "|:(?::[0-9a-f]{1,4}){1,7}|::)");

    /**
     * 掩码一个 IP。
     *
     * @param ip 原始 IP（可能带端口、可能为 null 或空）
     * @return IPv4 保留前两段（{@code 45.205.***.***}）；
     *         IPv6 保留前两组（{@code 2001:db8:****:****}）；
     *         无法识别时统一返回 {@code ***}（不猜、不原样透出）
     */
    public static String mask(String ip) {
        if (ip == null || ip.isBlank()) {
            // 公开端点上宁可为占位符，也不能把 null/空白直接透出去（与本类文档一致）
            return "***";
        }
        if (ip == null) {
            return null;
        }
        String v = ip.trim();
        if (v.isEmpty()) {
            return null;
        }

        boolean hasColon = v.indexOf(':') > 0;
        boolean hasDot = v.indexOf('.') > 0;

        // 纯 IPv6（不含点）：只留前两组
        if (hasColon && !hasDot) {
            String[] groups = v.split(":");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < groups.length && i < 2; i++) {
                if (!groups[i].isEmpty()) {
                    sb.append(groups[i]).append(':');
                }
            }
            if (sb.length() == 0) {
                return "***";
            }
            return sb + "****:****";
        }

        // IPv4（可能带 :port）
        String host = v;
        if (hasColon && hasDot) {
            host = v.substring(0, v.indexOf(':'));
        }
        String[] parts = host.split("\\.");
        if (parts.length == 4) {
            // 内网/保留地址直接写成「内部地址」。
            // 为什么不能只做掩码：10.0.0.10 掩码后是 10.0.***.***，
            // 虽然主机位被隐去，但「这是内网地址」这件事本身就已经透出去了 ——
            // 而公开页不需要让任何人知道内网用的是哪个段。
            if (isPrivateOrReserved(parts)) {
                return INTERNAL_ADDRESS_LABEL;
            }
            return parts[0] + "." + parts[1] + ".***.***";
        }
        return "***";
    }

    /**
     * 把一段<b>自由文本</b>里出现的所有 IPv4 换成掩码形式。
     *
     * <p>为什么需要它：告警/审计的文本字段（规则描述、处置原因）里经常内嵌 IP
     * （例：{@code 蜜罐: 新的 SSH 连接来自 106.37.205.248}）。
     * 只掩码结构化字段是不够的 —— 实测就是这样漏出去过一个完整 IP。
     */
    public static String maskAll(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        String out = replaceAll(text, IPV4_IN_TEXT);
        out = replaceAll(out, IPV6_IN_TEXT);
        return out;
    }

    private static String replaceAll(String text, java.util.regex.Pattern p) {
        java.util.regex.Matcher m = p.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(String.valueOf(mask(m.group()))));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * 自由文本里的 IPv4。
     *
     * <p><b>为什么不能再用 {@code \b}</b>：线上运行在 JDK 17 上，而 JDK 19 之前 {@code \b} 的
     * "词字符"判定是 <b>Unicode 感知</b>的 —— 中文也算词字符。于是
     * {@code 103.146.184.77和} 里 IP 后面紧跟一个汉字，<b>就没有词边界</b>，整条规则匹配失败，
     * 这个 IP 会原样透出到公开回答里（2026-10-13 匿名抽检实测泄露过 3 个完整 IP，
     * 而同一次响应里的 {@code outputFindings} 还写着 {@code ip-masked} —— 护栏以为掩过了）。
     *
     * <p>修法：用显式 lookaround 代替 {@code \b} ——
     * {@code (?<![\d.])} 与 {@code (?![\d.])} 只在"前后不是数字或点"时成立，
     * 与"什么算词字符"无关，因此中文、英文、标点相邻都能正确掩码；
     * 同时 {@code 1.2.3.4.5}/{@code 103.146.184.771} 这种更长数字串不会被误切。
     */
    private static final java.util.regex.Pattern IPV4_IN_TEXT =
            java.util.regex.Pattern.compile("(?<![\\d.])(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})(?![\\d.])");

    /**
     * 自由文本里的 IPv6。
     *
     * <p>要求至少 4 组十六进制（{@code ::} 压缩写法的常见形式），
     * 这样 {@code 10:20:30} 这类时间戳不会被误掩码（它只有 3 组数字）。
     */
    private static final java.util.regex.Pattern IPV6_IN_TEXT =
            java.util.regex.Pattern.compile("(?<![0-9A-Fa-f:])((?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4})(?![0-9A-Fa-f:])");

    /**
     * 自由文本里<b>压缩写法</b>的 IPv6（{@code fe80::1} / {@code ::1} / {@code 2001:db8::1}）。
     *
     * <p>要求出现 {@code ::}，所以 {@code 10:20:30} 这类时间戳（没有连续两个冒号）不会误命中。
     */
    private static final java.util.regex.Pattern IPV6_COMPRESSED_IN_TEXT = java.util.regex.Pattern.compile(
            "(?<![0-9A-Fa-f:])((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,5})?::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?)(?![0-9A-Fa-f:])");

    /**
     * 内网 / 保留网段判定。
     *
     * <p>只用于公开页脱敏（决定"显示成内部地址还是一段掩码"），
     * <b>不承担任何安全判定职责</b> —— 护栏用的白名单在 Security 侧，和这里无关。
     */
    private static boolean isPrivateOrReserved(String[] p) {
        int a;
        int b;
        try {
            a = Integer.parseInt(p[0]);
            b = Integer.parseInt(p[1]);
        } catch (NumberFormatException e) {
            return false;
        }
        if (a == 0 || a == 10 || a == 127) {
            return true;                       // 0.0.0.0/8、10/8、环回
        }
        if (a == 192 && b == 168) {
            return true;                       // 192.168/16
        }
        if (a == 172 && b >= 16 && b <= 31) {
            return true;                       // 172.16/12
        }
        if (a == 169 && b == 254) {
            return true;                       // 链路本地
        }
        // 运营商级 NAT（含云厂商元数据 100.100.100.200）
        return a == 100 && b >= 64 && b <= 127;
    }
}

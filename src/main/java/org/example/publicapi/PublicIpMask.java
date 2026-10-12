package org.example.publicapi;

/**
 * 公网只读端点的 IP 掩码工具。
 *
 * <h3>为什么公开页必须掩码</h3>
 * 告警里的源 IP、内网目的地址、资产名属于"能直接拼出内网拓扑"的信息。
 * 公开页只需要说明"有来自某个网段的扫描"，<b>不需要给出一张可用的资产地图</b>。
 * 所以这里的口径是：<b>保留网段级别、隐去主机级别</b> ——
 * {@code 45.205.1.230} → {@code 45.205.***.***}。
 *
 * <p>注意掩码本身不构成"匿名化保证"：攻击源 IP 在公开数据里被掩码，
 * 目的是不替攻击者/第三方做情报聚合，而不是宣称"看不出是谁"。
 */
public final class PublicIpMask {

    private PublicIpMask() {
    }

    /**
     * 掩码一个 IP。
     *
     * @param ip 原始 IP（可能带端口、可能为 null 或空）
     * @return IPv4 保留前两段（{@code 45.205.***.***}）；
     *         IPv6 保留前两组（{@code 2001:db8:****:****}）；
     *         无法识别时统一返回 {@code ***}（不猜、不原样透出）
     */
    public static String mask(String ip) {
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
                return "内部地址";
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
        java.util.regex.Matcher m = IPV4_IN_TEXT.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            m.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(String.valueOf(mask(m.group()))));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private static final java.util.regex.Pattern IPV4_IN_TEXT =
            java.util.regex.Pattern.compile("\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b");

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

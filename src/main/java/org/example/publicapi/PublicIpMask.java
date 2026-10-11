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
            return parts[0] + "." + parts[1] + ".***.***";
        }
        return "***";
    }
}

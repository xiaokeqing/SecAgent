package org.example.geoip;

/**
 * IP 解析与<b>地址性质分类</b>（不引任何第三方库：只用 JDK 的字符串与位运算）。
 *
 * <h3>为什么自己写而不引 {@code maxminddb} / {@code Guava InetAddresses}</h3>
 * ① 项目纪律是零新增第三方依赖（GeoIP 客户端库会把"离线库"变成"又一个要跟着升级的攻击面"）；
 * ② 我们需要的语义比通用库更窄也更明确 —— <b>只解析、不联网、不做 DNS 反查</b>，
 *    并且要把地址分成"能上地图的/内网的/保留的"三类，通用库没有这个口径；
 * ③ 解析失败必须<b>可解释</b>（返回 INVALID 而不是抛异常穿透到响应里），
 *    因为公开端点返回 500 会把"某条日志里的脏 IP"变成"公开页面挂了"。
 *
 * <h3>口径（写入 RUNBOOK，改动即口径变更）</h3>
 * <ul>
 *   <li>{@link IpScope#INTERNAL} 内网/本机：{@code 10/8}、{@code 172.16/12}、{@code 192.168/16}、
 *       {@code 127/8}、{@code 169.254/16}、{@code 100.64/10}（运营商级 NAT）、
 *       {@code fc00::/7}（ULA）、{@code ::1}、{@code fe80::/10}</li>
 *   <li>{@link IpScope#RESERVED} 保留/文档：{@code 0/8}、{@code 192.0.2/24}、{@code 198.51.100/24}、
 *       {@code 203.0.113/24}（RFC 5737 —— 内置样本就用它）、{@code 198.18/15}、{@code 224/4}、
 *       {@code 240/4}、{@code 2001:db8::/32}、{@code ff00::/8}</li>
 *   <li>{@link IpScope#GLOBAL} 其余（才允许拿去查库、才能上地图）</li>
 * </ul>
 */
public final class IpAddresses {

    private IpAddresses() {
    }

    /** 地址性质：决定它能不能进地理分布（内网与保留地址<b>不上地图</b>） */
    public enum IpScope {
        GLOBAL, INTERNAL, RESERVED, INVALID
    }

    /** 是否是 IPv4 字面量（不判定合法性，只看形状） */
    public static boolean looksLikeV4(String s) {
        return s != null && s.indexOf('.') > 0 && s.indexOf(':') < 0;
    }

    /**
     * 解析 IPv4 → 无符号 32 位（放进 int，比较时必须用 {@code Integer.compareUnsigned}）。
     *
     * @return 解析成功返回 {@code int}；失败返回 {@code null}（不抛异常）
     */
    public static Integer parseV4(String raw) {
        if (raw == null) {
            return null;
        }
        String s = raw.trim();
        if (s.isEmpty() || s.length() > 15) {
            return null;
        }
        int v = 0;
        int part = 0;
        int digits = 0;
        int value = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '.') {
                if (digits == 0 || part >= 3) {
                    return null;
                }
                v = (v << 8) | value;
                part++;
                digits = 0;
                value = 0;
                continue;
            }
            if (c < '0' || c > '9') {
                return null;
            }
            // 前导零（"010"）在 inet_aton 里是八进制，含义有歧义 —— 一律拒收，不猜
            if (digits == 0 && c == '0' && i + 1 < s.length() && s.charAt(i + 1) != '.') {
                return null;
            }
            value = value * 10 + (c - '0');
            digits++;
            if (value > 255) {
                return null;
            }
        }
        if (digits == 0 || part != 3) {
            return null;
        }
        return (v << 8) | value;
    }

    /**
     * 解析 IPv6（含 {@code ::} 压缩与 {@code ::ffff:1.2.3.4} 内嵌写法）。
     *
     * @return {@code {hi, lo}} 两个 64 位；失败返回 {@code null}
     */
    public static long[] parseV6(String raw) {
        if (raw == null) {
            return null;
        }
        String s = raw.trim();
        int pct = s.indexOf('%');          // 去掉 zone id（fe80::1%eth0）
        if (pct > 0) {
            s = s.substring(0, pct);
        }
        int br = s.indexOf('[');           // 去掉 URL 形态 [::1]
        int brEnd = s.indexOf(']');
        if (br == 0 && brEnd > 0) {
            s = s.substring(1, brEnd);
        }
        if (s.isEmpty() || s.indexOf(':') < 0) {
            return null;
        }
        int doubleColon = s.indexOf("::");
        if (doubleColon != s.lastIndexOf("::")) {
            return null;                   // 只允许一个 "::"
        }

        String head = doubleColon < 0 ? s : s.substring(0, doubleColon);
        String tail = doubleColon < 0 ? "" : s.substring(doubleColon + 2);

        int[] headGroups = groups(head);
        int[] tailGroups = groups(tail);
        if (headGroups == null || tailGroups == null) {
            return null;
        }
        int total = headGroups.length + tailGroups.length;
        if (doubleColon < 0) {
            if (total != 8) {
                return null;
            }
        } else if (total > 7) {
            return null;                   // "::" 至少要压掉一组
        }
        int[] all = new int[8];
        for (int i = 0; i < headGroups.length; i++) {
            all[i] = headGroups[i];
        }
        for (int i = 0; i < tailGroups.length; i++) {
            all[8 - tailGroups.length + i] = tailGroups[i];
        }
        long hi = 0;
        long lo = 0;
        for (int i = 0; i < 4; i++) {
            hi = (hi << 16) | all[i];
            lo = (lo << 16) | all[4 + i];
        }
        return new long[]{hi, lo};
    }

    /**
     * 解析一串 16 位组；内嵌 IPv4（"1.2.3.4"）占两组。失败返回 null。
     *
     * <p>空串返回<b>空数组</b>而不是 null：{@code "::1"} 的头部、{@code "2001:db8::"}
     * 的尾部都是"零组"，那是合法写法。这一点最初写错了 —— 真库一跑，
     * 416 万条 IPv6 区间全被判成坏行（坏行率 51%），整库直接不可用。
     * 合成夹具很难造出这个规模，所以"真库跑一遍"是必须的验收项。
     */
    private static int[] groups(String part) {
        if (part.isEmpty()) {
            return new int[0];
        }
        String[] items = part.split(":", -1);
        // split 会丢掉尾部的空项，这里不用管：尾随 ":" 只可能来自非法输入，下面长度校验会拦住
        int n = 0;
        int[] out = new int[10];
        for (String it : items) {
            if (it.isEmpty()) {
                return null;
            }
            if (it.indexOf('.') > 0) {
                Integer v4 = parseV4(it);
                if (v4 == null) {
                    return null;
                }
                out[n++] = (v4 >>> 16) & 0xFFFF;
                out[n++] = v4 & 0xFFFF;
            } else {
                if (it.length() > 4) {
                    return null;
                }
                int v = 0;
                for (int i = 0; i < it.length(); i++) {
                    int d = Character.digit(it.charAt(i), 16);
                    if (d < 0) {
                        return null;
                    }
                    v = (v << 4) | d;
                }
                out[n++] = v;
            }
        }
        return java.util.Arrays.copyOf(out, n);
    }

    /**
     * 地址性质判定。
     *
     * <p>先按形状解析；解析不了就是 {@link IpScope#INVALID} ——
     * 调用方据此把它计入"未定位"，<b>而不是当成国家为空</b>（后者会让脏数据静默混进分母）。
     */
    public static IpScope scope(String ip) {
        if (ip == null || ip.isBlank()) {
            return IpScope.INVALID;
        }
        String s = ip.trim();
        Integer v4 = parseV4(s);
        if (v4 != null) {
            return scopeV4(v4);
        }
        long[] v6 = parseV6(s);
        if (v6 != null) {
            return scopeV6(v6[0], v6[1]);
        }
        return IpScope.INVALID;
    }

    static IpScope scopeV4(int v4) {
        int a = (v4 >>> 24) & 0xFF;
        int b = (v4 >>> 16) & 0xFF;
        if (a == 0) {
            return IpScope.RESERVED;                       // 0.0.0.0/8
        }
        if (a == 10 || a == 127) {
            return IpScope.INTERNAL;
        }
        if (a == 172 && b >= 16 && b <= 31) {
            return IpScope.INTERNAL;
        }
        if (a == 192 && b == 168) {
            return IpScope.INTERNAL;
        }
        if (a == 169 && b == 254) {
            return IpScope.INTERNAL;
        }
        if (a == 100 && b >= 64 && b <= 127) {
            return IpScope.INTERNAL;                       // 运营商级 NAT（RFC 6598）
        }
        if (a == 203 && b == 0 && ((v4 >>> 8) & 0xFF) == 113) {
            return IpScope.RESERVED;                       // RFC 5737 文档网段（内置样本）
        }
        if (a == 198 && (b == 51 && ((v4 >>> 8) & 0xFF) == 100)) {
            return IpScope.RESERVED;
        }
        if (a == 198 && (b == 18 || b == 19)) {
            return IpScope.RESERVED;                       // 基准测试网段
        }
        if (a == 192 && b == 0 && ((v4 >>> 8) & 0xFF) == 2) {
            return IpScope.RESERVED;
        }
        if (a >= 224) {
            return IpScope.RESERVED;                       // 组播 224/4 + 保留 240/4
        }
        return IpScope.GLOBAL;
    }

    static IpScope scopeV6(long hi, long lo) {
        if (hi == 0 && lo == 0) {
            return IpScope.RESERVED;                       // ::
        }
        if (hi == 0 && lo == 1) {
            return IpScope.INTERNAL;                       // ::1
        }
        long top = (hi >>> 56) & 0xFF;
        if ((top & 0xFE) == 0xFC) {
            return IpScope.INTERNAL;                       // fc00::/7 ULA
        }
        if (top == 0xFE && ((hi >>> 54) & 0x3) == 0x2) {
            return IpScope.INTERNAL;                       // fe80::/10 链路本地
        }
        if (top == 0xFF) {
            return IpScope.RESERVED;                       // ff00::/8 组播
        }
        // 2001:db8::/32
        if (((hi >>> 32) & 0xFFFFFFFFL) == 0x20010DB8L) {
            return IpScope.RESERVED;
        }
        // ::ffff:0:0/96 与 ::/96 这类 IPv4 映射地址：按内嵌的 IPv4 再判一次
        if (hi == 0 && (lo >>> 32) == 0xFFFFL) {
            return scopeV4((int) lo);
        }
        return IpScope.GLOBAL;
    }
}

package org.example.response;

import java.util.regex.Pattern;

/**
 * 封禁命令模板（集合式：ipset 优先，iptables 回退）。
 *
 * <h3>为什么是集合（ipset）而不是逐条 iptables 规则</h3>
 * <ul>
 *   <li><b>O(1) 匹配</b>：iptables 规则是线性链表，封 1000 个 IP 就要按序走 1000 条；
 *       ipset 是哈希表，无论封多少条，包过滤只查一次哈希。扫描/爆破告警往往是
 *       短时间内几百上千个源 IP，线性规则会把转发路径拖慢（这是真实的性能事故形态）。</li>
 *   <li><b>原生 timeout 自动过期</b>：{@code ipset add ... timeout N} 到点由内核删除条目，
 *       不需要我们写定时任务逐条删规则。即使 SecAgent 停机、SSH 断了、调度器挂了，
 *       封禁也会按时失效 —— <b>这是"封禁兜底"而不是"解封兜底"</b>，
 *       默认安全方向：宁可自己恢复，不要永久封死。</li>
 *   <li><b>一条规则管所有 IP</b>：{@code iptables -m set --match-set} 只加一条，
 *       增删 IP 不碰防火墙规则集，不会出现"删错一条规则解封了半个网段"。</li>
 * </ul>
 *
 * <h3>回退策略（为什么回退点放在服务端脚本里）</h3>
 * 优先 {@code ipset create <set> hash:net family inet|inet6 timeout N}
 * + {@code iptables -I INPUT -m set --match-set <set> src -j DROP}；
 * 若服务器上<b>没有 ipset</b>（老发行版/精简镜像），自动回退到"逐条 iptables/ip6tables 规则"
 * （{@code -s <ip> -j DROP} + TTL 到期由脚本的 sweep 清理）。
 * <p>
 * 回退判断必须在<b>真正执行防火墙的那台机器（服务器 2）</b>上做：
 * SecAgent 跑在服务器 1，它既看不到也不是 iptables 的执行者；
 * 如果在 Java 侧探测，只会得到一个与真实执行环境不符的结论（这正是本项目
 * "判据过时 → 看着成功其实走了 MOCK"那一类故障）。所以 Java 只发语义命令
 * {@code block <ip> <ttl> <reason>}，由服务端脚本选后端，并把实际后端
 * ({@code backend=ipset|iptables}) 回显上来，Java 再记进审计/封禁记录。
 *
 * <h3>IPv6</h3>
 * 两个集合分开：{@code secagent_block}（family inet）与 {@code secagent_block6}（family inet6）。
 * 原因：ipset 的集合有<b>固定 family</b>，一个 hash:net 集合不能同时装 v4/v6；
 * 混装会直接 add 失败。所以按目标地址族选集合，过滤时 v4 走 iptables、v6 走 ip6tables。
 */
public final class BlockCommands {

    /** IPv4 集合名（服务端脚本里同名） */
    public static final String SET_V4 = "secagent_block";
    /** IPv6 集合名 */
    public static final String SET_V6 = "secagent_block6";

    /** ipset timeout 上限（秒）：与服务端脚本的校验保持一致 */
    public static final int MAX_TTL_SECONDS = 31_536_000;

    /** 原因参数只允许这些字符 —— 它会作为 argv 的一个元素过 SSH，仍然收紧到白名单形状 */
    private static final Pattern REASON_SLUG = Pattern.compile("^[a-z0-9][a-z0-9._-]{0,31}$");

    /** IPv6 形状（只用来决定走 v6 分支，真正的合法性由护栏判定） */
    private static final Pattern IPV6_SHAPE = Pattern.compile("^[0-9a-fA-F:.]+$");

    private BlockCommands() {
    }

    /** 目标地址族对应的集合名 */
    public static String setName(String ip) {
        return isIpv6(ip) ? SET_V6 : SET_V4;
    }

    /**
     * 原因 token：只保留 ASCII 白名单字符。
     *
     * <p>封禁原因本身是中文自由文本，直接拼进 forced command 会把"一个参数"
     * 变成"多个 token"，服务端解析立刻错位（更坏的情况是被当成额外参数）。
     * 所以这里只取一个<b>形状受控</b>的短 token 用于服务端日志，
     * 完整中文原因留在 Java 侧审计里，两边各记各的。
     */
    public static String reasonSlug(String reason) {
        if (reason == null) {
            return "auto";
        }
        String s = reason.trim().toLowerCase();
        if (s.isEmpty()) {
            return "auto";
        }
        if (REASON_SLUG.matcher(s).matches()) {
            return s;
        }
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
                sb.append(c);
            } else if (sb.length() > 0 && sb.charAt(sb.length() - 1) != '_') {
                sb.append('_');
            }
            if (sb.length() >= 32) {
                break;
            }
        }
        String out = sb.toString().replaceAll("^[_-]+|[_-]+$", "");
        if (out.isEmpty() || !REASON_SLUG.matcher(out).matches()) {
            return "auto";
        }
        return out;
    }

    /** 下发给服务器 2 的 forced command（服务端脚本按空白切分解析） */
    public static String forcedCommand(String ip, int ttlSeconds, String reasonSlug) {
        return "block " + ip + " " + ttlSeconds + " " + reasonSlug(reasonSlug);
    }

    /** @return 是否为 IPv6 字面量（决定走 ip6tables / family inet6） */
    public static boolean isIpv6(String ip) {
        return ip != null && ip.indexOf(':') >= 0 && IPV6_SHAPE.matcher(ip).matches();
    }

    /**
     * 是否是可解析的 IP 字面量（v4 或 v6）。
     *
     * <p>解封路径需要的校验：解封是"减少阻断"，不该套用封禁白名单
     * （否则一条历史误封进了白名单的目标就永远解不掉了），
     * 但仍必须挡住"根本不是 IP"的输入 —— 它会一路走到 SSH 命令行参数上。
     */
    public static boolean isIpLiteral(String ip) {
        if (ip == null || ip.isBlank() || ip.length() > 45) {
            return false;
        }
        String s = ip.trim();
        if (!s.matches("^[0-9a-fA-F:.]+$")) {
            return false;
        }
        // 不含冒号就必须是点分四段：否则 InetAddress 会把 "2130706433" 解析成
        // 127.0.0.1、"0177.0.0.1" 解析成 177.0.0.1，解封命令发下去删的就不是用户以为的那个条目
        if (s.indexOf(':') < 0 && !s.matches("^(\\d{1,3}\\.){3}\\d{1,3}$")) {
            return false;
        }
        try {
            // 形状已限定为 IP 字符集，getByName 不会触发 DNS 查询
            java.net.InetAddress a = java.net.InetAddress.getByName(s);
            return a instanceof java.net.Inet4Address || a instanceof java.net.Inet6Address;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 本应执行的完整命令计划（dry-run 与审计里用它说明"如果真下发会做什么"）。
     *
     * <p>包含三段：SSH forced command、ipset 主路径、iptables 回退路径。
     * 写全三段是刻意的：值班的人看到审计就知道"没下发"和"下发后会在服务器上发生什么"，
     * 而不是只看到一句"DRY_RUN"。
     */
    public static String plan(String ip, int ttlSeconds, String reasonSlug) {
        String set = setName(ip);
        String fam = isIpv6(ip) ? "inet6" : "inet";
        String ipt = isIpv6(ip) ? "ip6tables" : "iptables";
        StringBuilder sb = new StringBuilder();
        sb.append("ssh forced-command: ").append(forcedCommand(ip, ttlSeconds, reasonSlug));
        sb.append('\n').append("server(ipset): ipset create ").append(set)
                .append(" hash:net family ").append(fam).append(" timeout ").append(ttlSeconds).append(" -exist");
        sb.append('\n').append("server(ipset): ipset add ").append(set).append(' ').append(ip)
                .append(" timeout ").append(ttlSeconds).append(" -exist");
        sb.append('\n').append("server(ipset): ").append(ipt).append(" -I INPUT 1 -m set --match-set ")
                .append(set).append(" src -j DROP");
        sb.append('\n').append("server(fallback, 无 ipset): ").append(ipt).append(" -I INPUT 1 -s ")
                .append(ip).append(" -j DROP");
        return sb.toString();
    }

    /** 从服务端回显里解析实际使用的后端（ipset / iptables / unknown） */
    public static String parseBackend(String sshOutput) {
        if (sshOutput != null) {
            String s = sshOutput.toLowerCase();
            if (s.contains("backend=ipset")) {
                return "IPSET";
            }
            if (s.contains("backend=iptables")) {
                return "IPTABLES";
            }
        }
        return "UNKNOWN";
    }

    /** 解封计划（审计用） */
    public static String unblockPlan(String ip) {
        String set = setName(ip);
        String ipt = isIpv6(ip) ? "ip6tables" : "iptables";
        return "ssh forced-command: unblock " + ip
                + "\nserver: ipset del " + set + " " + ip
                + " （回退路径: " + ipt + " -D INPUT -s " + ip + " -j DROP）";
    }
}

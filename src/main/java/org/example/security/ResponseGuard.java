package org.example.security;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 自动处置（封禁 IP / 锁账号 / 杀进程）安全护栏。
 * 执行响应动作前统一做：保护白名单、非法 IP 校验、封禁时长上限。
 *
 * <h3>保护白名单的范围 —— 一次外部评审之后的补全</h3>
 * 原白名单只有 {@code 127.0.0.1, 0.0.0.0, 255.255.255.255, 10/8, 172.16/12, 192.168/16}，
 * 外加一句 {@code first == 0 || first == 127 || first >= 224} 的保留段判断。
 * 这挡得住 RFC1918 私网，但<b>漏了一整类：云元数据地址</b>。
 *
 * <ul>
 *   <li><b>100.64.0.0/10</b>（运营商级 NAT）—— <b>阿里云元数据是 100.100.100.200</b>，
 *       就落在这个段里。封掉它会直接打断实例读取元数据与临时凭据</li>
 *   <li><b>169.254.0.0/16</b>（链路本地）—— AWS/GCP 元数据是 169.254.169.254，
 *       云上通用风险</li>
 *   <li>192.0.0.0/24、198.18.0.0/15 等特殊用途段</li>
 * </ul>
 *
 * <p>另有三类<b>必须单独配置</b>的保护对象，它们的共同点是"代码猜不出来，只有部署者知道"：
 * <ol>
 *   <li>{@code app.response.self-assets}：自有公网资产（把自家域名 IP 封了 = 自我 DoS）</li>
 *   <li>{@code app.response.machine-public-ips}：<b>本机公网 IP</b>。
 *       告警里出现"自己的出口 IP"并不罕见（NAT 回环、日志串号、被伪造），
 *       一旦封掉，本机对外连接立刻中断，连 SSH 抢修都进不来</li>
 *   <li>{@code app.response.healthcheck-sources}：<b>健康检查源</b>（SLB/探活/监控探针）。
 *       探针被封 = 服务被判死 = 流量摘除，这是"安全动作导致业务中断"最典型的一种</li>
 * </ol>
 *
 * <h3>IPv6 支持（原来那句"属于后续工作"已经补上）</h3>
 * 旧版本直接用 {@code ^(\d{1,3}\.){3}\d{1,3}$} 判地址，注释里写着
 * "目前不支持封禁 IPv6，需要在 iptables 之外再走 ip6tables，属于后续工作"。
 * 现在封禁链路升级为集合式（ipset family inet / inet6，见 {@code BlockCommands}），
 * ip6tables 与 ipset 的 inet6 集合已经就位，护栏这边放开 IPv6 并<b>同步补上 IPv6 保护段</b>：
 * 只放行"确实是 IPv6 字面量"的输入（形状 + {@link InetAddress} 双重校验），
 * 且 ::1 / ::/128 / fc00::/7 / fe80::/10 / ff00::/8 / 文档段一律拒绝。
 * 放开地址族的同时把保护面一起补齐，是这次改动的硬要求 ——
 * 否则"支持 IPv6"就等于"给了一条绕过旧白名单的新路径"。
 */
@Service
public class ResponseGuard {

    private static final Logger logger = LoggerFactory.getLogger(ResponseGuard.class);

    /**
     * 禁止封禁的 IP / CIDR（逗号分隔）。
     *
     * <p>这里覆盖的是「任何情况下都不该被封」的地址：
     * 环回、未指定、广播、RFC1918 私网、链路本地、CGN、以及各特殊用途段。
     */
    @Value("${app.response.whitelist:"
            + "127.0.0.0/8,"            // 环回
            + "0.0.0.0/8,"              // 未指定
            + "10.0.0.0/8,"             // RFC1918
            + "172.16.0.0/12,"          // RFC1918
            + "192.168.0.0/16,"         // RFC1918
            + "169.254.0.0/16,"         // 链路本地（含 AWS/GCP 元数据 169.254.169.254）
            + "100.64.0.0/10,"          // CGN（含阿里云元数据 100.100.100.200）★ 关键
            + "192.0.0.0/24,"           // IETF 协议专用
            + "192.0.2.0/24,"           // TEST-NET-1
            + "198.51.100.0/24,"        // TEST-NET-2
            + "203.0.113.0/24,"         // TEST-NET-3
            + "198.18.0.0/15,"          // 基准测试
            + "255.255.255.255/32}")    // 广播
    private String whitelistRaw;

    /**
     * 自有资产白名单（额外，逗号分隔的 IP 或 CIDR）。
     *
     * <p>示例：{@code SECAGENT_SELF_ASSETS=47.96.106.187,203.0.113.10}
     */
    @Value("${app.response.self-assets:}")
    private String selfAssetsRaw;

    /**
     * 本机（及同机对外出口）的公网 IP，逗号分隔。
     *
     * <p>为什么单独一项而不要并进 whiteist：审计里要能一眼看出
     * "这次拦截是因为命中了【本机公网 IP】"，而不是笼统的"命中白名单"。
     * 值班的人需要这个区别来决定"是不是配置漏了"。
     */
    @Value("${app.response.machine-public-ips:}")
    private String machinePublicIpsRaw;

    /**
     * 健康检查 / 探活 / 监控源地址，逗号分隔。
     *
     * <p>探针被封的后果不是"少了一条告警"，而是<b>服务被判定不健康、流量被摘除</b>，
     * 属于典型的"安全动作造成业务故障"。所以单独成项、单独报原因。
     */
    @Value("${app.response.healthcheck-sources:}")
    private String healthcheckSourcesRaw;

    /** 人工封禁单次最长分钟数（运维/审批入口） */
    @Value("${app.response.max-duration-minutes:1440}")
    private int maxDurationMinutes = 1440;

    /**
     * 策略封禁最长分钟数（自动处置入口）。
     *
     * <p>分级 TTL 里"利用类 7 天"必须能真的落地，但<b>不能让人的手也伸到 7 天</b>：
     * 所以上限分两档 —— 自动处置用 policy 上限（默认 10080 = 7 天），
     * 手动/审批仍用 1440（24 小时）。这样策略生效、人工仍受约束，各管各的。
     */
    @Value("${app.response.policy-max-duration-minutes:10080}")
    private int policyMaxDurationMinutes = 10080;

    /** 默认封禁分钟数 */
    @Value("${app.response.default-duration-minutes:60}")
    private int defaultDurationMinutes = 60;

    /**
     * 内置 IPv6 保护段。
     *
     * <p>刻意写成代码常量而不是走配置：这些是协议规定的特殊地址，
     * <b>与部署环境无关</b>。走配置的话，一次误删配置就会放开 ::1/fc00::/7 这类"绝不该封"的地址，
     * 而这类错误在测试环境往往看不出来（测试机没有 IPv6 流量）。
     * 站点特有的 IPv6 资产仍可写进 self-assets / machine-public-ips。
     */
    private static final List<String> BUILTIN_IPV6 = Arrays.asList(
            "::1/128",          // 环回
            "::/128",           // 未指定
            "fc00::/7",         // 唯一本地地址（RFC4193）
            "fe80::/10",        // 链路本地
            "ff00::/8",         // 组播
            "100::/64",         // 丢弃前缀（RFC6666）
            "2001:db8::/32",    // 文档示例段
            "2001:2::/48"       // 基准测试
    );

    /** 通用保护条目（whiteist + 自有资产），判定逻辑不区分来源 */
    private final List<String> whitelist = new ArrayList<>();

    /** 分类保护条目，用于给出更精确的拒绝原因 */
    private final List<String> machineIps = new ArrayList<>();
    private final List<String> healthcheckSources = new ArrayList<>();

    @PostConstruct
    public void init() {
        whitelist.clear();
        machineIps.clear();
        healthcheckSources.clear();

        List<String> general = split(whitelistRaw);
        whitelist.addAll(general);
        int builtin = whitelist.size();

        // 自有资产并进同一张表：判定逻辑不需要区分来源，都该被保护
        List<String> selfAssets = split(selfAssetsRaw);
        whitelist.addAll(selfAssets);
        if (!selfAssets.isEmpty()) {
            logger.info("自有资产白名单已加载 {} 条", selfAssets.size());
        } else {
            // 没配就明确告警 —— 这是"缺配置"，不是"不需要"
            logger.warn("未配置 app.response.self-assets（自有资产白名单）。"
                    + "保护网段能挡住内网与云元数据地址，但挡不住把【你自己的公网 IP / 域名】封掉。"
                    + "生产部署请通过 SECAGENT_SELF_ASSETS 填入本机与关联资产的地址。");
        }

        // IPv6 协议级保护段始终生效（不依赖配置，理由见 BUILTIN_IPV6 注释）
        whitelist.addAll(BUILTIN_IPV6);

        machineIps.addAll(split(machinePublicIpsRaw));
        healthcheckSources.addAll(split(healthcheckSourcesRaw));
        if (machineIps.isEmpty()) {
            logger.warn("未配置 app.response.machine-public-ips（本机公网 IP）。"
                    + "一旦告警里出现本机出口 IP 并被自动封禁，本机对外连接会立即中断。");
        }
        if (healthcheckSources.isEmpty()) {
            logger.warn("未配置 app.response.healthcheck-sources（健康检查源）。"
                    + "探针被封会导致服务被判定不健康、流量被摘除。");
        }

        logger.info("处置护栏初始化：保护白名单 {} 条（内置 {} + 自有 {} + IPv6 内置 {}），"
                        + "本机公网 {} 条，健康检查源 {} 条，默认封禁 {} 分钟，人工上限 {} 分钟，策略上限 {} 分钟",
                whitelist.size(), builtin, selfAssets.size(), BUILTIN_IPV6.size(),
                machineIps.size(), healthcheckSources.size(),
                defaultDurationMinutes, maxDurationMinutes, policyMaxDurationMinutes);
    }

    private static List<String> split(String raw) {
        List<String> out = new ArrayList<>();
        if (raw == null) {
            return out;
        }
        for (String s : raw.split(",")) {
            if (!s.trim().isEmpty()) {
                out.add(s.trim());
            }
        }
        return out;
    }

    /**
     * 校验是否允许封禁该 IP（人工/审批入口，上限 1440 分钟）。
     *
     * @return null 表示允许；非空字符串为拒绝原因
     */
    public String validateBlock(String ip, Integer durationMinutes) {
        return validateBlock(ip, durationMinutes, false);
    }

    /**
     * 校验是否允许封禁该 IP。
     *
     * @param policyDerived true 表示时长由分级策略算出（自动处置），
     *                      此时用策略上限；false 表示人工指定，用人工上限
     * @return null 表示允许；非空字符串为拒绝原因
     */
    public String validateBlock(String ip, Integer durationMinutes, boolean policyDerived) {
        if (ip == null || ip.trim().isEmpty()) {
            return "封禁目标 IP 为空";
        }
        String target = ip.trim();
        if (target.length() > 45) {
            return "非法 IP 地址（长度超限）: " + target;
        }

        boolean v4 = isIpv4Literal(target);
        boolean v6 = !v4 && isIpv6Literal(target);
        if (!v4 && !v6) {
            // fail-safe：判不准就不放行。这里同时挡住十进制整数（2130706433）、
            // 十六进制（0x7f.0.0.1）、四位八进制段（0177.0.0.1）等历史绕过写法。
            return "非法 IP 地址（需为点分十进制 IPv4 或标准 IPv6）: " + target;
        }
        if (v4) {
            String[] parts = target.split("\\.");
            int first = Integer.parseInt(parts[0]);
            // 组播（224-239）与保留（240-255）直接拒绝
            if (first >= 224) {
                return "该地址为组播/保留地址，禁止封禁";
            }
        }

        // 三类保护名单：通用/自有（whitelist）、本机公网、健康检查源。
        // 顺序无所谓，但原因必须区分 —— 值班的人要根据"命中了哪一类"判断是配置漏了还是真该拦。
        for (String rule : machineIps) {
            if (matches(target, rule)) {
                return "目标命中本机公网 IP 保护（app.response.machine-public-ips）: " + rule;
            }
        }
        for (String rule : healthcheckSources) {
            if (matches(target, rule)) {
                return "目标命中健康检查源保护（app.response.healthcheck-sources）: " + rule;
            }
        }
        for (String rule : whitelist) {
            if (matches(target, rule)) {
                return "目标命中保护白名单: " + rule;
            }
        }

        int d = durationMinutes == null ? defaultDurationMinutes : durationMinutes;
        if (d <= 0) {
            return "封禁时长必须大于 0";
        }
        int cap = policyDerived ? policyMaxDurationMinutes : maxDurationMinutes;
        if (d > cap) {
            return "封禁时长超过上限 " + cap + " 分钟"
                    + (policyDerived ? "（自动处置策略上限）" : "（人工封禁上限）");
        }
        return null;
    }

    /** 给测试与排查用：当前生效的保护条目 */
    public List<String> getWhitelist() {
        return new ArrayList<>(whitelist);
    }

    public int getDefaultDurationMinutes() {
        return defaultDurationMinutes;
    }

    public int getMaxDurationMinutes() {
        return maxDurationMinutes;
    }

    public int getPolicyMaxDurationMinutes() {
        return policyMaxDurationMinutes;
    }

    /** 是否形如严格点分十进制 IPv4（每段 0-255） */
    static boolean isIpv4Literal(String s) {
        if (s == null || !s.matches("^(\\d{1,3}\\.){3}\\d{1,3}$")) {
            return false;
        }
        for (String p : s.split("\\.")) {
            if (Integer.parseInt(p) > 255) {
                return false;
            }
        }
        return true;
    }

    /**
     * 是否形如合法 IPv6 字面量。
     *
     * <p>先卡形状（只允许十六进制字符、冒号、点 —— 后者用于内嵌 IPv4 的形式），
     * 再交给 {@link InetAddress} 做真正的语法校验。
     * 形状白名单的意义：避免把一个<b>看起来像主机名</b>的字符串交给 getByName，
     * 那会触发 DNS 解析（配置里的笔误就变成一次外部查询，甚至被解析成某个真实 IP 后放行）。
     */
    static boolean isIpv6Literal(String s) {
        if (s == null || s.indexOf(':') < 0 || s.length() > 45) {
            return false;
        }
        if (!s.matches("^[0-9a-fA-F:.]+$")) {
            return false;
        }
        // 必须至少含一个冒号且不能是纯 IPv4 内嵌的混合写法（那样由 v4 分支处理）
        try {
            InetAddress a = InetAddress.getByName(s);
            return a instanceof Inet6Address;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean matches(String ip, String rule) {
        if (rule == null || rule.isEmpty()) {
            return false;
        }
        String r = rule.trim();
        if (r.contains("/")) {
            return inCidr(ip, r);
        }
        return sameAddress(ip, r);
    }

    private boolean sameAddress(String ip, String rule) {
        try {
            InetAddress a = InetAddress.getByName(ip);
            if (a instanceof Inet4Address) {
                return ip.equals(rule);
            }
            // IPv6 的文本形式可以有多种等价写法（::1 与 0:0:0:0:0:0:0:1），
            // 字符串相等会漏判，必须按字节比较。
            InetAddress b = InetAddress.getByName(rule);
            return Arrays.equals(a.getAddress(), b.getAddress());
        } catch (Exception e) {
            return ip.equals(rule);
        }
    }

    /**
     * CIDR 判定：按字节前缀比较，IPv4/IPv6 共用一套逻辑。
     *
     * <p>原来用 int 掩码，只对 v4 成立（v6 是 128 位，int 装不下）。
     * 现在两个地址族都要支持，统一成"字节数组 + 前缀位数"：
     * 先比整数个字节，再比最后那个不满一字节的位掩码。
     */
    private boolean inCidr(String ip, String cidr) {
        try {
            int slash = cidr.indexOf('/');
            if (slash <= 0) {
                return false;
            }
            String netPart = cidr.substring(0, slash).trim();
            // 只接受字面量，防止配置里的笔误触发 DNS 解析
            if (!netPart.matches("^[0-9a-fA-F:.]+$")) {
                return false;
            }
            int prefix = Integer.parseInt(cidr.substring(slash + 1).trim());
            byte[] a = InetAddress.getByName(ip).getAddress();
            byte[] b = InetAddress.getByName(netPart).getAddress();
            if (a.length != b.length || prefix < 0 || prefix > a.length * 8) {
                return false;
            }
            int fullBytes = prefix / 8;
            int remBits = prefix % 8;
            for (int i = 0; i < fullBytes; i++) {
                if (a[i] != b[i]) {
                    return false;
                }
            }
            if (remBits > 0) {
                int mask = 0xFF << (8 - remBits);
                return (a[fullBytes] & mask) == (b[fullBytes] & mask);
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}

package org.example.security;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * 自动处置（封禁 IP / 锁账号 / 杀进程）安全护栏。
 * 执行响应动作前统一做：保护白名单、非法与不可达 IP 校验、封禁时长上限。
 * 阶段3 的 ResponseActionService 将调用本类，避免误封关键资产，或被伪造源 IP 诱导形成自我 DoS。
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
 * 另外补了一个<b>自有资产白名单</b>（{@code app.response.self-assets}）：
 * 原白名单只防"内网地址"，防不住"你自己的公网资产"——
 * 把自家域名解析出的 IP 或第二台服务器封了，同样是自我 DoS。
 * 这个值必须由部署者按自己的资产填，代码里猜不出来。
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
     * <p>为什么单独一个配置项：保护网段是"通用规则"，自有资产是"部署者知识"。
     * 混在一起会让通用部分没法复用，而且换服务器时容易忘了改。
     *
     * <p>示例：{@code SECAGENT_SELF_ASSETS=47.96.106.187,203.0.113.10}
     */
    @Value("${app.response.self-assets:}")
    private String selfAssetsRaw;

    /** 单次封禁最长分钟数 */
    @Value("${app.response.max-duration-minutes:1440}")
    private int maxDurationMinutes;

    /** 默认封禁分钟数 */
    @Value("${app.response.default-duration-minutes:60}")
    private int defaultDurationMinutes;

    private final List<String> whitelist = new ArrayList<>();

    @PostConstruct
    public void init() {
        for (String s : whitelistRaw.split(",")) {
            if (!s.trim().isEmpty()) {
                whitelist.add(s.trim());
            }
        }
        int builtin = whitelist.size();

        // 自有资产并进同一张表：判定逻辑不需要区分来源，都该被保护
        if (selfAssetsRaw != null && !selfAssetsRaw.trim().isEmpty()) {
            for (String s : selfAssetsRaw.split(",")) {
                if (!s.trim().isEmpty()) {
                    whitelist.add(s.trim());
                }
            }
            logger.info("自有资产白名单已加载 {} 条", whitelist.size() - builtin);
        } else {
            // 没配就明确告警 —— 这是"缺配置"，不是"不需要"
            logger.warn("未配置 app.response.self-assets（自有资产白名单）。"
                    + "保护网段能挡住内网与云元数据地址，但挡不住把【你自己的公网 IP / 域名】封掉。"
                    + "生产部署请通过 SECAGENT_SELF_ASSETS 填入本机与关联资产的地址。");
        }

        logger.info("处置护栏初始化：保护白名单 {} 条（内置 {} + 自有 {}），默认封禁 {} 分钟，上限 {} 分钟",
                whitelist.size(), builtin, whitelist.size() - builtin,
                defaultDurationMinutes, maxDurationMinutes);
    }

    /**
     * 校验是否允许封禁该 IP。
     *
     * @return null 表示允许；非空字符串为拒绝原因
     */
    public String validateBlock(String ip, Integer durationMinutes) {
        if (ip == null || ip.trim().isEmpty()) {
            return "封禁目标 IP 为空";
        }
        String target = ip.trim();
        // 严格 IPv4 正则：IPv6、十进制整数形式（2130706433）、十六进制（0x7f.0.0.1）、
        // 四位八进制段（0177.0.0.1）在这里全被拒绝。这是 fail-safe —— 判不准就不放行。
        // 代价是目前不支持封禁 IPv6，需要在 iptables 之外再走 ip6tables，属于后续工作。
        if (!target.matches("^(\\d{1,3}\\.){3}\\d{1,3}$")) {
            return "非法 IPv4 地址: " + target;
        }
        String[] parts = target.split("\\.");
        for (String p : parts) {
            if (Integer.parseInt(p) > 255) {
                return "非法 IPv4 地址: " + target;
            }
        }
        int first = Integer.parseInt(parts[0]);
        // 组播（224-239）与保留（240-255）直接拒绝
        if (first >= 224) {
            return "该地址为组播/保留地址，禁止封禁";
        }
        for (String w : whitelist) {
            if (matchesWhitelist(target, w)) {
                return "目标命中保护白名单: " + w;
            }
        }
        int d = durationMinutes == null ? defaultDurationMinutes : durationMinutes;
        if (d <= 0) {
            return "封禁时长必须大于 0";
        }
        if (d > maxDurationMinutes) {
            return "封禁时长超过上限 " + maxDurationMinutes + " 分钟";
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

    private boolean matchesWhitelist(String ip, String rule) {
        if (rule.contains("/")) {
            return inCidr(ip, rule);
        }
        return ip.equals(rule);
    }

    private boolean inCidr(String ip, String cidr) {
        try {
            String[] la = cidr.split("/");
            int prefix = Integer.parseInt(la[1]);
            int mask = prefix == 0 ? 0 : 0xFFFFFFFF << (32 - prefix);
            return (toInt(ip) & mask) == (toInt(la[0]) & mask);
        } catch (Exception e) {
            return false;
        }
    }

    private static int toInt(String ip) {
        String[] p = ip.split("\\.");
        return (Integer.parseInt(p[0]) << 24) | (Integer.parseInt(p[1]) << 16)
                | (Integer.parseInt(p[2]) << 8) | Integer.parseInt(p[3]);
    }
}

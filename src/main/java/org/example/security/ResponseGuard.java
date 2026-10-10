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
 */
@Service
public class ResponseGuard {

    private static final Logger logger = LoggerFactory.getLogger(ResponseGuard.class);

    /** 禁止封禁的 IP / CIDR（逗号分隔），默认保护环回与全部私网地址 */
    @Value("${app.response.whitelist:127.0.0.1,0.0.0.0,255.255.255.255,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}")
    private String whitelistRaw;

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
        logger.info("处置护栏初始化：白名单 {} 条，默认封禁 {} 分钟，上限 {} 分钟",
                whitelist.size(), defaultDurationMinutes, maxDurationMinutes);
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
        if (first == 0 || first == 127 || first >= 224) {
            return "该地址为保留/环回/组播地址，禁止封禁";
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

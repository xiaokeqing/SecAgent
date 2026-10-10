package org.example.core.model;

/**
 * 安全告警类型（攻击手法大类），用于大屏"类型统计"与自动响应策略匹配。
 */
public enum AlertType {

    BRUTE_FORCE("暴力破解"),
    SQL_INJECTION("SQL注入"),
    XSS("跨站脚本"),
    COMMAND_INJECTION("命令注入"),
    FILE_UPLOAD("文件上传"),
    WEBSHELL("Webshell"),
    SCAN("扫描探测"),
    C2("恶意外联/C2"),
    MALWARE("恶意软件"),
    PRIVILEGE_ESCALATION("权限提升"),
    ACCOUNT_ABUSE("账号异常"),
    DDOS("拒绝服务"),
    POLICY("策略违规"),
    OTHER("其他");

    private final String label;

    AlertType(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    /** 根据规则名/描述关键字粗分类，三方数据源没有统一类型字段时使用。 */
    public static AlertType guess(String text) {
        if (text == null) {
            return OTHER;
        }
        String t = text.toLowerCase();
        if (t.contains("brute") || t.contains("暴力") || t.contains("爆破") || t.contains("sshd: authentication failure")) {
            return BRUTE_FORCE;
        }
        if (t.contains("sql") || t.contains("union select") || t.contains("注入")) {
            return SQL_INJECTION;
        }
        if (t.contains("xss") || t.contains("跨站")) {
            return XSS;
        }
        if (t.contains("webshell") || t.contains("一句话") || t.contains("cmd=")) {
            return WEBSHELL;
        }
        if (t.contains("command") || t.contains("命令注入") || t.contains(";cat ") || t.contains("|sh")) {
            return COMMAND_INJECTION;
        }
        if (t.contains("scan") || t.contains("sweep") || t.contains("扫描") || t.contains("404")) {
            return SCAN;
        }
        if (t.contains("c2") || t.contains("c&c") || t.contains("outbound") || t.contains("外联")
                || t.contains("/dev/tcp") || t.contains("reverse") || t.contains("反弹")) {
            return C2;
        }
        if (t.contains("malware") || t.contains("virus") || t.contains("trojan") || t.contains("勒索")
                || t.contains("挖矿") || t.contains("木马")) {
            return MALWARE;
        }
        if (t.contains("privilege") || t.contains("sudo") || t.contains("提权")) {
            return PRIVILEGE_ESCALATION;
        }
        if (t.contains("account") || t.contains("useradd") || t.contains("账号")) {
            return ACCOUNT_ABUSE;
        }
        if (t.contains("ddos") || t.contains("flood") || t.contains("syn")) {
            return DDOS;
        }
        return OTHER;
    }
}

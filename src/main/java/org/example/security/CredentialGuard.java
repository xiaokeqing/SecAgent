package org.example.security;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 启动期凭据强度校验（fail-closed）。
 *
 * <p><b>为什么需要它：</b>原实现检测到 {@code admin123} 这类默认口令后，
 * 只打印一条 WARN 日志便继续启动。本地演示无妨，但一旦暴露到公网，
 * 攻击者用公开的默认口令即可登录，进而消耗模型额度、调用处置接口、
 * 上传文件并写入知识库——告警不等于防护。
 *
 * <p><b>本类的做法：</b>把「是否允许弱凭据」变成一个显式的开关
 * {@code app.security.enforce-strong-credentials}：
 * <ul>
 *   <li>{@code false}（默认）—— 本地开发：检测到弱凭据仅打印告警，保持开箱即用；</li>
 *   <li>{@code true} —— 对外部署：检测到弱凭据 <b>直接抛出异常拒绝启动</b>。</li>
 * </ul>
 * 即「失败关闭（fail closed）」而非「告警后放行（warn and continue）」。
 * 容器化部署时由 docker-compose 默认置为 {@code true}，忘记注入强凭据就无法上线，
 * 而不是悄悄带着默认口令上线。
 *
 * <p><b>校验范围：</b>管理员密码、分析员密码、系统级 API Token。
 * 校验规则：不得命中已知默认口令；长度不得低于 {@value #MIN_LENGTH} 位。
 */
@Component
public class CredentialGuard {

    private static final Logger logger = LoggerFactory.getLogger(CredentialGuard.class);

    /**
     * 凭据最小长度。注意这里刻意与 {@link AuthService#addUser} 的校验保持一致，
     * 避免同一个系统里出现两套密码强度标准。
     */
    public static final int MIN_LENGTH = 12;

    /** 已知的演示/默认弱口令：命中即认为不适合对外提供服务 */
    private static final List<String> KNOWN_WEAK = List.of(
            "admin123", "analyst123", "secagent-demo-token",
            "admin", "administrator", "password", "passw0rd",
            "123456", "12345678", "changeme", "secret", "test");

    @Value("${app.security.enforce-strong-credentials:false}")
    private boolean enforce;

    @Value("${app.security.login.username:admin}")
    private String adminUsername;

    @Value("${app.security.login.password:${SECAGENT_PASSWORD:admin123}}")
    private String adminPassword;

    @Value("${app.security.analyst.username:${SECAGENT_ANALYST_USERNAME:analyst}}")
    private String analystUsername;

    @Value("${app.security.analyst.password:${SECAGENT_ANALYST_PASSWORD:analyst123}}")
    private String analystPassword;

    /** 仅在开启鉴权时才校验系统级 API Token，否则该凭据不参与鉴权、无需校验 */
    @Value("${app.auth.enabled:false}")
    private boolean authEnabled;

    @Value("${app.auth.token:secagent-demo-token}")
    private String apiToken;

    @PostConstruct
    public void verify() {
        Map<String, String> credentials = new LinkedHashMap<>();
        credentials.put("管理员密码（app.security.login.password / SECAGENT_PASSWORD）", adminPassword);
        credentials.put("分析员密码（app.security.analyst.password / SECAGENT_ANALYST_PASSWORD）", analystPassword);
        if (authEnabled) {
            credentials.put("系统级 API Token（app.auth.token / SECAGENT_API_TOKEN）", apiToken);
        }

        List<String> problems = new ArrayList<>();
        for (Map.Entry<String, String> entry : credentials.entrySet()) {
            String reason = weaknessOf(entry.getValue());
            if (reason != null) {
                problems.add(entry.getKey() + " —— " + reason);
            }
        }

        if (problems.isEmpty()) {
            logger.info("凭据强度校验通过（强制模式={}，最小长度={}）", enforce, MIN_LENGTH);
            return;
        }

        if (enforce) {
            // 失败关闭：宁可不启动，也不带着默认口令对外服务
            StringBuilder message = new StringBuilder(256);
            message.append("检测到不安全的默认/弱凭据，已拒绝启动")
                    .append("（app.security.enforce-strong-credentials=true）：\n");
            for (String problem : problems) {
                message.append("  - ").append(problem).append('\n');
            }
            message.append("请通过环境变量注入强凭据后重试：")
                    .append("建议 ").append(MIN_LENGTH)
                    .append(" 位以上，且包含大小写字母、数字与符号。");
            throw new IllegalStateException(message.toString());
        }

        logger.warn("==========================================================");
        logger.warn("[安全告警] 检测到默认/弱凭据（当前为非强制模式，仅适合本地演示）：");
        for (String problem : problems) {
            logger.warn("[安全告警]   - {}", problem);
        }
        logger.warn("[安全告警] 对外部署前必须注入强凭据，并设置");
        logger.warn("[安全告警]   app.security.enforce-strong-credentials=true");
        logger.warn("[安全告警] 否则服务将带着公开的默认口令对外提供访问。");
        logger.warn("==========================================================");
    }

    /**
     * 返回该凭据的弱点说明；合格则返回 {@code null}。
     *
     * <p>包级可见（而非 private）以便单元测试直接覆盖判定规则，
     * 无需启动 Spring 上下文。
     */
    static String weaknessOf(String value) {
        if (value == null || value.isBlank()) {
            return "未设置";
        }
        if (KNOWN_WEAK.contains(value.trim().toLowerCase(Locale.ROOT))) {
            return "命中已知默认口令";
        }
        if (value.length() < MIN_LENGTH) {
            return "长度不足 " + MIN_LENGTH + " 位（当前 " + value.length() + " 位）";
        }
        return null;
    }

    /** 供启动日志与排查使用（不输出凭据本身） */
    public String describeAccounts() {
        return "管理员账号=" + adminUsername + "，分析员账号=" + analystUsername
                + "，接口鉴权=" + (authEnabled ? "开启" : "关闭");
    }
}

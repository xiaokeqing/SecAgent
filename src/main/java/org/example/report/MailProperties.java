package org.example.report;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 邮件订阅的 SMTP 配置（前缀 {@code app.mail}）。
 *
 * <h3>为什么"配置齐全"是硬门槛</h3>
 * 日报里有攻击来源国、蜜罐、封禁明细 —— 它<b>不该被发到错误的人手里</b>。
 * 所以这里不做"能发就发"：{@link #enabled} 关着、或任何一项必填缺失时，
 * {@link MailSenderService} 一律只把 {@code .eml} 落到 {@code data/reports/outbox/}，
 * 并明说"未配置 SMTP"，绝不尝试连一个半配置的服务器。
 *
 * <p>字段与 {@code .env.example} 里的 {@code APP_MAIL_*} 一一对应，
 * 避免"改了 .env 没生效"这类问题。
 */
@Component
@ConfigurationProperties(prefix = "app.mail")
@Getter
@Setter
public class MailProperties {

    /** 总开关（默认关） */
    private boolean enabled = false;

    /** SMTP 主机（如 smtp.example.com） */
    private String host = "";

    /** SMTP 端口（465 走隐式 TLS，587 走 STARTTLS，25 明文） */
    private int port = 0;

    /** 认证用户名（多数服务商要求与 from 同域） */
    private String username = "";

    /** 认证密码 / 授权码 */
    private String password = "";

    /** 发件人地址（也用作信封 MAIL FROM） */
    private String from = "";

    /** 收件人列表（默认空 = 不发给任何人） */
    private List<String> to = new ArrayList<>();

    /** 隐式 TLS（465 端口常见）；false 时按 {@link #starttls} 决定是否升级 */
    private boolean ssl = false;

    /** 明文连接后 STARTTLS 升级（587 端口常见） */
    private boolean starttls = true;

    /** 连接 / 读超时（秒） */
    private int timeoutSeconds = 15;

    /** 未配置或被拒时的落盘目录 */
    private String outboxDir = "data/reports/outbox";

    /** 标题前缀（后接日期，如 {@code [安全日报] 2026-10-19}） */
    private String subjectPrefix = "[安全日报] ";
}

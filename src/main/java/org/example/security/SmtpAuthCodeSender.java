package org.example.security;

import org.example.report.MailSenderService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 验证码发信的生产实现：把信交给 {@link MailSenderService} 已有的手写 SMTP。
 *
 * <p>刻意没有重写 SMTP：465 隐式 TLS 那一版（连上先握手、再读 220）是踩过坑修好的，
 * 并且有 {@code MailSenderServiceTlsTest} 盯着；验证码没有理由再造一份第二实现。
 *
 * <p>这里只负责「写什么」，不负责「发没发出去之后怎么办」—— 后者由
 * {@link AuthCodeService} 决定（发不出去就当作功能不可用，对外不区分原因）。
 */
@Component
public class SmtpAuthCodeSender implements AuthCodeSender {

    private static final Logger logger = LoggerFactory.getLogger(SmtpAuthCodeSender.class);

    /** 邮件标题。带站点名，方便站主在收件箱里一眼认出这是谁发的。 */
    static final String SUBJECT = "[安全观测站] 登录验证码";

    private final MailSenderService mailSender;

    public SmtpAuthCodeSender(MailSenderService mailSender) {
        this.mailSender = mailSender;
    }

    @Override
    public boolean send(String toEmail, String code, int expiresInSeconds) {
        int minutes = Math.max(1, expiresInSeconds / 60);
        String text = "你的登录验证码是：" + code + "\n\n"
                + "有效期 " + minutes + " 分钟，只能使用一次。\n"
                + "如果这不是你本人的操作，请忽略这封邮件——它不会泄露给任何第三方，"
                + "也不会因为被转发就多出一个登录入口（本站没有注册功能）。\n";
        String html = "<p>你的登录验证码是：</p>"
                + "<p style=\"font-size:28px;font-weight:bold;letter-spacing:6px\">" + code + "</p>"
                + "<p>有效期 " + minutes + " 分钟，只能使用一次。</p>"
                + "<p style=\"color:#666\">如果这不是你本人的操作，请忽略这封邮件。</p>";

        boolean ok = mailSender.sendText(toEmail, SUBJECT, text, html);
        if (!ok) {
            // 只记结构性信息，不记验证码本身：日志会被收集，验证码 5 分钟内就是凭据
            logger.warn("验证码邮件未能发出（收件人 {}，SMTP 未配置或发送失败）", maskEmail(toEmail));
        }
        return ok;
    }

    /** 日志里打码：保留前两位与域名，够定位「发给谁了」，不够拼出完整地址。 */
    private static String maskEmail(String email) {
        if (email == null || email.isEmpty()) {
            return "(空)";
        }
        int at = email.indexOf('@');
        if (at <= 0) {
            return "***";
        }
        String local = email.substring(0, at);
        String keep = local.length() <= 2 ? local.substring(0, 1) : local.substring(0, 2);
        return keep + "***" + email.substring(at);
    }
}

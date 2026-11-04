package org.example.security;

/**
 * 验证码发信口。
 *
 * <p>为什么是接口，而不是在 {@link AuthCodeService} 里直接 new 一个 SMTP 会话：
 * <ul>
 *   <li>单测必须能断言「白名单外的请求一封都没发」—— 真发邮件既慢，又会真的打扰站主；</li>
 *   <li>发信是外部 IO，把它收成一个可替换的依赖，验证码的过期/作废/限流逻辑才可被确定性地测试。</li>
 * </ul>
 *
 * <p>生产实现是 {@link SmtpAuthCodeSender}（复用日报那套手写 SMTP，见
 * {@code org.example.report.MailSenderService#sendText}）。测试里一律用替身。
 */
public interface AuthCodeSender {

    /**
     * 发一封验证码邮件。
     *
     * <p>实现<b>不得</b>抛出异常（网络、认证、超时一律折成 {@code false}）：
     * 调用方要靠「发没发出去」来决定对外怎么答，而不是靠 catch。
     *
     * @param toEmail           收件人（已由调用方归一化）
     * @param code              6 位数字验证码
     * @param expiresInSeconds  有效秒数（写进正文，给收信人看）
     * @return true = 已交给 SMTP 服务器；false = 没发出去
     */
    boolean send(String toEmail, String code, int expiresInSeconds);
}

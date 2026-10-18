package org.example.report;

import java.time.LocalDate;

/**
 * 日报的<b>取数口</b>：一个方法，拿到"过去 24 小时的数字 + 出处"。
 *
 * <h3>为什么要一个接口</h3>
 * 真实现读 Wazuh / 蜜罐 / 处置留痕，测试里一个都不该连。把取数收成一个函数式接口后，
 * 渲染、落盘、语音、邮件四件事都能用固定输入测出确定的字节，
 * 而"取数失败"也能用"返回缺数据"精确表达，不用去模拟一整个 Spring 上下文。
 */
@FunctionalInterface
public interface DigestMetricsSource {

    /**
     * 汇总指定日期当天的日报数字。
     *
     * @param day 日报归属日（北京时区的自然日；窗口口径由实现决定并在 {@code sources} 里写清）
     */
    DigestMetrics collect(LocalDate day);
}

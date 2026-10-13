package org.example.notify;

import org.example.core.model.SecurityAlert;
import org.example.integration.WazuhGateway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * 高危告警的<b>定时巡检</b>：把"新出现的高危告警"推给手机。
 *
 * <h3>为什么不能挂在"打开告警大屏"的那个接口上</h3>
 * 最省事的做法是在 {@code /api/alerts/list} 里顺手通知一句 —— 但那等于
 * <b>"没人看屏就不通知"</b>，而通知存在的唯一理由恰恰是"人不在电脑前"。
 * 所以这里做成独立的定时任务：不依赖任何用户请求，服务活着就在巡检。
 *
 * <h3>三条冷静的约束</h3>
 * <ol>
 *   <li>通知没配就<b>不巡检</b>（{@code configured()==false} 直接返回）——
 *       不做无用功，也不制造"假巡检"的日志；</li>
 *   <li>数据源不是 REAL 时<b>不通知</b>：内置样本长得很像真告警
 *       （SSH 暴力破解、SQL 注入、Webshell），拿它去发手机告警是本项目明令禁止的
 *       "看着成功、实际是假的"。这里额外按 {@code extra.mock} 逐条剔除；</li>
 *   <li>同一条告警（按 id）只推一次，记忆在 {@link SecurityEventNotifier} 里。</li>
 * </ol>
 */
@Component
public class AlertNotificationPoller {

    private static final Logger logger = LoggerFactory.getLogger(AlertNotificationPoller.class);

    private final ObjectProvider<WazuhGateway> wazuhProvider;
    private final SecurityEventNotifier notifier;
    private final NotificationService notificationService;

    @Value("${app.notify.alert-poll-enabled:true}")
    private boolean enabled;

    /** 每次取多少条候选（窗口越大越不容易漏，但查询越贵） */
    @Value("${app.notify.alert-poll-limit:100}")
    private int limit;

    public AlertNotificationPoller(ObjectProvider<WazuhGateway> wazuhProvider,
                                   SecurityEventNotifier notifier,
                                   NotificationService notificationService) {
        this.wazuhProvider = wazuhProvider;
        this.notifier = notifier;
        this.notificationService = notificationService;
    }

    @Scheduled(fixedDelayString = "${app.notify.alert-poll-interval-ms:60000}",
               initialDelayString = "${app.notify.alert-poll-initial-delay-ms:60000}")
    public void poll() {
        if (!enabled) {
            return;
        }
        if (notificationService == null || !notificationService.configured()) {
            // 未配置：不巡检。启动自检里已经显式打印过"通知未配置"，这里不再每轮刷日志
            return;
        }
        WazuhGateway gw = wazuhProvider == null ? null : wazuhProvider.getIfAvailable();
        if (gw == null) {
            return;
        }
        String mode;
        try {
            mode = gw.mode();
        } catch (Exception e) {
            logger.warn("读取 Wazuh 模式失败，本轮跳过告警通知：{}", e.getMessage());
            return;
        }
        if (!"REAL".equalsIgnoreCase(mode == null ? "" : mode.trim())) {
            logger.debug("数据源模式={}（非 REAL），本轮不推送高危告警（不拿内置样本发真告警）", mode);
            return;
        }
        try {
            List<SecurityAlert> alerts = gw.recentAlerts(Math.max(1, limit));
            if (alerts == null || alerts.isEmpty()) {
                return;
            }
            int n = notifier.highSeverityAlerts(alerts.stream().filter(a -> !isMock(a)).toList(), "poller");
            if (n > 0) {
                logger.info("高危告警通知：本轮提交 {} 条新告警到通知中枢（候选 {} 条，模式={}）",
                        n, alerts.size(), mode);
            }
        } catch (Exception e) {
            // 巡检失败只记日志：下一轮还会来，不该把异常抛给调度线程（会停掉整个任务）
            logger.warn("高危告警巡检失败（下一轮重试）：{}", e.getMessage());
        }
    }

    /** 内置样本判定（{@code extra.mock=true}）——与公网端点同一口径，独立实现以避免包耦合 */
    static boolean isMock(SecurityAlert a) {
        if (a == null) {
            return true;
        }
        Map<String, Object> extra = a.getExtra();
        if (extra == null) {
            return false;
        }
        Object m = extra.get("mock");
        return m instanceof Boolean ? (Boolean) m : (m != null && "true".equalsIgnoreCase(String.valueOf(m)));
    }
}

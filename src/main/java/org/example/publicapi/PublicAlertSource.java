package org.example.publicapi;

import org.example.aggregation.AlertAggregationService;
import org.example.core.model.SecurityAlert;
import org.example.integration.WazuhGateway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 公网只读端点的<b>唯一数据入口</b>。
 *
 * <h3>代码层隔离（不是靠约定，靠测试）</h3>
 * 本包（{@code org.example.publicapi}）面向匿名访问者，所以它：
 * <ul>
 *   <li>只从 {@link WazuhGateway} 读<b>告警</b>（{@code mode()} / {@code recentAlerts()}），
 *       <b>不引用任何写能力</b>；</li>
 *   <li>不引用处置、审批、账号、知识库管理等任何 Bean。</li>
 * </ul>
 * 这条例外不是写在文档里的君子协定 —— {@code PublicApiIsolationTest}
 * 会扫描本包源码，出现禁用符号就直接让构建失败。
 * 原因是"以后有人为了方便顺手注入一个管理 Bean"这种事，
 * <b>不会报错、不会告警</b>，只会让匿名接口悄悄拿到写能力。
 *
 * <h3>为什么只读 Wazuh，不再读 Suricata 的 eve.json</h3>
 * 实测：服务器 2 上 Suricata 的真实告警已经由 Wazuh agent 采集进 indexer
 * （{@code rule.groups=suricata} 有 6633 条），而 {@code /var/log/suricata/eve.json}
 * 只存在于数据机本地 —— 服务机容器里读不到，读不到就会降级成内置样本。
 * 所以网络告警的正路是"跟着 indexer 一起回来"，来源判定见
 * {@code WazuhService} 里的来源分类逻辑。
 *
 * <h3>fail-closed</h3>
 * 数据源不是 REAL 时，本类返回<b>空列表</b>，绝不返回内置样本。
 * 公网页面上宁可显示"数据源不可用"，也不能把伪造的告警当成真实攻击记录展示。
 */
@Component
public class PublicAlertSource {

    private static final Logger logger = LoggerFactory.getLogger(PublicAlertSource.class);

    /** 取数窗口：公网端点固定取最近这么条做聚合，避免被人用参数放大查询 */
    private static final int WINDOW = 200;

    @Autowired
    private WazuhGateway wazuhGateway;

    @Autowired
    private AlertAggregationService aggregator;

    /** 数据源当前模式（REAL / MOCK / OFF），取不到时按 MOCK 处理（不乐观假设） */
    public String mode() {
        try {
            String m = wazuhGateway.mode();
            return (m == null || m.isBlank()) ? "MOCK" : m.trim();
        } catch (Exception e) {
            logger.warn("读取告警数据源模式失败，按 MOCK 处理：{}", e.getMessage());
            return "MOCK";
        }
    }

    /** 是否为真实数据源。只有 REAL 才算。 */
    public boolean available() {
        return "REAL".equalsIgnoreCase(mode());
    }

    /**
     * 读取原始告警（仅 REAL 时）。
     *
     * @return 告警列表；非 REAL 或读取异常时返回空列表（fail-closed，不返回样本）
     */
    public List<SecurityAlert> readAlerts() {
        if (!available()) {
            logger.info("公网只读端点：数据源为 {}，返回空数据（不展示内置样本）", mode());
            return new ArrayList<>();
        }
        try {
            List<SecurityAlert> list = wazuhGateway.recentAlerts(WINDOW);
            return list == null ? new ArrayList<>() : list;
        } catch (Exception e) {
            logger.warn("公网只读端点取告警失败，返回空数据：{}", e.getMessage());
            return new ArrayList<>();
        }
    }

    /** 聚合去重后的告警列表（与自用界面同一套聚合口径，避免两个页面数字对不上） */
    public List<Map<String, Object>> aggregated() {
        return aggregator.aggregate(readAlerts());
    }

    /**
     * 近 24 小时告警概览（按时间范围聚合，不受"最新 N 条"取数窗口影响）。
     *
     * <p>数据源不可用时返回 {@code {available:false}}，由前端显示"数据源不可用"，
     * 绝不用 0 冒充"这段时间没有严重告警"。
     */
    public Map<String, Object> summary24h() {
        try {
            Map<String, Object> m = wazuhGateway.summary24h();
            return m == null ? new java.util.LinkedHashMap<>() : m;
        } catch (Exception e) {
            logger.warn("公网只读端点读取 24h 概览失败：{}", e.getMessage());
            return new java.util.LinkedHashMap<>();
        }
    }

    public int windowSize() {
        return WINDOW;
    }

    public boolean aggregationEnabled() {
        return aggregator.isEnabled();
    }

    public int aggregationWindowMinutes() {
        return aggregator.getWindowMinutes();
    }
}

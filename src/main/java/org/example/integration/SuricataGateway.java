package org.example.integration;

import org.example.core.model.SecurityAlert;

import java.util.List;

/**
 * Suricata 对接统一入口。
 *
 * <p>架构取舍：Suricata 仅作为"网络层告警来源"，读取其 eve.json 中的 alert 事件；
 * 研判与处置仍在 SecAgent 内完成。无 eve.json 时自动降级为内置样本。
 */
public interface SuricataGateway {

    /** 是否成功读取到真实 eve.json */
    boolean isAvailable();

    /** 当前模式：REAL 读取真实 eve.json / MOCK 使用内置样本 / OFF 关闭 */
    String mode();

    /**
     * 读取近期网络告警（eve.json 中 event_type=alert 的记录）。
     *
     * @param limit 最多返回条数
     */
    List<SecurityAlert> recentNetworkAlerts(int limit);
}

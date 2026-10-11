package org.example.integration;

import org.example.core.model.ActiveResponseResult;
import org.example.core.model.RawLogLine;
import org.example.core.model.SecurityAlert;

import java.util.List;
import java.util.Map;

/**
 * Wazuh 对接统一入口（SecAgent 与 Wazuh 之间的边界）。
 *
 * <p>架构取舍：Wazuh 在本系统中只承担两个角色——"真实安全数据源"（告警/日志）
 * 与"执行封禁的手"（active-response）。所有研判、编排、护栏逻辑都在 SecAgent 内部，
 * 不放在 Wazuh 侧。
 *
 * <p>无 Wazuh 服务时，实现方必须自动降级为内置样本/Mock，保证开箱可演示。
 */
public interface WazuhGateway {

    /** 是否成功连上真实 Wazuh 服务 */
    boolean isAvailable();

    /** 当前模式：REAL 已连接真实服务 / MOCK 使用内置样本 / OFF 关闭 */
    String mode();

    /**
     * 拉取近期安全告警（对应 Wazuh JWT 登录后 GET /security/alerts 或 alerts 汇总）。
     *
     * @param limit 最多返回条数
     */
    List<SecurityAlert> recentAlerts(int limit);

    /**
     * 近 24 小时告警概览：总数、按本站四档分级计数、每小时趋势。
     *
     * <p>为什么单列一个方法：告警列表接口取的是"最新 N 条"，
     * 低危告警一刷屏，严重/高危就被挤出窗口，面板上会显示成 0 ——
     * 那是口径问题，不是真的没告警。时间窗口口径必须按时间范围聚合回答。
     *
     * @return {@code {available,total,bySeverity:{CRITICAL,HIGH,MEDIUM,LOW,INFO},trend:[{time,count}]}}；
     *         数据源不可用时 {@code available=false}，其余字段为空（不编造 0）
     */
    Map<String, Object> summary24h();

    /**
     * 日志取证检索（对应 GET 告警关联的归档日志/manager logs）。
     *
     * @param query 检索关键字（可空）
     * @param limit 最多返回条数
     */
    List<RawLogLine> forensicLogs(String query, int limit);

    /**
     * 下发主动响应（对应 PUT /active-response），例如 firewall-drop 封禁 IP。
     * 仅在配置允许且护栏校验通过后，由处置服务调用。
     *
     * @param command   Wazuh active-response 命令名（firewall-drop、win-disable-account 等）
     * @param arguments 参数（target/ip、agentid、duration 等）
     */
    ActiveResponseResult runActiveResponse(String command, Map<String, Object> arguments);
}

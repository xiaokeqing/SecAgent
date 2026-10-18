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
     * 蜜罐战报：从 indexer 取 Cowrie 告警，聚合连接/登录计数、账号口令 Top、
     * 来源分布与事件时间线。
     *
     * <p>返回<b>未脱敏</b>原始值 —— 掩码必须在公网边界（publicapi 包）做，内部界面可看完整值。
     *
     * <p><b>命令时间线当前没有数据源</b>：Wazuh 侧的蜜罐规则只覆盖
     * 连接 / 客户端版本 / 登录成功 / 登录失败，没有"命令执行"规则，
     * 因此 {@code commandsAvailable=false}，页面必须如实标注。
     */
    Map<String, Object> honeypotSummary(int size);

    /**
     * 近 24 小时<b>来源 IP 分布</b>：{@code IP → 告警条数}（indexer 侧 terms 聚合，非抽样）
     * + 带来源 IP 的告警按小时分桶 + 窗口总量。
     *
     * <h3>为什么不复用 {@link #recentAlerts(int)}</h3>
     * {@code recentAlerts} 取的是"最近 N 条"，会被低危噪声刷屏，也可能只覆盖几分钟；
     * 而"攻击来源分布"要的是整 24 小时窗口，且不该把原始日志（含 payload 与内网目的地址）
     * 搬进应用进程 —— 让 indexer 只回聚合结果，字节数从 MB 级降到 KB 级。
     * 口径与代价（TOP N 之外的长尾被截断）由 {@link GeoWindow#bucketsTruncated()} 如实暴露。
     *
     * <p>默认实现返回"不可用"：这样接口新增方法不会让既有替身/其它实现静默变成"空分布"。
     *
     * @param topN 每个来源字段取多少个 IP（上限 5000）
     */
    default org.example.geoip.GeoWindow geoWindow24h(int topN) {
        return org.example.geoip.GeoWindow.unavailable("DATA_SOURCE_UNAVAILABLE");
    }

    /**
     * <b>攻击故事线</b>：窗口内按来源 IP 汇总的各阶段计数（只读聚合，供公开故事线端点用）。
     *
     * <p>阶段口径（公开契约，见 RUNBOOK §32）：
     * <ul>
     *   <li>{@code alerts} —— 告警（排除蜜罐两类规则，避免与下面两段重复计数）；</li>
     *   <li>{@code decoyPorts} —— 诱饵端口（Dionaea，{@code rule.groups=dionaea}）；</li>
     *   <li>{@code honeypotLogins} —— 蜜罐登录事件（Cowrie 规则 100101/100102）。</li>
     * </ul>
     * 处置审计不在 indexer 里（是应用侧的留痕文件），由公开侧另外拼装。
     *
     * <p>返回形状（<b>未脱敏</b>，掩码与字段白名单必须在 publicapi 包做）：
     * <pre>
     * {available, reason, note, windowHours, indexerTotal, withSourceIp,
     *  sources:[{srcIp, alerts, decoyPorts, honeypotLogins, firstSeen, lastSeen, maxLevel, total}]}
     * </pre>
     * 默认实现返回"不可用"：接口新增方法不会让既有替身静默变成"空数据"。
     */
    default Map<String, Object> storySources(int windowHours, int topSources) {
        return Map.of("available", false, "reason", "DATA_SOURCE_UNAVAILABLE",
                "note", "网关未实现 storySources");
    }

    /**
     * <b>攻击故事线</b>：单个来源在窗口内按阶段分组的明细事件（每阶段独立限量）。
     *
     * <p>为什么不做"一条查询取全部、再在 Java 里分段"：某个阶段一旦刷屏
     * （实测单个 IP 24h 有 5.6 万条 Cowrie 事件），单条查询的 size 上限会被它吃光，
     * 另外两个阶段直接消失 —— 而页面上看不出"这一段是被挤掉的"。
     * 所以每段各自一条查询、各自一个上限，并在 {@code coverage} 里如实给出"查到了多少条"。
     *
     * <p>返回形状（<b>未脱敏</b>）：
     * <pre>
     * {available, reason, note, stages:{alerts|decoyPorts|honeypotLogins:
     *     {status, total, returned, truncated, events:[{ts, kind, summary, level, outcome}]}}}
     * </pre>
     * 默认实现返回"不可用"。
     */
    default Map<String, Object> storyEvents(String srcIp, int windowHours, int maxPerStage) {
        return Map.of("available", false, "reason", "DATA_SOURCE_UNAVAILABLE",
                "note", "网关未实现 storyEvents");
    }

    /**
     * <b>IP 画像</b>：单个来源在窗口内「告警 + 蜜罐会话」两侧的聚合（<b>未脱敏</b>）。
     *
     * <p>与 {@link #storyEvents} 的区别是"要一份能直接回答『这个 IP 干过什么』的汇总"，
     * 而不是逐条事件流：page 只需要 首末时间 / 总条数 / 按行为分类的计数 /
     * 触及过的端口 / 猜过的口令<b>结构</b> / 每次登录成功失败多少条。
     *
     * <p>返回形状（<b>未脱敏</b>；IP 与口令的处理一律在 publicapi 侧）：
     * <pre>
     * {available, reason, note, windowHours,
     *  total,                      // 精确值（track_total_hits），不是样本条数
     *  firstSeen, lastSeen,        // 索引里该来源最早/最晚一条（本地时间 yyyy-MM-dd HH:mm:ss）
     *  stages:{alerts, decoyPorts, honeypotLogins, honeypotSuccess, honeypotFailed},  // 均为精确值
     *  byKind:[{kind, count}],     // 样本口径（最近 sample 条），kind 由 rule.description 归类
     *  ports:[{port, count}],      // 样本口径：蜜罐/诱饵端口的 data.dst_port
     *  topCredentials:[{key, count}],  // 形如 "root / 123456"，<b>只允许</b>经
     *                                  // CredentialStructure 转成结构后再出海
     *  sampled, truncated}
     * </pre>
     * 默认实现返回"不可用"：接口新增方法不会让既有替身静默变成"空数据"。
     */
    default Map<String, Object> ipActivity(String srcIp, int windowHours) {
        return Map.of("available", false, "reason", "DATA_SOURCE_UNAVAILABLE",
                "note", "网关未实现 ipActivity");
    }

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

package org.example.integration;

import org.example.core.model.SecurityAlert;
import org.example.integration.suricata.FlowEvent;
import org.example.integration.suricata.Ja3Count;
import org.example.integration.suricata.PortCount;
import org.example.integration.suricata.SniCount;

import java.util.List;

/**
 * Suricata 对接统一入口。
 *
 * <p>架构取舍：Suricata 仅作为"网络层告警来源"，读取其 eve.json 中的 event_type=alert 记录；
 * 研判与处置仍在 SecAgent 内完成。无 eve.json 时自动降级为内置样本。
 *
 * <p>除了告警，eve.json 里的 flow/tls/http/dns 也是同一份连接的证据。告警只告诉你"命中了规则"，
 * 而"这台 IP 最近跟谁通过话、连的是哪个 SNI、JA3 是什么"往往才是定性时真正要看的，
 * 所以这里同时提供连接反查能力；反查无数据时返回空列表，不抛异常 —— 查不到是正常结果，不是故障。
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

    /**
     * 该 IP 作为源或目标的最近连接（新 → 旧）。
     *
     * <p>数据来自 flow/netflow 事件的环形缓冲，与告警读取的"每次重读文件"是两条独立路径：
     * 反查需要跨事件类型聚合，只能基于内存窗口做。
     *
     * @param ip    精确匹配的 IP 字面量
     * @param limit 最多返回条数
     */
    List<FlowEvent> connectionsByIp(String ip, int limit);

    /**
     * 最近 {@code minutes} 分钟内被访问最多的目标端口。
     *
     * @param minutes 时间窗（分钟）
     * @param limit   最多返回几个端口
     */
    List<PortCount> topDestPorts(int minutes, int limit);

    /** 最近 {@code minutes} 分钟内出现最多的 TLS SNI。 */
    List<SniCount> topSni(int minutes, int limit);

    /** 最近 {@code minutes} 分钟内出现最多的客户端 JA3 指纹。 */
    List<Ja3Count> ja3Stats(int minutes, int limit);
}

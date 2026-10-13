package org.example.geoip;

import java.util.List;

/**
 * 24 小时取数窗口的<b>原始聚合输入</b>（IP 计数 + 总量 + 趋势），跨层传递用。
 *
 * <h3>为什么用 terms 聚合而不是"取最近 N 条告警再本地统计"</h3>
 * 实测线上 24 小时有 <b>111,031 条</b>告警。按"最近 1000 条"取回来再本地数，
 * 一是要把几 MB 原始日志（含 payload、含内网目的地址）搬到应用进程里 ——
 * 公开端点根本不需要这些；二是取样偏差极大：24 小时里有两三个 IP 占了 99% 的条数，
 * "最近 1000 条"几乎只能看到那两个 IP，地图会退化成"一两个国家的攻击"。
 * <p>
 * 改用 indexer 侧的 terms 聚合（{@code size=topN}），拿到的是
 * <b>全窗口精确计数</b>的 TOP N 个 IP，传输量只有几十 KB，而且不搬原始日志。
 * 代价是"TOP N 之外的长尾"被 {@code sum_other_doc_count} 截断 ——
 * 这一点用 {@link #bucketsTruncated()} 如实告诉前端，不装作是完整分布。
 *
 * <p>本记录里的 {@code ipCounts} <b>只在进程内使用</b>：聚合器吃掉它，
 * 公开响应里一个 IP 都不会出现（测试会按正则断言这一点）。
 */
public record GeoWindow(boolean available,
                        String reason,
                        String note,
                        long alertsTotal24h,
                        long alertsWithSourceIp24h,
                        boolean bucketsTruncated,
                        List<GeoAggregator.IpCount> ipCounts,
                        List<GeoAggregator.TrendPoint> trend) {

    /** 不可用（链路未就绪/查询失败/未配置）——调用方据此如实降级，不返回空分布 */
    public static GeoWindow unavailable(String reason) {
        return new GeoWindow(false, reason, null, 0L, 0L, false, List.of(), List.of());
    }

    public static GeoWindow unavailable(String reason, String note) {
        return new GeoWindow(false, reason, note, 0L, 0L, false, List.of(), List.of());
    }

    /** 空窗口但数据源可用（"这段时间没有带来源 IP 的告警"不是故障） */
    public static GeoWindow empty(long alertsTotal24h) {
        return new GeoWindow(true, "NO_DATA_IN_WINDOW", null, alertsTotal24h, 0L, false, List.of(), List.of());
    }
}

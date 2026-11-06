package org.example.response;

import lombok.Data;

/**
 * 一次封禁请求的参数对象。
 *
 * <p>为什么在 blockIp 的五个位置参数之外再造一个对象：
 * 新增的两个可选维度（风险等级提示、dry-run）如果继续往后堆参数，
 * 就成了 7 个同类型的 String/Integer 位置参数 —— 调用点极易传错位，
 * 且每加一个维度都要改所有调用方。用对象后，既有 5 参入口只需构造它，
 * 新维度只在真正需要的调用点（HTTP 控制器）填。
 */
@Data
public class BlockRequest {

    /** 目标 IP（IPv4 或 IPv6） */
    private String ip;

    /** 显式封禁时长（分钟）；null 表示交给分级策略决定 */
    private Integer durationMinutes;

    /** 封禁原因/告警标题（参与攻击类型分类） */
    private String reason;

    /** 执行人或执行主体 */
    private String actor;

    /** 执行来源：手动 / 审批 / 智能体 / 自动 */
    private String source;

    /** 风险等级提示（HIGH/LOW，可空），仅在类型识别不出时参与兜底 */
    private String riskLevel;

    /**
     * 是否演练（true = 只记录本应执行的命令，不真正下发）。
     *
     * <p>注意它与全局 {@code response.dry-run} 是"或"的关系：全局开关是运维
     * "先在预发跑一圈"的手段，单次标记是智能体"先看命令对不对"的手段，
     * 任何一个为真都必须不碰真实防火墙。
     */
    private boolean dryRun;

    public static BlockRequest of(String ip, Integer durationMinutes, String reason,
                                  String actor, String source) {
        BlockRequest r = new BlockRequest();
        r.setIp(ip);
        r.setDurationMinutes(durationMinutes);
        r.setReason(reason);
        r.setActor(actor);
        r.setSource(source);
        return r;
    }
}

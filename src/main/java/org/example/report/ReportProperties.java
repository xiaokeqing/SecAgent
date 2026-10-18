package org.example.report;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * 每日日报的可配参数（前缀 {@code app.report}）。
 *
 * <h3>为什么默认关闭</h3>
 * 定时任务一旦默认开启，任何一次本地起服务都会往 {@code data/reports} 里写文件、
 * 还可能真的调一次语音合成（要花钱）。所以 {@code enabled} 默认 {@code false}：
 * 想让它跑，必须在配置里显式写 {@code app.report.enabled=true}——
 * 这与项目里其它"默认不碰外部世界"的开关（如 {@code app.tts.enabled}）同一套口径。
 */
@Component
@ConfigurationProperties(prefix = "app.report")
@Getter
@Setter
public class ReportProperties {

    /** 定时生成总开关（默认关：避免测试期乱跑 / 误花语音额度） */
    private boolean enabled = false;

    /** 每天生成时间（6 段 cron，默认 08:10） */
    private String dailyCron = "0 10 8 * * *";

    /** 产物目录（默认 {@code data/reports}，与后端 data/ 同级，不进版本库） */
    private String dir = "data/reports";

    /** 是否生成语音日报（关掉只出 md/html，仍不失败） */
    private boolean audioEnabled = true;

    /** 语音稿字数上限（日语口语稿；与 {@code app.tts.max-chars} 独立，取更小者） */
    private int speechMaxChars = 120;

    /** 日报归属日所用时区（cron 依赖宿主机时区，这里只用于文件名与窗口标注） */
    private String zone = "Asia/Shanghai";
}

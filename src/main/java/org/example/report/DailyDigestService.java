package org.example.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 每日安全日报生成器：<b>取数 → Markdown + HTML → 语音稿（可选合成）→ 邮件（可选真发）</b>。
 *
 * <h3>三条不可退让的规则</h3>
 * <ol>
 *   <li><b>每个数字都带出处</b>：出处来自 {@link DigestMetrics#sources()}，渲染时逐行打印。
 *       取不到就写 {@code null} 并进「缺数据」——用 0 顶替"没取到"是本类最不能犯的错；</li>
 *   <li><b>语音不是必需品</b>：合成失败只记日志（{@code audio=null}），日报本体照常产出。
 *       反过来，语音生成的异常把整份日报拖垮，就等于"因为念不出来，所以今天没有日报"；</li>
 *   <li><b>邮件不是必需品</b>：见 {@link MailSenderService}，配置不全只落 {@code .eml}。</li>
 * </ol>
 *
 * <h3>为什么产物里多一份 {@code .json}</h3>
 * 站点 {@code /status/} 的「今日日报」卡片要读日期、告警总数、Top1 来源与两个链接。
 * 让它去解析 HTML/Markdown 是错的方向（一改排版卡片就瞎）；写一份机读清单，
 * 卡片的失败模式就退化成"清单里 {@code available=false}"——
 * 于是页面能区分「日报没生成」与「其它数据读不到」，这正是任务要求的措辞。
 */
@Service
public class DailyDigestService {

    private static final Logger logger = LoggerFactory.getLogger(DailyDigestService.class);

    /** 时间戳口径：与 {@code /api/public/*} 的 {@code generatedAt} 一致 */
    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    /** 日报窗口说明（写进产物第 2 段，避免读者以为是"自然日 0 点到现在"） */
    static final String WINDOW_NOTE =
            "告警与来源国家 = 过去 24 小时（Wazuh 窗口）；蜜罐 = 最近 800 条蜜罐告警（非 24h 时间窗）；"
                    + "封禁/解封 = 全量处置留痕（不限 24h）";

    private final ReportProperties props;
    private final DigestMetricsSource source;
    private final ObjectProvider<SpeechSynthesizer> synthesizer;
    private final MailSenderService mail;
    private final ObjectMapper json = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    public DailyDigestService(ReportProperties props,
                              DigestMetricsSource source,
                              ObjectProvider<SpeechSynthesizer> synthesizer,
                              MailSenderService mail) {
        this.props = props;
        this.source = source;
        this.synthesizer = synthesizer;
        this.mail = mail;
    }

    /** 语音合成口（生产由 {@link TtsSpeechSynthesizer} 实现，测试给假实现）。 */
    @FunctionalInterface
    public interface SpeechSynthesizer {
        /** @return 音频字节（CosyVoice 为 wav） */
        byte[] synthesize(String text);

        /** 音频容器后缀（默认 wav，与 CosyVoice 一致）。 */
        default String extension() {
            return "wav";
        }
    }

    /**
     * 本次生成的产物清单。
     *
     * @param audio     音频路径；未生成 / 合成失败为 {@code null}
     * @param manifest  机读清单（{@code daily-YYYY-MM-DD.json}）
     * @param speech    日语口语稿（≤ {@code app.report.speech-max-chars}）
     * @param mail      邮件投递结果（{@code null} = 未尝试）
     */
    public record Artifacts(LocalDate day, DigestMetrics metrics, Path markdown, Path html,
                            Path audio, Path manifest, String speech, MailSenderService.Result mail) {
    }

    /**
     * 生成指定日期的一份日报（幂等：同一天重跑覆盖同名产物）。
     *
     * <p>本方法<b>不判断</b> {@code app.report.enabled}：开关只约束定时任务，
     * 手动 {@code --test} 入口与单测都要能直接调它。
     */
    public Artifacts generate(LocalDate day) {
        DigestMetrics metrics = source.collect(day);
        String markdown = renderMarkdown(metrics);
        String html = renderHtml(metrics);
        String speech = speakText(metrics, props.getSpeechMaxChars());

        Path dir = Paths.get(props.getDir());
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            throw new IllegalStateException("日报目录无法创建：" + dir, e);
        }
        Path mdPath = write(dir.resolve(fileName(day, "md")), markdown);
        Path htmlPath = write(dir.resolve(fileName(day, "html")), html);
        Path audioPath = props.isAudioEnabled() ? synthesize(day, dir, speech) : null;
        Path manifest = writeManifest(day, dir, metrics, speech, audioPath);

        MailSenderService.Result mailResult = deliver(day, markdown, html);
        logger.info("日报已生成：{}（告警 {}，Top1 来源 {}，语音 {}）", mdPath,
                metrics.alertTotal(), topCountryText(metrics),
                audioPath == null ? "未生成" : audioPath.getFileName() + " " + sizeOf(audioPath) + " 字节");
        return new Artifacts(day, metrics, mdPath, htmlPath, audioPath, manifest, speech, mailResult);
    }

    /** 定时入口：开关关着就什么都不做（连取数都不做，避免无谓的上游压力）。 */
    @Scheduled(cron = "${app.report.daily-cron:0 10 8 * * *}")
    public void runDaily() {
        if (!props.isEnabled()) {
            logger.debug("跳过每日日报：app.report.enabled=false");
            return;
        }
        LocalDate today = LocalDate.now(zone());
        try {
            generate(today);
        } catch (Exception e) {
            // 定时任务里抛异常只会进框架日志；这里主动记成 error 并带上日期，便于排障
            logger.error("每日日报生成失败（{}）：{}", today, e.getMessage(), e);
        }
    }

    private ZoneId zone() {
        try {
            return ZoneId.of(props.getZone());
        } catch (Exception e) {
            return ZoneId.systemDefault();
        }
    }

    /** 产物文件名：{@code daily-YYYY-MM-DD.<ext>}（任务指定的命名，不要改成"最新一份"之类）。 */
    public static String fileName(LocalDate day, String ext) {
        return "daily-" + day + "." + ext;
    }

    private static Path write(Path path, String content) {
        try {
            Files.writeString(path, content, StandardCharsets.UTF_8);
            return path;
        } catch (IOException e) {
            throw new IllegalStateException("写日报产物失败：" + path, e);
        }
    }

    // ------------------------------------------------------------------ 语音

    /**
     * 合成语音日报；<b>任何失败都只记日志并返回 {@code null}</b>（不使日报失败）。
     */
    private Path synthesize(LocalDate day, Path dir, String speech) {
        SpeechSynthesizer tts = synthesizer.getIfAvailable();
        if (tts == null) {
            logger.info("语音日报未生成：没有 SpeechSynthesizer（app.tts 未装配）");
            return null;
        }
        try {
            byte[] audio = tts.synthesize(speech);
            if (audio == null || audio.length == 0) {
                logger.warn("语音日报未生成：上游返回空音频");
                return null;
            }
            Path file = dir.resolve(fileName(day, tts.extension()));
            Files.write(file, audio);
            return file;
        } catch (Exception e) {
            logger.warn("语音日报合成失败（不影响日报本体）：{}", e.getMessage());
            return null;
        }
    }

    // ------------------------------------------------------------------ 渲染

    /** Markdown 渲染（表格三列：指标 / 数值 / 出处）。 */
    public static String renderMarkdown(DigestMetrics m) {
        StringBuilder sb = new StringBuilder();
        sb.append("# 安全日报 ").append(m.day()).append("\n\n");
        sb.append("生成时间：").append(m.generatedAt().format(STAMP)).append("\n\n");
        sb.append("窗口口径：").append(WINDOW_NOTE).append("\n\n");
        sb.append("> 每个数字后面都标了出处；取不到的写 `null` 并在「八、缺数据」里列明 —— 从不补数。\n\n");

        sb.append("## 一、告警总量\n\n");
        tableHeader(sb);
        row(sb, "24h 告警总数", num(m.alertTotal()), src(m, DigestMetrics.K_ALERTS));

        sb.append("\n## 二、严重度分布\n\n");
        if (m.alertsBySeverity().isEmpty()) {
            sb.append("（未取得：见「八、缺数据」）\n\n");
        } else {
            tableHeader(sb);
            for (Map.Entry<String, Long> e : m.alertsBySeverity().entrySet()) {
                row(sb, e.getKey(), num(e.getValue()), src(m, DigestMetrics.K_SEVERITY));
            }
            sb.append('\n');
        }

        sb.append("## 三、来源国家（Top ").append(m.countries().size()).append("）\n\n");
        if (m.countries().isEmpty()) {
            sb.append("（未取得：见「八、缺数据」）\n\n");
        } else {
            sb.append("| 排名 | 国家 | 告警条数 | 独立 IP | 占比 | 出处 |\n|---|---|---|---|---|---|\n");
            int i = 1;
            for (DigestMetrics.Country c : m.countries()) {
                row(sb, String.valueOf(i++), c.name() + "（" + c.code() + "）",
                        String.valueOf(c.count()), String.valueOf(c.uniqueIps()),
                        String.format(java.util.Locale.ROOT, "%.1f%%", c.sharePercent()),
                        src(m, DigestMetrics.K_COUNTRIES));
            }
            sb.append("\n带来源 IP 的 24h 告警共 ").append(num(m.sourceIpsWithGeo()))
                    .append(" 条（出处：同 /api/public/geo 的 coverage.withSourceIp）。\n\n");
        }

        sb.append("## 四、蜜罐（Cowrie）\n\n");
        if (m.honeypotConnections() == null) {
            sb.append("（未取得：见「八、缺数据」）\n\n");
        } else {
            tableHeader(sb);
            row(sb, "连接数", num(m.honeypotConnections()), src(m, DigestMetrics.K_HONEYPOT));
            row(sb, "登录尝试", num(m.honeypotLogins()), src(m, DigestMetrics.K_HONEYPOT));
            row(sb, "登录失败", num(m.honeypotLoginFails()), src(m, DigestMetrics.K_HONEYPOT));
            row(sb, "取样条数", num(m.honeypotSampled()), src(m, DigestMetrics.K_HONEYPOT));
            sb.append('\n');
        }

        sb.append("## 五、处置（封禁 / 解封）\n\n");
        if (m.blockTotal() == null) {
            sb.append("（未取得：见「八、缺数据」）\n\n");
        } else {
            tableHeader(sb);
            row(sb, "累计封禁", num(m.blockTotal()), src(m, DigestMetrics.K_BLOCKS));
            row(sb, "仍生效", num(m.blockActive()), src(m, DigestMetrics.K_BLOCKS));
            row(sb, "已解封", num(m.unblocked()), src(m, DigestMetrics.K_BLOCKS));
            row(sb, "被护栏拦截", num(m.blockedByGuard()), src(m, DigestMetrics.K_BLOCKS));
            row(sb, "成功执行动作", num(m.executedActions()), src(m, DigestMetrics.K_BLOCKS));
            sb.append('\n');
        }

        sb.append("## 六、今日最凶来源\n\n");
        DigestMetrics.IpSource worst = m.worst();
        if (worst == null) {
            sb.append("（未取得：见「八、缺数据」）\n\n");
        } else {
            sb.append("| 指标 | 数值 | 出处 |\n|---|---|---|\n");
            row(sb, "来源 IP", worst.ip(), src(m, DigestMetrics.K_TOP_SOURCE));
            row(sb, "尝试次数", String.valueOf(worst.attempts()), src(m, DigestMetrics.K_TOP_SOURCE));
            sb.append('\n');
        }

        sb.append("## 七、值得注意的一条\n\n");
        sb.append(m.notable() == null ? "未触发判定阈值（单一来源尝试 < 1000 次）。" : m.notable()).append('\n');
        if (m.notable() != null) {
            sb.append("\n出处：").append(src(m, DigestMetrics.K_NOTABLE)).append('\n');
        }
        sb.append('\n');

        sb.append("## 八、缺数据\n\n");
        if (m.missing().isEmpty()) {
            sb.append("无。本份日报所有数字均取得。\n");
        } else {
            for (String s : m.missing()) {
                sb.append("- ").append(s).append('\n');
            }
        }
        sb.append("\n---\n\n数据来源与口径同站点公开只读端点（/api/public/*）；地理库 DB-IP Lite，CC BY 4.0。\n");
        return sb.toString();
    }

    /** HTML 渲染：<b>全内联样式</b>（不引任何外部 CSS，单文件可直接打开/邮件内联）。 */
    public static String renderHtml(DigestMetrics m) {
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"utf-8\">\n");
        sb.append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n");
        sb.append("<title>安全日报 ").append(esc(m.day().toString())).append("</title>\n</head>\n");
        sb.append("<body style=\"margin:0;padding:24px;background:#f6f7f9;"
                + "font-family:-apple-system,'Segoe UI','Helvetica Neue',Arial,sans-serif;color:#1f2328;\">\n");
        sb.append("<div style=\"max-width:760px;margin:0 auto;background:#fff;border:1px solid #e3e6ea;"
                + "border-radius:10px;padding:24px 26px;\">\n");
        sb.append("<h1 style=\"margin:0 0 6px;font-size:24px;line-height:1.3;\">安全日报 ")
                .append(esc(m.day().toString())).append("</h1>\n");
        sb.append("<p style=\"margin:0 0 14px;color:#656d76;font-size:13px;\">生成时间 ")
                .append(esc(m.generatedAt().format(STAMP))).append("</p>\n");
        sb.append("<p style=\"margin:0 0 18px;padding:10px 12px;background:#f6f8fa;border-left:3px solid #d0d7de;"
                + "font-size:13px;color:#424a53;\">窗口口径：").append(esc(WINDOW_NOTE)).append("</p>\n");
        sb.append("<p style=\"margin:0 0 18px;font-size:13px;color:#656d76;\">每个数字后面都标了出处；"
                + "取不到的写 <code>null</code> 并在「八、缺数据」里列明 —— 从不补数。</p>\n");

        section(sb, "一、告警总量");
        sb.append(tableOpen());
        htmlRow(sb, "24h 告警总数", num(m.alertTotal()), src(m, DigestMetrics.K_ALERTS));
        sb.append("</table>\n");

        section(sb, "二、严重度分布");
        if (m.alertsBySeverity().isEmpty()) {
            emptyNote(sb);
        } else {
            sb.append(tableOpen());
            for (Map.Entry<String, Long> e : m.alertsBySeverity().entrySet()) {
                htmlRow(sb, e.getKey(), num(e.getValue()), src(m, DigestMetrics.K_SEVERITY));
            }
            sb.append("</table>\n");
        }

        section(sb, "三、来源国家（Top " + m.countries().size() + "）");
        if (m.countries().isEmpty()) {
            emptyNote(sb);
        } else {
            sb.append("<table style=\"").append(TABLE_STYLE).append("\"><thead><tr>");
            for (String h : List.of("排名", "国家", "告警条数", "独立 IP", "占比", "出处")) {
                sb.append("<th style=\"").append(TH_STYLE).append("\">").append(esc(h)).append("</th>");
            }
            sb.append("</tr></thead><tbody>");
            int i = 1;
            for (DigestMetrics.Country c : m.countries()) {
                sb.append("<tr>");
                cell(sb, String.valueOf(i++));
                cell(sb, c.name() + "（" + c.code() + "）");
                cell(sb, String.valueOf(c.count()));
                cell(sb, String.valueOf(c.uniqueIps()));
                cell(sb, String.format(java.util.Locale.ROOT, "%.1f%%", c.sharePercent()));
                cell(sb, src(m, DigestMetrics.K_COUNTRIES));
                sb.append("</tr>");
            }
            sb.append("</tbody></table>\n");
            sb.append("<p style=\"margin:8px 0 0;font-size:13px;color:#656d76;\">带来源 IP 的 24h 告警共 ")
                    .append(esc(num(m.sourceIpsWithGeo())))
                    .append(" 条（出处：同 /api/public/geo 的 coverage.withSourceIp）。</p>\n");
        }

        section(sb, "四、蜜罐（Cowrie）");
        if (m.honeypotConnections() == null) {
            emptyNote(sb);
        } else {
            sb.append(tableOpen());
            htmlRow(sb, "连接数", num(m.honeypotConnections()), src(m, DigestMetrics.K_HONEYPOT));
            htmlRow(sb, "登录尝试", num(m.honeypotLogins()), src(m, DigestMetrics.K_HONEYPOT));
            htmlRow(sb, "登录失败", num(m.honeypotLoginFails()), src(m, DigestMetrics.K_HONEYPOT));
            htmlRow(sb, "取样条数", num(m.honeypotSampled()), src(m, DigestMetrics.K_HONEYPOT));
            sb.append("</table>\n");
        }

        section(sb, "五、处置（封禁 / 解封）");
        if (m.blockTotal() == null) {
            emptyNote(sb);
        } else {
            sb.append(tableOpen());
            htmlRow(sb, "累计封禁", num(m.blockTotal()), src(m, DigestMetrics.K_BLOCKS));
            htmlRow(sb, "仍生效", num(m.blockActive()), src(m, DigestMetrics.K_BLOCKS));
            htmlRow(sb, "已解封", num(m.unblocked()), src(m, DigestMetrics.K_BLOCKS));
            htmlRow(sb, "被护栏拦截", num(m.blockedByGuard()), src(m, DigestMetrics.K_BLOCKS));
            htmlRow(sb, "成功执行动作", num(m.executedActions()), src(m, DigestMetrics.K_BLOCKS));
            sb.append("</table>\n");
        }

        section(sb, "六、今日最凶来源");
        DigestMetrics.IpSource worst = m.worst();
        if (worst == null) {
            emptyNote(sb);
        } else {
            sb.append(tableOpen());
            htmlRow(sb, "来源 IP", worst.ip(), src(m, DigestMetrics.K_TOP_SOURCE));
            htmlRow(sb, "尝试次数", String.valueOf(worst.attempts()), src(m, DigestMetrics.K_TOP_SOURCE));
            sb.append("</table>\n");
        }

        section(sb, "七、值得注意的一条");
        sb.append("<p style=\"margin:0;font-size:14px;line-height:1.7;\">")
                .append(esc(m.notable() == null ? "未触发判定阈值（单一来源尝试 < 1000 次）。" : m.notable()))
                .append("</p>\n");
        if (m.notable() != null) {
            sb.append("<p style=\"margin:6px 0 0;font-size:12px;color:#8b949e;\">出处：")
                    .append(esc(src(m, DigestMetrics.K_NOTABLE))).append("</p>\n");
        }

        section(sb, "八、缺数据");
        if (m.missing().isEmpty()) {
            sb.append("<p style=\"margin:0;font-size:14px;\">无。本份日报所有数字均取得。</p>\n");
        } else {
            sb.append("<ul style=\"margin:0;padding-left:20px;font-size:13px;line-height:1.8;color:#424a53;\">\n");
            for (String s : m.missing()) {
                sb.append("<li>").append(esc(s)).append("</li>\n");
            }
            sb.append("</ul>\n");
        }

        sb.append("<hr style=\"margin:22px 0 12px;border:0;border-top:1px solid #e3e6ea;\">\n");
        sb.append("<p style=\"margin:0;font-size:12px;color:#8b949e;\">数据来源与口径同站点公开只读端点"
                + "（/api/public/*）；地理库 DB-IP Lite，CC BY 4.0。</p>\n");
        sb.append("</div>\n</body>\n</html>\n");
        return sb.toString();
    }

    private static final String TABLE_STYLE =
            "width:100%;border-collapse:collapse;margin:0 0 4px;font-size:13px;";
    private static final String TH_STYLE =
            "text-align:left;padding:7px 9px;background:#f6f8fa;border:1px solid #e3e6ea;"
                    + "font-weight:600;color:#424a53;white-space:nowrap;";
    private static final String TD_STYLE =
            "padding:7px 9px;border:1px solid #e3e6ea;vertical-align:top;";
    private static final String TD_SRC_STYLE =
            "padding:7px 9px;border:1px solid #e3e6ea;vertical-align:top;color:#8b949e;font-size:12px;";

    private static String tableOpen() {
        return "<table style=\"" + TABLE_STYLE + "\"><thead><tr>"
                + "<th style=\"" + TH_STYLE + "\">指标</th>"
                + "<th style=\"" + TH_STYLE + "\">数值</th>"
                + "<th style=\"" + TH_STYLE + "\">出处</th>"
                + "</tr></thead><tbody>";
    }

    private static void section(StringBuilder sb, String title) {
        sb.append("<h2 style=\"margin:22px 0 8px;font-size:16px;line-height:1.4;\">")
                .append(esc(title)).append("</h2>\n");
    }

    private static void emptyNote(StringBuilder sb) {
        sb.append("<p style=\"margin:0;font-size:13px;color:#8b949e;\">（未取得：见「八、缺数据」）</p>\n");
    }

    private static void cell(StringBuilder sb, String text) {
        sb.append("<td style=\"").append(TD_STYLE).append("\">").append(esc(text)).append("</td>");
    }

    private static void htmlRow(StringBuilder sb, String k, String v, String src) {
        sb.append("<tr>");
        cell(sb, k);
        cell(sb, v);
        sb.append("<td style=\"").append(TD_SRC_STYLE).append("\">").append(esc(src)).append("</td>");
        sb.append("</tr>");
    }

    private static void tableHeader(StringBuilder sb) {
        sb.append("| 指标 | 数值 | 出处 |\n|---|---|---|\n");
    }

    /** Markdown 表格一行：列数随表头走（告警是 3 列，国家榜是 6 列）。 */
    private static void row(StringBuilder sb, String... cells) {
        sb.append('|');
        for (String c : cells) {
            sb.append(c).append('|');
        }
        sb.append('\n');
    }

    private static String src(DigestMetrics m, String key) {
        String v = m.sources().get(key);
        return v == null ? "未标注出处" : v;
    }

    /** 可缺数字的统一写法：{@code null} 原样写成 {@code null}（不写 0、不写"—"）。 */
    static String num(Number v) {
        return v == null ? "null" : String.valueOf(v.longValue());
    }

    static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    // ------------------------------------------------------------------ 语音稿

    /**
     * 日语口语稿（≤ {@code maxChars}）：只念<b>能负责</b>的数字，缺的部分明说"没取到"。
     *
     * <p>句子级拼装而不是模板填空：超字数时按"重要度"从尾部丢句
     * （收尾语 → 最凶来源 → 蜜罐 → 国家），保证前两句（问候 + 告警总数）永远在。
     * 硬截断只作为最后兜底，因为截断会切掉词尾，听起来像被打断。
     */
    public static String speakText(DigestMetrics m, int maxChars) {
        int cap = Math.max(30, maxChars);
        List<String> sentences = new ArrayList<>();
        sentences.add("おはようございます。過去24時間のセキュリティダイジェストです。");
        sentences.add(m.alertTotal() == null
                ? "アラート数は取得できませんでした。"
                : "アラートは" + m.alertTotal() + "件でした。");
        DigestMetrics.Country top = m.topCountry();
        if (top != null) {
            sentences.add("最多の発生源は" + jaCountry(top.code()) + "です。");
        }
        if (m.honeypotConnections() != null) {
            sentences.add("ハニーポットへの接続は" + m.honeypotConnections() + "件。");
        }
        DigestMetrics.IpSource worst = m.worst();
        if (worst != null) {
            sentences.add("単一の接続元からの最大試行は" + worst.attempts() + "回です。");
        }
        sentences.add("引き続き監視します。");

        StringBuilder sb = new StringBuilder();
        for (String s : sentences) {
            if (sb.length() + s.length() <= cap) {
                sb.append(s);
            }
        }
        if (sb.length() == 0) {
            // 极端兜底：连问候语都放不下时，截断它（保证非空且不超限）
            String head = sentences.get(0);
            return head.substring(0, Math.min(head.length(), cap));
        }
        return sb.toString();
    }

    /** ISO 国家码 → 日语国名（口语稿里不出现拉丁字母，避免 TTS 把 "US" 念成字母串）。 */
    static String jaCountry(String code) {
        if (code == null) {
            return "不明な地域";
        }
        return switch (code.toUpperCase(java.util.Locale.ROOT)) {
            case "US" -> "アメリカ";
            case "CN" -> "中国";
            case "RU" -> "ロシア";
            case "NL" -> "オランダ";
            case "BR" -> "ブラジル";
            case "DE" -> "ドイツ";
            case "FR" -> "フランス";
            case "IN" -> "インド";
            case "JP" -> "日本";
            case "KR" -> "韓国";
            case "SG" -> "シンガポール";
            case "VN" -> "ベトナム";
            case "ID" -> "インドネシア";
            case "GB" -> "イギリス";
            case "TW" -> "台湾";
            case "HK" -> "香港";
            case "TH" -> "タイ";
            case "UA" -> "ウクライナ";
            case "TR" -> "トルコ";
            case "PL" -> "ポーランド";
            case "SE" -> "スウェーデン";
            case "CA" -> "カナダ";
            case "AU" -> "オーストラリア";
            default -> "海外";
        };
    }

    // ------------------------------------------------------------------ 清单 / 邮件

    /** 机读清单：{@code /status/} 卡片与 {@code /api/public/daily.js} 都读它。 */
    private Path writeManifest(LocalDate day, Path dir, DigestMetrics m, String speech, Path audio) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("date", day.toString());
        map.put("generatedAt", m.generatedAt().format(STAMP));
        map.put("window", WINDOW_NOTE);
        map.put("available", true);
        map.put("alertTotal", m.alertTotal());
        map.put("alertsBySeverity", m.alertsBySeverity());

        DigestMetrics.Country top = m.topCountry();
        Map<String, Object> country = new LinkedHashMap<>();
        country.put("code", top == null ? null : top.code());
        country.put("name", top == null ? null : top.name());
        country.put("count", top == null ? null : top.count());
        country.put("uniqueIps", top == null ? null : top.uniqueIps());
        map.put("topCountry", country);

        List<Map<String, Object>> countries = new ArrayList<>();
        for (DigestMetrics.Country c : m.countries()) {
            Map<String, Object> one = new LinkedHashMap<>();
            one.put("code", c.code());
            one.put("name", c.name());
            one.put("count", c.count());
            one.put("uniqueIps", c.uniqueIps());
            one.put("sharePercent", c.sharePercent());
            countries.add(one);
        }
        map.put("countries", countries);

        Map<String, Object> honeypot = new LinkedHashMap<>();
        honeypot.put("connections", m.honeypotConnections());
        honeypot.put("logins", m.honeypotLogins());
        honeypot.put("loginFails", m.honeypotLoginFails());
        honeypot.put("sampled", m.honeypotSampled());
        map.put("honeypot", honeypot);

        Map<String, Object> blocks = new LinkedHashMap<>();
        blocks.put("total", m.blockTotal());
        blocks.put("active", m.blockActive());
        blocks.put("unblocked", m.unblocked());
        blocks.put("blockedByGuard", m.blockedByGuard());
        blocks.put("executedActions", m.executedActions());
        map.put("blocks", blocks);

        DigestMetrics.IpSource worst = m.worst();
        Map<String, Object> worstMap = new LinkedHashMap<>();
        worstMap.put("ip", worst == null ? null : worst.ip());
        worstMap.put("attempts", worst == null ? null : worst.attempts());
        map.put("worstSource", worstMap);

        map.put("notable", m.notable());
        map.put("speech", speech);
        map.put("speechChars", speech.length());

        Map<String, Object> files = new LinkedHashMap<>();
        files.put("markdown", fileName(day, "md"));
        files.put("html", fileName(day, "html"));
        files.put("audio", audio == null ? null : audio.getFileName().toString());
        map.put("files", files);

        map.put("sources", m.sources());
        map.put("missing", m.missing());

        try {
            return write(dir.resolve(fileName(day, "json")), json.writeValueAsString(map) + "\n");
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("日报清单序列化失败", e);
        }
    }

    private MailSenderService.Result deliver(LocalDate day, String markdown, String html) {
        try {
            return mail.deliver(day, mail.subject(day), markdown, html);
        } catch (Exception e) {
            logger.warn("日报邮件投递失败（不影响日报本体）：{}", e.getMessage());
            return null;
        }
    }

    private static String topCountryText(DigestMetrics m) {
        DigestMetrics.Country c = m.topCountry();
        return c == null ? "null" : c.name() + "(" + c.code() + ")";
    }

    private static long sizeOf(Path p) {
        try {
            return Files.size(p);
        } catch (IOException e) {
            return -1;
        }
    }
}

package org.example.report;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 日报生成器测试：<b>6 条</b>，全部不连 Wazuh / 不连 SMTP / 不调 TTS 上游。
 *
 * <p>构造方式：{@link DailyDigestService} 只依赖四个口（配置、取数、语音、邮件），
 * 前三个在测试里都是固定输入，邮件用"未配置"这一真实分支（落 .eml）。
 * 这样断言的是<b>产物字节</b>，不是内部调用次数 —— 日报的价值在产出物。
 */
class DailyDigestServiceTest {

    private static final LocalDate DAY = LocalDate.of(2026, 10, 19);
    private static final byte[] FAKE_WAV = "RIFF____WAVEfmt ".getBytes(StandardCharsets.US_ASCII);

    /** 一份"全部取到"的输入：数字刻意写成互不相同，避免断错行也能过。 */
    private static DigestMetrics fullMetrics() {
        Map<String, Long> sev = new LinkedHashMap<>();
        sev.put("CRITICAL", 7L);
        sev.put("HIGH", 23L);
        sev.put("MEDIUM", 41L);
        sev.put("LOW", 66L);
        return DigestMetrics.builder(DAY)
                .generatedAt(LocalDateTime.of(2026, 10, 19, 8, 10, 0))
                .alerts(137L, sev, "WazuhService.summary24h()（windowHours=24）")
                .countries(118L, List.of(
                        new DigestMetrics.Country("NL", "荷兰", 52, 19, 38.0),
                        new DigestMetrics.Country("US", "美国", 31, 12, 22.6),
                        new DigestMetrics.Country("RU", "俄罗斯", 21, 9, 15.3)),
                        "GeoAggregator.aggregate(geoWindow24h(24h))")
                .honeypot(4821, 913, 878, 800, "WazuhService.honeypotSummary(800)（最近 800 条 Cowrie 告警）")
                .blocks(64, 11, 2, 58, "PublicAuditReader.summary()（全量处置留痕）")
                .topSources(List.of(new DigestMetrics.IpSource("45.205.1.77", 1382),
                        new DigestMetrics.IpSource("103.9.44.2", 410)),
                        "WazuhService.honeypotSummary(800).topSources")
                .notable("45.205.1.77 在窗口内尝试 1382 次（阈值 1000）",
                        "同上（topSources[0].count ≥ 1000）")
                .build();
    }

    /** 一份"全都没取到"的输入：只能来自 builder 的缺口登记，不能伪造 0。 */
    private static DigestMetrics emptyMetrics() {
        return DigestMetrics.builder(DAY)
                .generatedAt(LocalDateTime.of(2026, 10, 19, 8, 10, 0))
                .alerts(null, null, null)
                .countries(null, List.of(), null)
                .honeypot(null, null, null, null, null)
                .blocks(null, null, null, null, null)
                .topSources(List.of(), null)
                .build();
    }

    private static ReportProperties props(Path dir) {
        ReportProperties p = new ReportProperties();
        p.setDir(dir.toString());
        p.setSpeechMaxChars(120);
        p.setAudioEnabled(true);
        return p;
    }

    private static ObjectProvider<DailyDigestService.SpeechSynthesizer> speaker(
            DailyDigestService.SpeechSynthesizer impl) {
        DefaultListableBeanFactory bf = new DefaultListableBeanFactory();
        if (impl != null) {
            bf.registerSingleton("speaker", impl);
        }
        return bf.getBeanProvider(DailyDigestService.SpeechSynthesizer.class);
    }

    private static DailyDigestService service(Path dir, DigestMetrics metrics,
                                              DailyDigestService.SpeechSynthesizer impl) {
        MailProperties mp = new MailProperties();
        mp.setOutboxDir(dir.resolve("outbox").toString());
        return new DailyDigestService(props(dir), day -> metrics, speaker(impl), new MailSenderService(mp));
    }

    // ---------------------------------------------------------------- 1. 正常汇总

    @Test
    void normalRunRendersEveryNumberWithItsSource(@TempDir Path dir) throws Exception {
        DailyDigestService svc = service(dir, fullMetrics(), text -> FAKE_WAV);
        DailyDigestService.Artifacts a = svc.generate(DAY);

        String md = Files.readString(a.markdown(), StandardCharsets.UTF_8);
        String html = Files.readString(a.html(), StandardCharsets.UTF_8);

        // 真实数字都在，且都在"带出处"的表格行里
        assertTrue(md.contains("|24h 告警总数|137|"), md);
        assertTrue(md.contains("WazuhService.summary24h()"), md);
        assertTrue(md.contains("|荷兰（NL）|52|19|38.0%|"), md);
        assertTrue(md.contains("|连接数|4821|"), md);
        assertTrue(md.contains("|已解封|53|"), "解封数 = 64 - 11，应由两个已取到的数字算出：" + md);
        assertTrue(md.contains("|来源 IP|45.205.1.77|"), md);
        assertTrue(md.contains("|尝试次数|1382|"), md);
        assertTrue(md.contains("1382 次（阈值 1000）"), md);
        // 全部取到时不该出现"缺数据"
        assertTrue(md.contains("无。本份日报所有数字均取得。"), md);
        assertFalse(md.contains("（未取得：见「八、缺数据」）"), md);

        // HTML 同源数据：内联样式、不引外部资源
        assertTrue(html.contains("137"), html);
        assertFalse(html.contains("<link"), "HTML 不许引外部 CSS");
        assertFalse(html.contains("<script"), "HTML 不许带脚本");
        assertFalse(html.contains("src=\"http"), html);
    }

    // ---------------------------------------------------------------- 2. 缺数据

    @Test
    void missingDataWritesNullAndListsGapsWithoutThrowing(@TempDir Path dir) throws Exception {
        DailyDigestService svc = service(dir, emptyMetrics(), text -> FAKE_WAV);

        DailyDigestService.Artifacts a = svc.generate(DAY); // 不抛异常就是第一层断言
        String md = Files.readString(a.markdown(), StandardCharsets.UTF_8);

        assertTrue(md.contains("|24h 告警总数|null|"), "取不到必须写 null，不能写 0：" + md);
        assertTrue(md.contains("## 八、缺数据"));
        assertTrue(md.contains("- 告警总数：stats24h 不可用"), md);
        assertTrue(md.contains("- 蜜罐连接数：蜜罐汇总不可用"), md);
        assertTrue(md.contains("- 封禁/解封数：处置审计留痕不可用"), md);
        assertTrue(md.contains("- 最凶来源 IP：蜜罐样本里没有来源地址计数"), md);
        assertFalse(md.contains("无。本份日报所有数字均取得。"));
        // 语音稿也要明说"没取到"，而不是念 0
        assertTrue(a.speech().contains("取得できませんでした"), a.speech());
    }

    // ---------------------------------------------------------------- 3. 双产物 + 语音 + 清单

    @Test
    void writesMarkdownHtmlAudioAndManifestWithDateNames(@TempDir Path dir) throws Exception {
        DailyDigestService svc = service(dir, fullMetrics(), text -> FAKE_WAV);
        DailyDigestService.Artifacts a = svc.generate(DAY);

        assertEquals("daily-2026-10-19.md", a.markdown().getFileName().toString());
        assertEquals("daily-2026-10-19.html", a.html().getFileName().toString());
        assertEquals("daily-2026-10-19.wav", a.audio().getFileName().toString());
        assertEquals("daily-2026-10-19.json", a.manifest().getFileName().toString());
        assertArrayEqualsBytes(FAKE_WAV, Files.readAllBytes(a.audio()));

        String manifest = Files.readString(a.manifest(), StandardCharsets.UTF_8);
        assertTrue(manifest.contains("\"date\" : \"2026-10-19\""), manifest);
        assertTrue(manifest.contains("\"alertTotal\" : 137"), manifest);
        assertTrue(manifest.contains("\"available\" : true"), manifest);
        assertTrue(manifest.contains("\"audio\" : \"daily-2026-10-19.wav\""), manifest);
        assertTrue(manifest.contains("\"name\" : \"荷兰\""), manifest);
        // 语音稿：≤120 字、纯日语（无拉丁字母，避免 TTS 念字母串）
        assertTrue(a.speech().length() <= 120, "口语稿超长：" + a.speech().length());
        assertFalse(a.speech().matches(".*[A-Za-z].*"), "口语稿含拉丁字母：" + a.speech());
        assertTrue(a.speech().contains("137件"));
    }

    // ---------------------------------------------------------------- 4. 语音失败不拖垮日报

    @Test
    void ttsFailureLeavesDigestIntactAndAudioNull(@TempDir Path dir) throws Exception {
        DailyDigestService svc = service(dir, fullMetrics(), text -> {
            throw new IllegalStateException("上游 502");
        });

        DailyDigestService.Artifacts a = svc.generate(DAY);

        assertNull(a.audio(), "合成失败时 audio 必须是 null（产物清单里写 null，不写一个空文件）");
        assertTrue(Files.exists(a.markdown()));
        assertTrue(Files.readString(a.markdown(), StandardCharsets.UTF_8).contains("137"));
        assertFalse(Files.exists(dir.resolve("daily-2026-10-19.wav")), "失败不许留半截音频");
        assertTrue(Files.readString(a.manifest(), StandardCharsets.UTF_8).contains("\"audio\" : null"));
    }

    // ---------------------------------------------------------------- 5. 命名按日期

    @Test
    void fileNameIsStampedWithTheDayItBelongsTo(@TempDir Path dir) throws Exception {
        DailyDigestService svc = service(dir, fullMetrics(), text -> FAKE_WAV);

        assertEquals("daily-2026-10-19.md", DailyDigestService.fileName(DAY, "md"));
        assertEquals("daily-2026-10-20.html", DailyDigestService.fileName(DAY.plusDays(1), "html"));
        assertEquals("daily-2026-02-03.wav", DailyDigestService.fileName(LocalDate.of(2026, 2, 3), "wav"));

        // 同一天重跑覆盖、不堆积；另一天并存
        svc.generate(DAY);
        svc.generate(DAY);
        svc.generate(DAY.plusDays(1));
        try (var s = Files.list(dir)) {
            long dailies = s.map(p -> p.getFileName().toString())
                    .filter(n -> n.startsWith("daily-"))
                    .count();
            assertEquals(8, dailies, "两天各 4 个产物（md/html/wav/json），重跑覆盖");
        }
    }

    // ---------------------------------------------------------------- 6. 邮件降级

    @Test
    void mailWithoutConfigWritesEmlAndSaysSo(@TempDir Path dir) throws Exception {
        DailyDigestService svc = service(dir, fullMetrics(), text -> FAKE_WAV);
        DailyDigestService.Artifacts a = svc.generate(DAY);

        assertNotNull(a.mail(), "日报总会尝试投递，结果必须是可读的（不是 null）");
        assertEquals(MailSenderService.Mode.EML, a.mail().mode());
        assertTrue(a.mail().note().startsWith("未配置 SMTP：已落盘 .eml"), a.mail().note());
        assertTrue(a.mail().missing().contains("app.mail.host"), "要能说清缺哪几项：" + a.mail().missing());

        Path eml = a.mail().file();
        assertNotNull(eml);
        assertTrue(Files.exists(eml), "应落到 outbox：" + eml);
        assertEquals("daily-2026-10-19.eml", eml.getFileName().toString());
        String raw = Files.readString(eml, StandardCharsets.UTF_8);
        assertTrue(raw.contains("Subject: =?UTF-8?B?"), "标题要用 RFC 2047 编码（含中文）：" + raw.substring(0, 200));
        assertTrue(raw.contains("Content-Type: text/plain; charset=UTF-8"), raw);
        // 正文是 base64（76 字符换行），解出来才是人读的 Markdown
        String plainB64 = between(raw,
                "Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n",
                "\r\n--=");
        String plain = new String(java.util.Base64.getMimeDecoder().decode(plainB64), StandardCharsets.UTF_8);
        assertTrue(plain.contains("安全日报 2026-10-19"), "正文应带 Markdown 原文：" + plain.substring(0, 80));
        assertTrue(plain.contains("|24h 告警总数|137|"), plain);
    }

    /** 取 {@code raw} 中 {@code from} 之后、{@code to} 之前的一段（找不到就返回空串，让断言自己失败）。 */
    private static String between(String raw, String from, String to) {
        int i = raw.indexOf(from);
        if (i < 0) {
            return "";
        }
        int start = i + from.length();
        int end = raw.indexOf(to, start);
        return end < 0 ? raw.substring(start) : raw.substring(start, end);
    }

    private static void assertArrayEqualsBytes(byte[] expected, byte[] actual) {
        assertEquals(expected.length, actual.length);
        for (int i = 0; i < expected.length; i++) {
            assertEquals(expected[i], actual[i], "第 " + i + " 字节不一致");
        }
    }
}

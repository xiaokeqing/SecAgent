package org.example.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.publicapi.PublicIpPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 日报的<b>公开只读出口</b>：给站点 {@code /status/} 的「今日日报」卡片取数，并托管交付物本身。
 *
 * <h3>为什么不用静态目录</h3>
 * 产物在 {@code data/reports}（运行时目录），不在 {@code src/main/resources/static} 里，
 * 而且文件名带日期。用一个极窄的控制器（只认 {@code daily-YYYY-MM-DD.<白名单后缀>}）
 * 比把整个目录挂成静态资源安全得多：目录挂出去，哪天有人在里面塞个 {@code index.html}
 * 就多出一个可写内容面。
 *
 * <h3>卡片需要区分两种"没有"</h3>
 * <ul>
 *   <li>{@code available=false, reason=not_generated} —— 今天还没生成（页面写"未生成"）；</li>
 *   <li>请求本身失败 —— 那是"读不到其它数据"，页面用另一句话。</li>
 * </ul>
 * 这两种情况在站点上必须长得不一样，否则一次后端重启会被读成"今天没有安全事件"。
 */
@RestController
@RequestMapping("/api/public")
public class DailyReportController {

    private static final Logger logger = LoggerFactory.getLogger(DailyReportController.class);

    /** 交付物文件名白名单：日期 + 已知后缀。放宽一个字符就等于开放整个目录。 */
    private static final Pattern NAME = Pattern.compile("^daily-\\d{4}-\\d{2}-\\d{2}\\.(?:html|md|wav|mp3|json)$");
    private static final Set<String> TEXT_SUFFIX = Set.of("html", "md", "json");
    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final ReportProperties props;
    private final PublicIpPolicy policy;
    private final ObjectMapper json = new ObjectMapper();

    public DailyReportController(ReportProperties props, PublicIpPolicy policy) {
        this.props = props;
        this.policy = policy;
    }

    /**
     * 今日日报的机读摘要。没生成时也返回 200 + {@code available=false}：
     * 让卡片能说"今日日报未生成（不是读不到其它数据）"，而不是把整张卡变成错误态。
     */
    @GetMapping("/daily.js")
    public ResponseEntity<Map<String, Object>> latest() {
        LocalDate today = LocalDate.now(zone());
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("generatedAt", LocalDateTime.now().format(STAMP));
        body.put("cacheSeconds", 60);
        body.put("date", today.toString());
        body.put("window", DailyDigestService.WINDOW_NOTE);

        Path manifest = reportDir().resolve(DailyDigestService.fileName(today, "json"));
        if (!Files.isReadable(manifest)) {
            body.put("available", false);
            body.put("reason", "not_generated");
            body.put("note", "今日日报未生成（不是读不到其它数据）");
            body.putAll(policy.disclosure());
            return ResponseEntity.ok().cacheControl(CacheControl.maxAge(Duration.ofSeconds(60))).body(body);
        }
        try {
            JsonNode node = json.readTree(Files.readString(manifest));
            body.put("available", true);
            body.put("alertTotal", num(node.get("alertTotal")));
            body.put("alertsBySeverity", json.convertValue(node.path("alertsBySeverity"), Map.class));
            body.put("topCountry", json.convertValue(node.path("topCountry"), Map.class));
            body.put("honeypot", json.convertValue(node.path("honeypot"), Map.class));

            // 最凶来源：IP 走与其它公开端点相同的口径（掩码态 / 真实态由 PublicIpPolicy 一处决定）
            JsonNode worst = node.path("worstSource");
            Map<String, Object> w = new LinkedHashMap<>();
            String ip = text(worst.get("ip"));
            w.put("ip", ip == null ? null : policy.display(ip));
            w.put("attempts", num(worst.get("attempts")));
            body.put("worstSource", w);

            body.put("speechChars", node.path("speechChars").asInt());
            body.put("files", files(today, node));
            body.put("note", node.path("missing").isArray() && !node.path("missing").isEmpty()
                    ? "本份日报有缺数据项，详见 HTML 的「八、缺数据」" : null);
        } catch (IOException | RuntimeException e) {
            logger.warn("日报清单读取失败，按未生成处理：{}", e.getMessage());
            body.put("available", false);
            body.put("reason", "manifest_unreadable");
            body.put("note", "今日日报清单损坏（不是读不到其它数据）");
        }
        body.putAll(policy.disclosure());
        return ResponseEntity.ok().cacheControl(CacheControl.maxAge(Duration.ofSeconds(60))).body(body);
    }

    /**
     * 归档索引：一次请求回答「有哪些天留下了日报」。
     *
     * <h3>为什么不是让前端按日期试探</h3>
     * 站点的 {@code /daily/} 栏目要"往前翻"。没有这个端点时，浏览器只能对最近 30 天逐个发
     * {@code /daily/daily-<日期>.json}：① 公网端点有 20 次/分钟的限流，30 个请求会互相踩；
     * ② 限流失败与"那天没生成"在直线上长得一样，页面只能说"未生成"，而那是两件不同的事。
     * 把"有没有"交给服务端回答，一次请求就够了。
     *
     * <p>只回摘要字段：归档表要的是「哪天、多少条、谁最凶」，不把 {@code speech}（日语长文本）
     * 之类的整份清单拖到浏览器上。
     */
    @GetMapping("/daily/index.json")
    public ResponseEntity<Map<String, Object>> index() {
        Path dir = reportDir();
        List<Path> found = new ArrayList<>();
        if (Files.isDirectory(dir)) {
            try (var stream = Files.list(dir)) {
                stream.filter(Files::isRegularFile)
                        .filter(p -> NAME.matcher(p.getFileName().toString()).matches())
                        .filter(p -> p.getFileName().toString().endsWith(".json"))
                        .forEach(found::add);
            } catch (IOException e) {
                logger.warn("日报归档目录读取失败：{}", e.getMessage());
            }
        }
        found.sort(Comparator.comparing((Path p) -> p.getFileName().toString()).reversed());
        List<Map<String, Object>> days = new ArrayList<>();
        for (Path p : found) {
            String name = p.getFileName().toString();
            String day = name.substring("daily-".length(), "daily-".length() + 10);
            Map<String, Object> one = new LinkedHashMap<>();
            one.put("date", day);
            try {
                JsonNode node = json.readTree(Files.readString(p));
                one.put("generatedAt", text(node.path("generatedAt")));
                one.put("alertTotal", num(node.get("alertTotal")));
                one.put("alertsBySeverity", json.convertValue(node.path("alertsBySeverity"), Map.class));
                one.put("topCountry", json.convertValue(node.path("topCountry"), Map.class));
                JsonNode worst = node.path("worstSource");
                Map<String, Object> w = new LinkedHashMap<>();
                String ip = text(worst.get("ip"));
                w.put("ip", ip == null ? null : policy.display(ip));
                w.put("attempts", num(worst.get("attempts")));
                one.put("worstSource", w);
                one.put("missingCount", node.path("missing").isArray() ? node.path("missing").size() : 0);
            } catch (IOException | RuntimeException e) {
                /* 单个清单坏了不能把整张归档表变成错误态：那一行显示「清单损坏」，其余照常 */
                logger.warn("日报清单解析失败，归档里标为不可读：{} {}", name, e.getMessage());
                one.put("reason", "unreadable");
            }
            one.put("files", files(LocalDate.parse(day)));
            days.add(one);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("generatedAt", LocalDateTime.now().format(STAMP));
        body.put("cacheSeconds", 600);
        body.put("count", days.size());
        body.put("days", days);
        body.putAll(policy.disclosure());
        return ResponseEntity.ok().cacheControl(CacheControl.maxAge(Duration.ofMinutes(10))).body(body);
    }

    /** 交付物本体（HTML / 音频 / Markdown / 清单）。名字不在白名单里一律 404，不暴露路径。 */
    @GetMapping("/daily/{name}")
    public ResponseEntity<byte[]> file(@PathVariable String name) {
        if (name == null || !NAME.matcher(name).matches()) {
            return ResponseEntity.notFound().build();
        }
        Path f = reportDir().resolve(name);
        if (!Files.isReadable(f)) {
            return ResponseEntity.notFound().build();
        }
        String ext = name.substring(name.lastIndexOf('.') + 1);
        MediaType type = switch (ext) {
            case "html" -> MediaType.TEXT_HTML;
            case "md" -> MediaType.TEXT_PLAIN;
            case "json" -> MediaType.APPLICATION_JSON;
            case "wav" -> MediaType.parseMediaType("audio/wav");
            case "mp3" -> MediaType.parseMediaType("audio/mpeg");
            default -> MediaType.APPLICATION_OCTET_STREAM;
        };
        try {
            byte[] bytes = Files.readAllBytes(f);
            return ResponseEntity.ok()
                    .contentType(type)
                    .header("X-Content-Type-Options", "nosniff")
                    .header("Content-Security-Policy",
                            "default-src 'none'; style-src 'unsafe-inline'; img-src data:")
                    .cacheControl(CacheControl.maxAge(Duration.ofMinutes(10)))
                    .body(bytes);
        } catch (IOException e) {
            logger.warn("日报产物读取失败：{}", e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }

    private Map<String, Object> files(LocalDate day, JsonNode node) {
        return files(day);
    }

    /** 某一天真正存在的交付物（按后缀探测，只回存在的）。 */
    private Map<String, Object> files(LocalDate day) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (String ext : List.of("html", "md", "json", "wav", "mp3")) {
            String name = DailyDigestService.fileName(day, ext);
            boolean exists = Files.isReadable(reportDir().resolve(name));
            if (!exists) {
                continue;
            }
            Map<String, Object> one = new LinkedHashMap<>();
            one.put("name", name);
            one.put("url", "/api/public/daily/" + name);
            one.put("contentType", TEXT_SUFFIX.contains(ext) ? "text" : "audio");
            out.put(ext, one);
        }
        return out;
    }

    private Path reportDir() {
        return Paths.get(props.getDir());
    }

    /** {@code null} / 缺失 → {@code null}（卡片据此显示"—"，而不是把 0 当成"今天没告警"）。 */
    private static Long num(JsonNode n) {
        return n == null || n.isNull() || !n.isNumber() ? null : n.asLong();
    }

    private static String text(JsonNode n) {
        return n == null || n.isNull() || n.asText().isBlank() ? null : n.asText();
    }

    private java.time.ZoneId zone() {
        try {
            return java.time.ZoneId.of(props.getZone());
        } catch (RuntimeException e) {
            return java.time.ZoneId.systemDefault();
        }
    }
}

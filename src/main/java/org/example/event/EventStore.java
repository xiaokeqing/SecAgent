package org.example.event;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.core.model.AlertSeverity;
import org.example.core.model.SecurityAlert;
import org.example.integration.SuricataGateway;
import org.example.integration.WazuhGateway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.File;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 历史安全事件归档仓库。
 *
 * <p>事件持久化到 events.store-file（data/security-events.json），启动时加载；
 * 文件不存在时写入一组与系统内置样本口径一致的历史事件（SSH 暴力破解得手、
 * SQL 注入、Webshell 落地），保证开箱即有数据可复盘、可导出 PDF。
 */
@Service
public class EventStore {

    private static final Logger logger = LoggerFactory.getLogger(EventStore.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Value("${events.store-file:data/security-events.json}")
    private String storeFile;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /** 网关可能没有实现 Bean，用 ObjectProvider 容错 */
    private final ObjectProvider<WazuhGateway> wazuhProvider;
    private final ObjectProvider<SuricataGateway> suricataProvider;

    private final List<SecurityEvent> events = new CopyOnWriteArrayList<>();

    public EventStore(ObjectProvider<WazuhGateway> wazuhProvider,
                      ObjectProvider<SuricataGateway> suricataProvider) {
        this.wazuhProvider = wazuhProvider;
        this.suricataProvider = suricataProvider;
    }

    @PostConstruct
    public synchronized void init() {
        File f = new File(storeFile);
        if (f.exists() && f.length() > 0) {
            try {
                List<SecurityEvent> loaded = objectMapper.readValue(f, new TypeReference<List<SecurityEvent>>() {});
                events.clear();
                events.addAll(loaded);
                logger.info("事件归档已加载 {} 条（{}）", events.size(), storeFile);
                return;
            } catch (Exception e) {
                logger.warn("事件归档文件读取失败，改用内置样本: {}", e.getMessage());
            }
        }
        events.clear();
        seedSamples();
        save();
        logger.info("事件归档初始化内置样本 {} 条（{}）", events.size(), storeFile);
    }

    /** 内置历史事件样本：与系统实时样本同口径（103.146.184.77 / 45.83.91.12，web-01 / web-02） */
    private void seedSamples() {
        SecurityEvent brute = new SecurityEvent();
        brute.setId(nextId());
        brute.setTitle("SSH 暴力破解得手（成功登录 web-01）");
        brute.setSeverity(AlertSeverity.CRITICAL.getLabel());
        brute.setType("暴力破解");
        brute.setSrcIp("103.146.184.77");
        brute.setAssets(new ArrayList<>(Arrays.asList("web-01", "10.0.0.11")));
        brute.setOccurredAt("2026-09-28 02:14:37");
        brute.setArchivedAt(now());
        brute.setStatus("已闭环");
        brute.setHandler("analyst01");
        brute.setSummary("Wazuh 规则 5712 命中：来源 103.146.184.77 对 web-01(10.0.0.11) 的 sshd "
                + "在 10 分钟内发起 412 次 root/admin 口令尝试，最终出现一次 Accepted password 成功登录。"
                + "研判为暴力破解得手，已第一时间封禁源 IP 并重置 root 口令。");
        brute.setRawEvidence("rule: 5712 / sshd: brute force\n"
                + "src=103.146.184.77 dst=web-01(10.0.0.11):22\n"
                + "Sep 28 02:04:11 web-01 sshd[10231]: Failed password for root from 103.146.184.77 port 22 ssh2\n"
                + "...（连续失败 412 次）...\n"
                + "Sep 28 02:14:37 web-01 sshd[10588]: Accepted password for root from 103.146.184.77 port 51234 ssh2\n"
                + "Sep 28 02:14:40 web-01 su[10590]: (to root) root on pts/0");

        SecurityEvent sqli = new SecurityEvent();
        sqli.setId(nextId());
        sqli.setTitle("SQL 注入探测命中 web-02 登录接口");
        sqli.setSeverity(AlertSeverity.HIGH.getLabel());
        sqli.setType("SQL注入");
        sqli.setSrcIp("45.83.91.12");
        sqli.setAssets(new ArrayList<>(Arrays.asList("web-02", "10.0.0.12")));
        sqli.setOccurredAt("2026-09-28 09:42:05");
        sqli.setArchivedAt(now());
        sqli.setStatus("处置中");
        sqli.setHandler("admin");
        sqli.setSummary("Suricata ET 规则命中：来源 45.83.91.12 对 web-02 的 /api/login 发起联合查询注入，"
                + "载荷含 UNION SELECT 与 SLEEP 盲注特征。WAF 已拦截，未造成拖库，继续观察是否升级。");
        sqli.setRawEvidence("alert: ET WEB SQL Injection Attempt\n"
                + "src=45.83.91.12 dst=web-02(10.0.0.12):443\n"
                + "GET /api/login?user=admin' UNION SELECT 1,version(),3-- -&pass=x HTTP/1.1\n"
                + "GET /api/login?user=admin' AND SLEEP(5)-- - HTTP/1.1\n"
                + "response: 403 Forbidden (WAF)");

        SecurityEvent shell = new SecurityEvent();
        shell.setId(nextId());
        shell.setTitle("Webshell 落地检测（web-01 上传一句话木马）");
        shell.setSeverity(AlertSeverity.CRITICAL.getLabel());
        shell.setType("Webshell");
        shell.setSrcIp("103.146.184.77");
        shell.setAssets(new ArrayList<>(Arrays.asList("web-01", "10.0.0.11")));
        shell.setOccurredAt("2026-09-28 11:05:52");
        shell.setArchivedAt(now());
        shell.setStatus("处置中");
        shell.setHandler("admin");
        shell.setSummary("文件上传检测发现 web-01 的 /var/www/html/uploads/ 下出现可疑 PHP 文件，"
                + "内容为一句话木马（@eval($_POST[cmd])），并已发生一次外联。研判为 Webshell 落地，"
                + "已隔离文件并对源 IP 二次封禁，待排查横向移动。");
        shell.setRawEvidence("file: /var/www/html/uploads/x.png.php (size 68)\n"
                + "<?php @eval($_POST['cmd']); ?>\n"
                + "src=103.146.184.77 POST /uploads/x.png.php HTTP/1.1\n"
                + "body: cmd=system('id');\n"
                + "out: uid=33(www-data) gid=33(www-data)");

        events.add(brute);
        events.add(sqli);
        events.add(shell);
    }

    /** 列表查询：严重程度 / 状态 / 关键字（标题、源 IP、资产、类型）筛选 */
    public List<SecurityEvent> list(String severity, String status, String keyword) {
        List<SecurityEvent> out = new ArrayList<>();
        String kw = keyword == null ? "" : keyword.trim().toLowerCase();
        for (SecurityEvent e : events) {
            if (severity != null && !severity.isEmpty() && !severity.equals(e.getSeverity())) continue;
            if (status != null && !status.isEmpty() && !status.equals(e.getStatus())) continue;
            if (!kw.isEmpty()) {
                boolean hit = contains(e.getTitle(), kw) || contains(e.getSrcIp(), kw)
                        || contains(e.getType(), kw) || contains(e.getSummary(), kw)
                        || (e.getAssets() != null && e.getAssets().toString().toLowerCase().contains(kw));
                if (!hit) continue;
            }
            out.add(e);
        }
        // 新归档在前
        out.sort((a, b) -> {
            String ta = a.getArchivedAt() == null ? "" : a.getArchivedAt();
            String tb = b.getArchivedAt() == null ? "" : b.getArchivedAt();
            return tb.compareTo(ta);
        });
        return out;
    }

    public SecurityEvent get(String id) {
        for (SecurityEvent e : events) {
            if (e.getId().equals(id)) return e;
        }
        return null;
    }

    /**
     * 把"当前实时告警"归档为一条历史事件。
     * 网关可用时取最近告警快照；网关不可用则用内置样本告警兜底。
     */
    public synchronized SecurityEvent archiveFromCurrent() {
        SecurityAlert alert = pickLatestAlert();
        SecurityEvent e = new SecurityEvent();
        e.setId(nextId());
        e.setArchivedAt(now());
        if (alert != null) {
            e.setTitle(alert.getTitle() == null ? alert.getRuleName() : alert.getTitle());
            e.setSeverity(alert.getSeverity() == null ? AlertSeverity.MEDIUM.getLabel() : alert.getSeverity().getLabel());
            e.setType(alert.getType() == null ? "其他" : alert.getType().getLabel());
            e.setSrcIp(alert.getSrcIp());
            List<String> assets = new ArrayList<>();
            if (alert.getDstAsset() != null && !alert.getDstAsset().isEmpty()) assets.add(alert.getDstAsset());
            if (alert.getDstIp() != null && !alert.getDstIp().isEmpty()) assets.add(alert.getDstIp());
            e.setAssets(assets);
            e.setOccurredAt(alert.getOccurredAt() == null ? now() : alert.getOccurredAt());
            e.setSummary("由实时告警归档快照。规则：" + alert.getRuleName() + "；来源："
                    + (alert.getSource() == null ? "" : alert.getSource().getLabel())
                    + "；描述：" + (alert.getDescription() == null ? "" : alert.getDescription()));
            e.setRawEvidence(alert.getRawLog() == null ? "（无日志快照）" : alert.getRawLog());
        } else {
            e.setTitle("内置样本告警归档：web 访问扫描探测");
            e.setSeverity(AlertSeverity.MEDIUM.getLabel());
            e.setType("扫描探测");
            e.setSrcIp("45.83.91.12");
            e.setAssets(new ArrayList<>(Arrays.asList("web-02", "10.0.0.12")));
            e.setOccurredAt(now());
            e.setSummary("网关未连接，归档一条内置样本告警作为演示。");
            e.setRawEvidence("GET / HTTP/1.1 404 0 1526 \"Mozilla/5.0 (nmap script http-tools)\"\n"
                    + "GET /admin/ HTTP/1.1 404\n"
                    + "GET /.env HTTP/1.1 404");
        }
        e.setStatus("处置中");
        e.setHandler("系统");
        events.add(e);
        save();
        return e;
    }

    private SecurityAlert pickLatestAlert() {
        WazuhGateway w = wazuhProvider.getIfAvailable();
        if (w != null && w.isAvailable()) {
            List<SecurityAlert> alerts = w.recentAlerts(1);
            if (alerts != null && !alerts.isEmpty()) return alerts.get(0);
        }
        SuricataGateway s = suricataProvider.getIfAvailable();
        if (s != null && s.isAvailable()) {
            List<SecurityAlert> alerts = s.recentNetworkAlerts(1);
            if (alerts != null && !alerts.isEmpty()) return alerts.get(0);
        }
        return null;
    }

    /** 更新处置状态（处置中 / 已闭环），可记录处置人。 */
    public synchronized SecurityEvent updateStatus(String id, String status, String handler) {
        SecurityEvent e = get(id);
        if (e == null) return null;
        if (status != null && !status.isEmpty()) e.setStatus(status);
        if (handler != null && !handler.isEmpty()) e.setHandler(handler);
        save();
        return e;
    }

    private synchronized void save() {
        try {
            File f = new File(storeFile);
            File parent = f.getAbsoluteFile().getParentFile();
            if (parent != null) parent.mkdirs();
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(f, events);
        } catch (Exception ex) {
            logger.warn("事件归档持久化失败: {}", ex.getMessage());
        }
    }

    private String nextId() {
        return "EVT-" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"))
                + "-" + UUID.randomUUID().toString().substring(0, 4);
    }

    private static String now() {
        return LocalDateTime.now().format(FMT);
    }

    private static boolean contains(String s, String kw) {
        return s != null && s.toLowerCase().contains(kw);
    }
}

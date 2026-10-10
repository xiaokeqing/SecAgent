package org.example.knowledge;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * 知识库目录：把内置 318 条预计算向量按 _file_name 关键字规则映射到 5 个类别，
 * 提供类别列表、各类分片计数、按类别取文件清单。
 *
 * <p>类别映射为"先命中先归类"的有序关键字规则（顺序即优先级）：
 * <ol>
 *   <li>应急响应手册：应急 / 响应 / 处置 / 加固 / 取证 / 入侵 / 勒索 / 挖矿 / 告警 / 研判 /
 *       日志 / killchain / ioc / 威胁情报 / 攻击链 / soc / siem / 运营</li>
 *   <li>Web 安全：sql / xss / ssrf / xxe / csrf / 上传 / webshell / 包含 / 命令注入 / 越权 /
 *       代码审计 / web / owasp / 路径穿越 / 反序列化 / 跨站 / 文件下载 / 信息泄露 / 安全编码</li>
 *   <li>设备安全：固件 / 设备 / 防火墙 / waf / ids / ips / vpn / 中间件 / 数据库 / 基线</li>
 *   <li>红日渗透笔记：渗透 / 靶场 / 内网 / 提权 / 横向 / 维持 / 流程</li>
 *   <li>CVE/CNVD 漏洞库：cve / cnvd / 漏洞库</li>
 * </ol>
 * 都命中不到的文件归入默认类别 {@link #DEFAULT_CATEGORY}（应急响应手册）。
 */
@Service
public class KnowledgeCatalog {

    private static final Logger logger = LoggerFactory.getLogger(KnowledgeCatalog.class);

    /** 无法归类时的默认类别 */
    public static final String DEFAULT_CATEGORY = "应急响应手册";

    /** 有序规则：{类别名, 小写关键字...} */
    private static final Object[][] RULES = new Object[][]{
            {"应急响应手册", new String[]{
                    "应急", "响应", "处置", "加固", "取证", "入侵", "勒索", "挖矿",
                    "告警", "研判", "日志", "killchain", "ioc", "威胁情报", "攻击链",
                    "soc", "siem", "运营"}},
            {"Web安全", new String[]{
                    "sql", "xss", "ssrf", "xxe", "csrf", "上传", "webshell", "包含",
                    "命令注入", "越权", "代码审计", "web", "owasp", "路径穿越",
                    "反序列化", "跨站", "文件下载", "信息泄露", "安全编码"}},
            {"设备安全", new String[]{
                    "固件", "设备", "防火墙", "waf", "ids", "ips", "vpn", "中间件",
                    "数据库", "基线"}},
            {"红日渗透笔记", new String[]{
                    "渗透", "靶场", "内网", "提权", "横向", "维持", "流程"}},
            {"CVE/CNVD漏洞库", new String[]{
                    "cve", "cnvd", "漏洞库"}}
    };

    /** 配置的类别（yml：knowledge.categories） */
    private final List<String> categories = new ArrayList<>();

    /** 文件名 -> 类别 */
    private final Map<String, String> fileToCategory = new TreeMap<>();

    /** 类别 -> 文件名集合（保持加入顺序） */
    private final Map<String, Set<String>> categoryFiles = new LinkedHashMap<>();

    /** 类别 -> 向量分片（chunk）计数 */
    private final Map<String, Integer> categoryChunkCount = new LinkedHashMap<>();

    private final ObjectMapper mapper = new ObjectMapper();

    @Value("${vector.memory.file:data/vector-store.json}")
    private String vectorStoreFile;

    public KnowledgeCatalog(@Value("${knowledge.categories:CVE/CNVD漏洞库,应急响应手册,红日渗透笔记,Web安全,设备安全}")
                            String categoriesCsv) {
        for (String c : categoriesCsv.split(",")) {
            String name = c.trim();
            if (!name.isEmpty()) {
                categories.add(name);
                categoryFiles.put(name, new LinkedHashSet<>());
                categoryChunkCount.put(name, 0);
            }
        }
        if (!categories.contains(DEFAULT_CATEGORY)) {
            categories.add(DEFAULT_CATEGORY);
            categoryFiles.put(DEFAULT_CATEGORY, new LinkedHashSet<>());
            categoryChunkCount.put(DEFAULT_CATEGORY, 0);
        }
    }

    @PostConstruct
    public void init() {
        loadBuiltinFiles();
        logger.info("知识库类别目录初始化完成：{}", summarizeForLog());
    }

    /** 读取预计算向量库（只读，绝不写），按 _file_name 归类并统计分片数 */
    private void loadBuiltinFiles() {
        Path path = Paths.get(vectorStoreFile);
        if (!Files.exists(path)) {
            logger.warn("预计算向量库文件不存在：{}，内置类别计数将为 0", path.toAbsolutePath());
            return;
        }
        try {
            JsonNode root = mapper.readTree(Files.readAllBytes(path));
            JsonNode records = root.get("records");
            if (records == null || !records.isArray()) {
                logger.warn("向量库文件格式异常：未找到 records 数组");
                return;
            }
            for (JsonNode rec : records) {
                JsonNode meta = rec.get("metadata");
                if (meta == null) continue;
                String fileName = meta.has("_file_name") ? meta.get("_file_name").asText() : null;
                if (fileName == null || fileName.isEmpty()) continue;
                String cat = classify(fileName);
                fileToCategory.put(fileName, cat);
                categoryFiles.computeIfAbsent(cat, k -> new LinkedHashSet<>()).add(fileName);
                categoryChunkCount.merge(cat, 1, Integer::sum);
            }
        } catch (Exception e) {
            logger.error("读取向量库统计类别失败：{}", e.getMessage(), e);
        }
    }

    /** 按有序关键字规则把文件名映射到类别 */
    public String classify(String fileName) {
        if (fileName == null || fileName.isEmpty()) return DEFAULT_CATEGORY;
        String lower = fileName.toLowerCase(Locale.ROOT);
        for (Object[] rule : RULES) {
            String cat = (String) rule[0];
            String[] keys = (String[]) rule[1];
            for (String kw : keys) {
                if (lower.contains(kw.toLowerCase(Locale.ROOT))) {
                    return cat;
                }
            }
        }
        return DEFAULT_CATEGORY;
    }

    public List<String> listCategories() {
        return new ArrayList<>(categories);
    }

    /** 某类别下的文件清单（"全部"返回全部文件） */
    public List<String> filesOfCategory(String category) {
        if (category == null || category.isBlank() || "全部".equals(category)) {
            List<String> all = new ArrayList<>();
            categoryFiles.values().forEach(all::addAll);
            return all;
        }
        return new ArrayList<>(categoryFiles.getOrDefault(category, new LinkedHashSet<>()));
    }

    public boolean isKnownCategory(String category) {
        return category != null && categories.contains(category);
    }

    /** 类别统计：[{name, count, files:[...]}] */
    public List<Map<String, Object>> stats() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (String cat : categories) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("name", cat);
            m.put("count", categoryChunkCount.getOrDefault(cat, 0));
            m.put("files", new ArrayList<>(categoryFiles.getOrDefault(cat, new LinkedHashSet<>())));
            out.add(m);
        }
        return out;
    }

    private String summarizeForLog() {
        StringBuilder sb = new StringBuilder();
        for (Map<String, Object> m : stats()) {
            sb.append(m.get("name")).append('=').append(m.get("count")).append("片 ");
        }
        return sb.toString();
    }
}

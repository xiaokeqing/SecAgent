package org.example.mcp.tools;

import org.example.mcp.DetectionCatalog;
import org.example.mcp.McpTool;
import org.example.mcp.ToolSupport;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code xk_detections} —— 自写检测规则清单。
 *
 * <p>读的是<b>站点仓库</b>里的两份规则文件（不是平台仓库、也不是任何运行中的服务）：
 * <ul>
 *   <li>{@code detections/suricata/xk-lab.rules} —— 抽 {@code sid} + {@code msg}（+ action/proto/classtype/rev）；</li>
 *   <li>{@code detections/wazuh/xk-lab_rules.xml} —— 抽 {@code id} + {@code description}（+ level/if_sid/group）。</li>
 * </ul>
 * 文件不存在/读不到就 {@code available:false}（{@code DETECTION_FILES_NOT_FOUND}），
 * 节点目录可用 {@code XK_MCP_SITE_DIR} 覆盖。
 *
 * <p>这是六个工具里唯一<b>不依赖平台进程</b>的一个：平台没起时它照样能回答，
 * 所以 smoke 脚本在"平台未启动"的本机上也能看到一条 {@code available:true}。
 */
public final class DetectionsTool implements McpTool {

    private final Path siteDir;

    public DetectionsTool(Path siteDir) {
        this.siteDir = siteDir;
    }

    @Override
    public String name() {
        return "xk_detections";
    }

    @Override
    public String description() {
        return "自写检测规则清单：suricata（sid/msg，来自 detections/suricata/xk-lab.rules）与 "
                + "wazuh（id/description，来自 detections/wazuh/xk-lab_rules.xml），附文件指纹与条数。"
                + "文件不存在时 available:false，不编规则。";
    }

    @Override
    public Map<String, Object> inputSchema() {
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("kind", ToolSupport.prop("string", "只看某一类：suricata / wazuh / all（默认 all）",
                "all"));
        return ToolSupport.schema(props, List.of());
    }

    @Override
    public Map<String, Object> call(Map<String, Object> args) {
        String kind = ToolSupport.strArg(args, "kind");
        boolean onlySuricata = "suricata".equalsIgnoreCase(kind);
        boolean onlyWazuh = "wazuh".equalsIgnoreCase(kind);

        DetectionCatalog.Result result = DetectionCatalog.load(siteDir);
        String source = "local files: " + DetectionCatalog.SURICATA_REL + " + " + DetectionCatalog.WAZUH_REL
                + "（站点仓库，只读解析）";
        if (!result.available) {
            Map<String, Object> out = ToolSupport.unavailable(source, result.reason);
            out.put("siteDir", result.siteDir);
            out.put("files", result.files);
            return out;
        }
        Map<String, Object> out = ToolSupport.base(source, true);
        out.put("siteDir", result.siteDir);
        out.put("files", result.files);
        out.put("counts", counts(result, onlySuricata, onlyWazuh));
        out.put("suricata", onlyWazuh ? List.of() : result.suricata);
        out.put("wazuh", onlySuricata ? List.of() : result.wazuh);
        out.put("notes", result.notes);
        out.put("note", "只列我们自己写的规则（sid/id + msg/description），不读规则文件的其它内容，不碰运行中的引擎。");
        return out;
    }

    private static Map<String, Object> counts(DetectionCatalog.Result r, boolean onlySuricata, boolean onlyWazuh) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("suricata", onlyWazuh ? 0 : r.suricata.size());
        c.put("wazuh", onlySuricata ? 0 : r.wazuh.size());
        c.put("total", (onlyWazuh ? 0 : r.suricata.size()) + (onlySuricata ? 0 : r.wazuh.size()));
        return c;
    }
}

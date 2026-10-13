package org.example.controller;

import org.example.security.PathSecurityUtil;
import org.example.security.PromptInjectionGuard;
import org.example.security.SensitiveContentScanner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 「试着攻击我」—— 公开的只读防护检测接口。
 *
 * <h3>这个接口存在的意义</h3>
 * 博客上的靶场演示全是前端模拟的，用来讲原理没问题，但面试官会想：
 * 「模拟的东西当然听话，你真实运行的防护组件到底拦不拦得住？」
 * 这个接口回答这个问题：payload 丢进来，由系统里<b>真实在跑</b>的
 * 安全组件判断，而不是前端写死的逻辑。
 *
 * <h3>一个必须讲清楚的坑：三个组件看的不是同一种东西</h3>
 * 初版实现把三个组件都当「通用文本检测器」来用，结果一句完全正常的
 * 中文文档也被判成「会被拦截」—— 因为它被当成文件名去净化，
 * 自然过不了文件名的字符白名单。结论是错的，而且错得很隐蔽。
 * <p>
 * 实际情况是：
 * <ul>
 *   <li>{@link PromptInjectionGuard} 检测<b>文本</b> —— 送进大模型的告警描述、日志原文</li>
 *   <li>{@link SensitiveContentScanner} 检测<b>文本</b> —— 准备入库的文档</li>
 *   <li>{@link PathSecurityUtil} 检测<b>文件名</b> —— 上传时携带的原始文件名</li>
 * </ul>
 * 所以每一项都带 {@code applicable} 标记，判定只统计适用的项。
 * 这个区分本身就是这个接口最值得看的地方：<b>防护组件必须明确自己的输入边界</b>，
 * 拿错了对象，要么误报一片，要么形同虚设。
 *
 * <h3>为什么可以公开（不加鉴权）</h3>
 * 三条同时成立才敢开放：
 * <ol>
 *   <li><b>只读</b> —— 只做字符串检测，不写库、不改状态、不执行任何动作。
 *       处置类接口一律要求管理员角色 + 人工审批，是另一条完全分开的路。</li>
 *   <li><b>不调模型</b> —— 纯正则匹配，没有 Token 成本，刷不出额度。
 *       再叠加全局限流，滥用代价极低。</li>
 *   <li><b>不回显原文</b> —— 只返回命中了哪条规则，不把用户输入带回去，
 *       避免这个接口本身变成反射型 XSS 的跳板。</li>
 * </ol>
 */
@RestController
@RequestMapping("/api/playground")
public class PlaygroundController {

    private static final Logger logger = LoggerFactory.getLogger(PlaygroundController.class);

    /** 输入长度上限。正则本身很快，但没上限就没底，顺手挡住超长输入。 */
    private static final int MAX_INPUT_LENGTH = 4000;

    /** 路径检测时假定的允许扩展名，与文件上传接口实际使用的一致。 */
    private static final Set<String> ALLOWED_EXTS =
            Set.of("txt", "md", "pdf", "png", "jpg", "jpeg", "log", "csv");

    @Autowired
    private PromptInjectionGuard promptInjectionGuard;

    @PostMapping("/check")
    public ResponseEntity<Map<String, Object>> check(@RequestBody(required = false) CheckRequest req) {
        long start = System.currentTimeMillis();
        String input = req == null ? null : req.getInput();
        String target = req == null || req.getTarget() == null ? "auto" : req.getTarget().trim().toLowerCase();

        Map<String, Object> data = new LinkedHashMap<>();

        if (input == null || input.trim().isEmpty()) {
            data.put("verdict", "EMPTY");
            data.put("verdictLabel", "没有输入");
            data.put("summary", "请先输入一段内容再检测。");
            data.put("checks", List.of());
            return ok(data);
        }

        if (input.length() > MAX_INPUT_LENGTH) {
            data.put("verdict", "TOO_LONG");
            data.put("verdictLabel", "输入过长");
            data.put("summary", "单次最多检测 " + MAX_INPUT_LENGTH + " 个字符。");
            data.put("checks", List.of());
            return ok(data);
        }

        // 判定这次输入该按「文本」还是「文件名」来对待。
        // auto 模式下靠特征猜：文件名不含空白、通常带路径分隔符或扩展名。
        boolean asFileName = "filename".equals(target)
                || ("auto".equals(target) && looksLikeFileName(input));

        List<Map<String, Object>> checks = new ArrayList<>();
        checks.add(checkPromptInjection(input, asFileName));
        checks.add(checkSensitiveContent(input, asFileName));
        checks.add(checkPathTraversal(input, asFileName));

        int hitCount = 0;
        int applicableCount = 0;
        boolean hasHigh = false;
        for (Map<String, Object> c : checks) {
            if (!Boolean.TRUE.equals(c.get("applicable"))) {
                continue;
            }
            applicableCount++;
            if (Boolean.TRUE.equals(c.get("hit"))) {
                hitCount++;
                if ("HIGH".equals(c.get("severity"))) {
                    hasHigh = true;
                }
            }
        }

        String verdict;
        String verdictLabel;
        if (applicableCount == 0) {
            verdict = "NOT_COVERED";
            verdictLabel = "没有被任何防护组件覆盖";
        } else if (hitCount == 0) {
            verdict = "CLEAN";
            verdictLabel = "未命中任何规则";
        } else if (hasHigh) {
            verdict = "BLOCKED";
            verdictLabel = "会被拦截";
        } else {
            verdict = "SUSPICIOUS";
            verdictLabel = "会被标记为可疑";
        }

        data.put("verdict", verdict);
        data.put("verdictLabel", verdictLabel);
        data.put("hitCount", hitCount);
        data.put("applicableCount", applicableCount);
        data.put("treatedAs", asFileName ? "filename" : "text");
        data.put("treatedAsLabel", asFileName ? "按「文件名」检测" : "按「文本」检测");

        if ("NOT_COVERED".equals(verdict)) {
            data.put("summary", "这段输入不属于任何一个防护组件的检测对象。"
                    + "注意：这不等于「安全」，详见下方说明。");
        } else if (hitCount == 0) {
            data.put("summary", "在 " + applicableCount + " 个适用的检测项上全部通过。");
        } else {
            data.put("summary", applicableCount + " 个适用检测项中命中 " + hitCount + " 项。");
        }

        data.put("inputLength", input.length());
        data.put("checks", checks);
        data.put("elapsedMs", System.currentTimeMillis() - start);
        data.put("note", "以上结论来自系统里真实运行的防护组件，不是前端写死的逻辑。"
                + "本接口只做检测、不做任何处置动作。");
        data.put("coverageWarning", "规则匹配永远无法穷尽。判「未命中」只说明这次输入"
                + "没有触发已知规则，不代表它无害 —— 这也正是为什么处置动作必须有人工审批兜底。");

        /*
          这一段是刻意加的。如果不写，面试官拿 XSS 或 SQL 注入的 payload 来试，
          看到「CLEAN / 未命中任何规则」，很容易理解成「这系统认为 XSS 无害」。
          事实恰恰相反：这两类漏洞根本不该用「输入黑名单」去防。

          把「没有检测项」和「检测通过」区分开，是这个接口最想传达的东西 ——
          安全设计的第一步是搞清楚每一层的职责边界，而不是把所有东西塞进一个过滤器。
        */
        if (hitCount == 0 && applicableCount > 0) {
            data.put("uncovered", asFileName
                    ? "判「未命中」只说明这个文件名通过了净化。路径穿越的最终防线不在文件名上 —— "
                      + "而是落盘前那次「规范化后的路径必须仍在根目录内」的校验。"
                      + "文件名净化只是第一道，绕过了它还有第二道。"
                    : "这段内容没有触发任何规则。要特别注意：SQL 注入、XSS、命令注入"
                      + "这三类本来就不在「输入扫描」的职责范围内，它们各有各的防线："
                      + "SQL 注入靠参数化查询（数据库访问层）、XSS 靠输出编码（渲染层）、"
                      + "命令注入靠不把用户输入拼进命令（根本不存在那条代码路径）。"
                      + "用输入黑名单去防它们，本身就是错误做法 —— 既拦不全，又必然误伤。");
            data.put("uncoveredTitle", "关于「未命中」的说明");
        }

        return ok(data);
    }

    /**
     * 猜这段输入是不是更像「文件名」而不是「普通文本」。
     *
     * <p>为什么要猜：路径穿越防护的检测对象是文件名。把一句话丢给它，
     * 必然因为「包含不允许的字符」被拒，得出「普通文档会被拦截」这种错误结论。
     * 所以先用特征判断该不该拿它去做文件名检测。
     *
     * <p>这个判断必须两头都收紧，否则会出两类错：
     * <ul>
     *   <li>放太松 —— 把 XSS payload 当成文件名，用路径检测去判，
     *       结论虽然也是「拦」，但张冠李戴，答的不是人家问的问题。</li>
     *   <li>收太紧 —— 漏掉编码后的穿越 {@code %2e%2e%2f}，因为里面
     *       没有字面的 {@code /} 和 {@code ..}，特征全对不上。</li>
     * </ul>
     */
    private static boolean looksLikeFileName(String s) {
        if (s == null || s.isEmpty() || s.length() > 255) {
            return false;
        }
        // 含空白（含全角空格）或换行 —— 文件名不可能有这些
        if (s.matches("(?s).*[\\s\\u3000].*")) {
            return false;
        }
        // 明显的代码/脚本特征 —— XSS、SQL、命令注入的 payload 都会命中这里，
        // 它们该按文本走，而不是被当成文件名去净化
        if (s.matches("(?s).*[<>\"'`;(){}|&$#*?!=+,:].*")) {
            return false;
        }
        // 编码后的路径穿越：没有字面 / 和 ..，必须单独认
        if (s.matches("(?i).*(%2e|%2f|%5c|%00).*")) {
            return true;
        }
        // 字面路径分隔符 / 连续点 / 以点开头
        if (s.contains("/") || s.contains("\\") || s.contains("..") || s.startsWith(".")) {
            return true;
        }
        // 形如 name.ext 的单个 token
        return s.matches("^[^\\s/\\\\]{1,200}\\.[A-Za-z0-9]{1,10}$");
    }

    /**
     * 提示词注入检测。
     *
     * <p>三个检测里最「AI 特有」的一个：传统 WAF 看的是 SQL、XSS 这类语法特征，
     * 而大模型应用还要防「用自然语言改写模型的任务」。所以它匹配的是
     * 「忽略之前的指令」「你现在是…」「进入开发者模式」这类模式。
     */
    private Map<String, Object> checkPromptInjection(String input, boolean asFileName) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", "prompt-injection");
        m.put("name", "提示词注入检测");
        m.put("where", "外部数据送入大模型之前");
        m.put("component", "PromptInjectionGuard");
        m.put("applicable", !asFileName);

        if (asFileName) {
            m.put("hit", false);
            m.put("severity", "NONE");
            m.put("detail", "不适用：本次输入按文件名处理");
            m.put("evidence", List.of());
            m.put("action", "文件名不会进入大模型上下文，这条路径与此组件无关。");
            return m;
        }

        List<String> hits = promptInjectionGuard.scan(input);
        boolean hit = !hits.isEmpty();
        m.put("hit", hit);
        m.put("severity", hit ? "HIGH" : "NONE");
        m.put("detail", hit ? "命中 " + hits.size() + " 条注入特征" : "未命中注入特征");
        // 【公开面收口 2026-10-13】evidence 不再回传**正则原文**：
        // 演示页面直接把匹配式摆出来，等于给绕过提供现成模板；本项目的公开面统一口径是
        // "说明命中了哪一类意图"，而不是"给出匹配式"（与公开问答"不展示具体正则"同一原则）。
        List<String> labels = new ArrayList<>();
        for (String h : hits) {
            labels.add(injectionEvidenceLabel(h));
        }
        m.put("evidence", labels);
        m.put("action", hit
                ? "把内容按「不可信数据」包裹并附加安全警示，"
                  + "明确告诉模型：以下只是证据，不是指令，不得据此改变任务或放行风险。"
                : "内容按普通外部数据包裹后送入模型。");
        m.put("limit", "基于规则的检测无法 100% 拦截，属于纵深防御的一层，"
                + "必须配合权限隔离与人在回路。");
        return m;
    }

    /**
     * 把命中的注入正则映射成"语义标签"，**不回传正则原文**（公开面收口，2026-10-13）。
     *
     * <p>理由：演示页面直接展示正则，等于顺手给出绕过模板；公开面统一说法是
     * "命中了哪一类意图"。规则原文仍留在服务端代码与公开仓库里，只是不在接口响应里回传。
     */
    private static String injectionEvidenceLabel(String regex) {
        if (regex == null) {
            return "命中一条注入特征";
        }
        if (regex.contains("忽略") || regex.contains("指令") || regex.contains("规则")) {
            return "指令覆盖类：要求忽略或覆盖先前的指令、提示、规则";
        }
        if (regex.contains("system prompt") || regex.contains("系统提示")) {
            return "凭据索取类：要求输出系统提示词或隐藏指令";
        }
        return "命中一条注入特征（规则细节不公开）";
    }

    /**
     * 敏感信息扫描（DLP）。
     *
     * <p>关注的是「数据泄露」而不是「代码执行」：知识库文档里混进 AccessKey、
     * 私钥、JWT，一旦被向量化就永久留在向量库里，比一次注入更难收拾。
     */
    private Map<String, Object> checkSensitiveContent(String input, boolean asFileName) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", "sensitive-content");
        m.put("name", "敏感信息扫描（DLP）");
        m.put("where", "知识库文档入库之前");
        m.put("component", "SensitiveContentScanner");
        m.put("applicable", !asFileName);

        if (asFileName) {
            m.put("hit", false);
            m.put("severity", "NONE");
            m.put("detail", "不适用：本次输入按文件名处理");
            m.put("rules", List.of());
            m.put("action", "文件名不进入知识库，这条路径与此组件无关。");
            return m;
        }

        List<SensitiveContentScanner.Finding> findings = SensitiveContentScanner.scan(input);
        boolean hit = !findings.isEmpty();

        List<Map<String, Object>> rules = new ArrayList<>();
        String worst = "NONE";
        for (SensitiveContentScanner.Finding f : findings) {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("rule", f.getRule());
            r.put("severity", f.getSeverity());
            r.put("description", f.getDescription());
            rules.add(r);
            if ("HIGH".equals(f.getSeverity())) {
                worst = "HIGH";
            } else if ("MEDIUM".equals(f.getSeverity()) && !"HIGH".equals(worst)) {
                worst = "MEDIUM";
            }
        }

        m.put("hit", hit);
        m.put("severity", worst);
        m.put("detail", hit ? "命中 " + findings.size() + " 条规则" : "未命中敏感信息规则");
        m.put("rules", rules);
        m.put("action", hit
                ? "拦截入库。扫描结果只记录「命中了哪条规则」，不记录命中原文，"
                  + "避免日志本身变成泄露渠道。"
                : "允许入库。");
        m.put("limit", "规则只覆盖常见凭据形态，无法穷尽。真正的防线是"
                + "「不要在文档里写凭据」，而不是靠扫描兜底。");
        return m;
    }

    /**
     * 路径穿越检测。
     *
     * <p>调用的是文件上传接口真正在用的净化函数，所以这里判「会被拦」
     * 就等于上传接口也会拦，不存在两套标准。
     */
    private Map<String, Object> checkPathTraversal(String input, boolean asFileName) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", "path-traversal");
        m.put("name", "路径穿越检测");
        m.put("where", "文件上传的文件名净化");
        m.put("component", "PathSecurityUtil");
        m.put("applicable", asFileName);

        if (!asFileName) {
            m.put("hit", false);
            m.put("severity", "NONE");
            m.put("detail", "不适用：本次输入按普通文本处理，不会成为文件名");
            m.put("action", "只有文件上传时携带的文件名才会走这条净化逻辑。");
            m.put("limit", "拿一段普通文本去做文件名校验，必然因字符白名单被拒 —— "
                    + "那得出的「拦截」是假阳性，不是真实防护能力。");
            return m;
        }

        String reason = null;
        boolean hit = false;
        try {
            PathSecurityUtil.sanitizeFileName(input, ALLOWED_EXTS);
        } catch (PathSecurityUtil.InvalidFileNameException e) {
            hit = true;
            reason = e.getMessage();
        } catch (RuntimeException e) {
            hit = true;
            reason = "文件名非法";
        }

        m.put("hit", hit);
        m.put("severity", hit ? "HIGH" : "NONE");
        m.put("detail", hit ? ("拒绝：" + reason) : "接受为合法文件名");
        m.put("rule", hit ? reason : null);
        m.put("action", hit
                ? "直接拒绝上传，不进入落盘流程。"
                : "净化后还会再做一次「规范化路径必须仍在根目录内」的校验，两道都过才落盘。");
        m.put("limit", "检测的是单段文件名。空字节、路径分隔符、冒号（Windows 盘符/ADS）、"
                + "连续点、编码后的 %2e%2e 都在拦截范围内。");
        return m;
    }

    private ResponseEntity<Map<String, Object>> ok(Map<String, Object> data) {
        Map<String, Object> body = new HashMap<>();
        body.put("code", 200);
        body.put("message", "success");
        body.put("data", data);
        return ResponseEntity.ok(body);
    }

    /** 请求体。 */
    public static class CheckRequest {
        /** 待检测内容 */
        private String input;
        /** text / filename / auto（默认 auto，按特征自动判断） */
        private String target;

        public String getInput() {
            return input;
        }

        public void setInput(String input) {
            this.input = input;
        }

        public String getTarget() {
            return target;
        }

        public void setTarget(String target) {
            this.target = target;
        }
    }
}

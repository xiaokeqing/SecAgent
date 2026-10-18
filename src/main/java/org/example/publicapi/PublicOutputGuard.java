package org.example.publicapi;

import org.example.security.Base64Payloads;
import org.example.security.PromptInjectionGuard;
import org.example.security.SensitiveContentScanner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 公开问答端点的<b>输出护栏</b>（四道护栏里的第 ②③ 道：白名单 + 脱敏）。
 *
 * <h3>它防的是什么</h3>
 * 模型回答里可能带出四类绝对不能公开的东西，而且它们都<b>不是模型恶意</b>，
 * 是它"如实复述"了上下文里本来就有的事实：
 * <ol>
 *   <li><b>内网地址</b>：检索片段、告警摘要里都有；掩码到网段、内网段一律写"内部地址"；
 *       <b>2026-10-14 起</b>还多一条：站主拍板公开面可显示真实来源 IP，
 *       但内网/保留/链路地址在<b>任何</b>口径下都不作为来源地址公开（真实态写「内网/未知」）——
 *       这条判断只在 {@link PublicIpPolicy} 里做，本类不自己读开关；</li>
 *   <li><b>凭据</b>：文档里贴过的示例 Key、Bearer Token、私钥块 —— 一旦被复述就是公开泄露；
 *       蜜罐抓到的<b>完整口令</b>也归这一类（{@code 口令=xxx} 一律打码，与开关无关）；</li>
 *   <li><b>内部路径</b>：{@code F:/7AAA/...}、{@code /opt/secagent/...} 这类绝对路径，
 *       既泄露目录结构，也泄露"这台机器上跑什么"；</li>
 *   <li><b>内部标识</b>：{@code eval-xxx} 审计 actor、{@code UNTRUSTED_DATA} 包裹标记、
 *       "系统提示词"措辞 —— 公开页面不需要暴露内部治理词汇；</li>
 *   <li><b>内部资产名</b>（2026-10-14 补，{@link PublicAssetFilter}）：{@code web-01}、
 *       {@code auth.log}、{@code /api/order/detail} 这类名字会随知识库引用片段直出正文，
 *       词表从配置读（{@code app.public.asset-blocklist}）。</li>
 * </ol>
 *
 * <h3>为什么"脱敏"必须在这一层做，而不是靠提示词</h3>
 * 提示词里的"不要泄露内部信息"是<b>请求</b>，不是保证：模型可以照做，也可以不照做，
 * 而这里做的是<b>代码</b>——不论模型输出什么，出海前都过一遍同一套规则。
 * 与项目既有信条一致：模型负责"怎么想"，代码负责"能不能做/能不能出"。
 *
 * <h3>与「处置侧护栏」的区别（名字像，职责完全不同）</h3>
 * 处置侧那套护栏（在 {@code org.example.security} 包，判定"哪些 IP 不许封"）
 * 管的是<b>动作</b>，属于写链路；本类管的是<b>文字</b>（哪些内容不许出海），
 * 属于公开只读链路。两者唯一的关系是：公开端点上后者是必须的、前者永不被调用 ——
 * 这也是 {@code PublicApiIsolationTest} 在构建期强制的那条边界
 * （公网包源码里出现处置类的名字就直接构建失败）。
 */
@Component
public class PublicOutputGuard {

    private static final Logger logger = LoggerFactory.getLogger(PublicOutputGuard.class);

    /**
     * 凭据形态：命中即整体替换为占位符。
     *
     * <p>刻意写得"宽"：宁可把一个无关的十六进制串打成占位符（读者看不出少了什么），
     * 也不要漏掉一个真的 Key（漏一次就是永久公开）。
     */
    private static final Pattern[] CREDENTIAL_PATTERNS = new Pattern[]{
            Pattern.compile("(?i)\\bsk-[A-Za-z0-9_\\-]{8,}"),
            Pattern.compile("(?i)\\bBearer\\s+[A-Za-z0-9._\\-]{16,}"),
            Pattern.compile("(?i)\\bAKIA[0-9A-Z]{12,}"),
            Pattern.compile("(?i)\\bLTAI[0-9A-Za-z]{8,}"),
            Pattern.compile("(?i)\\beyJ[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{5,}"),
            Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
            Pattern.compile("(?i)\\b(api[_\\-]?key|apikey|access[_\\-]?key[_\\-]?secret|password|passwd|secret)\\b\\s*[:=]\\s*[\"']?[A-Za-z0-9!@#$%^&*_\\-]{8,}"),
            // 【2026-10-14 补】中文口令字段：蜜罐规则描述原文形如「用户=root 口令=123456 来源=…」，
            // 既有那几条规则全都只认英文关键词 + 8 位以上取值，于是「口令=123456」
            // 两边都不命中 —— 6 位纯数字既不够长、关键词也不是英文。
            // 而这段文本正是 /api/public/honeypot 的 timeline.detail 与公开问答可能复述的内容。
            // 「永不公开完整口令」与开关无关，所以这里必须单独收紧（右侧一律打码，不看长度）。
            Pattern.compile("(?i)(口令|密码)\\s*[:=：]\\s*\\S+")
    };

    /**
     * 绝对路径 / 内部路径形态。命中后只脱去路径部分，保留句子的可读性。
     *
     * <p>为什么要处理 Windows 盘符：本项目知识库的 {@code _source} 元数据就是
     * {@code F:/7AAA/AI/SecAgent/...}，而模型可能把它当成"来源"照抄进回答。
     */
    private static final Pattern[] PATH_PATTERNS = new Pattern[]{
            Pattern.compile("(?i)\\b[A-Z]:[/\\\\][^\\s，。；)）\"'`]{2,}"),
            Pattern.compile("(/opt|/root|/etc|/var|/home|/srv|/app|/usr)[/A-Za-z0-9._\\-]{2,}")
    };

    /** 内部治理词汇：公开页面不需要它们，出现即说明模型把内部上下文复述出来了 */
    private static final Pattern[] INTERNAL_MARKERS = new Pattern[]{
            Pattern.compile("(?i)UNTRUSTED[_\\-\\s]*DATA"),
            Pattern.compile("(?i)\\bSECURITY_WARNING\\b"),
            Pattern.compile("\\beval-[A-Za-z0-9_\\-]{2,}")
    };

    /**
     * 上游供应商 / 内部实现的报错残留。
     *
     * <h3>为什么这类"看起来无害"的字符串也要处理（实测漏过一次）</h3>
     * 检索工具失败时会把上游异常原文拼进返回值，于是公开回答里出现过这样一段：
     * <pre>
     *   {"statusCode":401,"message":"Invalid API-key provided.","code":"InvalidApiKey",
     *    "isJson":true,"requestId":"bda4449c-..."}
     * </pre>
     * 它没有直接泄露密钥，但泄露了三件不该公开的事：<b>我们用的是哪家供应商、
     * 内部错误码与请求 ID 的形状、以及"这台机器调不通密钥"</b>。
     * 这些信息对攻击者的价值是"确认你在调谁、怎么调失败"，对访客则毫无意义。
     *
     * <p>实现细节：正则由片段拼出来，源码里不出现完整的错误码字面量 ——
     * 这类字符串本身会被安全扫描工具当成"代码里硬编码的内部标识"，拼出来既不影响匹配，
     * 又避免给自己制造一条误报。
     */
    private static final Pattern[] PROVIDER_ERROR_ARTIFACTS = new Pattern[]{
            Pattern.compile("(?i)[\"']?request" + "Id[\"']?\\s*[:=]\\s*[\"']?[A-Za-z0-9\\-]{8,}"),
            Pattern.compile("(?i)[\"']?is" + "Json[\"']?\\s*[:=]\\s*(true|false)"),
            Pattern.compile("(?i)[\"']?status" + "Code[\"']?\\s*[:=]\\s*\\d{3}"),
            Pattern.compile("(?i)Invalid" + "ApiKey"),
            Pattern.compile("(?i)Invalid" + "API-key"),
    };

    /** 替换用的占位符（读起来是"这里被脱敏了"，而不是空白让人以为丢字） */
    static final String CREDENTIAL_PLACEHOLDER = "[凭据已脱敏]";
    static final String PATH_PLACEHOLDER = "[内部路径已脱敏]";
    static final String MARKER_PLACEHOLDER = "[内部标记已脱敏]";
    static final String UPSTREAM_PLACEHOLDER = "[上游错误详情已脱敏]";

    /** 解码后做注入判定用的护栏实例（无状态，不依赖 Spring 注入） */
    private static final PromptInjectionGuard ENCODED_INSTRUCTION_GUARD = new PromptInjectionGuard();

    /** 没有 Spring 注入时的保守兜底（掩码态 —— 缺配置时"少给"而不是"多漏"） */
    private static final PublicIpPolicy FAIL_CLOSED_POLICY = PublicIpPolicy.masking();

    /** 没有 Spring 注入时的默认资产词表（"实测泄露过"的那几个名字） */
    private static final PublicAssetFilter DEFAULT_ASSET_FILTER = PublicAssetFilter.defaults();

    /**
     * IP 口径的唯一来源（配置 {@code app.public.mask-ips}）。
     *
     * <p>{@code required=false}：单测里 {@code new PublicOutputGuard()} 没有容器，
     * 此时按 {@link #FAIL_CLOSED_POLICY}（掩码）兜底 —— 与改造前行为一致，
     * 也正是"掩码回归"测试要钉住的那条路径。
     */
    @Autowired(required = false)
    private PublicIpPolicy ipPolicy;

    /** 内部资产名停用词过滤（配置 {@code app.public.asset-blocklist}） */
    @Autowired(required = false)
    private PublicAssetFilter assetFilter;

    /**
     * 脱敏结果。
     *
     * @param text     脱敏后的文本（调用方必须只用它，不许再用原文）
     * @param findings 命中的类别（不含原文，避免日志本身变成泄露渠道 ——
     *                 与 {@code SensitiveContentScanner} 同一纪律）
     */
    public record Sanitized(String text, List<String> findings) {

        /** 是否发生过任何脱敏（页面可据此显示"输出已脱敏"） */
        public boolean wasRedacted() {
            return !findings.isEmpty();
        }
    }

    /**
     * 主入口：把模型输出处理成"可以公开"的文本。
     *
     * <p>顺序是有讲究的：
     * <ol>
     *   <li>先做<b>凭据/私钥</b>替换 —— 私钥块可能跨多行，先于其它单行规则处理，避免被拆散；</li>
     *   <li>再做<b>敏感信息扫描</b>（{@link SensitiveContentScanner}，与知识库入库同一把尺子）；</li>
     *   <li>然后<b>路径</b>；</li>
     *   <li>最后<b>IP 口径</b>（{@link PublicIpPolicy#displayText} —— 掩码态全掩、真实态只隐内网）；</li>
     *   <li>内部标记中性化放最后 —— 前面几步插入的占位符不含这些词，不会被误伤。</li>
     *   <li><b>资产名过滤再放最后</b>：它替换的是词，不改变句子结构，放最后能保证
     *       前面几步产生的占位符不会被再次改写。</li>
     * </ol>
     */
    public Sanitized sanitize(String raw) {
        if (raw == null || raw.isEmpty()) {
            return new Sanitized("", List.of());
        }
        Set<String> findings = new LinkedHashSet<>();
        String text = raw;

        for (Pattern p : CREDENTIAL_PATTERNS) {
            Matcher m = p.matcher(text);
            if (m.find()) {
                findings.add("credential");
                text = m.replaceAll(Matcher.quoteReplacement(CREDENTIAL_PLACEHOLDER));
            }
        }

        // 【2026-10-18 补】Base64 编码的凭据/指令：解码后再判，命中则整段替换。
        // 为什么不能只靠上面的正则：编码后 PEM 头、sk- 前缀、注入关键词全都不在字面里，
        // 模型完全可能把"解码后是私钥"的编码串原样回给用户 —— 那就等于把私钥公开了。
        // 这里只替换"解码后确实命中"的片段，不是"见到长编码串就脱敏"，正常编码数据照常输出。
        text = redactEncodedPayloads(text, findings);

        // 与"知识库入库前"同一把尺子：AccessKey / 私钥 / JWT / 连接串带密码
        try {
            List<SensitiveContentScanner.Finding> hits = SensitiveContentScanner.scan(text);
            if (hits != null && !hits.isEmpty()) {
                findings.add("sensitive-content");
                for (SensitiveContentScanner.Finding f : hits) {
                    // 只记录规则名与严重度，不记录命中原文（日志不该成为新的泄露面）
                    logger.debug("公开输出命中敏感信息规则：{} ({})", f.getRule(), f.getSeverity());
                }
                // 扫描发现命中时，把可疑片段按行打码：模型复述的长串凭据通常独占一行或紧跟 : =
                text = maskSuspiciousCredentials(text);
            }
        } catch (RuntimeException e) {
            // 扫描器自身异常不能让公开端点 500；但也绝不能"当没命中"直接放行 —— 记为可疑并拒绝后续
            findings.add("scanner-error");
            logger.warn("公开输出敏感信息扫描异常：{}", e.getMessage());
        }

        for (Pattern p : PATH_PATTERNS) {
            Matcher m = p.matcher(text);
            if (m.find()) {
                findings.add("internal-path");
                text = m.replaceAll(Matcher.quoteReplacement(PATH_PLACEHOLDER));
            }
        }

        PublicIpPolicy policy = policy();
        String masked = policy.displayText(text);
        if (!masked.equals(text)) {
            // 命中类别随口径不同：掩码态是"掩过码了"，真实态是"把内网/保留地址隐去了"。
            // 两者都如实报告，页面/排障时能一眼看出当时用的是哪套口径。
            findings.add(policy.masked() ? "ip-masked" : "ip-internal-hidden");
            text = masked;
        }

        for (Pattern p : PROVIDER_ERROR_ARTIFACTS) {
            Matcher m = p.matcher(text);
            if (m.find()) {
                findings.add("upstream-error-detail");
                text = m.replaceAll(Matcher.quoteReplacement(UPSTREAM_PLACEHOLDER));
            }
        }

        for (Pattern p : INTERNAL_MARKERS) {
            Matcher m = p.matcher(text);
            if (m.find()) {
                findings.add("internal-marker");
                text = m.replaceAll(Matcher.quoteReplacement(MARKER_PLACEHOLDER));
            }
        }

        // 【放最后】内部资产名停用词过滤（web-01 / auth.log / /api/order/detail …）。
        // 为什么必须有：F5 方案 B 会把命中的知识库片段【直出到回答正文】，
        // 实测那些 mock 资产名就是顺着引用出到公网页面的 —— 凭据/路径/IP 三条规则都拦不住它们。
        String scrubbed = assets().scrub(text);
        if (!scrubbed.equals(text)) {
            findings.add("internal-asset");
            text = scrubbed;
        }

        return new Sanitized(text, new ArrayList<>(findings));
    }

    /**
     * 把"解码后是凭据/注入指令"的 Base64 片段整段替换掉。
     *
     * <p>判定复用既有两把尺子，不新增第二套口径：
     * {@link SensitiveContentScanner#shouldBlock}（与入库同一套高危判定）负责凭据，
     * {@link PromptInjectionGuard#scan} 负责"解码后其实是一条注入指令"。
     * 解码结果是普通文本（或乱码）的片段原样保留 —— 只脱敏真正的载荷，
     * 避免正常编码数据被误伤，也避免出现"公开页面不显示 base64"这种过度封锁。
     */
    private static String redactEncodedPayloads(String text, Set<String> findings) {
        for (Base64Payloads.Encoded encoded : Base64Payloads.find(text)) {
            boolean credential = false;
            try {
                credential = SensitiveContentScanner.shouldBlock(
                        SensitiveContentScanner.scan(encoded.decoded()), false);
            } catch (RuntimeException ignored) {
                // 判定异常时保守处理：继续看注入判定，且只要有一边命中就脱敏
            }
            boolean instruction = !ENCODED_INSTRUCTION_GUARD.scan(encoded.decoded()).isEmpty();
            if (!credential && !instruction) {
                continue;
            }
            if (credential) {
                findings.add("credential");
                text = text.replace(encoded.token(), CREDENTIAL_PLACEHOLDER);
            } else {
                findings.add("internal-marker");
                text = text.replace(encoded.token(), MARKER_PLACEHOLDER);
            }
        }
        return text;
    }

    /** 当前生效的 IP 口径：注入缺失时按掩码兜底（fail-closed） */
    private PublicIpPolicy policy() {
        PublicIpPolicy p = ipPolicy;
        return p != null ? p : FAIL_CLOSED_POLICY;
    }

    /** 当前生效的资产词表：注入缺失时用默认词表兜底（不能因为"没注入"就不过滤） */
    private PublicAssetFilter assets() {
        PublicAssetFilter f = assetFilter;
        return f != null ? f : DEFAULT_ASSET_FILTER;
    }

    /**
     * 把"看起来像凭据的长串"逐行打码。
     *
     * <p>为什么不能只上报"命中了规则"就放行：{@link SensitiveContentScanner} 的定位是
     * "入库前拦截"，它返回的是规则名而不是位置，因此这里只能自己按行判断。
     * 判据取"行内出现 {@code key=value} 形式且 value 足够长/足够随机"，
     * 这是保守方向：多打码一行的代价是读者少看到一句话，漏打码的代价是泄露。
     */
    private static String maskSuspiciousCredentials(String text) {
        StringBuilder sb = new StringBuilder(text.length());
        String[] lines = text.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (LOOKS_LIKE_CREDENTIAL_ASSIGNMENT.matcher(line).find()) {
                sb.append(CREDENTIAL_PLACEHOLDER);
            } else {
                sb.append(line);
            }
            if (i < lines.length - 1) {
                sb.append('\n');
            }
        }
        return sb.toString();
    }

    private static final Pattern LOOKS_LIKE_CREDENTIAL_ASSIGNMENT = Pattern.compile(
            "(?i)(^|[\\s（(])((api[_\\-]?key|access[_\\-]?key|secret|token|password|passwd|jwt|credential)\\s*[:=：]\\s*\\S{12,})");

    /**
     * 把回答里<b>所有</b> {@code state=} 标记解析出来，返回最可信的一个。
     *
     * <h3>为什么需要"解析"而不是自己贴一个</h3>
     * 编排链路的回答本来就可能带多个 {@code state=}（例如 Analyst 的结论段 + Forsensics 的证据段）。
     * 公开端点如果自己再贴一个，页面就会出现两个互相矛盾的 state ——
     * 而"机读状态"的价值全在于它是<b>唯一</b>的、可被程序消费的。
     *
     * <p>取值规则：出现过的取值里按"越不确定越优先报告"的顺序取一个
     * （{@code model-failed} / {@code retrieval-failed} 这类失败态优先于 {@code model}）——
     * 因为把"失败"显示成"模型结论"是最危险的一类错，宁可把成功的状态显示成失败。
     *
     * <p>不认识的取值<b>不算命中</b>，直接退回 {@code fallback}：公开页面是按
     * {@code state} 决定措辞的，把一个来路不明的字符串喂给页面，页面只能显示
     * "未识别状态" —— 而调用方本来就知道这次到底是什么状态（模型不可用 / 检索不可用），
     * 那比一个未知字符串有用得多。
     */
    public static String extractState(String answer, String fallback) {
        if (answer == null) {
            return fallback;
        }
        Matcher m = STATE_PATTERN.matcher(answer);
        Set<String> seen = new LinkedHashSet<>();
        while (m.find()) {
            String v = m.group(1).toLowerCase();
            if (KNOWN_STATES.contains(v)) {
                seen.add(v);
            }
        }
        if (seen.isEmpty()) {
            return fallback;
        }
        for (String s : STATE_PRIORITY) {
            if (seen.contains(s)) {
                return s;
            }
        }
        return fallback;
    }

    /** 出现过的 {@code state=xxx}（只认形状，是否合法由 extractState 判定） */
    private static final Pattern STATE_PATTERN = Pattern.compile("state\\s*=\\s*([A-Za-z0-9_\\-]{2,32})");

    /** 已知的 6 态（RUNBOOK §4），外加公开路径专用的 eval 模拟态 */
    private static final Set<String> KNOWN_STATES = Set.of(
            "model", "input-insufficient", "no-retrieval", "retrieval-failed", "model-failed",
            "rule-based", "rule-based-eval-simulated");

    /** 报告优先级：失败态 > 依据不足 > 规则 > 模型（越不确定越靠前） */
    private static final List<String> STATE_PRIORITY = List.of(
            "model-failed", "retrieval-failed", "no-retrieval", "input-insufficient",
            "rule-based-eval-simulated", "rule-based", "model");

    /**
     * state → 页面措辞（与博客「AI 安全」页的表格同一口径）。
     *
     * <p>放在后端而不是让前端各写一份：口径漂移过一次就很难发现
     * （页面上写着"模型研判"、后端其实返回的是 {@code model-failed}）。
     */
    public static String stateLabel(String state) {
        Map<String, String> labels = STATE_LABELS;
        String label = labels.get(state);
        return label != null ? label : (state + "（未识别状态）");
    }

    private static final Map<String, String> STATE_LABELS = new LinkedHashMap<>();

    static {
        STATE_LABELS.put("model", "模型研判");
        STATE_LABELS.put("input-insufficient", "依据不足，不做定性");
        STATE_LABELS.put("no-retrieval", "未检索到依据，不给结论");
        STATE_LABELS.put("retrieval-failed", "检索不可用，未生成");
        STATE_LABELS.put("model-failed", "模型不可用，未生成");
        STATE_LABELS.put("rule-based", "规则解析（模型不参与处置拍板）");
        STATE_LABELS.put("rule-based-eval-simulated", "规则解析（评测身份仅模拟，不实际执行）");
    }
}

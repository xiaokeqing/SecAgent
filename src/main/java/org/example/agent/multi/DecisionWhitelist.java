package org.example.agent.multi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * T14 情绪决策的<b>白名单</b>（38 个剪辑名 / 9 个宿主入口 / 8 类情绪 / 12 句已上线台词 id）。
 *
 * <h3>为什么必须落成 jar 内资源，而不是写死在 Java 里</h3>
 * 这些名字全部来自站点素材（{@code static/kurisu/statemachine.json}、
 * {@code voice/bank.json}、{@code manifest.json}）——素材一改名字集合就变。
 * 写死在代码里 = 下一次素材改动必然漂，而且是<b>静默</b>漂：模型选了不存在的剪辑名，
 * 前端查不到就什么都不做（不报错、只是演错）。所以真值由
 * {@code kurisu/decision-whitelist.json} 随 jar 一起发布，资源里带 {@code generatedFrom}
 * 记录三个源文件的 md5，部署后用启动自检行的 {@code decision=whitelist{…,md5=…}} 核对。
 *
 * <h3>读不到时 fail-closed</h3>
 * 打 WARN、按<b>空集</b>处理：所有值判非法 ⇒ 每条回答都走语义安全的回退决策
 * （{@code normal / idle / ""}）。刻意不在启动期抛异常（白名单坏掉不该让应用起不来），
 * 但也绝不静默 —— 应用启动日志里有一行 {@code decision=whitelist{MISSING}}。
 * 这与 {@code TtsPhrases}「读不到按空表处理 + WARN」是同一条纪律。
 */
@Component
public class DecisionWhitelist {

    private static final Logger logger = LoggerFactory.getLogger(DecisionWhitelist.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 决策契约版本（前端据此判断"认不认识这段结构"，不认识就整段不消费） */
    public static final String SCHEMA_VERSION = "xiaokeqing.kurisu.decision.v1";

    /** 契约里"只出字幕不出声"的合法值：空串不是错误 */
    public static final String NO_LINE = "";

    /**
     * 情绪标签协议（{@code [EMO:xxx]}）的唯一词表 —— 与白名单 JSON 的 {@code emotions} 同源同值。
     *
     * <p>提示词里写"标签只能取这几个值"时引用这里，而不是各写一份字面量：写死在提示词里的
     * 词表会与资源漂移，而漂移的表现是"她演错情绪"，很难从日志看出来。
     * 反查来源：{@link #isEmotion(String)} 校验的就是资源里的 {@code emotions} 数组，
     * 两份一致性由 {@code PersonaPromptTest} 钉住。
     */
    public static final List<String> EMOTION_VALUES = List.of(
            "angry", "blush", "disappointed", "happy", "normal", "sad", "sided_surprised", "sided_thinking");

    @Value("${app.decision.whitelist:classpath:kurisu/decision-whitelist.json}")
    private Resource resource;

    private Set<String> actions = Set.of();
    private Set<String> hostEntries = Set.of();
    private Set<String> emotions = Set.of();
    private Set<String> lineIds = Set.of();
    private Set<String> lineIdsPlanned = Set.of();
    private Set<String> clipsNotInGraph = Set.of();
    private String fallbackLineId = "fallback_no_data";
    private String md5 = "MISSING";
    private boolean loaded;

    @jakarta.annotation.PostConstruct
    void load() {
        try (InputStream in = resource.getInputStream()) {
            byte[] bytes = in.readAllBytes();
            JsonNode n = MAPPER.readTree(new String(bytes, StandardCharsets.UTF_8));
            actions = set(n.path("actions"));
            hostEntries = set(n.path("hostTriggeredEntries"));
            emotions = set(n.path("emotions"));
            lineIds = set(n.path("lineIds"));
            lineIdsPlanned = set(n.path("lineIdsPlanned"));
            clipsNotInGraph = set(n.path("clipsNotInGraph"));
            fallbackLineId = n.path("fallbackLineId").asText("fallback_no_data");
            md5 = hex(MessageDigest.getInstance("MD5").digest(bytes)).substring(0, 8);
            loaded = !actions.isEmpty() && !emotions.isEmpty() && !lineIds.isEmpty();
            if (!loaded) {
                logger.warn("T14 决策白名单内容为空（{}）：所有决策字段判非法并回退", resource);
            }
        } catch (Exception e) {
            loaded = false;
            logger.warn("T14 决策白名单加载失败（按空集处理 ⇒ 所有决策字段判非法并回退，不静默放行）：{}",
                    e.getMessage());
        }
    }

    private static Set<String> set(JsonNode a) {
        Set<String> s = new LinkedHashSet<>();
        if (a != null && a.isArray()) {
            a.forEach(x -> {
                if (x.isTextual() && !x.asText().isBlank()) {
                    s.add(x.asText().trim());
                }
            });
        }
        return s;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }

    // ==================== 校验 ====================

    public boolean isAction(String a) {
        return loaded && a != null && actions.contains(a);
    }

    public boolean isLine(String id) {
        return loaded && id != null && lineIds.contains(id);
    }

    public boolean isEmotion(String e) {
        return loaded && e != null && emotions.contains(e);
    }

    /** 是否属于"60 句计划里但尚未入库"的 id（命中即判非法，但报错原因要与"纯幻觉"区分） */
    public boolean isPlannedLine(String id) {
        return id != null && lineIdsPlanned.contains(id) && !lineIds.contains(id);
    }

    /** 是否属于"素材里有、但不在状态机 38 节点内"的剪辑名（如 sad/smile） */
    public boolean isNotInGraph(String clip) {
        return clip != null && clipsNotInGraph.contains(clip);
    }

    public boolean loaded() {
        return loaded;
    }

    public String md5() {
        return md5;
    }

    public Set<String> actions() {
        return actions;
    }

    public Set<String> hostEntries() {
        return hostEntries;
    }

    public Set<String> emotions() {
        return emotions;
    }

    public Set<String> lineIds() {
        return lineIds;
    }

    public String fallbackLineId() {
        return fallbackLineId;
    }

    /**
     * 拼进系统提示的清单（T14 §2.3-J3）。
     *
     * <p>清单<b>不写死</b>在提示词常量里：常量会与资源漂移，而这里每次请求都按当前资源拼。
     * 长度实测约 750 字符（38 个剪辑名本身就占 581）—— 原改动包建议"≤600 字符"，
     * 但砍掉动作列表等于让模型自创名字，所以保留完整清单，用
     * {@code AnalystVerdictTest#promptHintIsBounded} 钉住上限（&lt;900 字符）。
     */
    public String promptHint() {
        return "【可选动作清单（只能从这里选）】" + String.join(",", actions)
                + "。【可选台词 id（只能从这里选，或写空字符串）】" + String.join(",", lineIds) + "。";
    }

    // ==================== 契约工厂 ====================

    /**
     * 语义安全的回退决策 —— <b>唯一实现</b>（编排层与公开问答层共用，避免两份慢慢不一致）。
     *
     * <p>回退目标必须是语义安全的：`normal` 情绪 / `idle` 动作 / 空台词 id。
     * 红线是"任何一个字段非法都不许就地猜一个再播"——猜错情绪 = 她当场演错，
     * 比不演严重得多。
     *
     * @param why 回退原因（写进 {@code rejectReason}，前端据此如实标注）
     */
    public static Map<String, Object> fallbackDecision(String why) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("schemaVersion", SCHEMA_VERSION);
        m.put("emotionFrom", "normal");
        m.put("emotionTo", "normal");
        m.put("action", "idle");
        m.put("lineId", NO_LINE);
        m.put("urgency", 0.0);
        m.put("reason", "");
        m.put("citations", List.of());
        m.put("fallbackUsed", true);
        m.put("rejectReason", why == null ? "" : why);
        return m;
    }

    /** 供测试与排障：把一个 Map 的 rejectReason 拆成列表 */
    public static List<String> rejectsOf(Map<String, Object> decision) {
        List<String> out = new ArrayList<>();
        Object r = decision == null ? null : decision.get("rejectReason");
        if (r != null && !String.valueOf(r).isBlank()) {
            for (String s : String.valueOf(r).split("\\|")) {
                if (!s.isBlank()) {
                    out.add(s);
                }
            }
        }
        return out;
    }
}

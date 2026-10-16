package org.example.selfapi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 自用面的 <b>3~5 轮对话窗口</b>（仅登录面启用）。
 *
 * <h3>为什么公开面【不】给窗口</h3>
 * 多轮 = 更多上下文 token = 更多成本，而公开面是匿名可达的。
 * 「匿名 + 无限记忆」是成本漏洞，不是体验优化。所以窗口只挂在 {@code X-User-Token} 命中的路径上。
 *
 * <h3>为什么存储在进程内、且允许重启即清</h3>
 * 自用池是<b>一个用户</b>在用。为它引入 Redis / 数据库，等于把"登录功能"变成
 * "多一个必须运维的中间件" —— 而它的收益只是"重启后还记得刚才聊到哪"。
 * 站主明确说"内存或轻量存储"，所以这里就是 {@code ConcurrentHashMap}。
 *
 * <h3>三个上限（都不依赖调用方自觉）</h3>
 * <ul>
 *   <li><b>轮数上限</b>（默认 5，允许 3~5）：超出时逐出最旧的一轮 ——
 *       不是"拒绝新提问"，因为使用者是站主，窗口满了该忘掉旧的是自然语义；</li>
 *   <li><b>过期</b>（默认 30 分钟）：超过即当新会话，历史不参与上下文；</li>
 *   <li><b>会话总数</b>（默认 200）：超出按最久未访问淘汰 ——
 *       防"伪造 conversationId 撑内存"（攻击者能拿到令牌时才谈得上，但边界要写在代码里）。</li>
 * </ul>
 *
 * <p>历史格式与 {@code ChatController.SessionInfo} 一致：
 * 每个元素形如 {@code {"role":"user|assistant","content":"…"}}，
 * 这样 {@code OrchestrationService.run(question, history, deadline)} 不需要任何适配。
 */
@Component
public class UserConversationStore {

    private static final Logger logger = LoggerFactory.getLogger(UserConversationStore.class);

    /** 窗口轮数上限（3~5；越界值在这里夹回，配置写错也不会变成"无限窗口"） */
    @Value("${app.user.conversation.max-rounds:5}")
    private int maxRounds;

    /** 会话过期（分钟） */
    @Value("${app.user.conversation.ttl-minutes:30}")
    private int ttlMinutes;

    /** 同时跟踪的会话数上限 */
    @Value("${app.user.conversation.max-conversations:200}")
    private int maxConversations;

    private final Map<String, Conversation> conversations = new ConcurrentHashMap<>();

    /** 生效的轮数上限（夹到 3~5；供响应如实回显 + 单测断言） */
    public int effectiveMaxRounds() {
        return Math.min(5, Math.max(3, maxRounds));
    }

    public int ttlMinutes() {
        return Math.max(1, ttlMinutes);
    }

    /**
     * 取一个会话的历史（只读副本）。
     *
     * <p>会话不存在 / 已过期 ⇒ 返回<b>空历史</b>，并顺手清掉过期项。
     * 返回空历史而不是抛异常：对使用者而言"新会话"是正常状态，不是错误。
     */
    public List<Map<String, String>> history(String conversationId) {
        Conversation c = live(conversationId);
        if (c == null) {
            return List.of();
        }
        synchronized (c) {
            return copy(c.rounds);
        }
    }

    /**
     * 追加一轮（一问一答），并返回追加后窗口内的轮数。
     *
     * <p>超上限时逐出最旧的一轮 —— 窗口语义是「记住最近 N 轮」。
     */
    public int append(String conversationId, String question, String answer) {
        String id = normalizeId(conversationId);
        evictIfNeeded();
        Conversation c = conversations.computeIfAbsent(id, k -> new Conversation());
        synchronized (c) {
            c.rounds.addLast(new Round(question == null ? "" : question, answer == null ? "" : answer));
            c.lastAccess = System.currentTimeMillis();
            while (c.rounds.size() > effectiveMaxRounds()) {
                c.rounds.removeFirst();
            }
            return c.rounds.size();
        }
    }

    /** 当前窗口内的轮数（不计数、不创建） */
    public int rounds(String conversationId) {
        Conversation c = live(conversationId);
        if (c == null) {
            return 0;
        }
        synchronized (c) {
            return c.rounds.size();
        }
    }

    /** 清空一个会话 */
    public void clear(String conversationId) {
        conversations.remove(normalizeId(conversationId));
    }

    /** 会话是否仍然活着（未过期）；顺手淘汰过期项 */
    private Conversation live(String conversationId) {
        if (conversationId == null || conversationId.isBlank()) {
            return null;
        }
        Conversation c = conversations.get(conversationId.trim());
        if (c == null) {
            return null;
        }
        long ttlMs = ttlMinutes() * 60_000L;
        if (System.currentTimeMillis() - c.lastAccess > ttlMs) {
            conversations.remove(conversationId.trim(), c);
            return null;
        }
        return c;
    }

    /** 会话总数超上限：按最久未访问淘汰（含过期项一并清） */
    private void evictIfNeeded() {
        int cap = Math.max(1, maxConversations);
        if (conversations.size() <= cap) {
            return;
        }
        long ttlMs = ttlMinutes() * 60_000L;
        long now = System.currentTimeMillis();
        conversations.entrySet().removeIf(e -> now - e.getValue().lastAccess > ttlMs);
        while (conversations.size() > cap) {
            String oldestKey = null;
            long oldest = Long.MAX_VALUE;
            for (Map.Entry<String, Conversation> e : conversations.entrySet()) {
                if (e.getValue().lastAccess < oldest) {
                    oldest = e.getValue().lastAccess;
                    oldestKey = e.getKey();
                }
            }
            if (oldestKey == null) {
                return;
            }
            conversations.remove(oldestKey);
            logger.info("自用会话数超过上限 {}，已淘汰最久未访问的会话（只记哈希级标识，不记原值）",
                    cap);
        }
    }

    private static List<Map<String, String>> copy(Deque<Round> rounds) {
        List<Map<String, String>> out = new ArrayList<>(rounds.size() * 2);
        for (Round r : rounds) {
            out.add(Map.of("role", "user", "content", r.question));
            out.add(Map.of("role", "assistant", "content", r.answer));
        }
        return out;
    }

    /** 会话 id 归一化：空白 ⇒ 归入一个默认桶；同时截断超长 id（防用它撑内存） */
    static String normalizeId(String conversationId) {
        if (conversationId == null || conversationId.isBlank()) {
            return "default";
        }
        String v = conversationId.trim();
        return v.length() > 64 ? v.substring(0, 64) : v;
    }

    private static final class Conversation {
        private final Deque<Round> rounds = new ArrayDeque<>();
        private volatile long lastAccess = System.currentTimeMillis();
    }

    private record Round(String question, String answer) {
    }
}

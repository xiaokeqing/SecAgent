package org.example.selfapi;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 自用面 3~5 轮对话窗口的行为测试。
 *
 * <h3>为什么窗口值得单独测</h3>
 * 它的失败模式都很安静：
 * <ul>
 *   <li><b>轮数没夹住</b> ⇒ 上下文无限增长（成本涨，且没人会收到报错）；</li>
 *   <li><b>过期没生效</b> ⇒ 站主半小时后再问，模型却还记得半小时前的话题（
 *       "看起来更聪明"，实际是把过期数据当有效上下文）；</li>
 *   <li><b>历史格式不对</b> ⇒ 编排层拿到的不是 {@code role/content}，多轮直接失效，
 *       而表现只是"它好像忘了刚才说的话"。</li>
 * </ul>
 */
class UserConversationStoreTest {

    private UserConversationStore store;

    @BeforeEach
    void setUp() {
        store = new UserConversationStore();
        ReflectionTestUtils.setField(store, "maxRounds", 5);
        ReflectionTestUtils.setField(store, "ttlMinutes", 30);
        ReflectionTestUtils.setField(store, "maxConversations", 200);
    }

    @Test
    @DisplayName("【核心】窗口最多保留 5 轮：第 6 轮把第 1 轮挤出去")
    void windowKeepsAtMostFiveRounds() {
        assertEquals(5, store.effectiveMaxRounds());
        for (int i = 1; i <= 6; i++) {
            store.append("c1", "问题" + i, "回答" + i);
        }
        assertEquals(5, store.rounds("c1"), "轮数必须停在 5");

        List<Map<String, String>> history = store.history("c1");
        assertEquals(10, history.size(), "5 轮 = 10 条消息（user + assistant）");
        // 顺序必须是"最旧 → 最新"，且第 1 轮已被挤掉
        assertEquals("问题2", history.get(0).get("content"), "最早的应是第 2 轮（第 1 轮被逐出）");
        assertEquals("问题6", history.get(8).get("content"), "最新的应是第 6 轮");
        assertFalse(history.stream().anyMatch(m -> "问题1".equals(m.get("content"))),
                "被逐出的第 1 轮不得再出现");
    }

    @Test
    @DisplayName("历史格式是 role/content（编排层直接可用），且分 user / assistant 交替")
    void historyShapeMatchesOrchestrationContract() {
        store.append("c2", "Q", "A");
        List<Map<String, String>> history = store.history("c2");
        assertEquals(2, history.size());
        assertEquals("user", history.get(0).get("role"));
        assertEquals("Q", history.get(0).get("content"));
        assertEquals("assistant", history.get(1).get("role"));
        assertEquals("A", history.get(1).get("content"));
    }

    @Test
    @DisplayName("会话彼此隔离：别人的历史不会串进来")
    void conversationsAreIsolated() {
        store.append("a", "QA", "AA");
        store.append("b", "QB", "AB");
        store.append("b", "QB2", "AB2");

        assertEquals(1, store.rounds("a"));
        assertEquals(2, store.rounds("b"));
        assertEquals("QA", store.history("a").get(0).get("content"));
        assertEquals("QB", store.history("b").get(0).get("content"), "b 的历史起点是它自己的第一轮");
        assertEquals(0, store.rounds("never-seen"), "没见过的会话轮数为 0");
        assertTrue(store.history("never-seen").isEmpty());
    }

    @Test
    @DisplayName("【过期】TTL 之后历史归零（旧话题不得参与上下文）")
    void expiredConversationForgetsHistory() throws Exception {
        ReflectionTestUtils.setField(store, "ttlMinutes", 30);
        store.append("c3", "旧问题", "旧回答");
        assertEquals(1, store.rounds("c3"));

        // 把 lastAccess 直接拨回 31 分钟前（比 sleep 更确定，也不会让测试变慢）
        backdate("c3", 31 * 60_000L);

        assertEquals(0, store.rounds("c3"), "过期后轮数必须归零");
        assertTrue(store.history("c3").isEmpty(), "过期后不得再返回旧历史");
    }

    @Test
    @DisplayName("配置越界时轮数夹回 3~5（配错不会变成无上限窗口）")
    void roundsAreClamped() {
        ReflectionTestUtils.setField(store, "maxRounds", 99);
        assertEquals(5, store.effectiveMaxRounds(), "超过 5 夹到 5");
        ReflectionTestUtils.setField(store, "maxRounds", 1);
        assertEquals(3, store.effectiveMaxRounds(), "低于 3 夹到 3");
    }

    @Test
    @DisplayName("会话 id 归一化：空白归入默认桶、超长截断（防用它撑内存）")
    void conversationIdIsNormalized() {
        assertEquals("default", UserConversationStore.normalizeId(null));
        assertEquals("default", UserConversationStore.normalizeId("   "));
        assertEquals("x", UserConversationStore.normalizeId(" x "));
        assertEquals(64, UserConversationStore.normalizeId("y".repeat(200)).length());
    }

    /** 把某个会话的 lastAccess 拨回指定毫秒数之前（字段是 volatile long，反射可写） */
    private void backdate(String conversationId, long millisAgo) throws Exception {
        Field conversationsField = UserConversationStore.class.getDeclaredField("conversations");
        conversationsField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<String, Object> conversations = (Map<String, Object>) conversationsField.get(store);
        Object conversation = conversations.get(conversationId);
        assertTrue(conversation != null, "测试自身前提：会话应当存在");
        Field lastAccess = conversation.getClass().getDeclaredField("lastAccess");
        lastAccess.setAccessible(true);
        lastAccess.setLong(conversation, System.currentTimeMillis() - millisAgo);
    }
}

package org.example.mcp;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * MCP server 里唯一的 JSON 出入口。
 *
 * <p>为什么不直接各处 new ObjectMapper()：stdio 协议下"输出必须是纯 JSON-RPC、一个多余字节都不能混进去"，
 * 集中一处才能保证序列化口径（UTF-8、不缩进、不抛 checked）唯一。
 * 依赖只有 Jackson Databind —— 它本来就是这个仓库的编译期依赖（见 pom：jackson.version），
 * 因此**没有为这个 MCP server 新增任何第三方包**。
 */
public final class Json {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Json() {
    }

    public static ObjectMapper mapper() {
        return MAPPER;
    }

    /** 序列化成一行 JSON（换行由协议层按帧补，不在这里加）。 */
    public static String write(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (IOException e) {
            // 到这一步说明对象里有 Jackson 处理不了的形状（自引用等），属于编码错误，不能静默吞掉
            throw new IllegalStateException("JSON 序列化失败：" + e.getMessage(), e);
        }
    }

    public static ObjectNode object() {
        return MAPPER.createObjectNode();
    }

    /** 把一段 JSON 文本读成 Map；空文本/空白返回空 Map（不返回 null，调用方少一层判空）。 */
    public static Map<String, Object> readObject(String raw) throws IOException {
        if (raw == null || raw.isBlank()) {
            return new LinkedHashMap<>();
        }
        Map<String, Object> m = MAPPER.readValue(raw, new TypeReference<LinkedHashMap<String, Object>>() {
        });
        return m == null ? new LinkedHashMap<>() : m;
    }
}

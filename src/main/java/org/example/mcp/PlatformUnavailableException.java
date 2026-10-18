package org.example.mcp;

/**
 * 平台数据源不可用 / 参数被上游拒绝。
 *
 * <p>带 {@code code} 而不是只带一句人类可读的话：下游（MCP 客户端、smoke 脚本）
 * 需要机器可判的失败原因（{@code UPSTREAM_UNAVAILABLE}、{@code INVALID_IP}、{@code HTTP_400} …），
 * 只给字符串会逼着调用方去匹配自然语言。
 */
public class PlatformUnavailableException extends Exception {

    private final String code;

    public PlatformUnavailableException(String code, String message) {
        super(message);
        this.code = code;
    }

    public PlatformUnavailableException(String code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public String code() {
        return code;
    }
}

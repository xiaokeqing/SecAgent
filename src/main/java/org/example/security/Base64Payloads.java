package org.example.security;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Base64 编码载荷的「先解码、再判定」工具。
 *
 * <h3>为什么需要它</h3>
 * 红队回归里有两条绕过是把攻击意图整体 Base64 编码后塞进请求/文档的：
 * <ul>
 *   <li>{@code rt-bp-pi-base64-23}：指令 {@code ignore all previous instructions}
 *       编码成 {@code aWdub3Jl...}，纯关键词匹配一个特征都不命中；</li>
 *   <li>{@code rt-bp-dlp-b64-26}：{@code -----BEGIN RSA PRIVATE KEY-----}
 *       编码成 {@code LS0tLS1CRUdJTi...}，扫描器看不到 PEM 头。</li>
 * </ul>
 * 这类绕过的本质不是"新话术"，而是<b>换了一层编码</b>。所以正确修法不是"见长串 Base64 就拦"
 * （那会把 base64 图片、哈希、校验值、正常文档里的编码数据全打成误报），
 * 而是：<b>把编码片段还原成文本，再交给现有的同一套特征去判</b>。
 * 解码出来是普通文本的，判定结果与没编码时完全一致。
 *
 * <h3>边界</h3>
 * <ul>
 *   <li>只认长度 ≥16 的编码片段：正常凭据/指令编码后不会太短，短片段解码噪声大；</li>
 *   <li>解码结果必须"大部分可读"（{@link #MIN_PRINTABLE_RATIO}）：二进制、哈希、
 *       JPEG 头解码出来是乱码，占比不够就不当文本看；</li>
 *   <li>单次最多处理 {@link #MAX_CANDIDATES} 个片段、单个片段最长
 *       {@link #MAX_TOKEN_LENGTH}，避免长文档里的解码开销；</li>
 *   <li>同时兼容标准字母表与 URL-safe 字母表（{@code - _} 折叠成 {@code + /}），
 *       尾部不足 4 位时补 {@code =}。</li>
 * </ul>
 *
 * <p>本类是无状态工具：不做判定、不产生副作用，判定由调用方（
 * {@link PromptInjectionGuard} / {@link SensitiveContentScanner} /
 * {@code PublicOutputGuard}）用原有特征完成，避免同一份规则出现两套口径。
 */
public final class Base64Payloads {

    private Base64Payloads() {
    }

    /** 一个被识别出的编码片段及解码结果；{@code token} 保留原文，便于调用方整段替换/脱敏。 */
    public record Encoded(String token, String decoded) {
    }

    /**
     * 候选编码片段：Base64 字母表（含 URL-safe 的 {@code - _}），长度至少 16，尾部允许补位。
     *
     * <p>故意不锚定词边界：请求里常见"请先解码再执行：aWdub3Jl..."这种紧贴中文冒号/空格的写法。
     */
    private static final Pattern CANDIDATE =
            Pattern.compile("[A-Za-z0-9+/_-]{16,}={0,2}");

    /** 单片段长度上限：正常编码载荷远小于此，超出视为非文本数据，不做解码。 */
    private static final int MAX_TOKEN_LENGTH = 8192;

    /** 单次最多解码的片段数。 */
    private static final int MAX_CANDIDATES = 16;

    /** 解码结果中可读字符的最低占比；低于此值说明原始字节不是文本（二进制/哈希）。 */
    private static final double MIN_PRINTABLE_RATIO = 0.85;

    /**
     * 扫描文本里的 Base64 片段并尝试解码。
     *
     * @param text 原始文本，可为 {@code null}
     * @return 成功解码且看起来是文本的片段，按出现顺序去重；无命中时返回空列表
     */
    public static List<Encoded> find(String text) {
        List<Encoded> out = new ArrayList<>();
        if (text == null || text.isEmpty()) {
            return out;
        }
        Set<String> seen = new LinkedHashSet<>();
        Matcher m = CANDIDATE.matcher(text);
        while (m.find() && out.size() < MAX_CANDIDATES) {
            String token = m.group();
            if (token.length() > MAX_TOKEN_LENGTH || !seen.add(token)) {
                continue;
            }
            String decoded = tryDecode(token);
            if (decoded == null || decoded.length() < 4 || decoded.equals(text)) {
                continue;
            }
            if (!isMostlyReadable(decoded)) {
                continue;
            }
            out.add(new Encoded(token, decoded));
        }
        return out;
    }

    /**
     * 只取解码文本，供"把解码结果当作第二份输入再扫一遍"的调用方使用。
     *
     * @param text 原始文本，可为 {@code null}
     * @return 解码后的文本列表（可能为空）
     */
    public static List<String> decodedTexts(String text) {
        List<String> decoded = new ArrayList<>();
        for (Encoded encoded : find(text)) {
            decoded.add(encoded.decoded());
        }
        return decoded;
    }

    private static String tryDecode(String token) {
        String normalized = token.replace('-', '+').replace('_', '/');
        int pad = (4 - normalized.length() % 4) % 4;
        if (pad > 0) {
            normalized = normalized + "=".repeat(pad);
        }
        try {
            byte[] bytes = Base64.getDecoder().decode(normalized);
            // UTF-8 解码：非法字节被替换成 U+FFFD，由 isMostlyReadable 判掉
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static boolean isMostlyReadable(String s) {
        if (s.isEmpty()) {
            return false;
        }
        int readable = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\n' || c == '\r' || c == '\t') {
                readable++;
                continue;
            }
            if (c == '\uFFFD' || Character.isISOControl(c)) {
                continue;
            }
            readable++;
        }
        return (double) readable / s.length() >= MIN_PRINTABLE_RATIO;
    }
}

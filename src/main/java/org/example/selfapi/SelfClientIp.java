package org.example.selfapi;

import jakarta.servlet.http.HttpServletRequest;

/**
 * 自用面取调用方 IP（唯一入口）。
 *
 * <h3>为什么本包自带一份，而不是复用公开面的同名方法</h3>
 * 两条面要求互相隔离（见 {@code SelfApiIsolationTest}），而这段取 IP 的口径
 * 将来很可能各改各的（例如自用面只信任隧道头，公开面信任 CF 头）——
 * 共用一个私有方法会让"改一边"变成"改两边"，且没有任何编译期或测试期的提示。
 *
 * <p><b>边界说明（与公开面同一口径）</b>：{@code CF-Connecting-IP} / {@code X-Forwarded-For}
 * 在<b>直连</b>场景下可被伪造，因此它的用途只有两个：限速与审计掩码。
 * <b>不</b>作为任何身份判定依据 —— 身份只由令牌哈希决定。
 */
final class SelfClientIp {

    private SelfClientIp() {
    }

    static String resolve(HttpServletRequest req) {
        if (req == null) {
            return "unknown";
        }
        String cf = req.getHeader("CF-Connecting-IP");
        if (cf != null && !cf.isBlank()) {
            return cf.trim();
        }
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            int comma = xff.indexOf(',');
            return (comma > 0 ? xff.substring(0, comma) : xff).trim();
        }
        String remote = req.getRemoteAddr();
        return (remote == null || remote.isBlank()) ? "unknown" : remote;
    }
}

package org.example.publicapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 公开问答的<b>输出护栏 + 脱敏</b>测试（P4 的四道护栏里的 ②③）。
 *
 * <h3>为什么它必须有自己的测试</h3>
 * 这一层是"最后一道出海闸门"。它失效的表现不是报错，而是
 * <b>把内网地址 / 凭据 / 内部路径正常地返回给匿名访客</b> —— 接口 200、页面好看、
 * 没有任何异常日志。项目里已经真实漏过一次（结构化字段掩码了，自由文本里内嵌的 IP 漏出去），
 * 所以这里对每个类别都单独断言，而不是只测一条"看起来很安全"的样本。
 */
class PublicOutputGuardTest {

    private final PublicOutputGuard guard = new PublicOutputGuard();

    @Test
    @DisplayName("自由文本里内嵌的公网 IP 必须被掩码（实测漏过这一处）")
    void masksPublicIpInsideFreeText() {
        PublicOutputGuard.Sanitized s = guard.sanitize(
                "蜜罐记录：新的 SSH 连接来自 106.37.205.248，随后尝试登录 root。");

        assertFalse(s.text().contains("106.37.205.248"), "完整 IP 不得出现在公开回答里：" + s.text());
        assertTrue(s.text().contains("106.37.***.***"), "应保留网段级掩码：" + s.text());
        assertTrue(s.findings().contains("ip-masked"), "命中类别应含 ip-masked：" + s.findings());
    }

    @Test
    @DisplayName("内网地址写成「内部地址」，而不是掩码后的 10.0.***.***（后者也泄露了内网段）")
    void privateIpBecomesInternalAddress() {
        PublicOutputGuard.Sanitized s = guard.sanitize(
                "建议对 10.20.30.40 做处置，同时留意 192.168.1.9 与 172.16.5.5 的横向移动。");

        assertFalse(s.text().contains("10.20."), "不得暴露内网段：" + s.text());
        assertFalse(s.text().contains("192.168."), "不得暴露内网段：" + s.text());
        assertFalse(s.text().contains("172.16."), "不得暴露内网段：" + s.text());
        assertTrue(s.text().contains("内部地址"), "应写为「内部地址」：" + s.text());
    }

    @Test
    @DisplayName("凭据形态（API Key / Bearer / 私钥块 / key=value）必须被打码")
    void redactsCredentials() {
        PublicOutputGuard.Sanitized s = guard.sanitize(
                "示例：api_key=sk-abcdef0123456789abcdef\n"
                        + "调用时带 Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefg\n"
                        + "配置 access_key_secret=AKIAIOSFODNN7EXAMPLE");

        assertFalse(s.text().contains("sk-abcdef0123456789abcdef"), "API Key 不得透出：" + s.text());
        assertFalse(s.text().contains("eyJhbGciOiJIUzI1NiJ9"), "JWT 不得透出：" + s.text());
        assertFalse(s.text().contains("AKIAIOSFODNN7EXAMPLE"), "AK 不得透出：" + s.text());
        assertTrue(s.text().contains(PublicOutputGuard.CREDENTIAL_PLACEHOLDER), "应出现凭据占位符：" + s.text());
        assertTrue(s.findings().contains("credential"), "命中类别应含 credential：" + s.findings());
    }

    @Test
    @DisplayName("私钥块整体打码（跨多行）")
    void redactsPrivateKeyBlock() {
        String raw = "文档里的示例：\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234\nabcd5678\n-----END RSA PRIVATE KEY-----\n以上仅供演示。";
        PublicOutputGuard.Sanitized s = guard.sanitize(raw);

        assertFalse(s.text().contains("MIIEowIBAAKCAQEA"), "私钥内容不得透出：" + s.text());
        assertFalse(s.text().contains("BEGIN RSA PRIVATE KEY"), "私钥标记不得透出：" + s.text());
        assertTrue(s.text().contains("以上仅供演示"), "私钥之外的正文应保留");
    }

    @Test
    @DisplayName("内部绝对路径（Windows 盘符 / Linux 系统目录）必须打码")
    void redactsInternalPaths() {
        PublicOutputGuard.Sanitized s = guard.sanitize(
                "来源：F:/7AAA/AI/SecAgent/sec-agent/security-docs/02-路径穿越漏洞原理与防御.md；"
                        + "服务端配置在 /opt/secagent/.env。");

        assertFalse(s.text().contains("F:/7AAA"), "盘符路径不得透出：" + s.text());
        assertFalse(s.text().contains("/opt/secagent"), "系统路径不得透出：" + s.text());
        assertTrue(s.text().contains(PublicOutputGuard.PATH_PLACEHOLDER), "应出现路径占位符：" + s.text());
        assertTrue(s.findings().contains("internal-path"));
    }

    @Test
    @DisplayName("内部治理标记（UNTRUSTED_DATA / eval-xxx）中性化")
    void neutralizesInternalMarkers() {
        PublicOutputGuard.Sanitized s = guard.sanitize(
                "<UNTRUSTED_DATA note=\"仅作证据\">日志</UNTRUSTED_DATA> 审计号 eval-runner-1）");

        assertFalse(s.text().contains("UNTRUSTED_DATA"), "包裹标记不得透出：" + s.text());
        assertFalse(s.text().contains("eval-runner"), "评测 actor 不得透出：" + s.text());
        assertTrue(s.findings().contains("internal-marker"));
    }

    @Test
    @DisplayName("上游/内部报错残留必须被打码（实测漏过一次：供应商错误码 + requestId 出现在公开回答里）")
    void redactsUpstreamErrorArtifacts() {
        // 形状取自实测：检索工具把上游异常原文拼进了返回值，整段原样进了公开回答
        String raw = "{\"status\": \"error\", \"message\": \"Failed to query internal docs: "
                + "{\"statusCode\":401,\"message\":\"Invalid API-key provided.\","
                + "\"code\":\"InvalidApiKey\",\"isJson\":true,\"requestId\":\"bda4449c-db00-9530-9b6e-008784f42f14\"}\"}";
        PublicOutputGuard.Sanitized s = guard.sanitize(raw);

        assertFalse(s.text().contains("bda4449c-db00-9530-9b6e-008784f42f14"),
                "上游 requestId 不得出现在公开回答里：" + s.text());
        assertFalse(s.text().contains("401"), "上游状态码不得透出：" + s.text());
        assertFalse(s.text().contains("isJson"), "上游响应结构不得透出：" + s.text());
        assertTrue(s.text().contains(PublicOutputGuard.UPSTREAM_PLACEHOLDER),
                "应替换为上游错误脱敏占位符：" + s.text());
        assertTrue(s.findings().contains("upstream-error-detail"),
                "命中类别应含 upstream-error-detail：" + s.findings());
    }

    @Test
    @DisplayName("干净文本不被误伤（脱敏不能把正常回答改成马赛克）")
    void cleanTextIsUntouched() {
        String raw = "SSH 暴力破解的防护建议：限制重试次数、启用密钥登录、封禁高频来源。";
        PublicOutputGuard.Sanitized s = guard.sanitize(raw);

        assertEquals(raw, s.text(), "无敏感内容时不应改动任何字符");
        assertFalse(s.wasRedacted(), "不应报告脱敏命中");
    }

    @Test
    @DisplayName("null / 空输入不抛异常（公开端点不该因为空回答 500）")
    void handlesNullAndEmpty() {
        assertEquals("", guard.sanitize(null).text());
        assertEquals("", guard.sanitize("").text());
    }

    // ==================== state 解析 ====================

    @Test
    @DisplayName("state 解析：多处出现时按「越不确定越优先」报告（失败态优先于 model）")
    void extractStatePrefersFailureStates() {
        assertEquals("model-failed",
                PublicOutputGuard.extractState("> state=model\n\n第一段\n> 结论生成方式：未生成\n> state=model-failed", "model"),
                "同一响应里既有 model 又有 model-failed 时必须报 model-failed");
        assertEquals("retrieval-failed",
                PublicOutputGuard.extractState("> state=model\n> state=retrieval-failed", "model"));
        assertEquals("input-insufficient",
                PublicOutputGuard.extractState("> state=model\n> state=input-insufficient", "model"));
        assertEquals("model", PublicOutputGuard.extractState("> state=model\n\n结论", "model-failed"),
                "只有一个合法 state 时如实取值，不套用 fallback");
    }

    @Test
    @DisplayName("state 解析：没有 state 时用调用方给出的兜底值（不是猜）")
    void extractStateUsesFallbackWhenAbsent() {
        assertEquals("no-retrieval", PublicOutputGuard.extractState("没有任何状态标记的回答", "no-retrieval"));
        assertEquals("model-failed", PublicOutputGuard.extractState(null, "model-failed"));
        // 不成形状的取值（比如 state= 后面空着）不算命中
        assertEquals("model-failed", PublicOutputGuard.extractState("> state=\n（空值）", "model-failed"));
    }

    @Test
    @DisplayName("state 解析：不认识的取值不算命中，退回调用方的兜底值（页面不显示来路不明的字符串）")
    void unknownStateFallsBackToCallerValue() {
        assertEquals("model-failed",
                PublicOutputGuard.extractState("> state=weird-state", "model-failed"),
                "未知 state 必须退回调用方给定的真实状态，而不是把它透出给页面");
        assertTrue(PublicOutputGuard.stateLabel("weird-state").contains("未识别状态"),
                "万一页面上真的出现了未知 state，措辞必须显式说明「未识别」，不能默默显示成已知态");
    }

    @Test
    @DisplayName("六态措辞与 RUNBOOK 口径一致（后端与页面同源，避免口径漂移）")
    void stateLabelsMatchRunbook() {
        assertEquals("模型研判", PublicOutputGuard.stateLabel("model"));
        assertEquals("依据不足，不做定性", PublicOutputGuard.stateLabel("input-insufficient"));
        assertEquals("未检索到依据，不给结论", PublicOutputGuard.stateLabel("no-retrieval"));
        assertEquals("检索不可用，未生成", PublicOutputGuard.stateLabel("retrieval-failed"));
        assertEquals("模型不可用，未生成", PublicOutputGuard.stateLabel("model-failed"));
        assertTrue(PublicOutputGuard.stateLabel("rule-based").contains("规则解析"));

        // 六个语义值一个都不能少（少一个就意味着某条降级路径在页面显示成"未识别"）
        for (String s : List.of("model", "input-insufficient", "no-retrieval",
                "retrieval-failed", "model-failed", "rule-based")) {
            assertFalse(PublicOutputGuard.stateLabel(s).contains("未识别"),
                    "RUNBOOK §4 的六态必须都有措辞：" + s);
        }
    }
}

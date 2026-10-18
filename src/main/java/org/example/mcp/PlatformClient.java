package org.example.mcp;

import java.util.Map;

/**
 * 平台的只读数据源。
 *
 * <p><b>为什么是"读平台自己的只读 HTTP 端点"而不是直连 Wazuh 索引 / 留痕文件</b>：
 * IP 口径（{@code app.public.mask-ips}）、样本截断口径、降级判定、口令只给结构 ——
 * 这些"怎么回答"的规则平台里已经有一份经过线上校验的实现。MCP server 若自己再实现一遍，
 * 就会长出第二套口径，两个入口迟早给出不同答案（而这个仓库刚因为"两套口径"出过事故）。
 *
 * <p>换成"进程内直调 Service Bean"之所以也不做：任务要求 MCP 必须是**独立进程**（stdio），
 * 独立进程拿不到 9900 端口那个 Spring 容器里的 Bean，只读 HTTP 是唯一不打洞的接法。
 */
public interface PlatformClient {

    /**
     * GET 一个本机只读端点。
     *
     * @param path  以 {@code /} 开头的路径，例如 {@code /api/public/alerts}
     * @param query 查询参数（可为空 Map）
     * @return 解析后的 JSON 对象
     * @throws PlatformUnavailableException 连不上、非 2xx、返回不是 JSON 对象
     */
    Map<String, Object> get(String path, Map<String, String> query) throws PlatformUnavailableException;

    /** 人读的上游描述（写进日志与 docs，方便排查"到底连的是哪台"）。 */
    String describe();
}

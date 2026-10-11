package org.example.integration.wazuh;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * 直连封禁执行器 —— 通过 SSH forced command 在服务器 2 上封/解封 IP。
 *
 * <h3>为什么不用 Wazuh 的 active-response</h3>
 * 试过并且失败得很彻底：配置全部正确（命令已注册、ar.conf 两边一致、
 * agent 确认是 002 产生告警、srcip 也有、<expect>srcip</expect> 也加了），
 * API 也报 {@code "AR command was sent to all agents"} —— 但 agent 就是不执行。
 * 而封禁脚本手工执行时 100% 有效（iptables 规则真的出现）。
 * <p>
 * 也就是说：<b>问题不在"能不能封"，而在"Wazuh 的投递链路扣不动扳机"。</b>
 * 与其继续在一个不受我控制的投递机制上试错，不如换一条我能验证到底的链路。
 *
 * <h3>安全模型：一把钥匙只能做一个动作</h3>
 * 服务器 2 的 {@code authorized_keys} 里给这把密钥配了
 * {@code command="/usr/local/sbin/secagent-block-cli"} 和
 * {@code no-port-forwarding,no-pty,no-user-rc}。
 * 于是这把密钥<b>只能封/解封 IP</b>：开不了 shell、转不了端口、读不了文件。
 * 这比让 Wazuh agent 执行整个 active-response 目录的权限小得多。
 * <p>
 * 服务端还会**再做一次参数校验和白名单判断**（纵深防御）——
 * 即使这个类出了 bug，服务器 2 也不会执行非法指令。
 *
 * <h3>为什么严格用 ProcessBuilder 而不是 Runtime.exec(字符串)</h3>
 * 后者会把整串交给 shell 解析，传入的 IP 里带一个分号就是 root 级命令注入。
 * 这里用参数数组（每个参数独立成 argv 元素），shell 完全不经手，
 * 从机制上消除注入面 —— 而不是靠"我把特殊字符过滤干净了"。
 */
@Component
public class SshBlockExecutor {

    private static final Logger logger = LoggerFactory.getLogger(SshBlockExecutor.class);

    /** 只接受 add / delete，其它一律不构造命令。 */
    private static final Pattern ACTION = Pattern.compile("^(add|delete)$");

    /**
     * 目标 IP 的白名单正则。
     *
     * <p>本类只做"形状"校验（IPv4 / 简单 IPv6），**权威校验在服务器 2 的脚本里**
     * —— 那里用 Python 的 ipaddress 模块做完整解析 + 网段白名单。
     * 这里做一道是"尽早失败"，不是唯一防线。
     */
    private static final Pattern IPV4 = Pattern.compile(
            "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$");
    private static final Pattern IPV6 = Pattern.compile("^[0-9a-fA-F:]{2,45}$");

    @Value("${integration.block.ssh.enabled:true}")
    private boolean enabled;

    @Value("${integration.block.ssh.host:}")
    private String host;

    @Value("${integration.block.ssh.port:22}")
    private int port;

    @Value("${integration.block.ssh.user:root}")
    private String user;

    @Value("${integration.block.ssh.key:/opt/keys/secagent_block_ed25519}")
    private String keyPath;

    @Value("${integration.block.ssh.known-hosts:/opt/keys/known_hosts}")
    private String knownHosts;

    @Value("${integration.block.ssh.timeout:15}")
    private int timeoutSeconds;

    /**
     * 启动自检 —— 把配置的实际绑定值打出来。
     *
     * <h3>为什么加这一段</h3>
     * 这个功能连续几轮"代码看着对、运行起来不生效"，
     * 而我一直在猜原因（改一处 → 部署 → 失败，循环了五次，每次 5 分钟）。
     * 猜的成本远高于【把实际值打出来】。
     * 所以这里在启动时直接打印：
     *   · 配置有没有绑定上（host 是不是空）
     *   · 密钥文件在不在、能不能读
     *   · 最终判据 isEnabled() 的结果
     * 一次部署就能定位，不用再猜。
     */
    @jakarta.annotation.PostConstruct
    public void selfCheck() {
        logger.info("=== SSH 直连封禁自检 ===");
        logger.info("  enabled 配置值 = {}", enabled);
        logger.info("  host          = [{}]", host == null ? "null" : host);
        logger.info("  port / user   = {} / {}", port, user);
        logger.info("  key 路径       = {}", keyPath);
        logger.info("  known_hosts    = {}", knownHosts);
        try {
            java.nio.file.Path kp = java.nio.file.Paths.get(keyPath);
            boolean exists = java.nio.file.Files.exists(kp);
            boolean readable = exists && java.nio.file.Files.isReadable(kp);
            logger.info("  密钥文件存在   = {}   可读 = {}", exists, readable);
        } catch (Exception e) {
            logger.warn("  检查密钥文件失败: {}", e.getMessage());
        }
        try {
            java.nio.file.Path kh = java.nio.file.Paths.get(knownHosts);
            logger.info("  known_hosts 存在 = {}", java.nio.file.Files.exists(kh));
        } catch (Exception ignored) {
        }
        logger.info("  >>> isEnabled() 最终结果 = {}", isEnabled());
        logger.info("=== 自检结束 ===");
    }

    public boolean isEnabled() {
        return enabled && host != null && !host.isBlank();
    }

    /** 只做形状校验，真正的安全判断在服务端。 */
    static boolean looksLikeIp(String ip) {
        if (ip == null || ip.isBlank() || ip.length() > 45) {
            return false;
        }
        // 明确的危险形态先挡掉：shell 元字符、空白、以 - 开头（防止被当成选项）
        for (char c : ip.toCharArray()) {
            if (c == ';' || c == '|' || c == '&' || c == '$' || c == '`'
                    || c == '(' || c == ')' || c == '<' || c == '>'
                    || c == '"' || c == '\'' || c == '\\' || c == '\n'
                    || c == '\r' || c == '\t' || c == ' ') {
                return false;
            }
        }
        if (ip.startsWith("-")) {
            return false;
        }
        return IPV4.matcher(ip).matches() || IPV6.matcher(ip).matches();
    }

    /**
     * 执行一次封禁/解封。
     *
     * @param action {@code add} 或 {@code delete}
     * @param ip     目标 IP
     * @return 服务端返回的文本（形如 {@code OK add 1.2.3.4 ttl=1800s}）
     * @throws IOException 参数非法、SSH 失败、或服务端拒绝
     */
    public String run(String action, String ip) throws IOException {
        if (!isEnabled()) {
            throw new IOException("SSH 直连封禁未启用（integration.block.ssh.*）");
        }
        // 第一道：本地形状校验
        if (action == null || !ACTION.matcher(action).matches()) {
            throw new IOException("非法动作: " + action);
        }
        if (!looksLikeIp(ip)) {
            throw new IOException("非法 IP: " + ip);
        }

        // 用参数数组 —— shell 不经手，注入面从机制上消除
        List<String> cmd = new ArrayList<>();
        cmd.add("ssh");
        cmd.add("-i");
        cmd.add(keyPath);
        cmd.add("-p");
        cmd.add(String.valueOf(port));
        cmd.add("-o");
        cmd.add("BatchMode=yes");
        cmd.add("-o");
        // 严格校验 host key：预置在 known_hosts 里，防中间人
        cmd.add("StrictHostKeyChecking=yes");
        cmd.add("-o");
        cmd.add("UserKnownHostsFile=" + knownHosts);
        cmd.add("-o");
        cmd.add("ConnectTimeout=" + Math.max(5, timeoutSeconds));
        // 注意：整条指令作为【一个】参数传给 ssh，
        // 服务端的 forced command 会从 $SSH_ORIGINAL_COMMAND 读到它。
        cmd.add(user + "@" + host);
        cmd.add(action + " " + ip);

        logger.info("SSH 直连处置：{} {} -> {}@{}", action, ip, user, host);

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();

        StringBuilder out = new StringBuilder();
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                out.append(line).append('\n');
            }
        }
        boolean finished;
        try {
            finished = p.waitFor(timeoutSeconds + 5L, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            p.destroyForcibly();
            throw new IOException("等待 SSH 结果被中断");
        }
        if (!finished) {
            p.destroyForcibly();
            throw new IOException("SSH 执行超时");
        }

        String result = out.toString().trim();
        int code = p.exitValue();
        if (code != 0 || result.contains("REJECT")) {
            // 服务端拒绝也要如实上报，不能当成成功
            throw new IOException("服务端拒绝或执行失败（exit=" + code + "）: " + result);
        }
        logger.info("SSH 直连处置成功：{}", result);
        return result;
    }
}

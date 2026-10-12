package org.example.integration.wazuh;

import org.example.config.OutboundTimeouts;
import org.example.llm.OutboundGuard;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Wazuh 出站客户端（管理 API + indexer）的"不可达/挂起时不拖住调用方"测试。
 *
 * <h3>测的是什么（以及为什么不能只断言常量）</h3>
 * 断言"配置里写了 3s"证明不了任何事 —— 这个项目的真实故障形态是
 * "代码看着对、运行起来没生效"。所以这里用一个**只接受连接、永不回包**的
 * 本地服务端，让客户端真的挂在那里，再断言：
 * <ol>
 *   <li>调用会在有限时间内失败（而不是无限等）—— 这就是"外部依赖挂起"的复现；</li>
 *   <li>冷却期内的调用<b>立刻失败且不发出任何网络请求</b> ——
 *       证明客户端确实走了 OutboundGuard，而不是各调用点各等一遍超时。</li>
 * </ol>
 */
class WazuhClientBoundedOutboundTest {

    private StallingServer server;

    @AfterEach
    void tearDown() throws IOException {
        if (server != null) {
            server.close();
        }
    }

    private static OutboundGuard guardWithCooldown(long cooldownMs) {
        OutboundGuard guard = new OutboundGuard();
        ReflectionTestUtils.setField(guard, "defaultCooldownMs", cooldownMs);
        ReflectionTestUtils.setField(guard, "maxInflightPerDependency", 2);
        return guard;
    }

    @Test
    @Timeout(30)
    @DisplayName("indexer 挂起（连上但不回包）时，调用在有限时间内失败，不无限等")
    void stalledIndexerFailsWithinBudget() throws Exception {
        server = new StallingServer();

        // read(500ms) < call(1000ms)：传输层读超时先触发，证明"挂起"不会拖住调用方
        OutboundTimeouts timeouts = new OutboundTimeouts(1000, 500, 1000);
        WazuhClient client = new WazuhClient(
                "http://127.0.0.1:" + server.port(), "wazuh", "wazuh", false,
                timeouts, guardWithCooldown(60000),
                "http://127.0.0.1:" + server.port(), "admin", "admin");

        long start = System.nanoTime();
        Exception e = assertThrows(Exception.class,
                () -> client.search("wazuh-alerts-*", "{\"size\":1}"));
        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

        assertTrue(elapsedMs < 5000,
                "挂起的 indexer 必须被有界截断，实际耗时 " + elapsedMs + " ms（错误：" + e.getMessage() + "）");
        assertTrue(server.accepts() >= 1, "应当确实发出了 TCP 连接（否则测的不是挂起场景）");
    }

    @Test
    @Timeout(30)
    @DisplayName("冷却期内调用立刻 fail-closed，且不发出任何网络请求")
    void cooldownShortCircuitsWithoutNetworkIo() throws Exception {
        server = new StallingServer();
        OutboundGuard guard = guardWithCooldown(60000);

        WazuhClient client = new WazuhClient(
                "http://127.0.0.1:" + server.port(), "wazuh", "wazuh", false,
                new OutboundTimeouts(1000, 12000, 15000), guard,
                "http://127.0.0.1:" + server.port(), "admin", "admin");

        // 先用同一个依赖 key 触发一次真正的守卫超时 → 打开 60s 冷却
        assertThrows(IllegalStateException.class,
                () -> guard.call(WazuhClient.DEP_INDEXER, 200, () -> {
                    Thread.sleep(5000);
                    return null;
                }));
        assertTrue(guard.coolingDown(WazuhClient.DEP_INDEXER), "超时后该依赖应进入冷却");
        int acceptsBefore = server.accepts();

        long start = System.nanoTime();
        Exception e = assertThrows(Exception.class,
                () -> client.search("wazuh-alerts-*", "{\"size\":1}"));
        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

        assertTrue(e.getMessage() != null && e.getMessage().contains("冷却"),
                "冷却期应直接 fail-closed 并说明原因，实际：" + e.getMessage());
        assertTrue(elapsedMs < 300,
                "冷却期必须立刻失败（实测 " + elapsedMs + " ms），而不是再等一轮超时");
        assertEquals(acceptsBefore, server.accepts(),
                "冷却期内不应发出任何网络请求（说明客户端确实走了 OutboundGuard）");
    }

    @Test
    @Timeout(30)
    @DisplayName("管理 API 未配置/不可达时快速失败，不挂住调用线程")
    void managerApiFailsFastWhenUnreachable() {
        // 端口选一个几乎不可能有监听的：连接被拒 → 立刻失败（不是超时，但同样满足"不挂住"）
        WazuhClient client = new WazuhClient(
                "http://127.0.0.1:1", "wazuh", "wazuh", false,
                new OutboundTimeouts(300, 300, 300), guardWithCooldown(60000),
                null, null, null);

        long start = System.nanoTime();
        boolean reachable = client.testConnection();
        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

        assertTrue(!reachable, "不可达时 testConnection() 必须返回 false（不抛异常）");
        assertTrue(elapsedMs < 5000, "不可达必须快速返回，实际 " + elapsedMs + " ms");
    }

    /** 只接受连接、永不回包的服务端：用来复现"依赖挂起" */
    private static final class StallingServer implements AutoCloseable {

        private final ServerSocket serverSocket;
        private final List<Socket> held = Collections.synchronizedList(new ArrayList<>());
        private final AtomicInteger accepts = new AtomicInteger();

        StallingServer() throws IOException {
            this.serverSocket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            Thread acceptor = new Thread(() -> {
                while (!serverSocket.isClosed()) {
                    try {
                        Socket s = serverSocket.accept();
                        held.add(s);
                        accepts.incrementAndGet();
                        // 刻意不回任何数据：客户端会一直等到自己的 read 超时
                    } catch (IOException e) {
                        return;
                    }
                }
            }, "stalling-server");
            acceptor.setDaemon(true);
            acceptor.start();
        }

        int port() {
            return serverSocket.getLocalPort();
        }

        int accepts() {
            return accepts.get();
        }

        @Override
        public void close() throws IOException {
            serverSocket.close();
            synchronized (held) {
                for (Socket s : held) {
                    try {
                        s.close();
                    } catch (IOException ignored) {
                    }
                }
                held.clear();
            }
        }
    }
}

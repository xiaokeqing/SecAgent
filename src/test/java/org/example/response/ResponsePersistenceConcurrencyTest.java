package org.example.response;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.core.model.ActiveResponseResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntConsumer;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code response} 包"持锁做文件 I/O"重构的并发回归测试。
 *
 * <h3>为什么必须是并发测试（而不是读代码）</h3>
 * 重构后的形状是"锁内只改内存 + 锁外序列化/落盘"，它有两个容易写错的地方，
 * 而且<b>单线程测试一个都发现不了</b>：
 * <ul>
 *   <li>锁外落盘若没有顺序保护，"后完成的写"可能写了更旧的快照 → <b>静默丢记录</b>；</li>
 *   <li>把业务锁缩到只保护内存后，若 CAS 写错，并发批准会<b>重复执行处置动作</b>
 *       （在安全系统里等于同一 IP 被封两次、审计多一条）。</li>
 * </ul>
 * 所以这里用真实多线程 + 落盘文件解析结果来断言：条目完整、无重复、无撕裂、无死锁。
 */
@Timeout(120)
class ResponsePersistenceConcurrencyTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // ==================== 工具 ====================

    private static AuditService auditService(Path file) {
        AuditService s = new AuditService();
        ReflectionTestUtils.setField(s, "auditFilePath", file.toString());
        s.init();
        return s;
    }

    private static BlockRecordStore blockRecordStore(Path file) {
        BlockRecordStore s = new BlockRecordStore();
        ReflectionTestUtils.setField(s, "blocksFilePath", file.toString());
        s.init();
        return s;
    }

    private static List<ResponseAudit> readAudits(Path file) throws Exception {
        return MAPPER.readValue(Files.readAllBytes(file), new TypeReference<List<ResponseAudit>>() {});
    }

    private static List<BlockRecord> readBlocks(Path file) throws Exception {
        return MAPPER.readValue(Files.readAllBytes(file), new TypeReference<List<BlockRecord>>() {});
    }

    /** 同时启动 n 个线程跑 body，全部完成后返回；任何异常都让测试失败（并暴露死锁） */
    private static void runConcurrently(int n, IntConsumer body) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(n);
        CountDownLatch ready = new CountDownLatch(n);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(n);
        List<Throwable> errors = Collections.synchronizedList(new ArrayList<>());
        try {
            for (int i = 0; i < n; i++) {
                final int idx = i;
                pool.submit(() -> {
                    ready.countDown();
                    try {
                        start.await();
                        body.accept(idx);
                    } catch (Throwable t) {
                        errors.add(t);
                    } finally {
                        done.countDown();
                    }
                });
            }
            assertTrue(ready.await(30, TimeUnit.SECONDS), "线程池未能就绪");
            start.countDown();
            assertTrue(done.await(90, TimeUnit.SECONDS),
                    "并发任务在 90s 内未完成 —— 疑似死锁（锁顺序 / 自锁）");
        } finally {
            pool.shutdownNow();
        }
        assertTrue(errors.isEmpty(), "并发执行抛出异常：" + errors);
    }

    // ==================== AuditService ====================

    @Test
    @DisplayName("多线程同时 append：落盘条目数完整、无撕裂、无死锁")
    void concurrentAppendsLandCompleteFile(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("response-audit.json");
        AuditService svc = auditService(file);

        final int threads = 16;
        final int perThread = 40;
        final int total = threads * perThread;

        runConcurrently(threads, t -> {
            for (int k = 0; k < perThread; k++) {
                svc.append(ResponseAudit.of("thread-" + t, "block-ip", "198.51.100." + t,
                        "并发追加", "LOW", "MOCK", true, "k=" + k));
            }
        });

        assertEquals(total, svc.list(null, null).size(), "内存里少了记录");

        List<ResponseAudit> onDisk = readAudits(file);
        assertEquals(total, onDisk.size(),
                "落盘条目数不完整（" + onDisk.size() + "/" + total + "）—— 锁外落盘缺少顺序保护，"
                        + "后完成的写把新快照覆盖成了旧的");
        Set<String> ids = onDisk.stream().map(ResponseAudit::getId).collect(Collectors.toSet());
        assertEquals(total, ids.size(), "落盘出现重复/缺失 ID（撕裂或乱序覆盖）");
        for (ResponseAudit a : onDisk) {
            assertNotNull(a.getId(), "落盘记录缺 id");
            assertNotNull(a.getTime(), "落盘记录缺 time");
        }
    }

    @Test
    @DisplayName("落盘后立刻可被读回（原子替换不留半份文件）")
    void fileIsAlwaysParseableAfterEachAppend(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("response-audit.json");
        AuditService svc = auditService(file);

        runConcurrently(8, t -> {
            for (int k = 0; k < 30; k++) {
                svc.append(ResponseAudit.of("w" + t, "block-ip", "10.0.0.9", "conc",
                        "LOW", "MOCK", true, "x"));
                // 每写一次都立刻解析一遍：tmp + ATOMIC_MOVE 保证读到的永远是完整 JSON，
                // 直接 Files.write 覆盖时这里会随机读到被截断的半份文件
                try {
                    assertTrue(readAudits(file).size() >= 1, "落盘文件读不出记录");
                } catch (Exception e) {
                    throw new IllegalStateException("落盘文件出现撕裂（无法解析）：" + e.getMessage(), e);
                }
            }
        });

        assertEquals(8 * 30, readAudits(file).size());
    }

    // ==================== BlockRecordStore ====================

    @Test
    @DisplayName("多线程同时 register / markUnblocked：落盘完整、无撕裂、无死锁")
    void concurrentRegisterAndUnblock(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("blocked-ips.json");
        BlockRecordStore store = blockRecordStore(file);

        final int threads = 12;
        final int perThread = 25;
        final int total = threads * perThread;

        List<BlockRecord> created = Collections.synchronizedList(new ArrayList<>());
        runConcurrently(threads, t -> {
            for (int k = 0; k < perThread; k++) {
                created.add(store.register("203.0.113." + t, 60, "手动", "tester",
                        "AUD-" + t + "-" + k, "MOCK"));
            }
        });

        assertEquals(total, store.listAll().size());
        List<BlockRecord> onDisk = readBlocks(file);
        assertEquals(total, onDisk.size(), "封禁记录落盘不完整：" + onDisk.size() + "/" + total);
        assertEquals(total, onDisk.stream().map(BlockRecord::getId).distinct().count(),
                "封禁记录落盘出现重复 ID");

        // 并发解封：每个 id 只应被一个线程处理，最终全部标记为已解封
        List<String> ids = created.stream().map(BlockRecord::getId).toList();
        runConcurrently(8, t -> {
            for (int k = t; k < ids.size(); k += 8) {
                store.markUnblocked(ids.get(k), "MOCK");
            }
        });

        assertTrue(store.listAll().stream().allMatch(BlockRecord::isUnblocked),
                "有记录未被标记为已解封");
        List<BlockRecord> afterUnblock = readBlocks(file);
        assertEquals(total, afterUnblock.size(), "解封后落盘条目数变了");
        assertEquals(total, afterUnblock.stream().filter(BlockRecord::isUnblocked).count(),
                "解封状态没完整落盘");
    }

    // ==================== ApprovalService ====================

    /**
     * 可控"处置耗时"的 ResponseActionService 替身（只重写 blockIp）。
     *
     * <p>耗时只加在<b>第一次</b>处置上：这样才测得出"审批 B 是否被审批 A 的耗时执行挡住"，
     * 而不是把 B 自己的处置耗时也算进去（那会测出一个恒等于自身耗时的值，什么都没证明）。
     */
    private static ResponseActionService slowFirstDispatch(long firstDispatchMs, AtomicInteger executions) {
        return new ResponseActionService(null, null, null, null, null) {
            @Override
            public ActiveResponseResult blockIp(String ip, Integer durationMinutes,
                                                String reason, String actor, String source) {
                if (executions.incrementAndGet() == 1) {
                    try {
                        Thread.sleep(firstDispatchMs);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
                return ActiveResponseResult.mock("firewall-drop", ip, "已封禁（测试替身）", "AUD-test");
            }
        };
    }

    private static ApprovalService.Order newBlockOrder(ApprovalService approvals, String ip) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("ip", ip);
        params.put("durationMinutes", 180);
        return approvals.create("block-ip", ip, "并发测试", "HIGH", params, "tester");
    }

    @Test
    @DisplayName("并发批准同一张单：处置动作只执行一次，审计只加一条")
    void concurrentApproveExecutesExactlyOnce(@TempDir Path dir) throws Exception {
        AuditService audits = auditService(dir.resolve("audit.json"));
        AtomicInteger executions = new AtomicInteger();
        ApprovalService approvals = new ApprovalService(slowFirstDispatch(0, executions), audits);

        ApprovalService.Order order = newBlockOrder(approvals, "203.0.113.7");

        AtomicInteger success = new AtomicInteger();
        runConcurrently(8, t -> {
            Map<String, Object> r = approvals.approve(order.getId(), "admin-" + t);
            if (Boolean.TRUE.equals(r.get("success"))) {
                success.incrementAndGet();
            }
        });

        assertEquals(1, success.get(), "同一张审批单只能有一个线程批准成功");
        assertEquals(1, executions.get(), "处置动作被重复执行了（CAS 没在锁内完成）");
        assertEquals("APPROVED", order.getStatus());
        assertEquals(1, audits.list(null, null).stream()
                        .filter(a -> "approve".equals(a.getAction())).count(),
                "审批审计应恰好一条");
    }

    @Test
    @DisplayName("并发批准与驳回同一张单：只有一个生效")
    void concurrentApproveAndRejectOnlyOneWins(@TempDir Path dir) throws Exception {
        AuditService audits = auditService(dir.resolve("audit.json"));
        AtomicInteger executions = new AtomicInteger();
        ApprovalService approvals = new ApprovalService(slowFirstDispatch(0, executions), audits);
        ApprovalService.Order order = newBlockOrder(approvals, "203.0.113.8");

        AtomicInteger success = new AtomicInteger();
        runConcurrently(8, t -> {
            Map<String, Object> r = (t % 2 == 0)
                    ? approvals.approve(order.getId(), "admin-" + t)
                    : approvals.reject(order.getId(), "admin-" + t);
            if (Boolean.TRUE.equals(r.get("success"))) {
                success.incrementAndGet();
            }
        });

        assertEquals(1, success.get(), "批准与驳回只能有一个成功");
        assertTrue("APPROVED".equals(order.getStatus()) || "REJECTED".equals(order.getStatus()),
                "状态应为终态，实际 " + order.getStatus());
        assertEquals(1, audits.list(null, null).size(), "审计应恰好一条");
    }

    @Test
    @DisplayName("批准一张单时的耗时执行（模拟 SSH）不阻塞另一张单的审批")
    void slowDispatchDoesNotBlockOtherOrders(@TempDir Path dir) throws Exception {
        AuditService audits = auditService(dir.resolve("audit.json"));
        AtomicInteger executions = new AtomicInteger();
        // 第一次处置耗时 800ms —— 模拟"走了一次 SSH"
        ApprovalService approvals = new ApprovalService(slowFirstDispatch(800, executions), audits);

        ApprovalService.Order slow = newBlockOrder(approvals, "203.0.113.21");
        ApprovalService.Order other = newBlockOrder(approvals, "203.0.113.22");

        Thread slowApprover = new Thread(() -> approvals.approve(slow.getId(), "admin-A"), "slow-approve");
        slowApprover.start();
        Thread.sleep(200);   // 让它进入 dispatch（锁应已释放）

        long start = System.nanoTime();
        Map<String, Object> result = approvals.approve(other.getId(), "admin-B");
        long elapsedMs = (System.nanoTime() - start) / 1_000_000L;

        slowApprover.join(10_000);
        assertTrue(Boolean.TRUE.equals(result.get("success")), "第二张单应当能独立批准：" + result);
        assertTrue(elapsedMs < 400,
                "审批被另一个审批的耗时执行阻塞了（" + elapsedMs + " ms）—— "
                        + "说明锁内仍在做 I/O / 真实执行");
        assertEquals(2, executions.get(), "两张单各自执行一次");
    }

    @Test
    @DisplayName("未知审批单直接失败，不写审计、不执行")
    void unknownOrderIsHandled(@TempDir Path dir) throws Exception {
        AuditService audits = auditService(dir.resolve("audit.json"));
        AtomicInteger executions = new AtomicInteger();
        ApprovalService approvals = new ApprovalService(slowFirstDispatch(0, executions), audits);

        Map<String, Object> r = approvals.approve("APR-not-exist", "admin");
        assertEquals(Boolean.FALSE, r.get("success"));
        assertEquals(0, audits.list(null, null).size(), "未知审批单不应产生审计");
        assertEquals(0, executions.get(), "未知审批单不应执行任何处置");
    }
}

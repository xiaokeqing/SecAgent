package org.example.response;

import org.example.core.model.ActiveResponseResult;
import org.example.integration.wazuh.SshBlockExecutor;
import org.example.security.ResponseGuard;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 封禁主链路的单测：护栏拒绝、分级 TTL 落地、dry-run 不下发、回滚只动该动的东西、失败降级不抛。
 *
 * <p>执行通道用<b>手写替身</b>而不是 Mockito：本机 Maven 跑在 JDK 25 上，
 * 内联 mock maker 的 ByteBuddy 无法改写类层级（Mockito cannot mock this class），
 * 而项目现有测试（{@code SshBlockExecutorOutboundTest} 等）本来就是"new 对象 + ReflectionTestUtils"风格，
 * 这里沿用同一风格，不引入任何新依赖。
 * <p>护栏用<b>真实对象</b>："新路径是否仍然过护栏"本身是被测行为，把它也替身掉等于假设了它一定会被调用。
 */
class ResponseActionServiceBlockTest {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @TempDir
    Path tmp;

    private ResponseGuard guard;
    private FakeAuditService audits;
    private FakeBlockRecordStore store;
    private FakeSshBlockExecutor ssh;
    private ResponseActionService service;

    @BeforeEach
    void setUp() {
        guard = newGuard();
        audits = new FakeAuditService();
        store = new FakeBlockRecordStore();
        ssh = new FakeSshBlockExecutor();
        // Wazuh 通道给 null：SSH 是主路径，这里不测"降级到 Wazuh"的分支
        service = new ResponseActionService(guard, audits, store,
                provider(null), provider((SshBlockExecutor) ssh), provider(null), new BlockPolicy());
    }

    @Test
    void guardRejectionNeverReachesExecutor() {
        ActiveResponseResult r = service.blockIp(
                BlockRequest.of("10.1.2.3", null, "SSH 暴力破解", "tester", "手动"));

        assertThat(r.isSuccess()).isFalse();
        assertThat(r.getMode()).isEqualTo("BLOCKED");
        // 护栏拒绝 = 没有任何命令被下发、也没有留下"生效中"的记录
        assertThat(ssh.blockCalls).isZero();
        assertThat(store.registers).isEmpty();
        ResponseAudit audit = audits.last();
        assertThat(audit.getMode()).isEqualTo("BLOCKED");
        assertThat(audit.getReason()).contains("白名单");
    }

    @Test
    void policyTtlDecidesBothExecutorTtlAndRecordDuration() {
        ssh.blockResponse = "OK block 45.33.32.156 ttl=86400s set=secagent_block backend=ipset";

        ActiveResponseResult r = service.blockIp(BlockRequest.of(
                "45.33.32.156", null, "SSH 暴力破解，failed password 连续 50 次", "tester", "手动"));

        assertThat(r.isSuccess()).isTrue();
        assertThat(r.getMode()).isEqualTo("REAL");
        // 未指定时长 → 爆破档 24h = 86400s；reason 参数用 ASCII token
        assertThat(ssh.lastIp).isEqualTo("45.33.32.156");
        assertThat(ssh.lastTtl).isEqualTo(86400);
        assertThat(ssh.lastReason).isEqualTo("brute-force");
        // 登记记录用分钟数（1440），与 UnblockScheduler 的到期判断同一量纲
        assertThat(store.registers).hasSize(1);
        assertThat(store.registers.get(0))
                .containsExactly("45.33.32.156", 1440, "手动", "tester", "AUD-1", "REAL",
                        "brute-force", true, "IPSET", "block 45.33.32.156 86400 brute-force");
    }

    @Test
    void ipv6TargetUsesSetPathWithScanTtl() {
        ssh.blockResponse = "OK block 2001:470::1 ttl=1800s set=secagent_block6 backend=ipset";

        ActiveResponseResult r = service.blockIp(
                BlockRequest.of("2001:470::1", null, "端口扫描/目录枚举", "tester", "手动"));

        assertThat(r.isSuccess()).isTrue();
        assertThat(ssh.lastIp).isEqualTo("2001:470::1");
        assertThat(ssh.lastTtl).isEqualTo(1800);
        assertThat(ssh.lastReason).isEqualTo("scan");
        assertThat(r.getMessage()).contains("secagent_block6");
    }

    @Test
    void registerWritesExpiresAtSoSchedulerCanExpireIt() {
        BlockRecordStore realStore = new BlockRecordStore();
        ReflectionTestUtils.setField(realStore, "blocksFilePath", tmp.resolve("blocks.json").toString());
        realStore.init();

        BlockRecord r = realStore.register("45.33.32.156", 1440, "手动", "tester", "AUD-1", "REAL",
                "brute-force", true, "IPSET", "block 45.33.32.156 86400 brute-force");

        assertThat(r.getThreatClass()).isEqualTo("brute-force");
        assertThat(r.isPolicyDerived()).isTrue();
        assertThat(r.getBackend()).isEqualTo("IPSET");
        LocalDateTime expiresAt = LocalDateTime.parse(r.getExpiresAt(), FMT);
        long minutes = ChronoUnit.MINUTES.between(LocalDateTime.now(), expiresAt);
        // 允许 1 分钟内的执行漂移；关键是"到期点真的按策略 TTL 算出来了"
        assertThat(minutes).isBetween(1438L, 1440L);
        assertThat(realStore.listActive()).extracting(BlockRecord::getIp).containsExactly("45.33.32.156");
    }

    @Test
    void dryRunRecordsPlanButDispatchesNothing() {
        BlockRequest req = BlockRequest.of("45.33.32.156", null, "端口扫描", "tester", "手动");
        req.setDryRun(true);

        ActiveResponseResult r = service.blockIp(req);

        assertThat(r.getMode()).isEqualTo("DRY_RUN");
        assertThat(r.isSuccess()).isTrue();
        assertThat(r.getMessage()).contains("ipset").contains("match-set").contains("本应执行");
        assertThat(ssh.blockCalls).isZero();
        assertThat(store.registers).isEmpty();
        ResponseAudit audit = audits.last();
        assertThat(audit.getMode()).isEqualTo("DRY_RUN");
        assertThat(audit.getDetail()).contains("未下发");
    }

    @Test
    void rollbackFlushCallsFlushOnceAndMarksEveryActiveRecord() {
        store.active = List.of(rec("45.33.32.156"), rec("45.33.32.157"));

        Map<String, Object> out = service.rollback(true, "admin");

        assertThat(ssh.flushCalls).isEqualTo(1);
        assertThat(ssh.unblocked).isEmpty();
        assertThat(store.unblockedByIp).containsExactly("45.33.32.156", "45.33.32.157");
        assertThat(out.get("success")).isEqualTo(true);
        assertThat(out.get("removed")).isEqualTo(2);
    }

    @Test
    void rollbackSingleTargetOnlyUnblocksIt() {
        store.active = List.of(rec("45.33.32.156"));

        Map<String, Object> out = service.rollback(false, "admin");

        assertThat(ssh.unblocked).containsExactly("45.33.32.156");
        assertThat(ssh.flushCalls).isZero();
        assertThat(out.get("removed")).isEqualTo(1);
    }

    @Test
    void sshFailureDegradesWithAuditInsteadOfThrowing() {
        ssh.blockError = new IOException("ssh timeout");

        ActiveResponseResult r = service.blockIp(BlockRequest.of(
                "45.33.32.156", null, "webshell 利用 CVE-2021-44228", "tester", "手动"));

        assertThat(r.isSuccess()).isFalse();
        assertThat(r.getMessage()).contains("SSH");
        assertThat(store.registers).isEmpty();
        assertThat(audits.last().getDetail()).contains("SSH-FAILED");
    }

    // ---------------------------------------------------------------- 测试替身

    /** 真实护栏：只留 127/8 与 10/8 两条，其余保护段仍由内置默认值兜住 */
    private static ResponseGuard newGuard() {
        ResponseGuard g = new ResponseGuard();
        ReflectionTestUtils.setField(g, "whitelistRaw", "127.0.0.0/8,10.0.0.0/8");
        ReflectionTestUtils.setField(g, "selfAssetsRaw", "");
        ReflectionTestUtils.setField(g, "machinePublicIpsRaw", "");
        ReflectionTestUtils.setField(g, "healthcheckSourcesRaw", "");
        ReflectionTestUtils.setField(g, "maxDurationMinutes", 1440);
        ReflectionTestUtils.setField(g, "policyMaxDurationMinutes", 10080);
        ReflectionTestUtils.setField(g, "defaultDurationMinutes", 60);
        g.init();
        return g;
    }

    private static <T> ObjectProvider<T> provider(T value) {
        return new ObjectProvider<T>() {
            @Override
            public T getObject() {
                return value;
            }

            @Override
            public T getObject(Object... args) {
                return value;
            }

            @Override
            public T getIfAvailable() {
                return value;
            }

            @Override
            public T getIfUnique() {
                return value;
            }

            @Override
            public Iterator<T> iterator() {
                return Collections.singletonList(value).iterator();
            }
        };
    }

    /** 审计替身：只做"记下来"，不碰磁盘 */
    static class FakeAuditService extends AuditService {
        private final List<ResponseAudit> appended = new ArrayList<>();

        @Override
        public ResponseAudit append(ResponseAudit a) {
            a.setId("AUD-" + (appended.size() + 1));
            a.setTime(LocalDateTime.now().format(FMT));
            appended.add(a);
            return a;
        }

        ResponseAudit last() {
            return appended.get(appended.size() - 1);
        }
    }

    /** 记录替身：按参数回放给断言，不落盘 */
    static class FakeBlockRecordStore extends BlockRecordStore {
        List<BlockRecord> active = new ArrayList<>();
        final List<List<Object>> registers = new ArrayList<>();
        final List<String> unblockedByIp = new ArrayList<>();

        @Override
        public BlockRecord register(String ip, int durationMinutes, String source, String actor,
                                    String auditId, String mode, String threatClass,
                                    boolean policyDerived, String backend, String command) {
            registers.add(Arrays.asList(ip, durationMinutes, source, actor, auditId, mode,
                    threatClass, policyDerived, backend, command));
            return null;
        }

        @Override
        public List<BlockRecord> listActive() {
            return active;
        }

        @Override
        public int markUnblockedByIp(String ip, String unblockMode) {
            unblockedByIp.add(ip);
            return 1;
        }
    }

    /** SSH 执行器替身：记录最后一次调用参数，可注入失败 */
    static class FakeSshBlockExecutor extends SshBlockExecutor {
        boolean enabled = true;
        String blockResponse = "OK block backend=ipset";
        IOException blockError;
        int blockCalls;
        String lastIp;
        int lastTtl;
        String lastReason;
        int flushCalls;
        final List<String> unblocked = new ArrayList<>();

        FakeSshBlockExecutor() {
            super(null, null);
        }

        @Override
        public boolean isEnabled() {
            return enabled;
        }

        @Override
        public String block(String ip, int ttlSeconds, String reason) throws IOException {
            blockCalls++;
            lastIp = ip;
            lastTtl = ttlSeconds;
            lastReason = reason;
            if (blockError != null) {
                throw blockError;
            }
            return blockResponse;
        }

        @Override
        public String unblock(String ip) {
            unblocked.add(ip);
            return "OK unblock " + ip + " backend=ipset";
        }

        @Override
        public String flush() {
            flushCalls++;
            return "OK flush backend=ipset";
        }
    }

    private static BlockRecord rec(String ip) {
        BlockRecord r = new BlockRecord();
        r.setId("BLK-" + ip.replace('.', '-'));
        r.setIp(ip);
        r.setDurationMinutes(1440);
        return r;
    }
}

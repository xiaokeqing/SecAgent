package org.example.response;

import org.example.core.model.ActiveResponseResult;
import org.example.core.model.AlertSeverity;
import org.example.core.model.AlertSource;
import org.example.core.model.AlertType;
import org.example.core.model.SecurityAlert;
import org.example.integration.WazuhGateway;
import org.example.integration.wazuh.SshBlockExecutor;
import org.example.publicapi.PublicAlertSource;
import org.example.security.ResponseGuard;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * {@link AutoResponder} 的单测：阈值、护栏、dry-run、冷却、异常隔离。
 *
 * <p>为什么这些用例必须存在：这个类修的正是"自动封禁恒为 0 且没人发现"——
 * 一条只在真机上每分钟跑一次的调度，如果阈值算错、护栏被绕过或 dry-run 失效，
 * 页面照样显示 0 或悄悄把健康检查源封掉，单测是唯一能在部署前抓住它的地方。
 *
 * <p>替身全部手写（{@link PublicAlertSource} / {@link ResponseActionService} /
 * {@link AuditService} / {@link BlockRecordStore} 子类），不用 Mockito：
 * 本机 Maven 跑在 JDK 25 上，ByteBuddy 内联 mock 无法改写类层级，仓库既有测试也这个风格。
 * 护栏用<b>真实对象</b>——"是否先过护栏"本身是被测行为，替身掉它等于假设了它会被调用。
 */
class AutoResponderTest {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** 不在保护白名单里的公网地址（203.0.113.0/24 是 TEST-NET，会被护栏拒绝，不能用来测"该封"） */
    private static final String ATTACKER = "45.33.32.156";

    private ResponseGuard guard;
    private FakeAlertSource alerts;
    private FakeActionService actions;
    private FakeAuditService audits;
    private FakeBlockRecordStore store;
    private AutoResponder responder;

    @BeforeEach
    void setUp() {
        guard = newGuard();
        alerts = new FakeAlertSource();
        actions = new FakeActionService(guard);
        audits = new FakeAuditService();
        store = new FakeBlockRecordStore();
        responder = new AutoResponder(alerts, actions, guard, audits, store);
        // 时钟固定到秒，避免格式串里的纳秒让窗口边界抖动
        setClock(LocalDateTime.now().withNano(0));
    }

    // ---------------------------------------------------------------- 阈值

    @Test
    @DisplayName("HIGH+CRITICAL 命中次数达到 min-high(30) → 真正下发封禁（含 actor/source/reason）")
    void blocksWhenHighThresholdReached() {
        ReflectionTestUtils.setField(responder, "dryRun", false);
        alerts.list = alertsOf(ATTACKER, AlertSeverity.HIGH, 30, LocalDateTime.now().minusMinutes(1));

        responder.runOnce();

        assertThat(actions.calls).hasSize(1);
        ActionCall call = actions.calls.get(0);
        assertThat(call.ip).isEqualTo(ATTACKER);
        assertThat(call.durationMinutes).isEqualTo(60);
        assertThat(call.actor).isEqualTo("auto-responder");
        assertThat(call.source).isEqualTo("自动处置");
        assertThat(call.reason).isEqualTo("自动封禁：5 分钟内 30 条高危（含 0 条严重）");
        assertThat(lastAction()).isEqualTo("block");
    }

    @Test
    @DisplayName("未达阈值 → 不下发，也不产生决策（20 HIGH + 2 CRITICAL：22<30 且 2<3）")
    void doesNothingBelowThreshold() {
        ReflectionTestUtils.setField(responder, "dryRun", false);
        List<SecurityAlert> list = new ArrayList<>();
        list.addAll(alertsOf(ATTACKER, AlertSeverity.HIGH, 20, LocalDateTime.now().minusMinutes(1)));
        list.addAll(alertsOf(ATTACKER, AlertSeverity.CRITICAL, 2, LocalDateTime.now().minusMinutes(1)));
        alerts.list = list;

        responder.runOnce();

        assertThat(actions.calls).isEmpty();
        assertThat(responder.recentWindows(50)).isEmpty();
    }

    @Test
    @DisplayName("按告警的 count（命中次数）求和，而不是数行数：3 条 × count=10 即达 30")
    void aggregatesHitCountNotRowCount() {
        ReflectionTestUtils.setField(responder, "dryRun", false);
        List<SecurityAlert> list = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            SecurityAlert a = alert(ATTACKER, AlertSeverity.HIGH, LocalDateTime.now().minusMinutes(1));
            a.setCount(10);
            list.add(a);
        }
        alerts.list = list;

        responder.runOnce();

        assertThat(actions.calls).hasSize(1);
        assertThat(actions.calls.get(0).reason).contains("30 条高危");
    }

    @Test
    @DisplayName("CRITICAL 单路径：3 条严重远低于 min-high 也照样封（min-critical=3）")
    void criticalPathBlocksBelowHighThreshold() {
        ReflectionTestUtils.setField(responder, "dryRun", false);
        alerts.list = alertsOf(ATTACKER, AlertSeverity.CRITICAL, 3, LocalDateTime.now().minusMinutes(1));

        responder.runOnce();

        assertThat(actions.calls).hasSize(1);
        assertThat(actions.calls.get(0).reason).isEqualTo("自动封禁：5 分钟内 3 条高危（含 3 条严重）");
    }

    @Test
    @DisplayName("窗口外的老告警不计入：30 条全部是 30 分钟前的 → 不封")
    void ignoresAlertsOutsideFiveMinuteWindow() {
        ReflectionTestUtils.setField(responder, "dryRun", false);
        alerts.list = alertsOf(ATTACKER, AlertSeverity.HIGH, 30, LocalDateTime.now().minusMinutes(30));

        responder.runOnce();

        assertThat(actions.calls).isEmpty();
    }

    // ---------------------------------------------------------------- 护栏 / 输入

    @Test
    @DisplayName("白名单命中 → 跳过且不写 BLOCKED 审计（避免再往审计里刷空目标垃圾）")
    void whitelistedTargetIsSkippedWithoutBlockedAudit() {
        ReflectionTestUtils.setField(responder, "dryRun", false);
        alerts.list = alertsOf("10.1.2.3", AlertSeverity.HIGH, 30, LocalDateTime.now().minusMinutes(1));

        responder.runOnce();

        assertThat(actions.calls).isEmpty();
        assertThat(audits.appended).isEmpty();
        assertThat(lastAction()).isEqualTo("skip-guard");
        assertThat(lastReason()).contains("白名单");
    }

    @Test
    @DisplayName("非法 IP 形态 → 跳过并只留日志/决策，不调用 blockIp")
    void invalidIpShapeIsSkipped() {
        ReflectionTestUtils.setField(responder, "dryRun", false);
        alerts.list = alertsOf("not-an-ip", AlertSeverity.HIGH, 30, LocalDateTime.now().minusMinutes(1));

        responder.runOnce();

        assertThat(actions.calls).isEmpty();
        assertThat(lastAction()).isEqualTo("skip-guard");
        assertThat(lastReason()).contains("非法 IP");
    }

    @Test
    @DisplayName("srcIp 为空/空白 → 忽略，不抛异常也不封")
    void emptySrcIpIsIgnored() {
        ReflectionTestUtils.setField(responder, "dryRun", false);
        List<SecurityAlert> list = new ArrayList<>();
        for (int i = 0; i < 30; i++) {
            SecurityAlert a = alert("", AlertSeverity.CRITICAL, LocalDateTime.now().minusMinutes(1));
            list.add(a);
            list.add(alert("   ", AlertSeverity.CRITICAL, LocalDateTime.now().minusMinutes(1)));
        }
        alerts.list = list;

        assertThatCode(() -> responder.runOnce()).doesNotThrowAnyException();
        assertThat(actions.calls).isEmpty();
        assertThat(responder.recentWindows(50)).isEmpty();
    }

    // ---------------------------------------------------------------- dry-run / 冷却

    @Test
    @DisplayName("dry-run（默认 true）：不下发，只写 action=block-ip-dryrun 的自定义审计")
    void dryRunOnlyAuditsAndNeverDispatches() {
        // dryRun 默认就是 true，这里刻意不 setField：默认值本身是被测行为
        alerts.list = alertsOf(ATTACKER, AlertSeverity.HIGH, 30, LocalDateTime.now().minusMinutes(1));

        responder.runOnce();

        assertThat(actions.calls).isEmpty();
        assertThat(audits.appended).hasSize(1);
        ResponseAudit audit = audits.appended.get(0);
        assertThat(audit.getAction()).isEqualTo("block-ip-dryrun");
        assertThat(audit.getTarget()).isEqualTo(ATTACKER);
        assertThat(audit.getMode()).isEqualTo("DRY_RUN");
        assertThat(lastAction()).isEqualTo("dry-run");
    }

    @Test
    @DisplayName("冷却：10 分钟内同一 IP 只处置一次；超过 10 分钟可以再封")
    void cooldownPreventsRepeatWithinTenMinutesThenExpires() {
        ReflectionTestUtils.setField(responder, "dryRun", false);
        LocalDateTime t0 = LocalDateTime.now().withNano(0);
        setClock(t0);
        alerts.list = alertsOf(ATTACKER, AlertSeverity.HIGH, 30, t0.minusMinutes(1));

        responder.runOnce();
        responder.runOnce(); // 同一分钟内第二轮（真实调度每 60s 一次）

        assertThat(actions.calls).hasSize(1);
        assertThat(lastAction()).isEqualTo("skip-cooldown");
        assertThat(lastReason()).contains("冷却期内");

        // 11 分钟后：告警继续增长，这次应该真的再封一次
        LocalDateTime t1 = t0.plusMinutes(11);
        setClock(t1);
        alerts.list = alertsOf(ATTACKER, AlertSeverity.HIGH, 30, t1.minusMinutes(1));

        responder.runOnce();

        assertThat(actions.calls).hasSize(2);
    }

    @Test
    @DisplayName("已在生效封禁记录里（blockActive 等价物 listActive）→ 不重复封")
    void alreadyActiveBlockIsNotRepeated() {
        ReflectionTestUtils.setField(responder, "dryRun", false);
        store.active = List.of(rec(ATTACKER));
        alerts.list = alertsOf(ATTACKER, AlertSeverity.HIGH, 30, LocalDateTime.now().minusMinutes(1));

        responder.runOnce();

        assertThat(actions.calls).isEmpty();
        assertThat(lastAction()).isEqualTo("skip-cooldown");
        assertThat(lastReason()).contains("已封禁中");
    }

    // ---------------------------------------------------------------- 异常隔离 / 观测

    @Test
    @DisplayName("告警源抛异常 → tick() 不抛，调度不会被一轮失败带走")
    void alertSourceFailureNeverEscapesScheduler() {
        alerts.fail = true;

        assertThatCode(() -> responder.tick()).doesNotThrowAnyException();
        assertThat(responder.recentWindows(50)).isEmpty();
    }

    @Test
    @DisplayName("单个 IP 下发抛异常 → 不炸调度，记为 error 决策")
    void dispatchFailureIsRecordedInsteadOfThrown() {
        ReflectionTestUtils.setField(responder, "dryRun", false);
        actions.throwOnBlock = new IllegalStateException("ssh timeout");
        alerts.list = alertsOf(ATTACKER, AlertSeverity.HIGH, 30, LocalDateTime.now().minusMinutes(1));

        assertThatCode(() -> responder.tick()).doesNotThrowAnyException();
        assertThat(lastAction()).isEqualTo("error");
        assertThat(lastReason()).contains("ssh timeout");
    }

    @Test
    @DisplayName("state：暴露阈值与最近 10 次决策（内存环形队列保留 50 条）")
    void stateExposesThresholdsAndLastTenWindows() {
        LocalDateTime now = LocalDateTime.now().withNano(0);
        setClock(now);
        List<SecurityAlert> list = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            list.addAll(alertsOf("45.33.32." + (100 + i), AlertSeverity.HIGH, 30, now.minusMinutes(1)));
        }
        alerts.list = list;

        responder.runOnce();

        Map<String, Object> state = responder.state();
        assertThat(state.get("enabled")).isEqualTo(true);
        assertThat(state.get("dryRun")).isEqualTo(true);
        assertThat(state.get("minHigh")).isEqualTo(30);
        assertThat(state.get("minCritical")).isEqualTo(3);
        assertThat(state.get("durationMinutes")).isEqualTo(60);
        assertThat((List<?>) state.get("windows")).hasSize(10);
        assertThat(responder.recentWindows(50)).hasSize(12);
    }

    // ---------------------------------------------------------------- 蜜罐登录（真实入侵信号）

    @Test
    @DisplayName("蜜罐「登录成功」1 条即封（无视 min-high=30）：reason 写清\"攻击者已进入\"，matched=honeypot-login")
    void honeypotLoginBlocksRegardlessOfThreshold() {
        ReflectionTestUtils.setField(responder, "dryRun", false);
        // 刻意给 LOW：Cowrie 100102 的 level 不高，按等级过滤就会漏掉真实入侵
        SecurityAlert login = honeypotAlert(ATTACKER, "蜜罐: 攻击者\"登录成功\" (SSH)", AlertSeverity.LOW);
        alerts.list = List.of(login);

        responder.runOnce();

        assertThat(actions.calls).hasSize(1);
        ActionCall call = actions.calls.get(0);
        assertThat(call.ip).isEqualTo(ATTACKER);
        assertThat(call.durationMinutes).isEqualTo(60);
        assertThat(call.reason).isEqualTo("自动封禁：蜜罐登录成功（攻击者已进入）");
        assertThat(lastAction()).isEqualTo("block");
        assertThat(lastMatched()).isEqualTo("honeypot-login");
    }

    @Test
    @DisplayName("开关关闭（block-on-honeypot-login=false）→ 蜜罐登录不再单独成案，回到纯条数判定")
    void honeypotLoginRuleCanBeDisabled() {
        ReflectionTestUtils.setField(responder, "dryRun", false);
        ReflectionTestUtils.setField(responder, "blockOnHoneypotLogin", false);
        alerts.list = List.of(honeypotAlert(ATTACKER, "蜜罐: 攻击者\"登录成功\" (SSH)", AlertSeverity.LOW));

        responder.runOnce();

        assertThat(actions.calls).isEmpty();
        assertThat(responder.recentWindows(50)).isEmpty();
    }

    @Test
    @DisplayName("蜜罐来源的「连接尝试」「登录失败」不算登录成功：只认来源不认动作会误封扫描噪音")
    void honeypotNoiseWithoutSuccessfulLoginDoesNotBlock() {
        ReflectionTestUtils.setField(responder, "dryRun", false);
        List<SecurityAlert> list = new ArrayList<>();
        list.add(honeypotAlert(ATTACKER, "蜜罐: 连接尝试 cowrie ssh", AlertSeverity.LOW));
        list.add(honeypotAlert(ATTACKER, "蜜罐: 攻击者登录失败 (SSH)", AlertSeverity.LOW));
        alerts.list = list;

        responder.runOnce();

        assertThat(actions.calls).isEmpty();
        assertThat(responder.recentWindows(50)).isEmpty();
    }

    @Test
    @DisplayName("蜜罐登录的冷却按 30 分钟算：11 分钟时仍跳过，31 分钟才允许再封")
    void honeypotLoginCooldownIsThirtyMinutes() {
        ReflectionTestUtils.setField(responder, "dryRun", false);
        LocalDateTime t0 = LocalDateTime.now().withNano(0);
        setClock(t0);
        alerts.list = List.of(honeypotLoginAlert(ATTACKER, t0.minusMinutes(1)));

        responder.runOnce();
        assertThat(actions.calls).hasSize(1);

        // 11 分钟后：阈值路径的 10 分钟冷却已过期，但蜜罐路径是 30 分钟 → 必须还在冷却
        LocalDateTime t1 = t0.plusMinutes(11);
        setClock(t1);
        alerts.list = List.of(honeypotLoginAlert(ATTACKER, t1.minusMinutes(1)));
        responder.runOnce();

        assertThat(actions.calls).hasSize(1);
        assertThat(lastAction()).isEqualTo("skip-cooldown");
        assertThat(lastReason()).contains("30 分钟内");
        assertThat(lastMatched()).isEqualTo("honeypot-login");

        // 31 分钟后冷却真的过期：同一台蜜罐再次被登录成功，必须能再封（不能把下一次入侵吞掉）
        LocalDateTime t2 = t0.plusMinutes(31);
        setClock(t2);
        alerts.list = List.of(honeypotLoginAlert(ATTACKER, t2.minusMinutes(1)));
        responder.runOnce();

        assertThat(actions.calls).hasSize(2);
        assertThat(lastAction()).isEqualTo("block");
    }

    @Test
    @DisplayName("dry-run 下蜜罐登录同样只演练：不下发，审计 detail 里能看出是 honeypot-login 命中的")
    void dryRunStillSimulatesHoneypotLogin() {
        // dryRun 默认 true，刻意不 setField
        alerts.list = List.of(honeypotLoginAlert(ATTACKER, LocalDateTime.now().minusMinutes(1)));

        responder.runOnce();

        assertThat(actions.calls).isEmpty();
        assertThat(audits.appended).hasSize(1);
        ResponseAudit audit = audits.appended.get(0);
        assertThat(audit.getAction()).isEqualTo("block-ip-dryrun");
        assertThat(audit.getTarget()).isEqualTo(ATTACKER);
        assertThat(audit.getMode()).isEqualTo("DRY_RUN");
        assertThat(audit.getDetail()).contains("honeypot-login");
        assertThat(lastAction()).isEqualTo("dry-run");
        assertThat(lastMatched()).isEqualTo("honeypot-login");
    }

    @Test
    @DisplayName("windows 的 matched 能区分三种命中：high-threshold / critical-threshold / honeypot-login")
    void matchedFieldExplainsWhyEachIpWasChosen() {
        ReflectionTestUtils.setField(responder, "dryRun", false);
        LocalDateTime at = LocalDateTime.now().minusMinutes(1);
        String criticalIp = "45.33.32.157";
        String honeypotIp = "45.33.32.158";
        List<SecurityAlert> list = new ArrayList<>();
        list.addAll(alertsOf(ATTACKER, AlertSeverity.HIGH, 30, at));
        list.addAll(alertsOf(criticalIp, AlertSeverity.CRITICAL, 3, at));
        list.add(honeypotLoginAlert(honeypotIp, at));
        alerts.list = list;

        responder.runOnce();

        assertThat(actions.calls).hasSize(3);
        Map<String, String> matchedByIp = new java.util.HashMap<>();
        for (Map<String, Object> w : responder.recentWindows(50)) {
            matchedByIp.put(String.valueOf(w.get("ip")), String.valueOf(w.get("matched")));
        }
        assertThat(matchedByIp.get(ATTACKER)).isEqualTo("high-threshold");
        assertThat(matchedByIp.get(criticalIp)).isEqualTo("critical-threshold");
        assertThat(matchedByIp.get(honeypotIp)).isEqualTo("honeypot-login");
    }

    // ---------------------------------------------------------------- 测试替身

    private static SecurityAlert alert(String ip, AlertSeverity severity, LocalDateTime at) {
        SecurityAlert a = new SecurityAlert("alert-" + System.nanoTime(), "t", severity,
                AlertType.BRUTE_FORCE, AlertSource.WAZUH);
        a.setSrcIp(ip);
        a.setOccurredAt(at.format(FMT));
        a.setCount(1);
        return a;
    }

    /** 蜜罐类告警：type 常被 guess 成 OTHER，来源只体现在文本里（Wazuh 的 description 以"蜜罐"开头） */
    private static SecurityAlert honeypotAlert(String ip, String title, AlertSeverity severity) {
        SecurityAlert a = new SecurityAlert("hp-" + System.nanoTime(), title, severity,
                AlertType.OTHER, AlertSource.WAZUH);
        a.setSrcIp(ip);
        a.setRuleName(title);
        a.setService("ssh");
        a.setOccurredAt(LocalDateTime.now().withNano(0).format(FMT));
        a.setCount(1);
        return a;
    }

    private static SecurityAlert honeypotLoginAlert(String ip, LocalDateTime at) {
        SecurityAlert a = honeypotAlert(ip, "蜜罐: 攻击者\"登录成功\" (SSH)", AlertSeverity.LOW);
        a.setOccurredAt(at.format(FMT));
        return a;
    }

    private static List<SecurityAlert> alertsOf(String ip, AlertSeverity severity, int n, LocalDateTime at) {
        List<SecurityAlert> out = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            out.add(alert(ip, severity, at));
        }
        return out;
    }

    private void setClock(LocalDateTime at) {
        ZoneId zone = ZoneId.systemDefault();
        ReflectionTestUtils.setField(responder, "clock",
                Clock.fixed(at.atZone(zone).toInstant(), zone));
    }

    private String lastAction() {
        List<Map<String, Object>> w = responder.recentWindows(1);
        return w.isEmpty() ? null : String.valueOf(w.get(0).get("action"));
    }

    private String lastReason() {
        List<Map<String, Object>> w = responder.recentWindows(1);
        return w.isEmpty() ? null : String.valueOf(w.get(0).get("reason"));
    }

    private String lastMatched() {
        List<Map<String, Object>> w = responder.recentWindows(1);
        return w.isEmpty() ? null : String.valueOf(w.get(0).get("matched"));
    }

    /** 真实护栏：只留 127/8 与 10/8 两条，其余保护段由内置默认值兜住 */
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

    /** 告警源替身：直接返回给定列表，可注入读取异常 */
    static class FakeAlertSource extends PublicAlertSource {
        List<SecurityAlert> list = new ArrayList<>();
        boolean fail;

        @Override
        public List<SecurityAlert> readAlerts() {
            if (fail) {
                throw new IllegalStateException("indexer read timeout");
            }
            return list;
        }
    }

    /** 处置服务替身：只记录"有没有下发"，不碰 SSH/Wazuh/磁盘 */
    static class FakeActionService extends ResponseActionService {
        final List<ActionCall> calls = new ArrayList<>();
        RuntimeException throwOnBlock;

        FakeActionService(ResponseGuard guard) {
            super(guard, null, null, provider(null), provider((SshBlockExecutor) null));
        }

        @Override
        public ActiveResponseResult blockIp(String ip, Integer durationMinutes, String reason,
                                            String actor, String source) {
            calls.add(new ActionCall(ip, durationMinutes, reason, actor, source));
            if (throwOnBlock != null) {
                throw throwOnBlock;
            }
            return ActiveResponseResult.real("ipset-block", ip, "已封禁 " + ip, "AUD-test");
        }
    }

    /** 审计替身：只做"记下来"，不碰磁盘 */
    static class FakeAuditService extends AuditService {
        final List<ResponseAudit> appended = new ArrayList<>();

        @Override
        public ResponseAudit append(ResponseAudit a) {
            a.setId("AUD-" + (appended.size() + 1));
            a.setTime(LocalDateTime.now().format(FMT));
            appended.add(a);
            return a;
        }
    }

    /** 封禁记录替身：给 listActive 一个可控结果 */
    static class FakeBlockRecordStore extends BlockRecordStore {
        List<BlockRecord> active = new ArrayList<>();

        @Override
        public List<BlockRecord> listActive() {
            return active;
        }
    }

    static class ActionCall {
        final String ip;
        final Integer durationMinutes;
        final String reason;
        final String actor;
        final String source;

        ActionCall(String ip, Integer durationMinutes, String reason, String actor, String source) {
            this.ip = ip;
            this.durationMinutes = durationMinutes;
            this.reason = reason;
            this.actor = actor;
            this.source = source;
        }
    }

    private static BlockRecord rec(String ip) {
        BlockRecord r = new BlockRecord();
        r.setId("BLK-" + ip.replace('.', '-'));
        r.setIp(ip);
        r.setDurationMinutes(60);
        return r;
    }
}

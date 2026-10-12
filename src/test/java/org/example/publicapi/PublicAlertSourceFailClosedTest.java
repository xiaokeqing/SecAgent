package org.example.publicapi;

import org.example.core.model.SecurityAlert;
import org.example.integration.WazuhGateway;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 公开端点告警取数的 fail-closed 回归测试。
 *
 * <p>守的是 2026-10-13 演练实测到的一个窗口：
 * <b>链路连得上（mode=REAL），但查询失败 → WazuhService 退回内置样本</b>。
 * 那个窗口里 {@code mode()} 仍是 REAL，只看 mode 的话公网会把样本当真实攻击记录展示，
 * 并且 {@code degraded=false} —— 也就是"看着有数据、其实是假的"，
 * 正是这个项目吃过最多的那种亏。
 *
 * <p>为什么不用 Mockito：本仓库测试依赖里没有它；{@link WazuhGateway} 是接口，
 * 用动态代理做替身既够用又不引入新依赖。
 * <p>为什么必须有用例：这条路径以前没有任何测试，所以它坏掉时全量测试照样全绿。
 */
class PublicAlertSourceFailClosedTest {

    /** 造一条"内置样本"告警：WazuhService/SuricataService 都会打 extra.mock=true */
    private static SecurityAlert mockAlert() {
        SecurityAlert a = new SecurityAlert();
        a.setId("wz-mock-001");
        a.setTitle("SSH 暴力破解尝试（多次认证失败）");
        a.setSource(org.example.core.model.AlertSource.BUILTIN);
        Map<String, Object> extra = new HashMap<>();
        extra.put("mock", true);
        a.setExtra(extra);
        return a;
    }

    /** 造一条真实告警：没有 mock 标记 */
    private static SecurityAlert realAlert() {
        SecurityAlert a = new SecurityAlert();
        a.setId("real-" + System.nanoTime());
        a.setTitle("真实告警：来自 indexer 的蜜罐登录失败");
        a.setSource(org.example.core.model.AlertSource.WAZUH);
        a.setExtra(new HashMap<>());
        return a;
    }

    private static PublicAlertSource sourceWith(String mode, List<SecurityAlert> alerts) {
        WazuhGateway gateway = (WazuhGateway) Proxy.newProxyInstance(
                WazuhGateway.class.getClassLoader(),
                new Class<?>[]{WazuhGateway.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "mode":
                            return mode;
                        case "recentAlerts":
                            return alerts;
                        case "toString":
                            return "StubWazuhGateway(mode=" + mode + ", alerts=" + alerts.size() + ")";
                        default:
                            return null;
                    }
                });
        PublicAlertSource source = new PublicAlertSource();
        ReflectionTestUtils.setField(source, "wazuhGateway", gateway);
        return source;
    }

    @Test
    @DisplayName("fail-closed：mode=REAL 但整批是内置样本 → 全部剔除，且判为不可用（degraded=true）")
    void treatsMockFallbackAsUnavailable() {
        PublicAlertSource source = sourceWith("REAL", List.of(mockAlert(), mockAlert()));

        assertTrue(source.available(), "链路模式本身是 REAL");
        assertTrue(source.readAlerts().isEmpty(), "样本必须被剔除，绝不能当真实告警展示");
        assertFalse(source.realData(), "样本回退窗口必须判为不可用 → 响应里 degraded 应为 true");
    }

    @Test
    @DisplayName("真样本混在真告警里：只剔样本，真数据照常可用")
    void keepsRealAlertsAndDropsMockOnes() {
        PublicAlertSource source = sourceWith("REAL", List.of(realAlert(), mockAlert(), realAlert()));

        assertEquals(2, source.readAlerts().size(), "样本被剔除，真告警保留");
        assertTrue(source.realData(), "只要还有真实数据，就算可用");
    }

    @Test
    @DisplayName("mode=MOCK：直接返回空（不展示样本）")
    void returnsEmptyWhenModeIsMock() {
        PublicAlertSource source = sourceWith("MOCK", List.of(mockAlert()));
        assertTrue(source.readAlerts().isEmpty());
        assertFalse(source.realData());
    }

    @Test
    @DisplayName("取数抛异常：返回空且判为不可用（不把异常当空数据）")
    void returnsEmptyWhenGatewayThrows() {
        WazuhGateway gateway = (WazuhGateway) Proxy.newProxyInstance(
                WazuhGateway.class.getClassLoader(),
                new Class<?>[]{WazuhGateway.class},
                (proxy, method, args) -> {
                    if ("mode".equals(method.getName())) {
                        return "REAL";
                    }
                    if ("recentAlerts".equals(method.getName())) {
                        throw new java.io.IOException("Read timed out");
                    }
                    if ("toString".equals(method.getName())) {
                        return "ThrowingGateway";
                    }
                    return null;
                });
        PublicAlertSource source = new PublicAlertSource();
        ReflectionTestUtils.setField(source, "wazuhGateway", gateway);

        assertTrue(source.readAlerts().isEmpty());
        assertFalse(source.realData());
    }
}

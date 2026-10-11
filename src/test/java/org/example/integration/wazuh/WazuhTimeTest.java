package org.example.integration.wazuh;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Wazuh 时间戳转换的测试。
 *
 * <p>钉住的是一个真实出过的错：{@code @timestamp} 是 UTC，却被当成本地时间显示，
 * 于是北京时间 21:57 的告警在页面上显示成 13:57 ——
 * 格式合法、排序正确，只有跟墙上时钟对照才会发现。
 */
class WazuhTimeTest {

    private static final ZoneId SH = ZoneId.of("Asia/Shanghai");

    @Test
    @DisplayName("UTC 的 @timestamp 必须转成北京时间，而不是原样当本地时间")
    void convertsUtcToLocal() {
        assertEquals("2026-10-11 21:57:40",
                WazuhTime.toLocal("2026-10-11T13:57:40.279Z", SH));
    }

    @Test
    @DisplayName("Wazuh timestamp 字段的 +0000 形态（偏移量没有冒号）同样要转")
    void handlesOffsetWithoutColon() {
        assertEquals("2026-10-11 21:57:40",
                WazuhTime.toLocal("2026-10-11T13:57:40.279+0000", SH));
    }

    @Test
    @DisplayName("带 +08:00 偏移的时间不再二次转换")
    void respectsExplicitOffset() {
        assertEquals("2026-10-11 21:57:40",
                WazuhTime.toLocal("2026-10-11T21:57:40+08:00", SH));
    }

    @Test
    @DisplayName("不带时区的裸时间按目标时区解释")
    void treatsBareTimeAsLocal() {
        assertEquals("2026-10-11 21:57:40",
                WazuhTime.toLocal("2026-10-11 21:57:40", SH));
        assertEquals("2026-10-11 21:57:40",
                WazuhTime.toLocal("2026-10-11T21:57:40.279", SH));
    }

    @Test
    @DisplayName("解析不了就原样返回，不编造时间")
    void fallsBackToRawValue() {
        assertEquals("not-a-time", WazuhTime.toLocal("not-a-time", SH));
    }
}

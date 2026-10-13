package org.example.config;

import org.example.llm.DeepSeekLlmProvider;
import org.example.llm.OutboundGuard;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * DeepSeek 对话 provider 的 <b>Spring 装配</b>测试。
 *
 * <h3>为什么必须有这一层（它是本项目唯一一个"能编译但起不来"的坑）</h3>
 * 本仓库<b>没有任何 {@code @SpringBootTest}</b>（全量上下文需要一堆外部依赖），
 * 于是"Bean 装不上/歧义/装配类自己构造不出来"这类缺陷，
 * <b>编译和单测都不会报，只有生产容器起不来时才暴露</b>。
 * 这里用 {@link ApplicationContextRunner} 只装配涉及的那几个类，
 * 把"装配能不能成立"变成一条秒级、可重复的断言。
 *
 * <p>具体钉住三件曾在别处踩过的事：
 * <ol>
 *   <li><b>{@link DeepSeekConfig} 必须恰好是一个 Bean</b>：它同时是"不可变值对象"
 *       （{@code new DeepSeekConfig(1,2,3)} 被单测大量使用）。如果让<b>装配类</b>与
 *       <b>它产出的对象</b>同名同类型，Spring 要么把配置类本身当成那个 Bean 去构造
 *       （它的构造参数是三个 {@code long}，没有哪个 Bean 能填），要么出现两个候选
 *       —— 两种都是启动期硬失败；</li>
 *   <li><b>生效超时是钳制后的值</b>（放大无效、非法不变成永不超时），
 *       且打印/装配的是同一个对象；</li>
 *   <li><b>Key 缺失 ⇒ 不可用且显式</b>：{@code DEEPSEEK_API_KEY} 只从环境变量读，
 *       没配时 {@code available()=false}、{@code describe()} 写 {@code key=MISSING}，
 *       绝不静默变成"可用"。</li>
 * </ol>
 */
class DeepSeekWiringTest {

    /** 只装配 DeepSeek 那条链路所需的类；默认属性与 application.yml 的默认值一致 */
    private ApplicationContextRunner runner() {
        return new ApplicationContextRunner()
                .withUserConfiguration(DeepSeekOutboundConfig.class, DeepSeekLlmProvider.class)
                .withBean(OutboundGuard.class)
                .withPropertyValues("app.llm.deepseek.api-key=");
    }

    @Test
    @DisplayName("【核心】DeepSeek 链路能装配起来：上下文不失败，且 DeepSeekConfig 恰好一个 Bean")
    void deepSeekBeansWireUpWithoutStartingWholeApp() {
        runner().run(ctx -> {
            Throwable failure = ctx.getStartupFailure();
            if (failure != null) {
                // 这条断言的意义：把"生产容器起不来"提前成一条单测失败
                throw new AssertionError("DeepSeek 链路装配失败（生产里就是启动失败）：" + failure, failure);
            }
            assertTrue(ctx.containsBean("deepSeekConfig"), "必须有一个名为 deepSeekConfig 的 Bean: "
                    + java.util.Arrays.toString(ctx.getBeanDefinitionNames()));
            assertEquals(1, ctx.getBeansOfType(DeepSeekConfig.class).size(),
                    "DeepSeekConfig 必须恰好一个 Bean（两个候选会让 @Autowired 直接失败）");
            assertNotNull(ctx.getBean(DeepSeekLlmProvider.class));
        });
    }

    @Test
    @DisplayName("生效超时取自钳制后的值（3s/12s/15s），且与装配出来的对象是同一个")
    void effectiveTimeoutsAreClampedAndShared() {
        runner().run(ctx -> {
            assertNotNull(ctx.getBean(DeepSeekConfig.class), "上下文必须能启动并拿到 DeepSeekConfig");
            DeepSeekConfig timeouts = ctx.getBean(DeepSeekConfig.class);
            assertEquals(OutboundTimeouts.DEFAULT_CONNECT_MS, timeouts.getEffectiveConnectTimeoutMs());
            assertEquals(OutboundTimeouts.DEFAULT_READ_MS, timeouts.getEffectiveReadTimeoutMs());
            assertEquals(OutboundTimeouts.DEFAULT_CALL_MS, timeouts.getEffectiveCallTimeoutMs());

            DeepSeekLlmProvider provider = ctx.getBean(DeepSeekLlmProvider.class);
            assertTrue(provider.effectiveTimeouts() == timeouts,
                    "provider 真正用的必须是装配出来的那个对象（否则自检打印的值是骗人的）");
        });
    }

    @Test
    @DisplayName("app.llm.provider 不配置时默认 dashscope ⇒ DeepSeek 不可用（默认行为钉死在这里）")
    void defaultProviderIsDashScopeSoDeepSeekStaysOff() {
        runner().run(ctx -> {
            DeepSeekLlmProvider provider = ctx.getBean(DeepSeekLlmProvider.class);
            assertFalse(provider.available(),
                    "默认（不写 app.llm.provider）必须是 dashscope：DeepSeek 实现不得参与调用");
        });
    }

    @Test
    @DisplayName("DEEPSEEK_API_KEY 缺失 ⇒ 不可用 + describe() 显式写 key=MISSING（不静默）")
    void missingKeyIsExplicitNotSilent() {
        runner()
                .withPropertyValues("app.llm.provider=deepseek")
                .run(ctx -> {
                    DeepSeekLlmProvider provider = ctx.getBean(DeepSeekLlmProvider.class);
                    assertFalse(provider.keyConfigured(), "空 Key 必须判为未配置");
                    assertFalse(provider.available(), "选中但没 Key ⇒ 不可用");
                    assertTrue(provider.describe().contains("key=MISSING"),
                            "缺失必须显式打印，不能静默：" + provider.describe());
                });
    }

    @Test
    @DisplayName("Key 只从环境变量读：配了即为可用，且 describe() 绝不回显 Key 内容")
    void keyConfiguredFromEnvironmentOnly() {
        String secret = "sk-test-secret-should-never-be-logged";
        runner()
                .withPropertyValues("app.llm.provider=deepseek", "app.llm.deepseek.api-key=" + secret)
                .run(ctx -> {
                    DeepSeekLlmProvider provider = ctx.getBean(DeepSeekLlmProvider.class);
                    assertTrue(provider.keyConfigured());
                    assertTrue(provider.available());
                    assertTrue(provider.describe().contains("key=SET"), provider.describe());
                    assertFalse(provider.describe().contains(secret),
                            "describe() 绝不打印 Key 内容：" + provider.describe());
                });
    }
}

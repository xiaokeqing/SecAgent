package org.example;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.lang.reflect.Constructor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 门禁：Spring 组件的构造器必须"能被 Spring 选中"。
 *
 * <p>【为什么需要这道测试 —— 2026-10-13 的真实生产事故】
 * {@code ResponseActionService} 被加了第二个构造器（一个给单测的便捷构造器），两者都没有
 * {@code @Autowired}。Spring 4.3+ 只在"类里唯一构造器"时自动注入，多构造器且都没标注时，
 * 启动会以 {@code UnsatisfiedDependencyException: No default constructor found} 失败。
 *
 * <p>当时 CI 是<b>全绿</b>的 —— 因为单测直接 {@code new} 对象、从不加载 Spring 上下文。
 * 结果是"CI 绿 → 镜像推到 ACR → 定时器拉上生产 → 应用崩溃循环"，直到线上不可用才发现。
 *
 * <p>本测试不启动 Spring：按源码目录反射扫描所有 Spring 组件类，检查"构造器数量 &gt; 1 时，
 * 必须恰好有一个被 {@code @Autowired} 标注"。纯反射、毫秒级、零环境依赖，正好补上那个缺口。
 */
class SpringBeanConstructorTest {

    private static final String SOURCE_ROOT = "src/main/java";

    @Test
    @DisplayName("多构造器的 Spring 组件必须显式标注 @Autowired（否则启动即崩）")
    void springComponentsWithMultipleConstructorsMustBeAnnotated() throws Exception {
        List<String> offenders = new ArrayList<>();
        for (Class<?> c : loadComponentClasses()) {
            Constructor<?>[] ctors = c.getDeclaredConstructors();
            if (ctors.length <= 1) {
                continue;
            }
            long annotated = 0;
            for (Constructor<?> ctor : ctors) {
                if (ctor.isAnnotationPresent(Autowired.class)) {
                    annotated++;
                }
            }
            if (annotated != 1) {
                offenders.add(String.format("%s：%d 个构造器，其中 @Autowired 标注 %d 个（必须恰好 1 个）",
                        c.getName(), ctors.length, annotated));
            }
        }
        assertTrue(offenders.isEmpty(),
                "以下 Spring 组件会让应用启动失败（多构造器但没显式指定注入哪一个）：\n  "
                        + String.join("\n  ", offenders));
    }

    /** 反射扫描 src/main/java 下所有类，挑出带 Spring 注解的那些 */
    private List<Class<?>> loadComponentClasses() throws Exception {
        Path root = Paths.get(SOURCE_ROOT);
        assertTrue(Files.isDirectory(root),
                "找不到 " + root.toAbsolutePath() + "（测试需在仓库根目录运行）");
        List<Class<?>> out = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(root)) {
            List<Path> files = new ArrayList<>();
            walk.filter(p -> p.toString().endsWith(".java")).forEach(files::add);
            for (Path p : files) {
                String rel = root.relativize(p).toString()
                        .replace(File.separatorChar, '.')
                        .replaceAll("\\.java$", "");
                try {
                    Class<?> c = Class.forName(rel, false, Thread.currentThread().getContextClassLoader());
                    if (isSpringComponent(c)) {
                        out.add(c);
                    }
                } catch (Throwable ignored) {
                    // 加载不了的类跳过：这门禁只关心能加载的组件
                }
            }
        }
        return out;
    }

    private boolean isSpringComponent(Class<?> c) {
        return c.isAnnotationPresent(Service.class)
                || c.isAnnotationPresent(Component.class)
                || c.isAnnotationPresent(Repository.class)
                || c.isAnnotationPresent(Controller.class)
                || c.isAnnotationPresent(RestController.class);
    }
}

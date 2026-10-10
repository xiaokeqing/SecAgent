package org.example.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.ToolCallback;

import java.io.File;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 工具调用审计 + 熔断（统一服务两条链路）。
 *
 * <p>① ToolCallback 链路（对话 ReactAgent、一键研判 AiOpsService）：用动态代理
 * {@link #wrapAll} 包装工具回调，模型每次 call 工具自动留痕；
 * <p>② 多智能体路由链路（MultiAgentCoordinator 编排层直接调用工具方法、不走 ToolCallback）：
 * 在其统一包装层 safeCallTool 中直接调用 {@link #record} + {@link #registerFailure}。
 *
 * <p>审计字段：时间、链路/角色、工具名、参数、结果摘要、耗时、是否成功，
 * 追加写入 data/tool-call-audit.json，实现"Agent 调了哪些工具、怎么调的、花了多久"全链路可追溯。
 *
 * <p>熔断：同一工具连续失败 ≥ {@link #MAX_CONSECUTIVE_FAILURES} 次后，registerFailure 直接抛异常终止，
 * 避免模型陷入同一失败工具的无效循环（提示词"3 次停"的代码层硬约束，不依赖模型自觉）。
 */
public final class ToolAuditWrapper {

    private static final Logger logger = LoggerFactory.getLogger(ToolAuditWrapper.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<List<Map<String, Object>>> LIST_TYPE =
            new TypeReference<List<Map<String, Object>>>() {
            };

    /** 同一工具连续失败熔断阈值 */
    public static final int MAX_CONSECUTIVE_FAILURES = 5;
    private static final int PARAMS_PREVIEW_MAX = 200;
    private static final int RESULT_PREVIEW_MAX = 300;
    private static final String AUDIT_FILE = "data/tool-call-audit.json";

    /** 工具名 -> 当前连续失败次数（两条链路共用） */
    private static final Map<String, AtomicInteger> consecutiveFailures = new ConcurrentHashMap<>();

    private ToolAuditWrapper() {
    }

    // ==================== ToolCallback 链路（动态代理） ====================

    /** 包装工具回调数组：审计 + 熔断 */
    public static ToolCallback[] wrapAll(ToolCallback[] callbacks) {
        if (callbacks == null || callbacks.length == 0) {
            return callbacks;
        }
        ToolCallback[] wrapped = new ToolCallback[callbacks.length];
        for (int i = 0; i < callbacks.length; i++) {
            wrapped[i] = wrap(callbacks[i]);
        }
        return wrapped;
    }

    /** 包装单个工具回调（动态代理，只拦截 call 方法，其他方法原样透传） */
    public static ToolCallback wrap(ToolCallback target) {
        InvocationHandler handler = (proxy, method, args) -> {
            if ("call".equals(method.getName())) {
                return auditCall(target, method, args);
            }
            return method.invoke(target, args);
        };
        return (ToolCallback) Proxy.newProxyInstance(
                target.getClass().getClassLoader(),
                new Class<?>[]{ToolCallback.class},
                handler);
    }

    /** 审计一次 ToolCallback 调用并执行熔断检查 */
    private static Object auditCall(ToolCallback target, Method method, Object[] args) throws Throwable {
        String toolName = target.getToolDefinition().name();
        String params = clip(args == null || args.length == 0 ? "[]" : String.valueOf(args[0]), PARAMS_PREVIEW_MAX);

        long start = System.currentTimeMillis();
        try {
            Object result = method.invoke(target, args);
            record("ReactAgent/ToolCallback", toolName, params, String.valueOf(result),
                    System.currentTimeMillis() - start, true);
            registerSuccess(toolName);
            return result;
        } catch (Throwable t) {
            Throwable real = t instanceof InvocationTargetException && t.getCause() != null
                    ? t.getCause() : t;
            String preview = real.getClass().getSimpleName() + ": "
                    + (real.getMessage() == null ? "" : real.getMessage());
            record("ReactAgent/ToolCallback", toolName, params, preview,
                    System.currentTimeMillis() - start, false);
            registerFailure(toolName);
            throw real;
        }
    }

    // ==================== 多智能体路由链路（Coordinator 直接调用） ====================

    /** 成功：清零连续失败计数 */
    public static void registerSuccess(String tool) {
        consecutiveFailures.remove(tool);
    }

    /** 失败：连续失败计数 +1，达到熔断阈值直接抛异常终止该方向 */
    public static void registerFailure(String tool) {
        AtomicInteger n = consecutiveFailures.computeIfAbsent(tool, k -> new AtomicInteger(0));
        int now = n.incrementAndGet();
        if (now >= MAX_CONSECUTIVE_FAILURES) {
            logger.error("[熔断] 工具 {} 连续失败 {} 次，终止该方向", tool, now);
            throw new IllegalStateException("工具调用熔断：" + tool + " 连续失败超过 "
                    + MAX_CONSECUTIVE_FAILURES + " 次，已终止该方向，请换用其他路径");
        }
    }

    /**
     * 追加一条工具调用审计记录（两条链路统一入口，线程安全；文件/目录不存在自动创建）。
     *
     * @param role          链路或角色（如 ReactAgent/ToolCallback、MultiAgent-Coordinator）
     * @param tool          工具名 / 工具标签
     * @param params        入参摘要
     * @param resultPreview 结果摘要
     * @param latencyMs     耗时毫秒
     * @param success       是否成功
     */
    public static void record(String role, String tool, String params,
                              String resultPreview, long latencyMs, boolean success) {
        try {
            List<Map<String, Object>> records = new ArrayList<>();
            File f = new File(AUDIT_FILE);
            File parent = f.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            if (f.exists() && f.length() > 0) {
                records.addAll(MAPPER.readValue(f, LIST_TYPE));
            }
            Map<String, Object> rec = new LinkedHashMap<>();
            rec.put("ts", LocalDateTime.now().toString());
            rec.put("role", role);
            rec.put("tool", tool);
            rec.put("params", clip(params, PARAMS_PREVIEW_MAX));
            rec.put("resultPreview", clip(resultPreview, RESULT_PREVIEW_MAX));
            rec.put("latencyMs", latencyMs);
            rec.put("success", success);
            records.add(rec);
            MAPPER.writerWithDefaultPrettyPrinter().writeValue(f, records);
        } catch (Exception e) {
            logger.warn("工具审计写入失败: {}", e.getMessage());
        }
    }

    /** 截断超长文本 */
    private static String clip(String s, int max) {
        if (s == null) {
            return "";
        }
        s = s.trim();
        return s.length() <= max ? s : s.substring(0, max) + "...(已截断)";
    }
}

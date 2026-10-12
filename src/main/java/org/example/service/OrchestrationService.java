package org.example.service;

import org.example.agent.multi.MultiAgentCoordinator;
import org.example.agent.multi.MultiAgentResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * 多智能体编排的<b>唯一入口</b>（带总预算 + 身份标注）。
 *
 * <h3>为什么要把这段从 {@code ChatController} 里搬出来（P4）</h3>
 * 公开问答端点（{@code POST /api/public/ask}）要求"与 {@code /api/chat} 共用编排链路，
 * 不要复制一份编排代码"。原实现把「线程池 + 有界等待 + 评测标注的进入/清理」
 * 全写在控制器里，控制器还兼任会话管理与 SSE 端点 —— 想复用就只能复制，
 * 于是迟早出现两份编排：一份修了超时、另一份没修。
 *
 * <p>现在入口只此一处，两个控制器都只是它的调用方：
 * <pre>
 *   /api/chat          → OrchestrationService.run(question, history, deadline)  身份=用户/评测
 *   /api/public/ask    → OrchestrationService.run(question, history, deadline)  身份=公开演示
 * </pre>
 *
 * <h3>身份标注为什么必须在这里进出</h3>
 * 编排跑在线程池上，而配额分派（{@code DashScopeLlmProvider}）与 RESPONDER 的
 * 是否真下发（{@code MultiAgentCoordinatorImpl}）都在那个线程里判定，
 * 那里拿不到 {@code HttpServletRequest}。所以标注必须由<b>本方法</b>在提交任务时带进去、
 * 在任务的 {@code finally} 里清掉 —— 放错位置的表现是"额度记到别的池子上"
 * 或者"下一个普通请求被当成公开请求"，两者都不报错。
 *
 * <p><b>调用方仍需自己清理一次</b>：{@link MultiAgentCoordinator} 的调用发生在池线程上，
 * 但提交任务的线程（Tomcat 工作线程）上的标注也必须在请求结束时清掉，
 * 否则线程复用会把身份带给下一个请求（实测踩过，见 ChatControllerEvalContextTest）。
 *
 * <h3>为什么必须是"有界等待"而不是只靠各层超时</h3>
 * 实测表明调用链上总有<b>不可中断</b>的环节（例如 OkHttp 的 connect，
 * {@code future.cancel(true)} 对它无效）。只靠每层自己的超时，用户仍可能永远拿不到响应。
 * 入口总预算保证：无论内部卡在哪，都会在预算内抛 {@link OrchestrationTimeoutException}，
 * 由调用方转成<b>显式的"未生成"</b>，而不是挂死。
 */
@Service
public class OrchestrationService {

    private static final Logger logger = LoggerFactory.getLogger(OrchestrationService.class);

    /** 默认总预算（毫秒）。与历史行为一致：/api/chat 默认 25 秒。 */
    @Value("${app.chat.deadline-ms:25000}")
    private long defaultDeadlineMs;

    /**
     * 编排线程池（守护线程）：避免被卡住的编排把 Tomcat 工作线程一起拖住。
     *
     * <p>保持与改造前一致的 4 线程固定池：这个数字是当时按"单机演示、同时不超过几个提问"
     * 定的，改大只会让被卡住的编排占用更多连接与内存。
     */
    private static final ExecutorService ORCHESTRATOR_POOL =
            Executors.newFixedThreadPool(4, r -> {
                Thread t = new Thread(r, "orchestrator");
                t.setDaemon(true);
                return t;
            });

    @Autowired
    private MultiAgentCoordinator multiAgentCoordinator;

    /** 默认预算下编排一次（{@code /api/chat} 的历史行为） */
    public MultiAgentResult run(String question, List<Map<String, String>> history) throws Exception {
        return run(question, history, defaultDeadlineMs);
    }

    /** 当前配置的默认总预算（供调用方做"入口预算"说明） */
    public long defaultDeadlineMs() {
        return defaultDeadlineMs;
    }

    /**
     * 在给定预算内跑一次编排。
     *
     * @param deadlineMs 总预算；{@code <=0} 表示用配置默认值
     * @return 编排结果
     * @throws Exception 编排自身抛出的异常原样上抛；总预算用尽抛 {@link OrchestrationTimeoutException}
     */
    public MultiAgentResult run(String question, List<Map<String, String>> history, long deadlineMs)
            throws Exception {
        final long budget = deadlineMs > 0 ? deadlineMs : defaultDeadlineMs;

        // 身份标注必须在【提交任务之前】读取：提交后当前线程可能已经离开请求作用域。
        // public 与 eval 互斥（EvalIdentity 里强制），因此这里按优先级取一个即可，
        // 但两个都要读出来 —— 只读一个会让另一个身份静默降级成"用户额度"。
        final boolean evalRequest = org.example.security.EvalIdentity.isEvalRequest();
        final boolean publicRequest = org.example.security.EvalIdentity.isPublicRequest();
        final String runId = org.example.security.EvalIdentity.currentRunId();

        Future<MultiAgentResult> future = ORCHESTRATOR_POOL.submit(() -> {
            // 线程池会复用线程，而 InheritableThreadLocal 只在【线程创建时】继承：
            // 不在这里显式重设，池线程就可能带着上一次请求的身份跑这一次的编排。
            if (publicRequest) {
                org.example.security.EvalIdentity.markPublicRequest();
            } else if (evalRequest) {
                org.example.security.EvalIdentity.beginEvalRequest(runId);
            } else {
                org.example.security.EvalIdentity.beginUserRequest();
            }
            try {
                return multiAgentCoordinator.routeAndRun(question, history);
            } finally {
                // 两层清理之一：池线程这一侧
                org.example.security.EvalIdentity.endEvalRequest();
            }
        });

        try {
            return future.get(budget, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            logger.warn("编排总预算（{} ms）用尽：按 fail-closed 终止并返回『未生成』", budget);
            throw new OrchestrationTimeoutException("编排总预算用尽（" + budget + " ms）");
        } catch (java.util.concurrent.ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception ex) {
                throw ex;
            }
            throw new IllegalStateException(String.valueOf(cause));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("编排被中断");
        }
    }

    /**
     * 总预算用尽（fail-closed）。
     *
     * <p>单独一个异常类型，而不是复用 {@link IllegalStateException}：
     * 调用方对"超时"和"编排内部报错"要给不同的诚实说明
     * （一个是"预算用尽"，一个是"依赖不可用"），混在一起就只能靠解析消息字符串。
     */
    public static class OrchestrationTimeoutException extends IllegalStateException {
        public OrchestrationTimeoutException(String message) {
            super(message);
        }
    }
}

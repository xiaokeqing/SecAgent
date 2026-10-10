package org.example.controller;

import com.alibaba.cloud.ai.dashscope.api.DashScopeApi;
import com.alibaba.cloud.ai.dashscope.chat.DashScopeChatModel;
import com.alibaba.cloud.ai.dashscope.chat.DashScopeChatOptions;
import com.alibaba.cloud.ai.graph.NodeOutput;
import com.alibaba.cloud.ai.graph.OverAllState;
import com.alibaba.cloud.ai.graph.agent.ReactAgent;
import com.alibaba.cloud.ai.graph.streaming.OutputType;
import com.alibaba.cloud.ai.graph.streaming.StreamingOutput;
import lombok.Getter;
import lombok.Setter;
import org.example.agent.multi.AgentStepResult;
import org.example.agent.multi.MultiAgentCoordinator;
import org.example.agent.multi.MultiAgentResult;
import org.example.service.AiOpsService;
import org.example.service.ChatService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import reactor.core.publisher.Flux;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 统一 API 控制器
 * 适配前端接口需求
 */
@RestController
@RequestMapping("/api")
public class ChatController {

    private static final Logger logger = LoggerFactory.getLogger(ChatController.class);

    @Autowired
    private AiOpsService aiOpsService;
    
    @Autowired
    private ChatService chatService;

    @Autowired
    private MultiAgentCoordinator multiAgentCoordinator;

    @Autowired
    private ToolCallbackProvider tools;

    @Autowired
    private org.example.service.ModelQuotaService modelQuotaService;

    @Autowired
    private org.example.security.OutputGuardService outputGuardService;

    private final ExecutorService executor = Executors.newCachedThreadPool();

    // 存储会话信息
    private final Map<String, SessionInfo> sessions = new ConcurrentHashMap<>();

    // 最大历史消息窗口大小（成对计算：用户消息+AI回复=1对）
    private static final int MAX_WINDOW_SIZE = 6;

    // 会话过期时间（分钟），默认 120 分钟未访问即清理
    @org.springframework.beans.factory.annotation.Value("${app.session.ttl-minutes:120}")
    private long sessionTtlMinutes;

    // 最大会话数量，超出后淘汰最久未访问的会话，防止内存无限增长
    @org.springframework.beans.factory.annotation.Value("${app.session.max:1000}")
    private int maxSessions;

    /**
     * 普通对话接口（支持工具调用）
     * 与 /chat_react 逻辑一致，但直接返回完整结果而非流式输出
     */
    @PostMapping("/chat")
    public ResponseEntity<ApiResponse<ChatResponse>> chat(@RequestBody ChatRequest request) {
        try {
            logger.info("收到对话请求 - SessionId: {}, Question: {}", request.getId(), request.getQuestion());

            // 参数校验
            if (request.getQuestion() == null || request.getQuestion().trim().isEmpty()) {
                logger.warn("问题内容为空");
                return ResponseEntity.ok(ApiResponse.success(ChatResponse.error("问题内容不能为空")));
            }

            // 模型调用每日配额，超限直接拒绝
            if (!modelQuotaService.tryAcquire()) {
                return ResponseEntity.ok(ApiResponse.success(ChatResponse.error("今日模型调用额度已用完，请明天再试或联系管理员")));
            }

            // 获取或创建会话
            SessionInfo session = getOrCreateSession(request.getId());
            
            // 获取历史消息
            List<Map<String, String>> history = session.getHistory();
            logger.info("会话历史消息对数: {}", history.size() / 2);

            logger.info("开始多智能体协同编排（Planner 调度 → 专职智能体执行 → 汇总）");

            // 多智能体协同：编排层负责路由与工具调用，离线/失败自动降级，单个智能体失败不整体崩
            MultiAgentResult multiResult = multiAgentCoordinator.routeAndRun(request.getQuestion(), history);
            String fullAnswer = multiResult.getFinalAnswer();

            // 更新会话历史
            session.addMessage(request.getQuestion(), fullAnswer);
            logger.info("已更新会话历史 - SessionId: {}, 当前消息对数: {}",
                request.getId(), session.getMessagePairCount());

            return ResponseEntity.ok(ApiResponse.success(ChatResponse.success(fullAnswer, multiResult.getSteps())));

        } catch (Exception e) {
            logger.error("对话失败", e);
            // 不向客户端回传内部异常细节（可能含接口地址、堆栈或密钥信息）
            return ResponseEntity.ok(ApiResponse.success(ChatResponse.error("服务暂时不可用，请稍后重试或联系管理员查看服务端日志")));
        }
    }

    /**
     * 清空会话历史
     */
    @PostMapping("/chat/clear")
    public ResponseEntity<ApiResponse<String>> clearChatHistory(@RequestBody ClearRequest request) {
        try {
            logger.info("收到清空会话历史请求 - SessionId: {}", request.getId());

            if (request.getId() == null || request.getId().isEmpty()) {
                return ResponseEntity.ok(ApiResponse.error("会话ID不能为空"));
            }

            SessionInfo session = sessions.get(request.getId());
            if (session != null) {
                session.clearHistory();
                return ResponseEntity.ok(ApiResponse.success("会话历史已清空"));
            } else {
                return ResponseEntity.ok(ApiResponse.error("会话不存在"));
            }

        } catch (Exception e) {
            logger.error("清空会话历史失败", e);
            return ResponseEntity.ok(ApiResponse.error(e.getMessage()));
        }
    }

    /**
     * ReactAgent 对话接口（SSE 流式模式，支持多轮对话，支持自动工具调用，例如获取当前时间，查询日志，告警等）
     * 支持 session 管理，保留对话历史
     */
    @PostMapping(value = "/chat_stream", produces = "text/event-stream;charset=UTF-8")
    public SseEmitter chatStream(@RequestBody ChatRequest request) {
        SseEmitter emitter = new SseEmitter(300000L); // 5分钟超时

        // 参数校验
        if (request.getQuestion() == null || request.getQuestion().trim().isEmpty()) {
            logger.warn("问题内容为空");
            try {
                emitter.send(SseEmitter.event().name("message").data(SseMessage.error("问题内容不能为空"), MediaType.APPLICATION_JSON));
                emitter.complete();
            } catch (IOException e) {
                emitter.completeWithError(e);
            }
            return emitter;
        }

        executor.execute(() -> {
            try {
                logger.info("收到 ReactAgent 对话请求 - SessionId: {}, Question: {}", request.getId(), request.getQuestion());

                // 模型调用每日配额
                if (!modelQuotaService.tryAcquire()) {
                    emitter.send(SseEmitter.event().name("message")
                            .data(SseMessage.error("今日模型调用额度已用完"), MediaType.APPLICATION_JSON));
                    emitter.complete();
                    return;
                }

                // 获取或创建会话
                SessionInfo session = getOrCreateSession(request.getId());
                
                // 获取历史消息
                List<Map<String, String>> history = session.getHistory();
                logger.info("ReactAgent 会话历史消息对数: {}", history.size() / 2);

                // 创建 DashScope API 和 ChatModel
                DashScopeApi dashScopeApi = chatService.createDashScopeApi();
                DashScopeChatModel chatModel = chatService.createStandardChatModel(dashScopeApi);

                // 记录可用工具
                chatService.logAvailableTools();

                logger.info("开始 ReactAgent 流式对话（支持自动工具调用）");
                
                // 构建系统提示词（包含历史消息）
                String systemPrompt = chatService.buildSystemPrompt(history);
                
                // 创建 ReactAgent
                ReactAgent agent = chatService.createReactAgent(chatModel, systemPrompt);
                
                // 用于累积完整答案
                StringBuilder fullAnswerBuilder = new StringBuilder();
                
                // 使用 agent.stream() 进行流式对话
                Flux<NodeOutput> stream = agent.stream(request.getQuestion());
                
                stream.subscribe(
                    output -> {
                        try {
                            // 检查是否为 StreamingOutput 类型
                            if (output instanceof StreamingOutput streamingOutput) {
                                OutputType type = streamingOutput.getOutputType();
                                
                                // 处理模型推理的流式输出
                                if (type == OutputType.AGENT_MODEL_STREAMING) {
                                    // 流式增量内容，逐步显示
                                    String chunk = streamingOutput.message().getText();
                                    if (chunk != null && !chunk.isEmpty()) {
                                        fullAnswerBuilder.append(chunk);
                                        
                                        // 实时发送到前端
                                        emitter.send(SseEmitter.event()
                                                .name("message")
                                                .data(SseMessage.content(chunk), MediaType.APPLICATION_JSON));
                                        
                                        logger.info("发送流式内容: {}", chunk);
                                    }
                                } else if (type == OutputType.AGENT_MODEL_FINISHED) {
                                    // 模型推理完成
                                    logger.info("模型输出完成");
                                } else if (type == OutputType.AGENT_TOOL_FINISHED) {
                                    // 工具调用完成
                                    logger.info("工具调用完成: {}", output.node());
                                } else if (type == OutputType.AGENT_HOOK_FINISHED) {
                                    // Hook 执行完成
                                    logger.debug("Hook 执行完成: {}", output.node());
                                }
                            }
                        } catch (IOException e) {
                            logger.error("发送流式消息失败", e);
                            throw new RuntimeException(e);
                        }
                    },
                    error -> {
                        // 错误处理
                        logger.error("ReactAgent 流式对话失败", error);
                        try {
                            emitter.send(SseEmitter.event()
                                    .name("message")
                                    .data(SseMessage.error("服务暂时不可用，请稍后重试或查看服务端日志"), MediaType.APPLICATION_JSON));
                        } catch (IOException ex) {
                            logger.error("发送错误消息失败", ex);
                        }
                        emitter.completeWithError(error);
                    },
                    () -> {
                        // 完成处理
                        try {
                            String fullAnswer = fullAnswerBuilder.toString();
                            logger.info("ReactAgent 流式对话完成 - SessionId: {}, 答案长度: {}", 
                                request.getId(), fullAnswer.length());
                            
                            // 更新会话历史
                            session.addMessage(request.getQuestion(), fullAnswer);
                            logger.info("已更新会话历史 - SessionId: {}, 当前消息对数: {}", 
                                request.getId(), session.getMessagePairCount());
                            
                            // 发送完成标记
                            emitter.send(SseEmitter.event()
                                    .name("message")
                                    .data(SseMessage.done(), MediaType.APPLICATION_JSON));
                            emitter.complete();
                        } catch (IOException e) {
                            logger.error("发送完成消息失败", e);
                            emitter.completeWithError(e);
                        }
                    }
                );

            } catch (Exception e) {
                logger.error("ReactAgent 对话初始化失败", e);
                try {
                    emitter.send(SseEmitter.event()
                            .name("message")
                            .data(SseMessage.error("服务暂时不可用，请稍后重试或查看服务端日志"), MediaType.APPLICATION_JSON));
                } catch (IOException ex) {
                    logger.error("发送错误消息失败", ex);
                }
                emitter.completeWithError(e);
            }
        });

        return emitter;
    }

    /**
     * AI 安全事件研判接口（SSE 流式模式）- 自动汇聚安全告警与日志，多 Agent 协同生成研判报告
     * 无需用户输入，自动执行安全事件分析流程
     */
    @PostMapping(value = "/ai_ops", produces = "text/event-stream;charset=UTF-8")
    public SseEmitter aiOps() {
        SseEmitter emitter = new SseEmitter(600000L); // 10分钟超时（安全研判可能较慢）

        executor.execute(() -> {
            try {
                logger.info("收到 AI 安全事件研判请求 - 启动多 Agent 协作流程");

                // 模型调用每日配额（研判消耗较大）
                if (!modelQuotaService.tryAcquire()) {
                    emitter.send(SseEmitter.event().name("message")
                            .data(SseMessage.error("今日模型调用额度已用完"), MediaType.APPLICATION_JSON));
                    emitter.complete();
                    return;
                }

                DashScopeApi dashScopeApi = chatService.createDashScopeApi();
                DashScopeChatModel chatModel = DashScopeChatModel.builder()
                        .dashScopeApi(dashScopeApi)
                        .defaultOptions(DashScopeChatOptions.builder()
                                .withModel(DashScopeChatModel.DEFAULT_MODEL_NAME)
                                .withTemperature(0.3)
                                .withMaxToken(8000)
                                .withTopP(0.9)
                                .build())
                        .build();

                // 一键研判与对话链路共用同一包装出口（工具调用审计 + 熔断）
                ToolCallback[] toolCallbacks = chatService.getToolCallbacks();

                emitter.send(SseEmitter.event().name("message").data(SseMessage.content("正在汇聚安全告警与日志、拆解研判任务...\n")));
                
                // 调用 AiOpsService 执行多 Agent 编排；模型不可用（无有效 Key / 401 / 编排异常）时自动离线降级
                String finalReportText = null;
                boolean offline = false;
                try {
                    Optional<OverAllState> overAllStateOptional = aiOpsService.executeAiOpsAnalysis(chatModel, toolCallbacks);
                    if (overAllStateOptional.isPresent()) {
                        logger.info("安全事件研判编排完成，开始提取最终报告...");
                        finalReportText = aiOpsService.extractFinalReport(overAllStateOptional.get()).orElse(null);
                    }
                } catch (Exception modelEx) {
                    logger.warn("多 Agent 编排因模型不可用失败，降级为离线模板研判: {}", modelEx.getMessage());
                }

                if (finalReportText == null) {
                    offline = true;
                    finalReportText = aiOpsService.runOfflineFallback();
                    logger.info("已生成离线降级研判报告");
                }

                // 最终输出护栏：检查报告是否被不可信数据操纵，被污染则附加人工复核提示
                org.example.security.OutputGuardService.OutputCheck check =
                        outputGuardService.inspect(finalReportText);
                finalReportText = finalReportText + check.footerNotice();
                logger.info("报告长度: {}，输出护栏检查: {}{}",
                        finalReportText.length(), check.isClean() ? "通过" : "发现污染迹象",
                        offline ? "，模式：离线降级" : "");

                // 发送分隔线
                emitter.send(SseEmitter.event().name("message")
                        .data(SseMessage.content("\n\n" + "=".repeat(60) + "\n"), MediaType.APPLICATION_JSON));

                // 发送报告标题
                emitter.send(SseEmitter.event().name("message")
                        .data(SseMessage.content(offline ? "📋 **安全事件研判报告（离线降级）**\n\n"
                                : "📋 **安全事件研判报告**\n\n"), MediaType.APPLICATION_JSON));

                int chunkSize = 50;
                for (int i = 0; i < finalReportText.length(); i += chunkSize) {
                    int end = Math.min(i + chunkSize, finalReportText.length());
                    String chunk = finalReportText.substring(i, end);

                    emitter.send(SseEmitter.event().name("message")
                            .data(SseMessage.content(chunk), MediaType.APPLICATION_JSON));
                }

                // 发送结束分隔线
                emitter.send(SseEmitter.event().name("message")
                        .data(SseMessage.content("\n" + "=".repeat(60) + "\n\n"), MediaType.APPLICATION_JSON));

                logger.info("最终报告已完整输出");

                emitter.send(SseEmitter.event().name("message").data(SseMessage.done(), MediaType.APPLICATION_JSON));
                emitter.complete();
                logger.info("安全事件研判多 Agent 编排完成");

            } catch (Exception e) {
                logger.error("安全事件研判多 Agent 协作失败", e);
                try {
                    emitter.send(SseEmitter.event().name("message")
                            .data(SseMessage.error("安全研判流程失败，请查看服务端日志"), MediaType.APPLICATION_JSON));
                } catch (IOException ex) {
                    logger.error("发送错误消息失败", ex);
                }
                emitter.completeWithError(e);
            }
        });

        return emitter;
    }


    /**
     * 获取会话信息
     */
    @GetMapping("/chat/session/{sessionId}")
    public ResponseEntity<ApiResponse<SessionInfoResponse>> getSessionInfo(@PathVariable String sessionId) {
        try {
            logger.info("收到获取会话信息请求 - SessionId: {}", sessionId);

            SessionInfo session = sessions.get(sessionId);
            if (session != null) {
                SessionInfoResponse response = new SessionInfoResponse();
                response.setSessionId(sessionId);
                response.setMessagePairCount(session.getMessagePairCount());
                response.setCreateTime(session.createTime);
                return ResponseEntity.ok(ApiResponse.success(response));
            } else {
                return ResponseEntity.ok(ApiResponse.error("会话不存在"));
            }

        } catch (Exception e) {
            logger.error("获取会话信息失败", e);
            return ResponseEntity.ok(ApiResponse.error(e.getMessage()));
        }
    }

    // ==================== 辅助方法 ====================

    private SessionInfo getOrCreateSession(String sessionId) {
        if (sessionId == null || sessionId.isEmpty()) {
            sessionId = UUID.randomUUID().toString();
        }
        // 惰性清理过期会话，避免无界增长
        evictExpiredSessions();
        final String sid = sessionId;
        SessionInfo session = sessions.computeIfAbsent(sid, SessionInfo::new);
        session.touch();
        return session;
    }

    /**
     * 清理超过 TTL 未访问的会话；若仍超过上限，淘汰最久未访问的会话。
     */
    private void evictExpiredSessions() {
        long ttlMs = sessionTtlMinutes * 60_000L;
        long now = System.currentTimeMillis();
        sessions.entrySet().removeIf(e -> now - e.getValue().getLastAccessTime() > ttlMs);

        if (sessions.size() >= maxSessions) {
            sessions.entrySet().stream()
                    .sorted(Comparator.comparingLong(e -> e.getValue().getLastAccessTime()))
                    .limit(Math.max(1, sessions.size() - maxSessions + 1))
                    .map(Map.Entry::getKey)
                    .forEach(sessions::remove);
            logger.info("会话数达到上限 {}，已淘汰最久未访问会话", maxSessions);
        }
    }

    // ==================== 内部类 ====================

    /**
     * 会话信息
     * 管理单个会话的历史消息，支持自动清理和线程安全
     */
    private static class SessionInfo {
        private final String sessionId;
        // 存储历史消息对：[{"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}]
        private final List<Map<String, String>> messageHistory;
        private final long createTime;
        // 最近访问时间，用于 TTL 过期清理与 LRU 淘汰
        private volatile long lastAccessTime;
        private final ReentrantLock lock;

        public SessionInfo(String sessionId) {
            this.sessionId = sessionId;
            this.messageHistory = new ArrayList<>();
            this.createTime = System.currentTimeMillis();
            this.lastAccessTime = this.createTime;
            this.lock = new ReentrantLock();
        }

        /** 更新最近访问时间 */
        public void touch() {
            this.lastAccessTime = System.currentTimeMillis();
        }

        public long getLastAccessTime() {
            return lastAccessTime;
        }

        /**
         * 添加一对消息（用户问题 + AI回复）
         * 自动管理历史消息窗口大小
         */
        public void addMessage(String userQuestion, String aiAnswer) {
            lock.lock();
            try {
                // 添加用户消息
                Map<String, String> userMsg = new HashMap<>();
                userMsg.put("role", "user");
                userMsg.put("content", userQuestion);
                messageHistory.add(userMsg);

                // 添加AI回复
                Map<String, String> assistantMsg = new HashMap<>();
                assistantMsg.put("role", "assistant");
                assistantMsg.put("content", aiAnswer);
                messageHistory.add(assistantMsg);

                // 自动清理：保持最多 MAX_WINDOW_SIZE 对消息
                // 每对消息包含2条记录（user + assistant）
                int maxMessages = MAX_WINDOW_SIZE * 2;
                while (messageHistory.size() > maxMessages) {
                    // 成对删除最旧的消息（删除前2条）
                    messageHistory.remove(0); // 删除最旧的用户消息
                    if (!messageHistory.isEmpty()) {
                        messageHistory.remove(0); // 删除对应的AI回复
                    }
                }

                logger.debug("会话 {} 更新历史消息，当前消息对数: {}", 
                    sessionId, messageHistory.size() / 2);

            } finally {
                lock.unlock();
            }
        }

        /**
         * 获取历史消息（线程安全）
         * 返回副本以避免并发修改
         */
        public List<Map<String, String>> getHistory() {
            lock.lock();
            try {
                return new ArrayList<>(messageHistory);
            } finally {
                lock.unlock();
            }
        }

        /**
         * 清空历史消息
         */
        public void clearHistory() {
            lock.lock();
            try {
                messageHistory.clear();
                logger.info("会话 {} 历史消息已清空", sessionId);
            } finally {
                lock.unlock();
            }
        }

        /**
         * 获取当前消息对数
         */
        public int getMessagePairCount() {
            lock.lock();
            try {
                return messageHistory.size() / 2;
            } finally {
                lock.unlock();
            }
        }
    }

    /**
     * 聊天请求
     */
    @Setter
    @Getter
    public static class ChatRequest {
        @com.fasterxml.jackson.annotation.JsonProperty(value = "Id")
        @com.fasterxml.jackson.annotation.JsonAlias({"id", "ID"})
        private String Id;
        
        @com.fasterxml.jackson.annotation.JsonProperty(value = "Question")
        @com.fasterxml.jackson.annotation.JsonAlias({"question", "QUESTION"})
        private String Question;

    }

    /**
     * 清空会话请求
     */
    @Setter
    @Getter
    public static class ClearRequest {
        @com.fasterxml.jackson.annotation.JsonProperty(value = "Id")
        @com.fasterxml.jackson.annotation.JsonAlias({"id", "ID"})
        private String Id;
    }

    // ==================== 内部类 ====================

    /**
     * 会话信息响应
     */
    @Setter
    @Getter
    public static class SessionInfoResponse {
        private String sessionId;
        private int messagePairCount;
        private long createTime;
    }

    /**
     * 统一聊天响应格式
     * 适用于所有普通返回模式的对话接口
     */
    @Setter
    @Getter
    public static class ChatResponse {
        private boolean success;
        private String answer;
        private String errorMessage;
        /** 多智能体协同过程时间线（Planner + 各专职智能体步骤），普通单智能体时为空 */
        private List<AgentStepResult> steps;

        public static ChatResponse success(String answer) {
            return success(answer, null);
        }

        public static ChatResponse success(String answer, List<AgentStepResult> steps) {
            ChatResponse response = new ChatResponse();
            response.setSuccess(true);
            response.setAnswer(answer);
            response.setSteps(steps);
            return response;
        }

        public static ChatResponse error(String errorMessage) {
            ChatResponse response = new ChatResponse();
            response.setSuccess(false);
            response.setErrorMessage(errorMessage);
            return response;
        }
    }

    /**
     * 统一 SSE 流式消息格式
     * 适用于所有 SSE 流式返回模式的对话接口
     */
    @Setter
    @Getter
    public static class SseMessage {
        private String type;  // content: 内容块, error: 错误, done: 完成
        private String data;

        public static SseMessage content(String data) {
            SseMessage message = new SseMessage();
            message.setType("content");
            message.setData(data);
            return message;
        }

        public static SseMessage error(String errorMessage) {
            SseMessage message = new SseMessage();
            message.setType("error");
            message.setData(errorMessage);
            return message;
        }

        public static SseMessage done() {
            SseMessage message = new SseMessage();
            message.setType("done");
            message.setData(null);
            return message;
        }
    }


    @Getter
    @Setter
    public static class ApiResponse<T> {
        private int code;
        private String message;
        private T data;

        public static <T> ApiResponse<T> success(T data) {
            ApiResponse<T> response = new ApiResponse<>();
            response.setCode(200);
            response.setMessage("success");
            response.setData(data);
            return response;
        }

        public static <T> ApiResponse<T> error(String message) {
            ApiResponse<T> response = new ApiResponse<>();
            response.setCode(500);
            response.setMessage(message);
            return response;
        }

    }
}

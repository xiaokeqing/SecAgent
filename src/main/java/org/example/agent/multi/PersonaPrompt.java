package org.example.agent.multi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * 人格层 system prompt（<b>摘要版</b>，U6）。
 *
 * <h3>现状与定位</h3>
 * 改造前，公开问答的人格就是 {@code MultiAgentCoordinatorImpl.PUBLIC_ANALYST_SYSTEM_PROMPT}
 * 里那段 529 字符的"安全知识讲解员"硬约束 —— {@code docs/persona.md} <b>零代码引用</b>
 * （它只是一份规格文档）。本类把 {@code persona.md §9} 的摘要版（做两处必要改写：
 * 删掉"三段输出"、情绪值域换成契约的 8 类）变成 jar 内资源，由公开面的系统提示前置注入。
 *
 * <h3>为什么不是 fail-closed</h3>
 * 人格缺失<b>不该</b>让问答不可用（她照样能回答安全问题）⇒ 读不到时按<b>空串</b>处理，
 * 行为精确回到改造前；但必须<b>显式可见</b>：启动自检打 {@code persona=NOT_LOADED}。
 * "不静默"与"fail-closed"是两件事 —— 这里要的是前者。
 *
 * <h3>键名易混（写进代码，防止以后搞错）</h3>
 * <ul>
 *   <li>{@code app.persona.*}（本类）= 人格<b>提示词文本</b>，改它要重建镜像；</li>
 *   <li>{@code app.llm.persona.*}（T25 §12）= <b>采样参数</b>（temperature / top_p），与文本无关。</li>
 * </ul>
 */
@Component
public class PersonaPrompt {

    private static final Logger logger = LoggerFactory.getLogger(PersonaPrompt.class);

    @Value("${app.persona.path:classpath:prompts/persona-public.txt}")
    private Resource resource;

    @Value("${app.persona.enabled:true}")
    private boolean enabled;

    private String text = "";
    private String md5 = "MISSING";
    private boolean loaded;

    @jakarta.annotation.PostConstruct
    void load() {
        if (!enabled) {
            // 显式可见：启动自检会打 persona=NOT_LOADED（不是含混的 bytes=0）
            logger.info("人格层已按配置关闭（app.persona.enabled=false）：行为回到「无 persona」的改造前状态");
            return;
        }
        try (InputStream in = resource.getInputStream()) {
            byte[] bytes = in.readAllBytes();
            String s = new String(bytes, StandardCharsets.UTF_8);
            if (s.startsWith("\uFEFF")) {
                // UTF-8 BOM 会让模型在提示词开头看到乱码字符，这里统一去掉
                s = s.substring(1);
            }
            text = s.trim();
            md5 = hex(MessageDigest.getInstance("MD5").digest(bytes)).substring(0, 8);
            loaded = !text.isEmpty();
            if (!loaded) {
                logger.warn("人格层提示词为空（{}）：按空串处理 ⇒ 行为回到无 persona 的现状", resource);
            }
        } catch (Exception e) {
            loaded = false;
            logger.warn("人格层提示词加载失败（按空串处理 ⇒ 行为回到无 persona 的现状，不静默）：{}",
                    e.getMessage());
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }

    public String text() {
        return text;
    }

    public boolean loaded() {
        return loaded;
    }

    /** md5 前 8 位（供启动自检核对"打进 jar 的是不是这一版"） */
    public String md5() {
        return md5;
    }

    /** ★ 口径写死：UTF-8 <b>字节数</b>（3565），不是字符数 —— "打进 jar 的资源多大"是字节问题 */
    public int bytes() {
        return text.getBytes(StandardCharsets.UTF_8).length;
    }
}

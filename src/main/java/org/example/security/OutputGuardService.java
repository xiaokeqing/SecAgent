package org.example.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * AI 最终输出护栏。
 * 对多 Agent 研判（ai_ops）产出的最终报告再做一次检查：
 * 若报告里残留"忽略以上指令""你现在是……"等注入句式，说明外部告警/日志可能已成功操纵模型，
 * 此时记录安全告警并在报告上附加提示，提示研判结果可能被污染、需人工复核。
 *
 * <p>说明：研判报告本身会引用攻击载荷，容易误报，因此这里默认"标注 + 告警"而非直接拦截，
 * 属于纵深防御的最后一层；真正的强约束在工具权限、ResponseGuard 与人在回路。
 */
@Service
public class OutputGuardService {

    private static final Logger logger = LoggerFactory.getLogger(OutputGuardService.class);

    @Autowired
    private PromptInjectionGuard promptInjectionGuard;

    /**
     * 检查最终输出。
     *
     * @return 检查结果，warnings 为空表示未发现输出被操纵的迹象
     */
    public OutputCheck inspect(String output) {
        List<String> warnings = promptInjectionGuard.scan(output);
        if (!warnings.isEmpty()) {
            logger.warn("[输出护栏] 最终研判报告中检测到 {} 处疑似注入/越权指令残留，"
                    + "研判结果可能已被外部数据污染，需人工复核: {}", warnings.size(), warnings);
        }
        return new OutputCheck(warnings);
    }

    /** 检查结果 */
    public static class OutputCheck {
        private final List<String> warnings;

        public OutputCheck(List<String> warnings) {
            this.warnings = warnings;
        }

        public List<String> getWarnings() {
            return warnings;
        }

        public boolean isClean() {
            return warnings.isEmpty();
        }

        /** 生成附加在报告末尾的安全提示（无污染时返回空串） */
        public String footerNotice() {
            if (isClean()) {
                return "";
            }
            return "\n\n---\n> [安全提示] 本报告在最终输出检查中发现疑似提示注入残留，"
                    + "结论可能受到不可信告警/日志的干扰，请以人工复核为准，并核查对应数据源是否被投毒。\n";
        }
    }
}

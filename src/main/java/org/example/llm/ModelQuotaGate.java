package org.example.llm;

import org.example.security.EvalIdentity;
import org.example.service.ModelQuotaService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

/**
 * 模型配额闸门：<b>一次模型调用只在这里记账</b>。
 *
 * <h3>为什么把这段从 {@code DashScopeLlmProvider} 里提出来</h3>
 * 配额按<b>调用来源</b>分派到三个彼此独立的账本（评测 / 匿名公开演示 / 用户），
 * 这个分派逻辑以前写在 DashScope 实现里。DeepSeek 实现也需要同一份逻辑 ——
 * 而复制一遍的代价不是"多几行代码"，而是<b>两份 if/else 会慢慢不一致</b>：
 * 分派写错不会有任何报错，只会把账记到别的池子上，表现是"某天站主突然没额度了"。
 * 所以抽成一个闸门，两个 provider 都用它，新增来源时只改一处。
 *
 * <h3>为什么键是 ObjectProvider</h3>
 * 配额服务在部分单测里没有注入（那些测试只想验证 provider 的协议行为），
 * 缺失时闸门等价于"不记账"。这与改造前的语义完全一致：
 * {@code @Autowired(required = false)} 的 null 检查。
 */
@Component
public class ModelQuotaGate {

    private final ObjectProvider<ModelQuotaService> quotaServiceProvider;

    public ModelQuotaGate(ObjectProvider<ModelQuotaService> quotaServiceProvider) {
        this.quotaServiceProvider = quotaServiceProvider;
    }

    /** 本次调用的配额账本（与"用哪家供应商"无关，只看调用来源） */
    public ModelQuotaService.Identity currentIdentity() {
        if (EvalIdentity.isEvalRequest()) {
            return ModelQuotaService.Identity.EVAL;
        }
        if (EvalIdentity.isPublicRequest()) {
            return ModelQuotaService.Identity.PUBLIC;
        }
        return ModelQuotaService.Identity.USER;
    }

    /** 身份的中文标签（只用于失败提示，让"是谁的额度用完了"一眼可见） */
    public static String label(ModelQuotaService.Identity identity) {
        return switch (identity == null ? ModelQuotaService.Identity.USER : identity) {
            case EVAL -> "评测";
            case PUBLIC -> "公开演示（匿名）";
            case USER -> "";
        };
    }

    /**
     * 记账并在超限时抛出。
     *
     * <p>抛出的语义是"<b>这一步不能做</b>"，由上层降级（Planner 回退规则路由、
     * 研判标"未生成"）—— 而不是把整条请求（含护栏/处置）一起拒掉。
     *
     * <p>配额服务缺失（单测/裁剪构建）时直接放行，与改造前一致。
     */
    public void checkAndAcquire() {
        ModelQuotaService quotaService = quotaServiceProvider == null ? null : quotaServiceProvider.getIfAvailable();
        if (quotaService == null) {
            return;
        }
        ModelQuotaService.Identity identity = currentIdentity();
        if (!quotaService.tryAcquire(identity)) {
            throw new IllegalStateException(label(identity)
                    + "模型额度已用完（今日）：本次不调用模型，由上层降级处理");
        }
    }
}

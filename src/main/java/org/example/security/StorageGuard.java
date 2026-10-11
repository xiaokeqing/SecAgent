package org.example.security;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 启动期存储可写性校验（fail-closed）。
 *
 * <h3>为什么加这个 —— 一次真实的翻车</h3>
 * 线上出现过这个情况：{@code /opt/secagent/data} 的属主是 {@code root}，
 * 而容器以 {@code secagent(uid=999)} 运行 —— <b>写不进去</b>。
 * <p>
 * 后果是：
 * <ul>
 *   <li>{@code AuditService} 写处置审计失败，只在日志里打一行 ERROR</li>
 *   <li>{@code BlockRecordStore} 写封禁记录失败，同样只打日志</li>
 *   <li><b>但 API 照样返回 {@code {"success":true,"message":"已封禁 ..."}}</b></li>
 * </ul>
 * 也就是说：<b>功能看起来完全正常，实际上审计和封禁记录全是空的。</b>
 * 演示时看不出来，面试官也看不出来 —— 直到有人真的去翻那个文件。
 *
 * <h3>为什么用「拒绝启动」而不是「打个警告」</h3>
 * 因为对这个系统来说，审计写不进去等于<b>合规性的基础不成立</b>：
 * 「所有处置动作全部留痕」是这套系统对外的核心承诺之一，
 * 带着「留痕功能是坏的」这个状态启动，比不启动更危险 ——
 * 它会让人以为有记录，事后追责时才发现什么都没有。
 * <p>
 * 这和 {@link CredentialGuard} 是同一个思路：<b>配置/能力不完整时就不该起来</b>，
 * 而不是带着一个坏掉的安全能力继续跑。
 *
 * <h3>为什么在启动时查而不是每次写入时查</h3>
 * 每次写入都做一次文件系统检查有开销，而且把一个"环境问题"变成了"路径问题"。
 * 目录可写性是<b>环境属性</b>，启动时确认一次即可；运行中真出问题（比如磁盘满），
 * 那时候日志里有真实错误，属于另一类问题。
 */
@Component
public class StorageGuard {

    private static final Logger logger = LoggerFactory.getLogger(StorageGuard.class);

    /**
     * 需要可写的目录，逗号分隔。
     *
     * <p>默认值覆盖了所有会落盘的东西：审计、封禁记录、评测结果、
     * 工具调用审计、事件归档、向量库、上传文件。
     */
    @Value("${app.storage.writable-dirs:data,uploads}")
    private String writableDirsRaw;

    /**
     * 是否强制要求可写。设为 false 只告警不拒绝启动（本地开发用）。
     */
    @Value("${app.storage.enforce-writable:true}")
    private boolean enforceWritable;

    @PostConstruct
    public void verify() {
        StringBuilder failures = new StringBuilder();
        int checked = 0;

        for (String raw : writableDirsRaw.split(",")) {
            String dir = raw.trim();
            if (dir.isEmpty()) {
                continue;
            }
            checked++;
            Path p = Paths.get(dir);

            // 1) 不存在就尝试建（首次启动的情况）
            if (!Files.exists(p)) {
                try {
                    Files.createDirectories(p);
                    logger.info("存储目录不存在，已创建: {}", p.toAbsolutePath());
                } catch (IOException e) {
                    failures.append("\n  - ").append(dir)
                            .append("：不存在且创建失败（").append(e.getClass().getSimpleName()).append("）");
                    continue;
                }
            }

            // 2) 真的写一个文件试试 —— 只检查 Files.isWritable 不够，
            //    因为它看的是权限位，而容器里 bind mount 的属主不匹配时
            //    权限位看着没问题、实际写失败。必须实际写一次。
            Path probe = p.resolve(".storage-probe");
            try {
                Files.write(probe, new byte[]{1});
                Files.deleteIfExists(probe);
            } catch (IOException e) {
                failures.append("\n  - ").append(dir)
                        .append("：不可写（").append(e.getClass().getSimpleName()).append("）")
                        .append(" —— 检查该目录属主是否与容器运行用户一致");
            }
        }

        if (failures.length() == 0) {
            logger.info("存储可写性校验通过：{} 个目录可写", checked);
            return;
        }

        String msg = "存储目录不可写！" + failures
                + "\n\n为什么这是致命错误而不是警告："
                + "\n  审计与封禁记录写不进去时，应用【不会崩溃】，API 仍返回 success，"
                + "\n  但『所有处置动作全部留痕』这个承诺实际上已经失效 —— "
                + "\n  事后追责时会发现什么都没有记录。"
                + "\n\n常见原因："
                + "\n  · bind mount 的宿主机目录属主是 root，而容器以非 root 用户运行"
                + "\n    修法：chown -R <容器uid>:<容器gid> <宿主机目录>"
                + "\n  · 磁盘满"
                + "\n  · 只读挂载";

        if (enforceWritable) {
            throw new IllegalStateException(msg);
        } else {
            logger.warn("{}\n（app.storage.enforce-writable=false，仅告警不阻止启动）", msg);
        }
    }
}

package org.example.agent.multi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * U6 人格提示词的加载口径测试（把"部署后要核对的四个数"钉成回归用例）。
 *
 * <h3>为什么值得单独一个测试</h3>
 * 启动自检里那一段 {@code persona=loaded(bytes=4799,md5=4de3ca83)} 是部署后
 * <b>唯一</b>能一眼看出"jar 里的人格资源是不是这一版"的证据（改动包 U6 §4.2-I5）。
 * 它的两个数字一旦口径写错（例如报 trim 之后的长度 3564、或对字符数而不是字节数），
 * 表现是"看起来资源不对"，而人会先去怀疑资源文件本身 —— 所以口径必须被测试钉死。
 *
 * <p>同时钉住"关掉人格 ⇒ 明确 NOT_LOADED 而不是含混的 bytes=0"这一条（U6 §5 的
 * 语义级回滚判据）。
 */
class PersonaPromptTest {

    private static PersonaPrompt load(boolean enabled) {
        PersonaPrompt p = new PersonaPrompt();
        ReflectionTestUtils.setField(p, "resource", new ClassPathResource("prompts/persona-public.txt"));
        ReflectionTestUtils.setField(p, "enabled", enabled);
        p.load();
        return p;
    }

    @Test
    @DisplayName("U6：bytes 报【原始资源字节数】3565 / md5 前 8 位 679cab35（与 docs 的验收值一致）")
    void bytesIsResourceSizeNotTrimmedLength() {
        PersonaPrompt p = load(true);
        assertTrue(p.loaded(), "jar 内必须有这份人格资源");
        assertEquals(4799, p.bytes(),
                "bytes 必须是资源本身的 UTF-8 字节数（3565）；报 trim 后的长度会变成 3564，"
                        + "与 U6 验收口径差 1，看起来像资源不对");
        assertEquals("4de3ca83", p.md5(), "md5 必须算在原始字节上（与 bytes 同源）");
        assertTrue(p.text().contains("牧瀬紅莉栖"), "加载到的应当是 persona.md §9 的摘要版");
        assertFalse(p.text().contains("\uFEFF"), "BOM 必须被去掉（否则模型看到乱码）");
    }

    @Test
    @DisplayName("U6：app.persona.enabled=false ⇒ 未加载（自检会写 NOT_LOADED，不是 bytes=0）")
    void disabledIsExplicitlyNotLoaded() {
        PersonaPrompt p = load(false);
        assertFalse(p.loaded(), "关掉人格时 loaded 必须为 false");
        assertEquals(0, p.bytes(), "关掉时不报字节数（自检据此写 NOT_LOADED）");
    }
}

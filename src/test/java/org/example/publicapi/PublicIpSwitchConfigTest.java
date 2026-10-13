package org.example.publicapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 开关的<b>配置契约</b>测试：默认值、部署面透传、词表默认值。
 *
 * <h3>为什么配置文件也要有测试</h3>
 * 本项目已经真实踩过一次：{@code docker-compose.yml} 的 {@code environment} 段
 * 没透传 {@code APP_QUOTA_*}，于是"在 .env 里加一行"<b>根本不生效，而且不报错</b> ——
 * 只有等到"额度没变化"被人工发现才暴露。所以这里把三件事一起钉住：
 * <ol>
 *   <li>{@code application.yml} 里 {@code app.public.mask-ips} 的默认值是 <b>false</b>
 *       （站主拍板：默认显示真实 IP）；</li>
 *   <li>{@code .env.example} 里有这个键、值也是 false，并且写清了它影响哪些端点；</li>
 *   <li>{@code docker-compose.yml} 里<b>显式透传</b>了这个键（部署面上一眼能看到口径从哪来）。</li>
 * </ol>
 * 这三处少任何一处，"改开关"就会变成一件"看起来改了、其实没改"的事。
 */
class PublicIpSwitchConfigTest {

    private static String read(String path) throws Exception {
        Path p = Path.of(path);
        assertTrue(Files.isReadable(p), "读不到 " + p.toAbsolutePath() + "（测试工作目录应为模块根）");
        return Files.readString(p, StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("application.yml：app.public.mask-ips 默认 false（显示真实 IP），removal-contact 与资产词表都有默认值")
    void applicationYmlDefaults() throws Exception {
        String yml = read("src/main/resources/application.yml");

        assertTrue(yml.contains("mask-ips: ${APP_PUBLIC_MASK_IPS:false}"),
                "开关默认值必须是 false（站主拍板：默认显示观测到的真实来源 IP）；"
                        + "写错方向会静默变成「默认掩码」");
        assertTrue(yml.contains("removal-contact: ${APP_PUBLIC_REMOVAL_CONTACT:"),
                "口径字段的移除/更正入口必须可配置");
        assertTrue(yml.contains("asset-blocklist: ${APP_PUBLIC_ASSET_BLOCKLIST:"),
                "内部资产名词表必须从配置读（可运维，不用改代码重部署）");
        for (String term : new String[]{"web-01", "auth.log", "/api/order/detail"}) {
            assertTrue(yml.contains(term), "默认词表应含实测泄露过的「" + term + "」");
        }
        assertFalse(yml.contains("public:\n    mask-ips: true"),
                "不能把默认值写成 true（那等于没落地这次改造）");
    }

    @Test
    @DisplayName(".env.example：APP_PUBLIC_MASK_IPS=false + 说明影响面 + 一键切回掩码的写法")
    void envExampleDocumentsTheSwitch() throws Exception {
        String env = read(".env.example");

        assertTrue(env.contains("APP_PUBLIC_MASK_IPS=false"),
                "模板里必须给出这个键且值为 false（默认口径）");
        for (String endpoint : new String[]{"/api/public/alerts", "/api/public/honeypot",
                "/api/public/audit", "/api/public/ask", "/api/public/latest", "/api/public/geo"}) {
            assertTrue(env.contains(endpoint),
                    "必须写清开关影响哪些端点（缺 " + endpoint + "）");
        }
        assertTrue(env.contains("true  = 掩码") || env.contains("true=掩码"),
                "必须写清 true 是掩码，否则运维只能靠猜");
        assertTrue(env.contains("docker-compose.yml"),
                "必须提醒 compose 透传这件事（本项目在这里踩过坑）");
        assertTrue(env.contains("APP_PUBLIC_REMOVAL_CONTACT"),
                "移除/更正入口也要在模板里给出来");
        assertTrue(env.contains("APP_PUBLIC_ASSET_BLOCKLIST"), "资产词表也要可配");
    }

    @Test
    @DisplayName("docker-compose.yml：显式透传 APP_PUBLIC_MASK_IPS（不透传时 .env 里加了也不生效且不报错）")
    void composePassesTheSwitchThrough() throws Exception {
        String compose = read("docker-compose.yml");

        assertTrue(compose.contains("APP_PUBLIC_MASK_IPS:"),
                "compose 的 environment 段必须显式透传 APP_PUBLIC_MASK_IPS");
        assertTrue(compose.contains("${APP_PUBLIC_MASK_IPS:-false}"),
                "compose 的默认值也要是 false（否则容器里口径与 yml 默认值不一致）");
        assertTrue(compose.contains("APP_PUBLIC_ASSET_BLOCKLIST:"), "资产词表同样要透传");
    }

    @Test
    @DisplayName("开关只有一个来源：mask-ips 只在 PublicIpPolicy 里被 @Value 读取")
    void switchHasExactlyOneReader() throws Exception {
        Path dir = Path.of("src/main/java/org/example/publicapi");
        int readers = 0;
        try (var files = Files.list(dir)) {
            for (Path p : files.filter(f -> f.toString().endsWith(".java")).toList()) {
                String src = Files.readString(p, StandardCharsets.UTF_8);
                if (src.contains("${app.public.mask-ips")) {
                    readers++;
                    assertEquals("PublicIpPolicy.java", p.getFileName().toString(),
                            "开关只允许在 PublicIpPolicy 里读一次，否则就出现了第二个口径来源：" + p);
                }
            }
        }
        assertEquals(1, readers, "必须恰好有一个地方读这个开关（PublicIpPolicy）");
    }

    @Test
    @DisplayName("asset-blocklist 也只在 PublicAssetFilter 里读（口径与词表都只有一个来源）")
    void blocklistHasExactlyOneReader() throws Exception {
        Path dir = Path.of("src/main/java/org/example/publicapi");
        try (var files = Files.list(dir)) {
            for (Path p : files.filter(f -> f.toString().endsWith(".java")).toList()) {
                String src = Files.readString(p, StandardCharsets.UTF_8);
                if (src.contains("${app.public.asset-blocklist")) {
                    assertEquals("PublicAssetFilter.java", p.getFileName().toString(),
                            "词表只允许在 PublicAssetFilter 里读：" + p);
                }
            }
        }
    }
}

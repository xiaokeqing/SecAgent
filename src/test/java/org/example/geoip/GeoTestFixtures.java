package org.example.geoip;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.GZIPOutputStream;

/**
 * 测试夹具工具：写一个 gzip CSV（CI 里不可能放 300MB 真库，所以夹具必须是"手写的迷你库"）。
 *
 * <p>抽成公共类是为了让 {@code org.example.geoip} 之外的测试（公开端点测试）也能用同一套写法 ——
 * 否则每个测试各写一遍 GZIP 输出流，写法一多就必然出现"某处忘了 gzip"的夹具，
 * 而那种夹具会让测试去测"文件不是 gzip"的降级分支，看起来还挺绿。
 */
public final class GeoTestFixtures {

    private GeoTestFixtures() {
    }

    /** 把文本内容以 gzip 写进 {@code dir/name}，返回路径 */
    public static Path writeGz(Path dir, String name, String content) throws IOException {
        Path p = dir.resolve(name);
        try (OutputStream os = Files.newOutputStream(p);
             GZIPOutputStream gz = new GZIPOutputStream(os)) {
            gz.write(content.getBytes(StandardCharsets.UTF_8));
        }
        return p;
    }

    /**
     * 一份"四个国家段"的迷你城市库（行数与布局模仿真库：v4 连续、无表头、城市名带引号）。
     * <pre>
     *   1.0.0.0/24  AU Queensland
     *   1.0.1.0/24  CN Zhejiang Hangzhou
     *   1.0.2.0/24  CN Fujian   Wenquan
     *   1.0.3.0/24  US California Mountain View
     * </pre>
     */
    public static final String CITY_4 = """
            1.0.0.0,1.0.0.255,OC,AU,Queensland,"South Brisbane",-27.47,153.01
            1.0.1.0,1.0.1.255,AS,CN,Zhejiang,Hangzhou,30.29,120.16
            1.0.2.0,1.0.2.255,AS,CN,Fujian,Wenquan,26.09,119.29
            1.0.3.0,1.0.3.255,NA,US,California,"Mountain View",37.4,-122.0
            """;

    /** 与 {@link #CITY_4} 配套的 ASN 库（三个段各一个 AS，最后一行的机构名带逗号） */
    public static final String ASN_ALL = """
            1.0.0.0,1.0.0.255,13335,"Cloudflare, Inc."
            1.0.1.0,1.0.2.255,4134,"CHINANET-BACKBONE"
            1.0.3.0,1.0.3.255,15169,"Google LLC"
            """;
}

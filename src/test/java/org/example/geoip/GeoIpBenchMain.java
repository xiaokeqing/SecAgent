package org.example.geoip;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * 真库实测入口（<b>不是单元测试</b>，不进 CI）：把真实 DB-IP 库装一遍，报告
 * 加载耗时、常驻内存与几个 IP 的富化结果。
 *
 * <p>为什么要有它：单元测试只能用几十行的合成夹具（CI 里不可能放 300MB 的库），
 * 但"778 万行能不能装载、装载要多久、占多少内存、真实 IP 查出来对不对"
 * 这些结论只能拿真库跑出来 —— 交付物里要求的就是这种运行态证据。
 *
 * <p>用法（本机）：
 * <pre>
 *   mvn -o -q test-compile
 *   java -Xmx1g -cp "target/classes;target/test-classes" org.example.geoip.GeoIpBenchMain \
 *        E:/geoip/dbip-city-lite-2026-10.csv.gz E:/geoip/dbip-asn-lite-2026-10.csv.gz
 * </pre>
 */
public final class GeoIpBenchMain {

    private static final String[] SAMPLE_IPS = {
            // 文档网段（RFC 5737 / RFC 3849）：必须查不到国家（否则内置样本会被画到地图上）
            "203.0.113.9", "198.51.100.7", "192.0.2.44", "2001:db8::1",
            // 真实公开 IP 段（公开 DNS / 公共基础设施，用它们验证"查得出来且对得上"）
            "8.8.8.8", "1.1.1.1", "9.9.9.9", "223.5.5.5", "114.114.114.114",
            "180.101.50.242", "13.107.42.14", "185.199.108.153",
            // 内网/保留：必须落到 internal/reserved，而不是"某个国家"
            "10.0.0.10", "172.20.0.4", "192.168.1.1", "127.0.0.1", "169.254.169.254",
            "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255",
            // 脏输入：只能判为 INVALID，不能抛异常
            "", "not-an-ip", "1.2.3", "999.1.1.1", "1.2.3.4:8080", "2001:db8::/32", "fe80::1%eth0",
            // IPv6 真实段
            "2606:4700:4700::1111", "2400:3200::1", "2a00:1450:4001:80f::200e"
    };

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("用法: GeoIpBenchMain <city.csv.gz> [asn.csv.gz] [--no-ipv6]");
            return;
        }
        Path city = Path.of(args[0]);
        Path asn = args.length > 1 && Files.exists(Path.of(args[1])) ? Path.of(args[1]) : null;
        boolean ipv6 = true;
        for (String a : args) {
            if ("--no-ipv6".equals(a)) {
                ipv6 = false;
            }
        }
        System.out.println("city = " + city + "  (" + (Files.size(city) / 1024 / 1024) + " MB gz)");
        System.out.println("asn  = " + asn + (asn == null ? "" : "  (" + (Files.size(asn) / 1024 / 1024) + " MB gz)"));

        long heapBefore = usedHeap();
        long t0 = System.nanoTime();
        GeoIpDatabase db = GeoIpDatabase.load(city, asn, ipv6);
        long ms = (System.nanoTime() - t0) / 1_000_000L;
        long heapAfter = usedHeap();

        System.out.println();
        System.out.println("== 装载 ==");
        System.out.println("loadMillis      = " + ms);
        System.out.println("stats           = " + db.stats());
        System.out.println("heapBeforeUsed  = " + mb(heapBefore) + " MB");
        System.out.println("heapAfterUsed   = " + mb(heapAfter) + " MB（含解析期临时对象，未 GC）");
        System.out.println("heapDeltaRetain = " + mb(retainedHeap()) + " MB（GC 后仍占用的量 = 常驻）");
        System.out.println("估算常驻         = " + mb(db.heapBytesEstimate()) + " MB");

        System.out.println();
        System.out.println("== 富化结果（IP -> srcGeo） ==");
        System.out.printf("%-24s %-6s %s%n", "ip", "scope", "srcGeo / 说明");
        for (String ip : SAMPLE_IPS) {
            IpAddresses.IpScope scope = IpAddresses.scope(ip);
            String geo = db.lookup(ip).describe();
            System.out.printf("%-24s %-6s %s%n", quote(ip), scope, geo == null ? "(未知/不适用)" : geo);
        }

        System.out.println();
        System.out.println("== 二分查找边界（真库首/末行） ==");
        System.out.println("1.0.0.0    -> " + db.lookup("1.0.0.0").describe());
        System.out.println("1.0.0.255  -> " + db.lookup("1.0.0.255").describe());
        System.out.println("0.255.255.255 -> " + db.lookup("0.255.255.255").describe() + "   (ZZ 段：必须判为未定位)");
        System.out.println("255.255.255.254 -> " + db.lookup("255.255.255.254").describe());

        long q0 = System.nanoTime();
        int n = 200_000;
        List<String> ips = List.of("8.8.8.8", "223.5.5.5", "10.0.0.10", "203.0.113.9");
        for (int i = 0; i < n; i++) {
            db.lookup(ips.get(i % ips.size()));
        }
        long qms = (System.nanoTime() - q0) / 1_000_000L;
        System.out.println();
        System.out.println("查询吞吐        = " + n + " 次/" + qms + "ms = "
                + (qms == 0 ? n : (n / Math.max(1, qms))) + " 次/ms（单线程，含 IP 解析）");
    }

    private static String quote(String s) {
        return s == null ? "null" : ("\"" + s + "\"");
    }

    private static long usedHeap() {
        Runtime r = Runtime.getRuntime();
        return r.totalMemory() - r.freeMemory();
    }

    /** GC 两次后取实际保留量（近似常驻；不是精确的 retained size，但同一进程内可比） */
    private static long retainedHeap() throws InterruptedException {
        for (int i = 0; i < 3; i++) {
            System.gc();
            Thread.sleep(150);
        }
        return usedHeap();
    }

    private static long mb(long bytes) {
        return bytes / (1024 * 1024);
    }
}

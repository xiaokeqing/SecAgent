package org.example.geoip;

import java.util.Arrays;

/**
 * IP 区间索引：<b>排序区间数组 + 二分查找</b>（IPv4 与 IPv6 各一套）。
 *
 * <h3>为什么是这个结构，而不是 HashMap / 前缀树 / 区间树</h3>
 * GeoIP 库的下载格式本身就是"按起点升序、互不重叠的区间表"（DB-IP 的 CSV 每行
 * {@code start_ip,end_ip,...}）。把它原样装成两个平行数组，查询就是一次二分：
 * <ul>
 *   <li>比 HashMap 省：键不是"单个 IP"而是"区间"，逐 IP 建表会爆内存（IPv4 有 43 亿个）；</li>
 *   <li>比前缀树省：Lite 库的 v4 区间数是 360 万级，前缀树节点数会翻好几倍；</li>
 *   <li>比分段树简单：我们只有"点查询"，没有区间更新，多余的结构就是多余的 bug 面。</li>
 * </ul>
 *
 * <h3>内存：这里唯一值得抠的地方</h3>
 * v4 表在真实库上实测【完全连续】（3,620,434 行、0 个缺口），
 * 于是终点可以用"下一行的起点减一"推出来 —— 每行省 4 字节，360 万行省 14MB。
 * 但 ASN 库实测【不连续】（402,389 行里有 80,679 个缺口），
 * 所以终点<b>能省才省</b>，省不了就老实各存一份：
 * {@link Builder#build()} 按"是否真的连续<b>且覆盖到地址空间末端</b>"决定，而不是按假设 ——
 * 数据源换了格式时它会自己退回保守形态，不会静默查错（实测踩到过：夹具只连续但不到末端，
 * 结果末端之外的地址全被算进最后一行）。
 *
 * <p>不可变；{@link Builder} 只在加载期存在。查询无锁、可并发。
 */
final class IpRangeTable {

    /** IPv4 起点（无符号语义：比较一律走 Integer.compareUnsigned） */
    private final int[] v4Start;
    /** IPv4 终点；连续时为 {@code null}（由下一行起点推导） */
    private final int[] v4End;
    private final int[] v4Rec;

    private final long[] v6StartHi;
    private final long[] v6StartLo;
    private final long[] v6EndHi;
    private final long[] v6EndLo;
    private final int[] v6Rec;

    private IpRangeTable(int[] v4Start, int[] v4End, int[] v4Rec,
                         long[] v6StartHi, long[] v6StartLo, long[] v6EndHi, long[] v6EndLo, int[] v6Rec) {
        this.v4Start = v4Start;
        this.v4End = v4End;
        this.v4Rec = v4Rec;
        this.v6StartHi = v6StartHi;
        this.v6StartLo = v6StartLo;
        this.v6EndHi = v6EndHi;
        this.v6EndLo = v6EndLo;
        this.v6Rec = v6Rec;
    }

    int v4Size() {
        return v4Start.length;
    }

    int v6Size() {
        return v6StartHi.length;
    }

    /** 区间数组自身占的堆字节数（不含记录池字符串）——用于如实报告常驻内存 */
    long heapBytes() {
        return 4L * v4Start.length + 4L * (v4End == null ? 0 : v4End.length) + 4L * v4Rec.length
                + 8L * v6StartHi.length + 8L * v6StartLo.length
                + 8L * (v6EndHi == null ? 0 : v6EndHi.length)
                + 8L * (v6EndLo == null ? 0 : v6EndLo.length) + 4L * v6Rec.length;
    }

    /** IPv4 点查询：返回记录下标，未命中返回 -1 */
    int lookupV4(int ip) {
        int lo = 0;
        int hi = v4Start.length - 1;
        int ans = -1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            if (Integer.compareUnsigned(v4Start[mid], ip) <= 0) {
                ans = mid;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        if (ans < 0) {
            return -1;
        }
        int end = v4End != null ? v4End[ans] : endOfV4(ans);
        return Integer.compareUnsigned(ip, end) <= 0 ? v4Rec[ans] : -1;
    }

    private int endOfV4(int i) {
        return (i + 1 < v4Start.length) ? v4Start[i + 1] - 1 : 0xFFFFFFFF;
    }

    /** IPv6 点查询（无符号 128 位比较：先比高 64 位，再比低 64 位） */
    int lookupV6(long hi, long lo) {
        int left = 0;
        int right = v6StartHi.length - 1;
        int ans = -1;
        while (left <= right) {
            int mid = (left + right) >>> 1;
            if (cmp128(v6StartHi[mid], v6StartLo[mid], hi, lo) <= 0) {
                ans = mid;
                left = mid + 1;
            } else {
                right = mid - 1;
            }
        }
        if (ans < 0) {
            return -1;
        }
        if (v6EndHi != null) {
            return cmp128(hi, lo, v6EndHi[ans], v6EndLo[ans]) <= 0 ? v6Rec[ans] : -1;
        }
        // 连续且覆盖到末端的表：终点 = 下一行起点减一；最后一行（由 Builder 保证真的到 ffff:…）
        if (ans + 1 < v6StartHi.length) {
            long nhi = v6StartHi[ans + 1];
            long nlo = v6StartLo[ans + 1];
            long chi;
            long clo;
            if (nlo == 0) {
                chi = nhi - 1;
                clo = -1L;                    // 无符号 0-1 = 全 1
            } else {
                chi = nhi;
                clo = nlo - 1;
            }
            return cmp128(hi, lo, chi, clo) <= 0 ? v6Rec[ans] : -1;
        }
        return v6Rec[ans];
    }

    /** 无符号 128 位比较 */
    static int cmp128(long aHi, long aLo, long bHi, long bLo) {
        int c = Long.compareUnsigned(aHi, bHi);
        return c != 0 ? c : Long.compareUnsigned(aLo, bLo);
    }

    // ==================== 加载期构建 ====================

    /** 逐行追加区间的构建器（只在加载期使用；一次性，不保证线程安全） */
    static final class Builder {

        private int[] v4Start = new int[1024];
        private int[] v4End = new int[1024];
        private int[] v4Rec = new int[1024];
        private int v4n;

        private long[] v6StartHi = new long[256];
        private long[] v6StartLo = new long[256];
        private long[] v6EndHi = new long[256];
        private long[] v6EndLo = new long[256];
        private int[] v6Rec = new int[256];
        private int v6n;

        private boolean v4Contiguous = true;
        private boolean v6Contiguous = true;

        /** 追加一个 IPv4 区间（要求按起点升序、互不重叠；违反即抛，交给上层判为库不可用） */
        void addV4(int start, int end, int rec) {
            if (end != 0 && Integer.compareUnsigned(start, end) > 0) {
                throw new IllegalArgumentException("IPv4 区间起点大于终点：" + start + ">" + end);
            }
            if (v4n > 0 && Integer.compareUnsigned(start, v4End[v4n - 1]) <= 0) {
                throw new IllegalArgumentException("IPv4 区间未按升序/存在重叠（第 " + (v4n + 1) + " 行）");
            }
            if (v4n > 0 && v4End[v4n - 1] != 0xFFFFFFFF && start != v4End[v4n - 1] + 1) {
                v4Contiguous = false;
            }
            if (v4n == v4Start.length) {
                int cap = v4n + (v4n >> 1) + 16;
                v4Start = Arrays.copyOf(v4Start, cap);
                v4End = Arrays.copyOf(v4End, cap);
                v4Rec = Arrays.copyOf(v4Rec, cap);
            }
            v4Start[v4n] = start;
            v4End[v4n] = end;
            v4Rec[v4n] = rec;
            v4n++;
        }

        /** 追加一个 IPv6 区间（同样要求升序） */
        void addV6(long startHi, long startLo, long endHi, long endLo, int rec) {
            if (cmp128(startHi, startLo, endHi, endLo) > 0) {
                throw new IllegalArgumentException("IPv6 区间起点大于终点（第 " + (v6n + 1) + " 行）");
            }
            if (v6n > 0 && cmp128(startHi, startLo, v6EndHi[v6n - 1], v6EndLo[v6n - 1]) <= 0) {
                throw new IllegalArgumentException("IPv6 区间未按升序/存在重叠（第 " + (v6n + 1) + " 行）");
            }
            if (v6n > 0) {
                long[] prev = plusOne(v6EndHi[v6n - 1], v6EndLo[v6n - 1]);
                if (prev != null && cmp128(startHi, startLo, prev[0], prev[1]) != 0) {
                    v6Contiguous = false;
                }
            }
            if (v6n == v6StartHi.length) {
                int cap = v6n + (v6n >> 1) + 16;
                v6StartHi = Arrays.copyOf(v6StartHi, cap);
                v6StartLo = Arrays.copyOf(v6StartLo, cap);
                v6EndHi = Arrays.copyOf(v6EndHi, cap);
                v6EndLo = Arrays.copyOf(v6EndLo, cap);
                v6Rec = Arrays.copyOf(v6Rec, cap);
            }
            v6StartHi[v6n] = startHi;
            v6StartLo[v6n] = startLo;
            v6EndHi[v6n] = endHi;
            v6EndLo[v6n] = endLo;
            v6Rec[v6n] = rec;
            v6n++;
        }

        /** 加一；溢出（全 1）时返回 null，表示"没有下一个地址" */
        private static long[] plusOne(long hi, long lo) {
            if (lo == -1L) {
                if (hi == -1L) {
                    return null;
                }
                return new long[]{hi + 1, 0L};
            }
            return new long[]{hi, lo + 1};
        }

        int v4Count() {
            return v4n;
        }

        int v6Count() {
            return v6n;
        }

        boolean v4Contiguous() {
            return v4Contiguous;
        }

        boolean v6Contiguous() {
            return v6Contiguous;
        }

        /**
         * 定稿：按"是否真的连续<b>且覆盖到地址空间末端</b>"决定要不要留终点数组。
         *
         * <h3>为什么"连续"还不够，必须再加"到末端"</h3>
         * 连续时终点由下一行起点推导，最后一行没有"下一行" —— 只能假定它一直延伸到
         * 地址空间末尾（真库确实如此：实测 City 库最后一行是
         * {@code fec0::,ffff:...:ffff}、最后一段 IPv4 是 {@code 224.0.0.0,255.255.255.255}）。
         * 但测试夹具与将来可能裁剪过的库<b>不一定覆盖到末端</b>，那时这个假定会把
         * 末端之外的地址全部算进最后一行（实测过：{@code 8.8.8.8} 被算成夹具里最后一个国家的 IP，
         * 于是"美国"的计数里混进了本来"未定位"的流量）。所以判据写成"连续 + 末行到末端"。
         */
        IpRangeTable build() {
            int[] s4 = Arrays.copyOf(v4Start, v4n);
            int[] r4 = Arrays.copyOf(v4Rec, v4n);
            boolean dense4 = v4Contiguous && v4n > 0 && v4End[v4n - 1] == 0xFFFFFFFF;
            int[] e4 = dense4 ? null : Arrays.copyOf(v4End, v4n);

            long[] s6h = Arrays.copyOf(v6StartHi, v6n);
            long[] s6l = Arrays.copyOf(v6StartLo, v6n);
            int[] r6 = Arrays.copyOf(v6Rec, v6n);
            boolean dense6 = v6Contiguous && v6n > 0
                    && v6EndHi[v6n - 1] == -1L && v6EndLo[v6n - 1] == -1L;
            long[] e6h = null;
            long[] e6l = null;
            if (!dense6) {
                e6h = Arrays.copyOf(v6EndHi, v6n);
                e6l = Arrays.copyOf(v6EndLo, v6n);
            }
            return new IpRangeTable(s4, e4, r4, s6h, s6l, e6h, e6l, r6);
        }
    }
}

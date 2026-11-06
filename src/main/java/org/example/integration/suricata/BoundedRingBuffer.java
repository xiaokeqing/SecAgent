package org.example.integration.suricata;

import java.util.ArrayList;
import java.util.List;

/**
 * 定长环形缓冲：写满后覆盖最旧的一条。
 *
 * <h3>为什么必须有界</h3>
 * <p>eve.json 是持续追加的日志文件，如果按"全收进内存"的思路做，
 * 一个几 GB 的文件会在启动/回放阶段直接把堆吃穿 —— 本项目容器只有 512MiB cgroup，
 * 真实发生过 Suricata 校验时 OOM。反查（最近 N 分钟的端口/SNI 分布）只需要最近一段时间的数据，
 * 所以宁可丢掉最旧的，也不允许内存随运行时长无上限增长。
 *
 * <h3>为什么用 synchronized 而不是无锁</h3>
 * <p>写入是"每条事件一次 add"，读取是"整体快照"，两段临界区都只有一次数组赋值或一次复制，
 * 争用可以忽略；而并发正确性一眼可验，比无锁实现少一类"看起来能跑、边界时丢数据"的出错方式。
 * 快照要在锁内复制：如果直接把内部数组交出去，调用方遍历时正好发生覆盖，就会读到被挪位的元素。
 *
 * @param <T> 元素类型
 */
public final class BoundedRingBuffer<T> {

    private final Object[] ring;
    /** 最旧元素的下标；缓冲未满时恒为 0 */
    private int head;
    /** 当前元素个数（≤ capacity） */
    private int size;
    /** 累计写入条数（含已被覆盖的），用于观测"到底来过多少数据" */
    private long totalAdded;

    public BoundedRingBuffer(int capacity) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("环形缓冲容量必须大于 0，实际：" + capacity);
        }
        this.ring = new Object[capacity];
    }

    public synchronized void add(T element) {
        if (element == null) {
            return;
        }
        int idx = (head + size) % ring.length;
        ring[idx] = element;
        if (size == ring.length) {
            // 已满：最旧的位置被新元素覆盖，头指针前移
            head = (head + 1) % ring.length;
        } else {
            size++;
        }
        totalAdded++;
    }

    /** 按"旧 → 新"顺序返回一份独立副本，调用方可以安全遍历。 */
    @SuppressWarnings("unchecked")
    public synchronized List<T> snapshot() {
        List<T> out = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            out.add((T) ring[(head + i) % ring.length]);
        }
        return out;
    }

    public synchronized int size() {
        return size;
    }

    public int capacity() {
        return ring.length;
    }

    public synchronized long totalAdded() {
        return totalAdded;
    }
}

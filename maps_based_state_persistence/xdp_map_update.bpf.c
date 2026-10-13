#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_ENTRIES 4096

#ifndef PAYLOAD_SIZE
#define PAYLOAD_SIZE 8
#endif

#define KEY_LOOKUP          0
#define KEY_READ            1
#define KEY_UPDATE          2
#define KEY_SPINLOCK_UPDATE 3
#define TEST_COUNT          4

struct payload {
    struct bpf_spin_lock lock;
    __u8 data[PAYLOAD_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct payload);
} target_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, TEST_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} latency_map SEC(".maps");

static __always_inline void accumulate_latency(__u32 key, __u64 latency)
{
    __u64 *total = bpf_map_lookup_elem(&latency_map, &key);
    if (total)
        __sync_fetch_and_add(total, latency);
}

static long map_initialize(__u32 i, void *ctx)
{
    struct payload *val = bpf_map_lookup_elem(&target_map, &i);
    if (!val)
        return 1;

    bpf_spin_lock(&val->lock);
#pragma unroll
    for (int j = 0; j < PAYLOAD_SIZE; j++)
        val->data[j] = 42;
    bpf_spin_unlock(&val->lock);
    return 0;
}

static long map_lookup(__u32 i, void *ctx)
{
    struct payload *val = bpf_map_lookup_elem(&target_map, &i);
    return val ? 0 : 1;
}

/* Lookup and actually read every payload byte. */
static long map_read(__u32 i, void *ctx)
{
    volatile struct payload *val;

    val = bpf_map_lookup_elem(&target_map, &i);
    if (!val)
        return 1;

#pragma unroll
    for (int j = 0; j < PAYLOAD_SIZE; j++) {
        /* volatile forces an actual load for every byte. */
        (void)val->data[j];
    }
    return 0;
}

static long map_update(__u32 i, void *ctx)
{
    struct payload *val = bpf_map_lookup_elem(&target_map, &i);
    if (!val)
        return 1;

#pragma unroll
    for (int j = 0; j < PAYLOAD_SIZE; j++)
        val->data[j] = 42;
    return 0;
}

static long map_spinlock_update(__u32 i, void *ctx)
{
    struct payload *val = bpf_map_lookup_elem(&target_map, &i);
    if (!val)
        return 1;

    bpf_spin_lock(&val->lock);
#pragma unroll
    for (int j = 0; j < PAYLOAD_SIZE; j++)
        val->data[j] = 42;
    bpf_spin_unlock(&val->lock);
    return 0;
}

SEC("xdp")
int xdp_map_update(struct xdp_md *ctx)
{
    __u32 key;
    __u64 start, latency;

    bpf_loop(MAX_ENTRIES, map_initialize, NULL, 0);
    start = bpf_ktime_get_ns();
    bpf_loop(MAX_ENTRIES, map_lookup, NULL, 0);
    latency = bpf_ktime_get_ns() - start;
    key = KEY_LOOKUP;
    accumulate_latency(key, latency);

    bpf_loop(MAX_ENTRIES, map_initialize, NULL, 0);
    start = bpf_ktime_get_ns();
    bpf_loop(MAX_ENTRIES, map_read, NULL, 0);
    latency = bpf_ktime_get_ns() - start;
    key = KEY_READ;
    accumulate_latency(key, latency);

    bpf_loop(MAX_ENTRIES, map_initialize, NULL, 0);
    start = bpf_ktime_get_ns();
    bpf_loop(MAX_ENTRIES, map_update, NULL, 0);
    latency = bpf_ktime_get_ns() - start;
    key = KEY_UPDATE;
    accumulate_latency(key, latency);

    bpf_loop(MAX_ENTRIES, map_initialize, NULL, 0);
    start = bpf_ktime_get_ns();
    bpf_loop(MAX_ENTRIES, map_spinlock_update, NULL, 0);
    latency = bpf_ktime_get_ns() - start;
    key = KEY_SPINLOCK_UPDATE;
    accumulate_latency(key, latency);

    return XDP_DROP;
}

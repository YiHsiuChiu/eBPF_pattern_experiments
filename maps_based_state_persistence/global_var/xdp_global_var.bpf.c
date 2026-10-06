#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_ENTRIES 4096

#ifndef SAMPLES
#define SAMPLES 2000
#endif

#ifndef PAYLOAD_SIZE
#define PAYLOAD_SIZE 8
#endif

#define KEY_READ   0
#define KEY_UPDATE 1

/*
 * The benchmark target is ordinary BPF global data (.bss), not an explicit
 * SEC(".maps") map.  We keep MAX_ENTRIES logical slots so the number of
 * operations matches the map benchmark.
 *
 * volatile is intentional: every byte read/write must remain observable to
 * the compiler, otherwise LLVM could fold or eliminate the benchmarked work.
 */
volatile __u8 global_data[MAX_ENTRIES][PAYLOAD_SIZE];

/* Latency collection is outside the timed region, same idea as map benchmark. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} latency_map SEC(".maps");

static __always_inline void accumulate_latency(__u32 key, __u64 latency)
{
    __u64 *total = bpf_map_lookup_elem(&latency_map, &key);

    if (total)
        __sync_fetch_and_add(total, latency);
}

static long global_initialize(__u32 i, void *ctx)
{
    if (i >= MAX_ENTRIES)
        return 1;

#pragma unroll
    for (int j = 0; j < PAYLOAD_SIZE; j++)
        global_data[i][j] = 42;

    return 0;
}

static long global_read(__u32 i, void *ctx)
{
    if (i >= MAX_ENTRIES)
        return 1;

#pragma unroll
    for (int j = 0; j < PAYLOAD_SIZE; j++) {
        /* Volatile global_data forces an actual load for every byte. */
        (void)global_data[i][j];
    }

    return 0;
}

static long global_update(__u32 i, void *ctx)
{
    if (i >= MAX_ENTRIES)
        return 1;

#pragma unroll
    for (int j = 0; j < PAYLOAD_SIZE; j++)
        global_data[i][j] = 42;

    return 0;
}

SEC("xdp")
int xdp_global_var(struct xdp_md *ctx)
{
    __u32 key;
    __u64 latency;

    /* Warm/initialize the same 4096 logical slots before the read test. */
    bpf_loop(MAX_ENTRIES, global_initialize, NULL, 0);

    __u64 read_start = bpf_ktime_get_ns();
    bpf_loop(MAX_ENTRIES, global_read, NULL, 0);
    __u64 read_end = bpf_ktime_get_ns();

    latency = read_end - read_start;
    key = KEY_READ;
    accumulate_latency(key, latency);

    /* Match the original structure: initialize again before update timing. */
    bpf_loop(MAX_ENTRIES, global_initialize, NULL, 0);

    __u64 update_start = bpf_ktime_get_ns();
    bpf_loop(MAX_ENTRIES, global_update, NULL, 0);
    __u64 update_end = bpf_ktime_get_ns();

    latency = update_end - update_start;
    key = KEY_UPDATE;
    accumulate_latency(key, latency);

    return XDP_DROP;
}

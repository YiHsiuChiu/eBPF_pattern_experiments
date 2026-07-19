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

struct payload {
    __u8 data[PAYLOAD_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct payload);
} target_map SEC(".maps");

/* Scratch buffer */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct payload);
} scratch_map SEC(".maps");

/* 延遲記錄 Map */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} latency_map SEC(".maps");

static long map_initialize(__u32 i, void *ctx) {
    __u32 zero = 0;
    
    struct payload *val = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!val) 
        return 1;

    #pragma unroll
    for (int j = 0; j < PAYLOAD_SIZE; j++) {
        val->data[j] = 42;
    }

    bpf_map_update_elem(&target_map, &i, val, BPF_ANY);

    return 0;
}

static long map_update(__u32 i, void *ctx) {
    
    struct payload *val = bpf_map_lookup_elem(&target_map, &i);
    if (!val) 
        return 1;

    #pragma unroll
    for (int j = 0; j < PAYLOAD_SIZE; j++) {
        val->data[j] = 42;
    }

    return 0;
}

SEC("xdp")
int xdp_map_update(struct xdp_md *ctx)
{
    __u32 zero = 0;

    bpf_loop(MAX_ENTRIES, map_initialize, NULL, 0);

    __u64 start = bpf_ktime_get_ns();
    bpf_loop(SAMPLES, map_update, NULL, 0);
    __u64 end = bpf_ktime_get_ns();
    
    __u64 total_latency = end - start;
    bpf_map_update_elem(&latency_map, &zero, &total_latency, BPF_ANY);

    return XDP_DROP;
}
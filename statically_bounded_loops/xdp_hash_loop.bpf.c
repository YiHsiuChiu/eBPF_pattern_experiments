#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef K
#define K 1500
#endif

SEC("xdp")
int xdp_hash_bounded_loop(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u8 *ptr = (__u8 *)data;

    if ((void *)(ptr + K) > data_end) {
        return XDP_PASS; // 或者 XDP_DROP，看你的業務邏輯
    }
    
    volatile __u32 hash = 5381;

    #pragma clang loop unroll(disable)
    for (int i = 0; i < K; i++) {

        __u8 val = *ptr;
        hash = ((hash << 5) + hash) + val;
        ptr++;

        asm volatile("" ::: "memory");
    }

    return XDP_PASS;
}
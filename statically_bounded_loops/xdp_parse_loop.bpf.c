#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef K
#define K 1500
#endif

SEC("xdp")
int xdp_parse_bounded_loop(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u8 *ptr = (__u8 *)data;
    
    if ((void *)(ptr + 1500) > data_end) {
        return XDP_PASS;
    }

    volatile __u32 hash = 5381;

    #pragma clang loop unroll(disable)
    for (int i = 0; i < K; i++) {
        if (ptr + 1 > (__u8 *)data_end)
        break;

        (void)*(volatile __u8 *)ptr;
        ptr += 1;

        asm volatile("" ::: "memory");
    }

    return XDP_PASS;
}
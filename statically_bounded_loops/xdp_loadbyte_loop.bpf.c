#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef K
#define K 1500
#endif

SEC("xdp")
int xdp_loadbyte_bounded_loop(struct xdp_md *ctx)
{
    unsigned char byte = 0;
    long ret;

    #pragma clang loop unroll(disable)
    for (int i = 0; i < K; i++) {
        
        ret = bpf_xdp_load_bytes(ctx, i, &byte, 1);
        
    }

    return XDP_PASS;
}
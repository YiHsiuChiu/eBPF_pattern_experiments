#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef K
#define K 1500
#endif

#ifndef VARIABLE_TYPE
#define VARIABLE_TYPE __u16
#endif

SEC("xdp")
int xdp_unbounded_loop(struct xdp_md *ctx)
{
    volatile VARIABLE_TYPE len = 1000;
    unsigned char byte = 0;
    long ret;
    
    #pragma clang loop unroll(disable)
    for (int i = 0; i < len; i++) {

        ret = bpf_xdp_load_bytes(ctx, i, &byte, 1);
        
    }

    return XDP_PASS;
}

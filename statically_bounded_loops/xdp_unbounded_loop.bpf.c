#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef K
#define K 1500
#endif

#ifndef VARIABLE_TYPE
#define VARIABLE_TYPE __u32
#endif

SEC("xdp")
int xdp_unbounded_loop(struct xdp_md *ctx)
{
    volatile __u32 sum = 0;
    volatile VARIABLE_TYPE len = 1000;
    
    #pragma clang loop unroll(disable)
    for (int i = 0; i < len; i++) {

        sum += i * (i + 1);
        asm volatile("" ::: "memory");
        
    }

    return XDP_PASS;
}

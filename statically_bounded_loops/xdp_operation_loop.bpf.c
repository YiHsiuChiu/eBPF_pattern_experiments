#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef MAX_LOOP
#define MAX_LOOP 1500
#endif

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    volatile const __u32 len = 1500;
    volatile __u32 sum = 0;

#pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_LOOP; i++) {

        if (i >= len)
            break;

        sum += i * (i + 1);
        asm volatile("" ::: "memory");
    }

    return XDP_PASS;
}

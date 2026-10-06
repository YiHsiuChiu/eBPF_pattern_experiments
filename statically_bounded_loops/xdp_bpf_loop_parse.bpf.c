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
int xdp_bpf_loop(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u8 *ptr = (__u8 *)data;
    
    if ((void *)(ptr + 1) > data_end) {
        return XDP_PASS;
    }

    volatile VARIABLE_TYPE len = 1000;

    int i;
    bpf_for(i, 0, len) {

        if (ptr + 1 > (__u8 *)data_end)
            break;

        (void)*(volatile __u8 *)ptr;
        ptr += 1;
        
    }

    return XDP_PASS;
}

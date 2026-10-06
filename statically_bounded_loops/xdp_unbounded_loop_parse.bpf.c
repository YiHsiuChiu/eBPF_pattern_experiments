#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef K
#define K 1500
#endif

#ifndef VARIABLE_TYPE
#define VARIABLE_TYPE __u32
#endif

SEC("xdp")
int xdp_unbounded_parse(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 解析 Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // 只處理 IPv4 封包
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // 解析 IP Header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // 只處理 UDP 封包
    if (ip->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    // 取得 IP Header 長度 (處理含有 IP options 的情況)
    __u32 ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr)) {
        return XDP_PASS;
    }

    // 解析 UDP Header
    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end) {
        return XDP_PASS;
    }

    // 檢查目標 Port 是否為 DNS Port (5333)
    if (udp->dest != bpf_htons(5333)) {
        return XDP_PASS;
    }

    __u8 *ptr = (__u8 *)(udp + 1);
    
    if (ptr + 8 > (__u8 *)data_end)
        return XDP_DROP;


    __u64 temp = (__u64)ptr[0] << 56 | (__u64)ptr[1] << 48 | (__u64)ptr[2] << 40 | (__u64)ptr[3] << 32 | (__u64)ptr[4] << 24 | (__u64)ptr[5] << 16 | (__u64)ptr[6] << 8 | ptr[7];
    volatile VARIABLE_TYPE len = temp;

    #pragma clang loop unroll(disable)
    for (int i = 0; i < len; i++) {
    // for(int i = 0; i < max; i++){
        if (ptr + 1 > (__u8 *)data_end)
            break;

        (void)*(volatile __u8 *)ptr;
        ptr += 1;
    }

    return XDP_PASS;
}

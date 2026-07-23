#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

/* 可在檔頭或 Makefile 透過 -DMAX_QPS=xxxx 設定上限，預設為每秒 10,000 筆 */
#ifndef MAX_QPS
#define MAX_QPS 1000
#endif

/* DNS Header 結構 */
struct dns_hdr {
    __be16 id;
    __be16 flags;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
};

#define MAX_LOOP 2

/* Rate limiter Map 的 Key */
struct query_key {
    __u32 client_ip;   /* Client IPv4 位址 */
    __u32 qname_hash;  /* DNS QNAME 的雜湊值 */
};

/* Rate limiter Map 的 Value (紀錄秒數與當秒累積計數) */
struct limit_val {
    __u64 last_time;   /* 上次紀錄的 timestamp (單位: 秒) */
    __u32 count;       /* 在當前這一秒內已累積的查詢次數 */
};

/* 紀錄 client IP + Domain 上次查詢時間與計數的 HASH Map
 * 限制最大容量 10240 筆
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct query_key);
    __type(value, struct limit_val);
} dns_limit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64); 
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} boot_time_map SEC(".maps");

SEC("xdp")
int xdp_dns_limit(struct xdp_md *ctx) {
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

    // 解析 DNS Header
    struct dns_hdr *dns = (void *)(udp + 1);
    if ((void *)(dns + 1) > data_end) {
        return XDP_PASS;
    }

    // 檢查是否為 DNS Query 封包 (QR bit 必須為 0)
    // flags 的最高位 (bit 15) 為 QR bit
    if (bpf_ntohs(dns->flags) & 0x8000) {
        return XDP_PASS; // 這是 Response 封包，直接放行
    }

    // 讀取 Question 的數量
    __u16 qdcount = bpf_ntohs(dns->qdcount);

    __u32 client_ip = ip->saddr;
    void *ptr = (void *)(dns + 1);

    #pragma unroll
    for (int q = 0; q < MAX_LOOP; q++) {
        if (q >= qdcount) {
            break;
        }

        // 實作 DJB2 雜湊演算法來雜湊 QNAME
        __u32 hash = 5381;
        
        // 限制 QNAME 最大解析長度為 64 bytes，避免 verifier 報錯
        // QNAME 編碼格式為: [len][label][len][label]...[0x00]
        // 我們直接一個一個 byte 讀取並雜湊，直到遇到結束字元 0x00
        #pragma unroll
        for (int i = 0; i < 32; i++) {
            if (ptr + 1 > data_end) {
                return XDP_PASS; // 封包不完整，放行讓 TCP/IP stack 處理
            }

            __u8 val = *(__u8 *)ptr;
            if (val == 0) {
                ptr++;
                break;
            }

            // DJB2 hash: hash * 33 + val
            hash = ((hash << 5) + hash) + val;
            ptr++;
        }

        // 解析完 QNAME 後，ptr 會指向 QTYPE 的起點
        // 我們必須跳過 QTYPE (2 bytes) 與 QCLASS (2 bytes) 以便指向下一個 Question 的起點
        // if (ptr + 4 > data_end) {
        //     return XDP_PASS; // 封包不完整
        // }
        ptr += 4;

        // 速率限制檢查
        struct query_key key = {
            .client_ip = client_ip,
            .qname_hash = hash
        };

        __u64 now = bpf_ktime_get_ns() / 1000000000;
        struct limit_val *val = bpf_map_lookup_elem(&dns_limit_map, &key);

        if (val) {
            if (val->last_time == now) {
                // 1. 還在同這一秒內
                if (val->count >= MAX_QPS) {
                    // 超過 MAX_QPS，檢查時間豁免條款
                    __u32 b_key = 0;
                    __u64 *boot_time = bpf_map_lookup_elem(&boot_time_map, &b_key);
                    if (boot_time) {
                        __u64 current_hour = ((now + *boot_time) % 86400) / 3600;
                        bpf_printk("Current Hour: %d", current_hour);
                        // 0-5點沒有限制
                        if (current_hour >= 1)
                            return XDP_DROP;
                    } else {
                        return XDP_DROP;
                    }
                } else {
                    // 未超過上限，計數器 +1
                    val->count++;
                }
            } else {
                // 2. 進入新的一秒，重置時間與計數器
                val->last_time = now;
                val->count = 1;
            }
        } else {
            // 3. 第一次查詢，記錄目前時間與初始計數 1
            struct limit_val new_val = {
                .last_time = now,
                .count = 1
            };
            bpf_map_update_elem(&dns_limit_map, &key, &new_val, BPF_ANY);
        }
    }

    return XDP_PASS;
}


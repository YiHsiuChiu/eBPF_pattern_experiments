#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

#define KEY_BASELINE     0 
#define KEY_GET_KTIME    1 
#define KEY_RECONSTRUCT  2
#define KEY_DATETIME     3
#define NUM_STAGES       4
#define UTC_OFFSET_SECONDS (8 * 60 * 60)

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} boot_time_map SEC(".maps");

struct stat_val {
    __u64 sum;
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, NUM_STAGES);
    __type(key, __u32);
    __type(value, struct stat_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} latency_map SEC(".maps");

struct datetime {
    __u16 year;
    __u8  month;
    __u8  day;
    __u8  hour;
    __u8  minute;
    __u8  second;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct datetime);
} datetime_map SEC(".maps");

static __always_inline void record_latency(__u32 stage_key, __u64 latency)
{
    struct stat_val *sv = bpf_map_lookup_elem(&latency_map, &stage_key);
    if (!sv)
        return;

    sv->sum += latency;
    sv->count += 1;
}

static __always_inline void epoch_to_datetime(__u64 epoch_sec, struct datetime *dt)
{
    epoch_sec += UTC_OFFSET_SECONDS;

    __u64 days = epoch_sec / 86400;
    __u64 rem  = epoch_sec % 86400;

    dt->hour   = (__u8)(rem / 3600);
    rem %= 3600;
    dt->minute = (__u8)(rem / 60);
    dt->second = (__u8)(rem % 60);

    __s64 z   = (__s64)days + 719468;
    __s64 era = (z >= 0 ? z : z - 146096) / 146097;
    __u64 doe = (__u64)(z - era * 146097);
    __u64 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    __s64 y   = (__s64)yoe + era * 400;
    __u64 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    __u64 mp  = (5 * doy + 2) / 153;
    __u64 d   = doy - (153 * mp + 2) / 5 + 1;
    __u64 m   = mp + (mp < 10 ? 3 : -9);
    y += (m <= 2);

    dt->year  = (__u16)y;
    dt->month = (__u8)m;
    dt->day   = (__u8)d;
}

SEC("xdp")
int xdp_time_offset(struct xdp_md *ctx)
{
    __u64 start, end;
    __u32 zero = 0;

    // get_tai()
    start = bpf_ktime_get_ns();
    __u64 now_ns = bpf_ktime_get_tai_ns();
    end = bpf_ktime_get_ns();
    record_latency(KEY_BASELINE, end - start);

    // constant offset 
    __u64 real_epoch_sec = 0;
    start = bpf_ktime_get_ns();
    __u64 now_sec = bpf_ktime_get_tai_ns() / 1000000000;
    real_epoch_sec = now_sec - 37;
    end = bpf_ktime_get_ns();
    record_latency(KEY_GET_KTIME, end - start);

    // reconstruct
    __u64 real_epoch_sec2 = 0;
    start = bpf_ktime_get_ns();
    __u64 now_sec2 = bpf_ktime_get_tai_ns() / 1000000000;
    __u64 *boot_time_epoch = bpf_map_lookup_elem(&boot_time_map, &zero);
    if (boot_time_epoch)
        real_epoch_sec2 = *boot_time_epoch + now_sec2;
    end = bpf_ktime_get_ns();
    record_latency(KEY_RECONSTRUCT, end - start);

    // datetime
    struct datetime dt = {};
    start = bpf_ktime_get_ns();
    now_sec = bpf_ktime_get_tai_ns() / 1000000000;
    boot_time_epoch = bpf_map_lookup_elem(&boot_time_map, &zero);
    if (boot_time_epoch)
        real_epoch_sec = *boot_time_epoch + now_sec;
    epoch_to_datetime(real_epoch_sec, &dt);
    end = bpf_ktime_get_ns();
    record_latency(KEY_DATETIME, end - start);

    bpf_map_update_elem(&datetime_map, &zero, &dt, BPF_ANY);

    return XDP_PASS;
}
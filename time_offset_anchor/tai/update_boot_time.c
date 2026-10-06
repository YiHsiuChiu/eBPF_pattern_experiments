#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define OBJ_PATH       "xdp_time_offset.bpf.o"
#define PROG_NAME      "xdp_time_offset"
#define BOOT_TIME_MAP  "boot_time_map"
#define LATENCY_MAP    "latency_map"
#define DATETIME_MAP   "datetime_map"

#define KEY_BASELINE    0
#define KEY_GET_KTIME   1
#define KEY_RECONSTRUCT 2
#define KEY_DATETIME    3
#define NUM_STAGES      4

struct stat_val {
    uint64_t sum;
    uint64_t count;
};

struct datetime {
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
};

static const char *stage_name[NUM_STAGES] = {
    "get tai",
    "reconstruct (add constant offset)",
    "reconstruct (lookup + add)",
    "epoch to datetime",
};

static uint64_t compute_boot_epoch_sec(void)
{
    struct timespec realtime, boottime;

    if (clock_gettime(CLOCK_REALTIME, &realtime) ||
        clock_gettime(CLOCK_BOOTTIME, &boottime)) {
        perror("clock_gettime");
        return 0;
    }

    return ((uint64_t)realtime.tv_sec * 1000000000ULL + realtime.tv_nsec -
            ((uint64_t)boottime.tv_sec * 1000000000ULL + boottime.tv_nsec)) /
           1000000000ULL;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-n samples]\n", prog);
}

int main(int argc, char **argv)
{
    int samples = 10000;
    int opt;
    int err;

    while ((opt = getopt(argc, argv, "n:h")) != -1) {
        switch (opt) {
        case 'n':
            samples = atoi(optarg);
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }
    if (samples <= 0) {
        fprintf(stderr, "samples must be positive\n");
        return 1;
    }

    libbpf_set_print(NULL);

    struct bpf_object *obj = bpf_object__open_file(OBJ_PATH, NULL);
    err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "Failed to open %s: %s\n", OBJ_PATH, strerror(-err));
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load %s: %s\n", OBJ_PATH, strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_map *boot_map = bpf_object__find_map_by_name(obj, BOOT_TIME_MAP);
    struct bpf_map *latency_map = bpf_object__find_map_by_name(obj, LATENCY_MAP);
    struct bpf_map *datetime_map = bpf_object__find_map_by_name(obj, DATETIME_MAP);
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, PROG_NAME);
    if (!boot_map || !latency_map || !datetime_map || !prog) {
        fprintf(stderr, "Required program or map was not found in %s\n", OBJ_PATH);
        bpf_object__close(obj);
        return 1;
    }

    int boot_fd = bpf_map__fd(boot_map);
    int latency_fd = bpf_map__fd(latency_map);
    int datetime_fd = bpf_map__fd(datetime_map);
    int prog_fd = bpf_program__fd(prog);
    __u32 zero = 0;
    __u64 boot_epoch_sec = compute_boot_epoch_sec();
    struct stat_val empty = {};

    if (!boot_epoch_sec ||
        bpf_map_update_elem(boot_fd, &zero, &boot_epoch_sec, BPF_ANY)) {
        fprintf(stderr, "Failed to initialise boot_time_map: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    for (__u32 key = 0; key < NUM_STAGES; key++) {
        if (bpf_map_update_elem(latency_fd, &key, &empty, BPF_ANY)) {
            fprintf(stderr, "Failed to reset latency_map: %s\n", strerror(errno));
            bpf_object__close(obj);
            return 1;
        }
    }

    __u8 packet[64] = {};
    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in = packet,
        .data_size_in = sizeof(packet),
        .repeat = samples);

    err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err) {
        fprintf(stderr, "XDP test run failed: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    struct datetime dt = {};
    if (bpf_map_lookup_elem(datetime_fd, &zero, &dt)) {
        fprintf(stderr, "Failed to read datetime_map: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    printf("Datetime from BPF epoch_to_datetime (UTC+8): %04u-%02u-%02u %02u:%02u:%02u\n",
           dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second);
    for (__u32 key = 0; key < NUM_STAGES; key++) {
        struct stat_val value = {};

        if (bpf_map_lookup_elem(latency_fd, &key, &value)) {
            fprintf(stderr, "Failed to read latency_map[%u]: %s\n", key, strerror(errno));
            bpf_object__close(obj);
            return 1;
        }
        if (!value.count) {
            printf("[%u] %-28s: no samples\n", key, stage_name[key]);
            continue;
        }
        printf("[%u] %-28s: avg=%8.1f ns  sum=%llu  n=%llu\n",
               key, stage_name[key], (double)value.sum / value.count,
               (unsigned long long)value.sum,
               (unsigned long long)value.count);
    }

    bpf_object__close(obj);
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define DEFAULT_MAP_PATH "/sys/fs/bpf/xdp/boot_time_map"

void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -p, --path <path>    Path to the pinned eBPF map (default: %s)\n", DEFAULT_MAP_PATH);
    printf("  -m, --mode <mode>    Mode of value to write:\n");
    printf("                         boot_time : Write system boot time epoch (RealTime - Uptime) [Default]\n");
    printf("                         uptime    : Write system uptime (RealTime - BootTime)\n");
    printf("  -h, --help           Show this help message\n");
}

int main(int argc, char **argv) {
    const char *map_path = DEFAULT_MAP_PATH;
    const char *mode = "boot_time";
    int opt;

    struct option long_options[] = {
        {"path", required_argument, NULL, 'p'},
        {"mode", required_argument, NULL, 'm'},
        {"help", no_argument,       NULL, 'h'},
        {NULL, 0,                   NULL, 0}
    };

    while ((opt = getopt_long(argc, argv, "p:m:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                map_path = optarg;
                break;
            case 'm':
                mode = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // 1. 取得 CLOCK_REALTIME (現在時間 - Epoch) 與 CLOCK_BOOTTIME (開機以來的時間)
    struct timespec ts_real, ts_boot;
    if (clock_gettime(CLOCK_REALTIME, &ts_real) < 0) {
        perror("clock_gettime CLOCK_REALTIME failed");
        return 1;
    }
    if (clock_gettime(CLOCK_BOOTTIME, &ts_boot) < 0) {
        perror("clock_gettime CLOCK_BOOTTIME failed");
        return 1;
    }

    uint64_t real_sec = (uint64_t)ts_real.tv_sec;
    uint64_t boot_sec = (uint64_t)ts_boot.tv_sec;

    // 計算系統開機時間戳記 (Boot Time Epoch) = 現在時間 - 開機以來的時間 (秒)
    uint64_t boot_time_epoch_sec = real_sec - boot_sec;
    uint64_t value_to_write = 0;

    if (strcmp(mode, "boot_time") == 0) {
        value_to_write = boot_time_epoch_sec;
        printf("[*] Mode: boot_time (Writing Boot Time Epoch in seconds)\n");
    } else if (strcmp(mode, "uptime") == 0) {
        value_to_write = boot_sec;
        printf("[*] Mode: uptime (Writing System Uptime in seconds)\n");
    } else {
        fprintf(stderr, "[-] Invalid mode '%s'. Use 'boot_time' or 'uptime'.\n", mode);
        return 1;
    }

    // 2. 開啟掛載的 BPF Map
    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        fprintf(stderr, "[-] Failed to get BPF map from pinned path '%s': %s\n", map_path, strerror(errno));
        fprintf(stderr, "    Please check if the map is pinned and you are running with sufficient privileges (sudo).\n");
        return 1;
    }

    // 3. 更新 Map 內容 (Array Map Key 恆為 0)
    uint32_t key = 0;
    if (bpf_map_update_elem(map_fd, &key, &value_to_write, BPF_ANY) < 0) {
        fprintf(stderr, "[-] Failed to update map element: %s\n", strerror(errno));
        close(map_fd);
        return 1;
    }

    close(map_fd);

    printf("[+] Successfully updated boot_time map!\n");
    printf("    Map Path: %s\n", map_path);
    printf("    Current Real Time (CLOCK_REALTIME): %lu s\n", real_sec);
    printf("    System Uptime (CLOCK_BOOTTIME)   : %lu s\n", boot_sec);
    printf("    Calculated Boot Epoch Time       : %lu s\n", boot_time_epoch_sec);
    printf("    Written Value                    : %lu s\n", value_to_write);

    return 0;
}

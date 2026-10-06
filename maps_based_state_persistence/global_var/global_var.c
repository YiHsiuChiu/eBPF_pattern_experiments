#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define OBJ_PATH  "xdp_global_var.bpf.o"
#define PROG_NAME "xdp_global_var"
#define MAP_NAME  "latency_map"

#define MAX_ENTRIES 4096

#ifndef SAMPLES
#define SAMPLES 2000
#endif

#define KEY_READ   0
#define KEY_UPDATE 1

static const char *latency_names[] = {
    "read",
    "update",
};

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <value_size_bytes>\n", argv[0]);
        return 1;
    }

    int value_size = atoi(argv[1]);

    libbpf_set_print(NULL);

    struct bpf_object *obj = bpf_object__open_file(OBJ_PATH, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open %s\n", OBJ_PATH);
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, PROG_NAME);
    if (!prog) {
        fprintf(stderr, "Program %s not found\n", PROG_NAME);
        bpf_object__close(obj);
        return 1;
    }
    int prog_fd = bpf_program__fd(prog);

    struct bpf_map *latency_map = bpf_object__find_map_by_name(obj, MAP_NAME);
    if (!latency_map) {
        fprintf(stderr, "Map %s not found\n", MAP_NAME);
        bpf_object__close(obj);
        return 1;
    }
    int latency_map_fd = bpf_map__fd(latency_map);

    __u8 pkt_in[64] = {0};
    __u8 pkt_out[64] = {0};

    LIBBPF_OPTS(
        bpf_test_run_opts,
        opts,
        .data_in = pkt_in,
        .data_size_in = sizeof(pkt_in),
        .data_out = pkt_out,
        .data_size_out = sizeof(pkt_out),
        .repeat = SAMPLES
    );

    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err) {
        fprintf(stderr, "Program execution failed: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    __u64 total_latency[2];
    __u32 keys[2] = { KEY_READ, KEY_UPDATE };

    for (int i = 0; i < 2; i++) {
        if (bpf_map_lookup_elem(latency_map_fd, &keys[i], &total_latency[i])) {
            fprintf(stderr, "Failed to read latency_map[%d]\n", keys[i]);
            bpf_object__close(obj);
            return 1;
        }
    }

    printf("RESULTS payload=%d bytes\n", value_size);
    for (int i = 0; i < 2; i++) {
        double avg_latency = (double)total_latency[i] /
                             (SAMPLES * MAX_ENTRIES);
        printf("  %-16s: %.2f ns\n", latency_names[i], avg_latency);
    }

    bpf_object__close(obj);
    return 0;
}

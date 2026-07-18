#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define OBJ_PATH "xdp_map_update.bpf.o"
#define PROG_NAME "xdp_map_update"
#define MAP_NAME "latency_map"

#ifndef SAMPLES
#define SAMPLES 2000
#endif


int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s <value_size_bytes>\n",
            argv[0]);
        return 1;
    }


    int value_size = atoi(argv[1]);

    libbpf_set_print(NULL);

    struct bpf_object *obj =
        bpf_object__open_file(
            OBJ_PATH,
            NULL
        );

    if (libbpf_get_error(obj)) {
        fprintf(stderr,
            "Failed to open %s\n",
            OBJ_PATH);
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr,
            "Failed to load BPF object\n");

        bpf_object__close(obj);
        return 1;
    }

    struct bpf_program *prog =
        bpf_object__find_program_by_name(
            obj,
            PROG_NAME
        );

    if (!prog) {
        fprintf(stderr,
            "Program %s not found\n",
            PROG_NAME);

        bpf_object__close(obj);
        return 1;
    }

    int prog_fd =
        bpf_program__fd(prog);

    struct bpf_map *map =
        bpf_object__find_map_by_name(
            obj,
            MAP_NAME
        );

    if (!map) {
        fprintf(stderr,
            "Map %s not found\n",
            MAP_NAME);

        bpf_object__close(obj);
        return 1;
    }

    int map_fd =
        bpf_map__fd(map);

    __u8 pkt_in[64] = {0};
    __u8 pkt_out[64];

    LIBBPF_OPTS(
        bpf_test_run_opts,
        opts,
        .data_in = pkt_in,
        .data_size_in = sizeof(pkt_in),
        .data_out = pkt_out,
        .data_size_out = sizeof(pkt_out),
        .repeat = 1
    );

    int err =
        bpf_prog_test_run_opts(
            prog_fd,
            &opts
        );

    if (err) {
        fprintf(stderr,
            "Program execution failed: %s\n",
            strerror(-err));

        bpf_object__close(obj);
        return 1;
    }

    __u32 key = 0;
    __u64 total_latency = 0;

    if (bpf_map_lookup_elem(
            map_fd,
            &key,
            &total_latency))
    {
        fprintf(stderr,
            "Failed to read latency map\n");

        bpf_object__close(obj);
        return 1;
    }

    double avg_latency =
        (double)total_latency / SAMPLES;

    printf(
        "payload=%d bytes, avg update latency = %.2f ns\n",
        value_size,
        avg_latency
    );

    bpf_object__close(obj);

    return 0;
}
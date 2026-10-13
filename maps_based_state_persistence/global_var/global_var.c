
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

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <value_size_bytes>\n", argv[0]);
        return 1;
    }

    int value_size = atoi(argv[1]);
    int ret = 1;
    FILE *csv = NULL;

    char filename[128];
    snprintf(filename, sizeof(filename),
             "global_var_%d.csv", value_size);

    libbpf_set_print(NULL);

    struct bpf_object *obj =
        bpf_object__open_file(OBJ_PATH, NULL);

    if (!obj || libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        goto cleanup;
    }

    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, PROG_NAME);

    if (!prog) {
        fprintf(stderr, "Program not found\n");
        goto cleanup;
    }

    int prog_fd = bpf_program__fd(prog);

    struct bpf_map *latency_map =
        bpf_object__find_map_by_name(obj, MAP_NAME);

    if (!latency_map) {
        fprintf(stderr, "Latency map not found\n");
        goto cleanup;
    }

    int latency_map_fd = bpf_map__fd(latency_map);

    csv = fopen(filename, "w");
    if (!csv) {
        perror("Failed to open CSV");
        goto cleanup;
    }

    fprintf(csv, "sample,read_ns,update_ns\n");

    __u8 pkt_in[64] = {0};
    __u8 pkt_out[64] = {0};

    LIBBPF_OPTS(
        bpf_test_run_opts,
        opts,
        .data_in = pkt_in,
        .data_size_in = sizeof(pkt_in),
        .data_out = pkt_out,
        .data_size_out = sizeof(pkt_out),
        .repeat = 1
    );

    __u32 keys[2] = {KEY_READ, KEY_UPDATE};
    __u64 previous[2] = {0, 0};
    __u64 current[2] = {0, 0};

    // Read initial cumulative counters.
    for (int i = 0; i < 2; i++) {
        if (bpf_map_lookup_elem(latency_map_fd,
                                &keys[i], &previous[i])) {
            fprintf(stderr, "Initial lookup failed\n");
            goto cleanup;
        }
    }

    double read_sum = 0.0;
    double update_sum = 0.0;

    for (int sample = 0; sample < SAMPLES; sample++) {

        // Execute XDP program exactly once.
        opts.data_size_out = sizeof(pkt_out);

        int err = bpf_prog_test_run_opts(prog_fd, &opts);

        if (err) {
            fprintf(stderr,
                    "Sample %d execution failed: %s\n",
                    sample + 1, strerror(-err));
            goto cleanup;
        }

        // Read cumulative latency counters.
        for (int i = 0; i < 2; i++) {
            if (bpf_map_lookup_elem(latency_map_fd,
                                    &keys[i], &current[i])) {
                fprintf(stderr,
                        "Map lookup failed at sample %d\n",
                        sample + 1);
                goto cleanup;
            }
        }

        // Difference gives the current sample latency.
        __u64 read_total = current[KEY_READ]
                         - previous[KEY_READ];

        __u64 update_total = current[KEY_UPDATE]
                           - previous[KEY_UPDATE];

        // Average latency per logical slot.
        double read_ns =
            (double)read_total / MAX_ENTRIES;

        double update_ns =
            (double)update_total / MAX_ENTRIES;

        // Write one CSV row per sample.
        fprintf(csv, "%d,%.4f,%.4f\n",
                sample + 1, read_ns, update_ns);

        read_sum += read_ns;
        update_sum += update_ns;

        // Update previous cumulative values.
        for (int i = 0; i < 2; i++)
            previous[i] = current[i];
    }

    if (fclose(csv) != 0) {
        csv = NULL;
        perror("Failed to close CSV");
        goto cleanup;
    }
    csv = NULL;

    printf("RESULTS payload=%d bytes\n", value_size);
    printf("  read            : %.2f ns\n",
           read_sum / SAMPLES);
    printf("  update          : %.2f ns\n",
           update_sum / SAMPLES);

    printf("CSV saved: %s (%d samples)\n",
           filename, SAMPLES);

    ret = 0;

cleanup:
    if (csv)
        fclose(csv);

    bpf_object__close(obj);
    return ret;
}



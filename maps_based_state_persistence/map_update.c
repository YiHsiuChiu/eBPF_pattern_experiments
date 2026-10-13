
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define OBJ_PATH "xdp_map_update.bpf.o"
#define PROG_NAME "xdp_map_update"
#define MAP_NAME "latency_map"
#define TARGET_MAP_NAME "target_map"

#define MAX_ENTRIES 4096

#ifndef SAMPLES
#define SAMPLES 2000
#endif

#define KEY_LOOKUP          0
#define KEY_READ            1
#define KEY_UPDATE          2
#define KEY_SPINLOCK_UPDATE 3
#define TEST_COUNT          4

static const char *latency_names[] = {
    "lookup",
    "map_read",
    "update",
    "spinlock_update"
};

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "Usage: %s <value_size_bytes>\n",
                argv[0]);
        return 1;
    }

    int value_size = atoi(argv[1]);

    if (value_size <= 0) {
        fprintf(stderr, "Invalid payload size\n");
        return 1;
    }

    libbpf_set_print(NULL);

    struct bpf_object *obj =
        bpf_object__open_file(OBJ_PATH, NULL);

    if (!obj || libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open %s\n", OBJ_PATH);
        return 1;
    }

    int ret = 1;
    FILE *csv = NULL;

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        goto cleanup;
    }

    struct bpf_map *target_map =
        bpf_object__find_map_by_name(
            obj, TARGET_MAP_NAME);

    if (!target_map) {
        fprintf(stderr, "Target map not found\n");
        goto cleanup;
    }

    int target_map_fd = bpf_map__fd(target_map);

    // Initialize target_map before benchmarking.
    /* Use the kernel map value size (including any alignment padding). */
    size_t payload_struct_size = bpf_map__value_size(target_map);

    void *dummy_payload =
        calloc(1, payload_struct_size);

    if (!dummy_payload) {
        fprintf(stderr,
                "Failed to allocate payload\n");
        goto cleanup;
    }

    for (__u32 i = 0; i < MAX_ENTRIES; i++) {
        if (bpf_map_update_elem(
                target_map_fd,
                &i,
                dummy_payload,
                BPF_ANY) != 0) {

            fprintf(stderr,
                    "Failed to initialize key %u: %s\n",
                    i, strerror(errno));

            free(dummy_payload);
            goto cleanup;
        }
    }

    free(dummy_payload);

    struct bpf_program *prog =
        bpf_object__find_program_by_name(
            obj, PROG_NAME);

    if (!prog) {
        fprintf(stderr, "Program not found\n");
        goto cleanup;
    }

    int prog_fd = bpf_program__fd(prog);

    struct bpf_map *latency_map =
        bpf_object__find_map_by_name(
            obj, MAP_NAME);

    if (!latency_map) {
        fprintf(stderr, "Latency map not found\n");
        goto cleanup;
    }

    int latency_map_fd =
        bpf_map__fd(latency_map);

    // Create CSV file.
    char filename[128];

    snprintf(filename, sizeof(filename),
             "map_update_%d.csv", value_size);

    csv = fopen(filename, "w");

    if (!csv) {
        perror("Failed to create CSV");
        goto cleanup;
    }

    fprintf(csv,
            "sample,lookup_ns,map_read_ns,update_ns,"
            "spinlock_update_ns\n");

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

    __u32 keys[TEST_COUNT] = {
        KEY_LOOKUP,
        KEY_READ,
        KEY_UPDATE,
        KEY_SPINLOCK_UPDATE
    };

    __u64 previous[TEST_COUNT] = {0};
    __u64 current[TEST_COUNT] = {0};

    double latency_sum[TEST_COUNT] = {0};

    // Read initial cumulative latency values.
    for (int i = 0; i < TEST_COUNT; i++) {
        if (bpf_map_lookup_elem(
                latency_map_fd,
                &keys[i],
                &previous[i])) {

            fprintf(stderr,
                    "Initial latency lookup failed\n");
            goto cleanup;
        }
    }

    // Run exactly SAMPLES independent tests.
    for (int sample = 0;
         sample < SAMPLES;
         sample++) {

        opts.data_size_out = sizeof(pkt_out);

        int err =
            bpf_prog_test_run_opts(prog_fd, &opts);

        if (err) {
            fprintf(stderr,
                    "Sample %d failed: %s\n",
                    sample + 1,
                    strerror(-err));
            goto cleanup;
        }

        // Read cumulative values after this sample.
        for (int i = 0; i < TEST_COUNT; i++) {
            if (bpf_map_lookup_elem(
                    latency_map_fd,
                    &keys[i],
                    &current[i])) {

                fprintf(stderr,
                        "Latency lookup failed "
                        "at sample %d\n",
                        sample + 1);
                goto cleanup;
            }
        }

        double latency_ns[TEST_COUNT];

        for (int i = 0; i < TEST_COUNT; i++) {

            // Extract this sample's latency.
            __u64 sample_total =
                current[i] - previous[i];

            // Average latency per logical entry.
            latency_ns[i] =
                (double)sample_total / MAX_ENTRIES;

            latency_sum[i] += latency_ns[i];

            // Save cumulative value for next sample.
            previous[i] = current[i];
        }

        // Write sample to CSV.
        fprintf(csv, "%d,%.4f,%.4f,%.4f,%.4f\n",
                sample + 1,
                latency_ns[KEY_LOOKUP],
                latency_ns[KEY_READ],
                latency_ns[KEY_UPDATE],
                latency_ns[KEY_SPINLOCK_UPDATE]);
    }

    if (fclose(csv) != 0) {
        csv = NULL;
        perror("Failed to close CSV");
        goto cleanup;
    }
    csv = NULL;

    // Print averages in original output format.
    printf("RESULTS payload=%d bytes\n",
           value_size);

    for (int i = 0; i < TEST_COUNT; i++) {
        double avg_latency =
            latency_sum[i] / SAMPLES;

        printf("  %-16s: %.2f ns\n",
               latency_names[i],
               avg_latency);
    }

    printf("CSV saved: %s (%d samples)\n",
           filename, SAMPLES);

    ret = 0;

cleanup:
    if (csv)
        fclose(csv);

    bpf_object__close(obj);
    return ret;
}




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
#define TAI_OFFSET_MAP "tai_offset_map"
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
    "reconstruct (subtract constant offset)",
    "reconstruct (lookup + subtract)",
    "epoch to datetime",
};

static uint64_t get_tai_offset_sec(void)
{
    return 37;
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
    int ret = 1;

    FILE *csv = NULL;
    struct bpf_object *obj = NULL;

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

    obj = bpf_object__open_file(OBJ_PATH, NULL);
    err = libbpf_get_error(obj);

    if (err) {
        fprintf(stderr,
                "Failed to open %s: %s\n",
                OBJ_PATH, strerror(-err));
        return 1;
    }

    err = bpf_object__load(obj);

    if (err) {
        fprintf(stderr,
                "Failed to load %s: %s\n",
                OBJ_PATH, strerror(-err));
        goto cleanup;
    }

    struct bpf_map *tai_offset_map =
        bpf_object__find_map_by_name(
            obj, TAI_OFFSET_MAP);

    struct bpf_map *latency_map =
        bpf_object__find_map_by_name(
            obj, LATENCY_MAP);

    struct bpf_map *datetime_map =
        bpf_object__find_map_by_name(
            obj, DATETIME_MAP);

    struct bpf_program *prog =
        bpf_object__find_program_by_name(
            obj, PROG_NAME);

    if (!tai_offset_map || !latency_map ||
        !datetime_map || !prog) {

        fprintf(stderr,
                "Required program or map was not found\n");
        goto cleanup;
    }

    int tai_offset_fd = bpf_map__fd(tai_offset_map);
    int latency_fd = bpf_map__fd(latency_map);
    int datetime_fd = bpf_map__fd(datetime_map);
    int prog_fd = bpf_program__fd(prog);

    __u32 zero = 0;
    __u64 tai_offset_sec = get_tai_offset_sec();

    struct stat_val empty = {};

    if (bpf_map_update_elem(
            tai_offset_fd, &zero, &tai_offset_sec, BPF_ANY)) {

        fprintf(stderr,
                "Failed to initialise tai_offset_map: %s\n",
                strerror(errno));
        goto cleanup;
    }

    // Reset all latency counters.
    for (__u32 key = 0; key < NUM_STAGES; key++) {

        if (bpf_map_update_elem(
                latency_fd, &key, &empty, BPF_ANY)) {

            fprintf(stderr,
                    "Failed to reset latency_map: %s\n",
                    strerror(errno));
            goto cleanup;
        }
    }

    // Create output CSV.
    char filename[128];

    snprintf(filename, sizeof(filename),
             "time_offset_%d.csv", samples);

    csv = fopen(filename, "w");

    if (!csv) {
        perror("Failed to create CSV");
        goto cleanup;
    }

    fprintf(csv,
            "sample,get_tai_ns,"
            "reconstruct_constant_ns,"
            "reconstruct_lookup_ns,"
            "epoch_to_datetime_ns\n");

    __u8 packet[64] = {};

    // One execution per test-run call.
    LIBBPF_OPTS(
        bpf_test_run_opts,
        opts,
        .data_in = packet,
        .data_size_in = sizeof(packet),
        .repeat = 1
    );

    struct stat_val previous[NUM_STAGES] = {};
    struct stat_val current[NUM_STAGES] = {};

    uint64_t total_sum[NUM_STAGES] = {};
    uint64_t total_count[NUM_STAGES] = {};

    // Read initial cumulative values.
    for (__u32 key = 0; key < NUM_STAGES; key++) {

        if (bpf_map_lookup_elem(
                latency_fd, &key, &previous[key])) {

            fprintf(stderr,
                    "Initial latency lookup failed\n");
            goto cleanup;
        }
    }

    // Collect each sample individually.
    for (int sample = 0; sample < samples; sample++) {

        err = bpf_prog_test_run_opts(prog_fd, &opts);

        if (err) {
            fprintf(stderr,
                    "Sample %d failed: %s\n",
                    sample + 1, strerror(-err));
            goto cleanup;
        }

        double latency_ns[NUM_STAGES] = {};

        for (__u32 key = 0; key < NUM_STAGES; key++) {

            if (bpf_map_lookup_elem(
                    latency_fd, &key, &current[key])) {

                fprintf(stderr,
                        "Failed reading stage %u "
                        "at sample %d\n",
                        key, sample + 1);
                goto cleanup;
            }

            // Ensure cumulative counters do not decrease.
            if (current[key].sum < previous[key].sum ||
                current[key].count < previous[key].count) {

                fprintf(stderr,
                        "Counter decreased at sample %d, "
                        "stage %u\n",
                        sample + 1, key);
                goto cleanup;
            }

            uint64_t delta_sum =
                current[key].sum - previous[key].sum;

            uint64_t delta_count =
                current[key].count - previous[key].count;

            if (delta_count > 0) {
                latency_ns[key] =
                    (double)delta_sum / delta_count;

                total_sum[key] += delta_sum;
                total_count[key] += delta_count;
            } else {
                // No measurement for this stage.
                latency_ns[key] = -1.0;
            }

            previous[key] = current[key];
        }

        // Write a CSV row for this sample.
        fprintf(csv, "%d,%.4f,%.4f,%.4f,%.4f\n",
                sample + 1,
                latency_ns[KEY_BASELINE],
                latency_ns[KEY_GET_KTIME],
                latency_ns[KEY_RECONSTRUCT],
                latency_ns[KEY_DATETIME]);
    }

    if (fclose(csv) != 0) {
        csv = NULL;
        perror("Failed to close CSV");
        goto cleanup;
    }
    csv = NULL;

    // Read the most recent converted datetime.
    struct datetime dt = {};

    if (bpf_map_lookup_elem(
            datetime_fd, &zero, &dt)) {

        fprintf(stderr,
                "Failed reading datetime_map: %s\n",
                strerror(errno));
        goto cleanup;
    }

    printf("Datetime from BPF epoch_to_datetime "
           "(UTC+8): %04u-%02u-%02u "
           "%02u:%02u:%02u\n",
           dt.year, dt.month, dt.day,
           dt.hour, dt.minute, dt.second);

    printf("\nRESULTS samples=%d\n", samples);

    for (__u32 key = 0; key < NUM_STAGES; key++) {

        if (!total_count[key]) {
            printf("[%u] %-28s: no samples\n",
                   key, stage_name[key]);
            continue;
        }

        double avg =
            (double)total_sum[key] / total_count[key];

        printf("[%u] %-28s: "
               "avg=%8.1f ns  sum=%llu  n=%llu\n",
               key,
               stage_name[key],
               avg,
               (unsigned long long)total_sum[key],
               (unsigned long long)total_count[key]);
    }

    printf("\nCSV saved: %s (%d samples)\n",
           filename, samples);

    ret = 0;

cleanup:
    if (csv)
        fclose(csv);

    if (obj)
        bpf_object__close(obj);

    return ret;
}



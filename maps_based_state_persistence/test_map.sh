#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

SIZES=(8 16 32 64 128 256 512 1024)
SAMPLES=${SAMPLES:-2000}
RESULTS=()

printf '=== 開始進行 BPF Map 效能測試 (SAMPLES=%s) ===\n' "$SAMPLES"
make map_update SAMPLES="$SAMPLES"

for n in "${SIZES[@]}"; do
    printf '[*] 正在測試 payload size: %s bytes...\n' "$n"
    # Force rebuilding the BPF object for the new compile-time payload size.
    make -B xdp_map_update.bpf.o PAYLOAD_SIZE="$n" SAMPLES="$SAMPLES"
    OUTPUT=$(sudo ./map_update "$n")
    printf '%s\n' "$OUTPUT"

    # Match the full metric name, not the substring "update".
    LOOKUP=$(awk '$1 == "lookup" && $2 == ":" {print $3}' <<< "$OUTPUT")
    READ=$(awk '$1 == "map_read" && $2 == ":" {print $3}' <<< "$OUTPUT")
    UPDATE=$(awk '$1 == "update" && $2 == ":" {print $3}' <<< "$OUTPUT")
    SPINLOCK=$(awk '$1 == "spinlock_update" && $2 == ":" {print $3}' <<< "$OUTPUT")

    if [[ -z "$LOOKUP" || -z "$READ" || -z "$UPDATE" || -z "$SPINLOCK" ]]; then
        printf 'ERROR: Missing latency value for payload=%s\n' "$n" >&2
        exit 1
    fi
    RESULTS+=("${n}:${LOOKUP}:${READ}:${UPDATE}:${SPINLOCK}")
done

printf '\n%-20s | %-15s | %-15s | %-15s | %-15s\n' \
    'Payload Size (Bytes)' 'Lookup (ns)' 'Map Read (ns)' 'Update (ns)' 'Spinlock (ns)'
printf '%s\n' '----------------------------------------------------------------------------------------------------'
for res in "${RESULTS[@]}"; do
    IFS=: read -r size lookup read update spinlock <<< "$res"
    printf '%-20s | %-15s | %-15s | %-15s | %-15s\n' \
        "$size B" "$lookup" "$read" "$update" "$spinlock"
done

#!/bin/bash

set -e

# Keep the same payload sizes as test_map.sh.
SIZES=(8 16 32 64 128 256 512 1024)
RESULTS=()

# Keep the same repetition count as test_map.sh.
SAMPLES=2000

echo "=== 開始進行 BPF Global Variable 效能測試 ==="

make -f Makefile global_var SAMPLES="$SAMPLES"

for n in "${SIZES[@]}"; do
    echo "[*] 正在測試 payload size: ${n} bytes..."

    rm -f xdp_global_var.bpf.o

    make -f Makefile xdp_global_var.bpf.o \
        PAYLOAD_SIZE="$n" SAMPLES="$SAMPLES"

    OUTPUT=$(sudo ./global_var "$n")

    READ=$(echo "$OUTPUT" | awk '/^[[:space:]]*read[[:space:]]*:/ {print $3}')
    UPDATE=$(echo "$OUTPUT" | awk '/^[[:space:]]*update[[:space:]]*:/ {print $3}')

    RESULTS+=("${n}:${READ}:${UPDATE}")
done

echo -e "\n================================================================="
echo -e "              BPF Global Variable 效能測試結果"
echo -e "================================================================="
printf "%-20s | %-15s | %-15s\n" \
    "Payload Size (Bytes)" "Read (ns)" "Update (ns)"
echo -e "-----------------------------------------------------------------"

for res in "${RESULTS[@]}"; do
    IFS=":" read -r size read update <<< "$res"
    printf "%-20s | %-15s | %-15s\n" \
        "  $size B" "$read ns" "$update ns"
done

echo -e "=================================================================\n"

rm -f xdp_global_var.bpf.o global_var

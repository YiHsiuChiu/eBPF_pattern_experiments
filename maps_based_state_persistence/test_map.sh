#!/bin/bash

set -e

# payload 大小
SIZES=(8 16 32 64 128 256 512 1024)
RESULTS=()

SAMPLES=2000

echo "=== 開始進行 BPF Map Update 效能測試 ==="

make map_update SAMPLES="$SAMPLES"

for n in "${SIZES[@]}"; do
    echo "[*] 正在測試 payload size: ${n} bytes..."
    
    rm -f xdp_map_update.bpf.o
    
    make xdp_map_update.bpf.o PAYLOAD_SIZE="$n" SAMPLES="$SAMPLES"
    
    OUTPUT=$(sudo ./map_update "$n")
    
    LOOKUP=$(echo "$OUTPUT" | awk '/lookup/ {print $3}')
    UPDATE=$(echo "$OUTPUT" | awk '/update/ && !/spinlock/ {print $3}')
    SPINLOCK=$(echo "$OUTPUT" | awk '/spinlock_update/ {print $3}')
    
    RESULTS+=("${n}:${LOOKUP}:${UPDATE}:${SPINLOCK}")
done

echo -e "\n========================================================================="
echo -e "                       BPF Map 效能測試結果"
echo -e "========================================================================="
printf "%-20s | %-15s | %-15s | %-15s\n" "Payload Size (Bytes)" "Lookup (ns)" "Update (ns)" "Spinlock (ns)"
echo -e "-------------------------------------------------------------------------"

for res in "${RESULTS[@]}"; do
    IFS=":" read -r size lookup update spinlock <<< "$res"
    printf "%-20s | %-15s | %-15s | %-15s\n" "  $size B" "$lookup ns" "$update ns" "$spinlock ns"
done

echo -e "=========================================================================\n"

rm -f xdp_map_update.bpf.o map_update
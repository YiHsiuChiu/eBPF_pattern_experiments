#!/bin/bash

# 確保遇到錯誤就停止
set -e

# 定義要測試的 payload 大小
SIZES=(8 16 32 64 128 256 512 1024)
RESULTS=()

SAMPLES=20000

echo "=== 開始進行 BPF Map Update 效能測試 ==="

# 1. 先把 User-space 執行檔編譯起來
echo "[*] 正在編譯主程式..."
make map_update SAMPLES="$SAMPLES"

# 2. 迴圈測試每個大小
for n in "${SIZES[@]}"; do
    echo "[*] 正在測試 payload size: ${n} bytes..."
    
    # 強制刪除舊的物件檔，確保 make 偵測到檔案需要重新編譯
    rm -f xdp_map_update.bpf.o
    
    make xdp_map_update.bpf.o PAYLOAD_SIZE="$n" SAMPLES="$SAMPLES"
    
    # 執行測試
    OUTPUT=$(sudo ./map_update "$n")
    
    # 擷取 ns 延遲數據
    LATENCY=$(echo "$OUTPUT" | sed -E 's/.*= ([0-9.]+) ns.*/\1/')
    RESULTS+=("${n}:${LATENCY}")
done

# 3. 在 Terminal 直接列印結果表格
echo -e "\n========================================"
echo -e "       BPF Map Update 測試結果"
echo -e "========================================"
printf "%-20s | %-15s\n" "Payload Size (Bytes)" "Avg Latency (ns)"
echo -e "----------------------------------------"

for res in "${RESULTS[@]}"; do
    size="${res%%:*}"
    latency="${res#*:}"
    printf "%-20s | %-15s\n" "  $size" "$latency ns"
done

echo -e "========================================\n"

rm -f xdp_map_update.bpf.o map_update
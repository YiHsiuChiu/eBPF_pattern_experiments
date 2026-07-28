#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# K 當邊界，K = end
start="${1:-8000}"
end="${2:-150000}"
step="${3:-100}"
# 指定實驗 TEST 模式（0 = sum, 1 = loadbyte, 2 = hash, 3 = 跑TYPE邊界）
run_mode="${4:-1}"

# 要測試的型態
types=("__u16" "__u32" "__u64")

# 根據 run_mode 決定要編譯的目標檔案
case "$run_mode" in
    0) bpf_obj="xdp_sum_loop.bpf.o" ;;
    1) bpf_obj="xdp_loadbyte_loop.bpf.o" ;;
    2) bpf_obj="xdp_hash_loop.bpf.o" ;;
    3) bpf_obj="xdp_unbounded_loop.bpf.o" ;;
    *) echo "Error: Invalid run_mode $run_mode"; exit 1 ;;
esac

# =====================================================================
# 實驗一：run_mode 0, 1, 2 (測試 Bounded Loop，找常數 K 的極限)
# =====================================================================
if [ "$run_mode" = "0" ] || [ "$run_mode" = "1" ] || [ "$run_mode" = "2" ]; then
    echo "=================================================="
    echo " RUNNING EXPERIMENT: Bounded Loop by K ($bpf_obj)"
    echo "=================================================="

    for n in $(seq "$start" "$step" "$end"); do

        make clean >/dev/null 2>&1
        # 改為指定對應的 bpf_obj，並傳入 K
        if ! make "$bpf_obj" K="$n" >/tmp/xdp_make.log 2>&1; then
            echo "BUILD FAILED"
            cat /tmp/xdp_make.log
            exit 1
        fi

        echo "K=$n"

        if sudo bpftool prog load "$bpf_obj" /sys/fs/bpf/xdp_operation_loop_test 2>/tmp/xdp_increasing_load.err 1>/tmp/xdp_increasing_load.out; then
            echo "LOAD_OK"
            sudo rm -f /sys/fs/bpf/xdp_operation_loop_test
        else
            echo "LOAD_FAIL"
            echo "----------------------------------------"
            tail -n 10 /tmp/xdp_increasing_load.err
            echo "----------------------------------------"
            echo "==> Threshold found for $bpf_obj at K=$n"
            break 
        fi
    done
fi

# =====================================================================
# 實驗二：run_mode 3 (由型態當變數邊界)
# =====================================================================
if [ "$run_mode" = "3" ]; then
    echo ""
    echo "=================================================="
    echo " RUNNING EXPERIMENT: Data-Dependent Loop ($bpf_obj)"
    echo "=================================================="

    for type in "${types[@]}"; do
        echo -n "Testing $bpf_obj with VARIABLE_TYPE=$type ... "

        make clean >/dev/null 2>&1
        # 指定編譯 xdp_unbounded_loop.bpf.o 並傳入型態
        if ! make "$bpf_obj" VARIABLE_TYPE="$type" >/tmp/xdp_make.log 2>&1; then
            echo "BUILD FAILED"
            cat /tmp/xdp_make.log
            exit 1
        fi

        if sudo bpftool prog load "$bpf_obj" /sys/fs/bpf/xdp_operation_loop_test 2>/tmp/xdp_increasing_load.err 1>/tmp/xdp_increasing_load.out; then
            echo "LOAD_OK"
            sudo rm -f /sys/fs/bpf/xdp_operation_loop_test
        else
            echo "LOAD_FAIL"
            echo "--- Verifier Reason ---"
            tail -n 5 /tmp/xdp_increasing_load.err
            echo "[!] Variable type $type failed to load. Terminating experiment."
            exit 1
        fi
    done
fi

echo "Experiment completed."
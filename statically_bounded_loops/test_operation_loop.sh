#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# K 當邊界，K = end
start="${1:-80000}"
end="${2:-10000000}"
step="${3:-10000}"
# 指定實驗 TEST 模式（0 = 跑K邊界, 1 = 跑TYPE邊界）
run_mode="${4:-1}"

# 要測試的型態
types=("__u16" "__u32" "__u64")

# =====================================================================
# 實驗一：TEST = 0 (測試 Bounded Loop，找常數 K 的極限)
# =====================================================================
if [ "$run_mode" = "0" ]; then
    echo "=================================================="
    echo " RUNNING EXPERIMENT 1: TEST=0 (Bounded Loop by K)"
    echo "=================================================="

    for n in $(seq "$start" "$step" "$end"); do

        make clean >/dev/null 2>&1
        if ! make xdp_operation_loop.bpf.o K="$n" TEST=0 >/tmp/xdp_make.log 2>&1; then
            echo "BUILD FAILED"
            cat /tmp/xdp_make.log
            exit 1
        fi

        echo "K=$n"

        if sudo bpftool prog load xdp_operation_loop.bpf.o /sys/fs/bpf/xdp_operation_loop_test 2>/tmp/xdp_increasing_load.err 1>/tmp/xdp_increasing_load.out; then
            echo "LOAD_OK"
            sudo rm -f /sys/fs/bpf/xdp_operation_loop_test
        else
            echo "LOAD_FAIL"
            echo "----------------------------------------"
            tail -n 10 /tmp/xdp_increasing_load.err
            echo "----------------------------------------"
            echo "==> Threshold found for $type at K=$n"
            break 
        fi
    done
fi

# =====================================================================
# 實驗二：TEST = 1 (由型態當變數邊界)
# =====================================================================
if [ "$run_mode" = "1" ]; then
    echo ""
    echo "=================================================="
    echo " RUNNING EXPERIMENT 2: TEST=1 (Data-Dependent Loop)"
    echo "=================================================="

    for type in "${types[@]}"; do
        echo -n "Testing TEST=1 with VARIABLE_TYPE=$type ... "

        make clean >/dev/null 2>&1
        if ! make xdp_operation_loop.bpf.o TEST=1 VARIABLE_TYPE="$type" >/tmp/xdp_make.log 2>&1; then
            echo "BUILD FAILED"
            cat /tmp/xdp_make.log
            exit 1
        fi

        if sudo bpftool prog load xdp_operation_loop.bpf.o /sys/fs/bpf/xdp_operation_loop_test 2>/tmp/xdp_increasing_load.err 1>/tmp/xdp_increasing_load.out; then
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
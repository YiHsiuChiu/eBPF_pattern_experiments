#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

start="${1:-8000}"
end="${2:-10000}"
step="${3:-1}"

for n in $(seq "$start" "$step" "$end"); do
    echo "=== MAX_LOOP=$n ==="

    make clean >/dev/null 2>&1
    if ! make xdp_operation_loop.bpf.o MAX_LOOP="$n" >/tmp/xdp_make.log 2>&1; then
        echo "build failed"
        cat /tmp/xdp_make.log
        exit 1
    fi

    if sudo bpftool prog load xdp_operation_loop.bpf.o /sys/fs/bpf/xdp_operation_loop_test 2>/tmp/xdp_increasing_load.err 1>/tmp/xdp_increasing_load.out; then
        echo "LOAD_OK"
        sudo rm -f /sys/fs/bpf/xdp_operation_loop_test
    else
        echo "LOAD_FAIL"
        tail -n 20 /tmp/xdp_increasing_load.err
        echo "Threshold found at MAX_LOOP=$n"
        exit 0
    fi

done

echo "No failure found in the requested range."

echo "=== Running experiment ==="
if sudo bpftool prog load xdp_operation_loop.bpf.o /sys/fs/bpf/xdp_operation_loop_test 2>/tmp/xdp_increasing_load.err 1>/tmp/xdp_increasing_load.out; then
    echo "LOAD_OK"
    sudo rm -f /sys/fs/bpf/xdp_operation_loop_test
else
    echo "LOAD_FAIL"
    tail -n 20 /tmp/xdp_increasing_load.err
    exit 1
fi

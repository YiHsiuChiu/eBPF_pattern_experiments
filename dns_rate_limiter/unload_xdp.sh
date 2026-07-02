#!/bin/bash

# 偵測預設網路介面
DEFAULT_IFACE=$(ip route show default | awk '/default/ {print $5}')
IFACE=${1:-$DEFAULT_IFACE}

if [ -z "$IFACE" ]; then
    IFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo' | head -n 1)
fi

IFACE=${IFACE:-eth0}

echo "========================================="
echo "   eBPF/XDP DNS Limiter 卸載腳本"
echo "========================================="
echo "[*] 正在從網路介面 ${IFACE} 卸載 XDP 程式..."
echo "[*] 執行指令: sudo ip link set dev ${IFACE} xdp off"

sudo ip link set dev "${IFACE}" xdp off

if [ $? -eq 0 ]; then
    echo "[+] 成功從 ${IFACE} 卸載 XDP 程式！"
    
    # 清理 /sys/fs/bpf/xdp 下的 pinned map 或 BPF 物件
    if [ -e "/sys/fs/bpf/xdp" ]; then
        echo "[*] 正在清除 BPF 檔案系統中的掛載目錄 /sys/fs/bpf/xdp ..."
        sudo rm -rf /sys/fs/bpf/xdp
        if [ $? -eq 0 ]; then
            echo "[+] 成功清除 /sys/fs/bpf/xdp！"
        else
            echo "[-] 無法清除 /sys/fs/bpf/xdp，請手動確認權限。"
        fi
    fi
else
    echo "[-] 卸載失敗！請確認 ${IFACE} 上是否已掛載 XDP 程式，或您是否有 sudo 權限。"
    exit 1
fi
echo "========================================="

#!/bin/bash

# 偵測預設網路介面
DEFAULT_IFACE=$(ip route show default | awk '/default/ {print $5}')
IFACE=${1:-$DEFAULT_IFACE}

if [ -z "$IFACE" ]; then
   # 如果找不到預設路由，列出所有可用介面（排除 lo）
   IFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo' | head -n 1)
fi

# 仍為空時的最後備用值
IFACE=${IFACE:-eth0}

echo "========================================="
echo "   eBPF/XDP DNS Limiter 載入腳本"
echo "========================================="

# 1. 檢查並編譯 BPF 核心程式碼
if [ ! -f "xdp_dns_limiter.bpf.o" ]; then
   echo "[*] 未偵測到編譯好的 BPF 物件檔，正在執行 make 編譯..."
   make
   if [ $? -ne 0 ]; then
       echo "[-] 編譯失敗，請檢查是否安裝了 clang, llvm, libbpf-dev 等依賴！"
       exit 1
   fi
   echo "[+] 編譯成功！"
fi

# 2. 載入 XDP 程式
echo "[*] 正在將 XDP 程式掛載至網路介面: ${IFACE} ..."
echo "[*] 執行指令: sudo ip link set dev ${IFACE} xdp obj xdp_dns_limiter.bpf.o sec xdp"

sudo ip link set dev "${IFACE}" xdp obj xdp_dns_limiter.bpf.o sec xdp

if [ $? -eq 0 ]; then
   echo "[+] 成功載入 XDP 速率限制器到 ${IFACE}！"

   # =================================================================
   # 3. 手動將 boot_time_map 固定 (Pin) 到 /sys/fs/bpf/xdp/
   # =================================================================
   echo "[*] 正在偵測核心中的 boot_time_map 並進行固定..."
   
   MAP_ID=$(sudo bpftool map show | grep "name boot_time_map" | awk '{print $1}' | tr -d ':')
   
   if [ -n "$MAP_ID" ]; then
       sudo mkdir -p /sys/fs/bpf/xdp
       [ -e "/sys/fs/bpf/xdp/boot_time_map" ] && sudo rm "/sys/fs/bpf/xdp/boot_time_map"
       
       sudo bpftool map pin id "$MAP_ID" /sys/fs/bpf/xdp/boot_time_map
       echo "[+] Map 已成功固定至: /sys/fs/bpf/xdp/boot_time_map"
       
       # -------------------------------------------------------------
       # 新增：Map 固定成功後，執行 User-space 的時間更新程式
       # -------------------------------------------------------------
       if [ -x "./update_boot_time" ]; then
           echo "[*] 正在初始化 Map 資料：執行 sudo ./update_boot_time ..."
           sudo ./update_boot_time
           if [ $? -eq 0 ]; then
               echo "[+] 基礎時間資料已順利寫入 Map！"
           else
               echo "[-] 警告: ./update_boot_time 執行回傳錯誤，請檢查該程式邏輯！"
           fi
       else
           echo "[-] 提示: 找不到可執行的 ./update_boot_time。"
           echo "    請確認該檔案存在，並已執行過 'chmod +x update_boot_time'"
       fi
       # -------------------------------------------------------------
       
   else
       echo "[-] 警告: 在核心中找不到 boot_time_map，跳過時間初始化動作。"
   fi
   # =================================================================

   echo "[*] 您可以使用以下指令查看狀態："
   echo "    ip link show dev ${IFACE}"
else
   echo "[-] 載入失敗！請確認 ${IFACE} 介面是否存在，或您是否有 sudo 權限。"
   exit 1
fi
echo "========================================="


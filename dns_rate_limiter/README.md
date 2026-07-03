# eBPF/XDP DNS 查詢速率限制器 - 使用說明

本專案是一個基於 eBPF/XDP 的 DNS 查詢速率限制器，限制針對特定網域（Domain）與來源 IP 的查詢頻率為 **每秒最多一次**（每日 UTC 時間 00:00 - 05:59 除外，此期間無限制）。本限制器監聽目標埠口（Port）**5333**。

---

## 1. 環境準備

在部署與執行前，請確保系統已安裝編譯與執行所需的依賴套件（以 Ubuntu/Debian 為例）：

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) nodejs npm
```

在專案目錄下安裝 Node.js 測試套件的相依套件：
```bash
npm install
```

---

## 2. 編譯專案

使用 `make` 編譯 BPF 核心程式以及使用者空間的時間初始化工具：

```bash
make
```

編譯完成後，會產生以下兩個檔案：
- `xdp_dns_limiter.bpf.o`：eBPF/XDP 核心程式位元組碼。
- `update_boot_time`：用於將系統開機時間寫入 BPF Map 的使用者空間 C 程式。

---

## 3. 部署與載入 XDP 程式

可以使用專案提供的自動化腳本進行載入。該腳本會自動偵測預設網路介面並載入 XDP 程式，接著自動執行 `update_boot_time` 初始化 BPF Map 中的開機時間。

### 自動載入
```bash
# 自動偵測介面並載入 (需 root 權限)
sudo ./load_xdp.sh

# 或是手動指定網路介面 (例如本機測試用的環回介面 lo)
sudo ./load_xdp.sh lo
```

### 手動載入 (若不使用腳本)
若您想逐步手動執行：
```bash
# 1. 掛載 XDP 程式到網路介面 (以 lo 為例)
sudo ip link set dev lo xdp obj xdp_dns_limiter.bpf.o sec xdp

# 2. 將 Map 固定 (Pin) 到 BPF 虛擬檔案系統
sudo mkdir -p /sys/fs/bpf/xdp
sudo bpftool map pin name boot_time_map /sys/fs/bpf/xdp/boot_time_map

# 3. 執行時間初始化工具寫入系統時間
sudo ./update_boot_time
```

---

## 4. 測試速率限制

### 方案一：使用 eBPF/XDP 核心限速

#### 步驟 1：啟動原始測試 DNS 伺服器
在獨立的終端機視窗中啟動監聽在 Port `5333` 的測試 DNS 伺服器（此時不包含限速邏輯，限速由已部署的 XDP 程式在核心中執行）：
```bash
node orig_dns_server.js
```

#### 步驟 2：執行測試
您可以選擇使用 Node.js 測試用戶端或傳統的 `dig` 指令進行測試。

##### 使用 Node.js 測試用戶端
專案中提供了 `dns_test_client.js`，它會自動發送查詢並驗證速率限制：
```bash
# 執行測試 (預設會向 127.0.0.1 查詢 www.google.com)
node dns_test_client.js [目標IP] [Domain]

# 範例：
node dns_test_client.js 127.0.0.1 www.google.com
```
*測試流程說明：*
1. **Query #1**：立即發送（預期**成功**收到回應）。
2. **Query #2**：間隔 100 毫秒後發送相同的查詢（若在限制時間內，預期被 XDP **丟棄**並超時）。
3. **Query #3**：間隔 1.5 秒後再次發送（預期**成功**收到回應）。

##### 使用 `dig` 指令手動測試
請注意，必須指定埠口 `-p 5333`：
```bash
# 第一次查詢：預期成功返回
dig @127.0.0.1 -p 5333 www.google.com

# 立即發送第二次查詢（間隔小於 1 秒）：預期會逾時 (Timeout)，因為封包被 XDP_DROP 丟棄
dig @127.0.0.1 -p 5333 www.google.com

# 等待 1 秒以上後再次查詢：預期成功返回
sleep 1.5
dig @127.0.0.1 -p 5333 www.google.com
```

---

### 方案二：使用 Node.js 模擬限速 DNS 伺服器 (免裝/免載入 eBPF/XDP)

如果您不想部署 eBPF/XDP 核心程式，或在不支援 XDP 的環境下，可以直接啟動內建限速邏輯的模擬 DNS 伺服器 `limited_dns_server.js`（它在 Node.js 中以與 BPF 程式完全相同的邏輯與演算法執行限速）：

#### 步驟 1：啟動模擬限速 DNS 伺服器
```bash
node limited_dns_server.js
```

#### 步驟 2：執行測試
同樣可以使用 `dns_test_client.js` 或 `dig` 來驗證限速功能：
```bash
# 使用 Node.js 測試客戶端
node dns_test_client.js 127.0.0.1 www.google.com

# 或者使用 dig 指令
dig @127.0.0.1 -p 5333 www.google.com
```

> [!NOTE]
> **時間段免限制規則**
> 根據 eBPF 程式與 Node.js 模擬邏輯，若當前 UTC 時間在 `00:00` 至 `05:59` 之間（即 `current_hour < 6`），系統將不會進行任何限速與丟包，所有查詢皆會直接放行。

---

## 5. 觀察與管理

### 查看 BPF Map 內容
可以使用 `bpftool` 來觀察核心中的對應紀錄（Client IP 與網域雜湊值）：
```bash
# 列出系統中所有的 BPF Map
sudo bpftool map show

# 查看限速 Map (dns_limit_map) 內容
sudo bpftool map dump name dns_limit_map
```

### 查看偵錯日誌 (Debug Trace)
eBPF 程式中的 `bpf_printk` 輸出可以透過核心追蹤管道查看：
```bash
sudo cat /sys/kernel/tracing/trace_pipe
```

---

## 6. 卸載與清理

測試完成後，可以使用專案提供的自動化腳本卸載 XDP 程式並清理暫存檔案。

### 自動卸載
```bash
# 自動偵測介面並卸載 (需 root 權限)
sudo ./unload_xdp.sh

# 或是手動指定介面
sudo ./unload_xdp.sh lo
```

### 手動卸載 (若不使用腳本)
```bash
# 1. 卸載特定介面上的 XDP (以 lo 為例)
sudo ip link set dev lo xdp off

# 2. 清理 Pinned Map 檔案
sudo rm -rf /sys/fs/bpf/xdp
```

### 清理編譯檔案
```bash
make clean
```

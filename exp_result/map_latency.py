import matplotlib.pyplot as plt

# 1. 準備數據
payload = [8, 16, 32, 64, 128, 256, 512, 1024]
lookup = [26.15, 26.14, 26.24, 27.44, 27.56, 28.98, 30.99, 30.66]
update = [27.92, 27.12, 29.76, 42.19, 55.75, 87.74, 151.21, 279.43]
spinlock_update = [39.19, 39.54, 41.72, 49.74, 66.44, 98.83, 163.53, 297.34]

# 2. 建立圖表畫布
plt.figure(figsize=(6, 3))

# 3. 繪製三條折線（加上不同標記以利區分）
plt.plot(payload, lookup, marker='o', linewidth=2, label='Lookup')
plt.plot(payload, update, marker='s', linewidth=2, label='Update')
plt.plot(payload, spinlock_update, marker='^', linewidth=2, label='Spinlock-protected update')

# 4. 設定 X 軸為以 2 為底的對數刻度，並顯式顯示每個 Payload 數字
plt.xscale('log', base=2)
plt.xticks(payload, labels=[str(p) for p in payload])

# 5. 設定圖表標題與軸標籤
# plt.title('Average Latency vs. Payload Size', fontsize=14, fontweight='bold', pad=15)
plt.xlabel('Map Value Size (Bytes)', fontsize=12)
plt.ylabel('Latency (ns)', fontsize=12)

plt.ylim(bottom=0)

# 6. 加入圖例與網格線
plt.legend(fontsize=14, loc='upper left')
plt.grid(True, which="both", linestyle="--", alpha=0.6)

# 7. 自動調整佈局並顯示
plt.tight_layout()
plt.savefig('result/map.png', dpi=300)
plt.show()

import os
import numpy as np
import matplotlib.pyplot as plt

# 1. 準備數據
payload = np.array([8, 16, 32, 64, 128, 256, 512, 1024])

# Lookup
lookup = np.array([
    25.673, 26.299, 24.025, 25.116,
    27.381, 25.701, 29.504, 30.121
])
lookup_q1 = np.array([
    25.560, 26.050, 22.658, 25.263,
    27.093, 23.254, 29.234, 29.901
])
lookup_q3 = np.array([
    25.994, 26.494, 25.532, 25.740,
    27.555, 27.060, 29.627, 31.141
])

# Read
read = np.array([
    25.964, 26.695, 28.231, 35.892,
    46.509, 66.200, 107.855, 187.066
])
read_q1 = np.array([
    25.887, 26.455, 27.295, 36.161,
    46.254, 65.599, 107.357, 182.480
])
read_q3 = np.array([
    26.235, 26.838, 28.690, 36.547,
    46.653, 66.328, 108.330, 198.335
])

# Update
update = np.array([
    26.120, 27.496, 28.239, 39.276,
    53.581, 77.648, 150.800, 277.096
])
update_q1 = np.array([
    25.937, 27.253, 27.182, 39.700,
    53.303, 75.848, 150.381, 272.653
])
update_q3 = np.array([
    26.325, 27.646, 29.309, 40.166,
    53.779, 81.267, 151.316, 281.239
])

# Spinlock-protected Update
spinlock_update = np.array([
    36.755, 38.218, 41.599, 46.433,
    63.077, 86.820, 163.246, 292.379
])
spinlock_q1 = np.array([
    36.817, 37.899, 40.155, 46.302,
    62.623, 84.694, 162.760, 287.334
])
spinlock_q3 = np.array([
    37.282, 38.398, 42.501, 46.855,
    63.384, 90.226, 163.772, 297.320
])

# 2. 建立圖表
fig, ax = plt.subplots(figsize=(6, 3))

# 3. 繪製平均值折線 + Q1/Q3 範圍
datasets = [
    ("Lookup", lookup, lookup_q1, lookup_q3, "o"),
    ("Read", read, read_q1, read_q3, "d"),
    ("Update", update, update_q1, update_q3, "s"),
    ("Spinlock-protected update",
     spinlock_update, spinlock_q1, spinlock_q3, "^")
]

for label, mean, q1, q3, marker in datasets:
    # 先畫平均值折線
    line, = ax.plot(
        payload,
        mean,
        marker=marker,
        linewidth=2,
        markersize=5,
        label=label
    )

    color = line.get_color()

    # # Q1 至 Q3 的半透明區域
    # ax.fill_between(
    #     payload,
    #     q1,
    #     q3,
    #     color=color,
    #     alpha=0.15
    # )

    # 顯示 Q1/Q3 上下界
    ax.vlines(
        payload,
        q1,
        q3,
        color=color,
        linewidth=1.2,
        alpha=0.8
    )

    ax.scatter(
        payload, q1,
        marker="_",
        color=color,
        s=50,
        zorder=3
    )

    ax.scatter(
        payload, q3,
        marker="_",
        color=color,
        s=50,
        zorder=3
    )

# 4. X 軸設定
ax.set_xscale("log", base=2)
ax.set_xticks(payload)
ax.set_xticklabels([str(p) for p in payload])

# 5. 標籤
ax.set_xlabel("Map Value Size (Bytes)", fontsize=12)
ax.set_ylabel("Latency (ns)", fontsize=12)

ax.set_ylim(bottom=0)

# 6. 圖例與網格
ax.legend(fontsize=14, loc="upper left")
ax.grid(True, which="both", linestyle="--", alpha=0.6)

# 7. 儲存與顯示
plt.tight_layout()

os.makedirs("result", exist_ok=True)
plt.savefig("result/map_q1_q3.png", dpi=300, bbox_inches="tight")

plt.show()

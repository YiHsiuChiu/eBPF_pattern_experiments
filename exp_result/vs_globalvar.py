
import os
import numpy as np
import matplotlib.pyplot as plt

# 1. 準備數據
payload = np.array([8, 16, 32, 64, 128, 256, 512, 1024])

data = {
    "read": [
        (
            "Hash Map",
            [25.964, 26.695, 28.231, 35.892, 46.509, 66.200, 107.855, 187.066],
            [25.887, 26.455, 27.295, 36.161, 46.254, 65.599, 107.357, 182.480],
            [26.235, 26.838, 28.690, 36.547, 46.653, 66.328, 108.330, 198.335],
            "o"
        ),
        (
            "Global Variable",
            [2.183, 2.707, 4.874, 9.195, 17.783, 44.301, 74.587, 141.346],
            [2.174, 2.697, 4.840, 8.989, 17.668, 43.972, 73.790, 140.735],
            [2.179, 2.704, 4.870, 9.392, 17.674, 44.451, 74.619, 141.958],
            "s"
        ),
        (
            "Array Map",
            [2.524, 3.724, 6.959, 9.232, 20.178, 40.749, 75.621, 145.960],
            [2.513, 3.712, 6.923, 9.123, 17.807, 40.278, 70.579, 145.328],
            [2.520, 3.728, 6.964, 9.128, 21.645, 41.054, 78.580, 146.343],
            "^"
        )
    ],

    "update": [
        (
            "Hash Map",
            [26.120, 27.496, 28.239, 39.276, 53.581, 77.648, 150.800, 277.096],
            [25.937, 27.253, 27.182, 39.700, 53.303, 72.848, 150.381, 272.653],
            [26.325, 27.646, 29.309, 40.166, 53.779, 82.267, 151.316, 281.239],
            "o"
        ),
        (
            "Global Variable",
            [2.207, 4.475, 7.527, 12.944, 22.718, 45.241, 118.365, 228.376],
            [2.175, 4.452, 7.523, 11.414, 22.546, 44.810, 117.026, 234.486],
            [2.180, 4.469, 7.537, 14.654, 22.555, 45.370, 117.917, 235.476],
            "s"
        ),
        (
            "Array Map",
            [2.805, 5.923, 9.840, 12.380, 26.745, 54.349, 105.675, 229.470],
            [2.513, 5.873, 9.807, 12.218, 22.261, 57.721, 100.027, 228.973],
            [3.367, 5.949, 9.823, 12.229, 29.604, 57.782, 113.550, 229.462],
            "^"
        )
    ]
}



# 2. 建立圖表
fig, axes = plt.subplots(
    1, 2,
    figsize=(8, 2.8),
    sharex=True,
    sharey=True
)

colors = {
    "Hash Map": "tab:blue",
    "Global Variable": "tab:orange",
    "Array Map": "tab:green"
}

markers = {
    "Hash Map": "o",
    "Global Variable": "s",
    "Array Map": "^"
}

# 3. 左圖 Read，右圖 Update
for ax, operation, panel in zip(
    axes,
    ["read", "update"],
    ["(a) Read", "(b) Update"]
):

    for label, mean, q1, q3, _ in data[operation]:

        mean = np.array(mean)
        q1 = np.array(q1)
        q3 = np.array(q3)

        color = colors[label]

        # 平均值折線
        ax.plot(
            payload,
            mean,
            marker=markers[label],
            linewidth=2,
            markersize=4,
            color=color,
            label=label
        )

        # Q1/Q3 誤差棒
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
            s=40,
            zorder=3
        )

        ax.scatter(
            payload, q3,
            marker="_",
            color=color,
            s=40,
            zorder=3
        )

    # X 軸
    ax.set_xscale("log", base=2)
    ax.set_xticks(payload)
    ax.set_xticklabels([str(p) for p in payload])

    # Y 軸（兩張子圖共用）
    ax.set_ylim(0, 320)
    ax.set_yticks([0, 50, 100, 150, 200, 250, 300])

    # 子圖標記放上方
    ax.set_title(panel, fontsize=11, pad=6)

    # 網格
    ax.grid(
        True,
        which="both",
        linestyle="--",
        alpha=0.6
    )

    ax.tick_params(axis="both", labelsize=9)

# 4. 共用軸標籤
fig.supylabel("Latency (ns)", fontsize=11, x=0.02)
fig.supxlabel("Map Value Size (Bytes)", fontsize=11, y=0.02)

# 5. 共用圖例
handles, labels = axes[0].get_legend_handles_labels()

fig.legend(
    handles,
    labels,
    loc="upper center",
    bbox_to_anchor=(0.5, 0.98),
    ncol=3,
    fontsize=9,
    frameon=False
)

# 6. 調整排版
fig.subplots_adjust(
    left=0.10,
    right=0.99,
    bottom=0.23,
    top=0.78,
    wspace=0.08
)

# 7. 儲存圖片
os.makedirs("result", exist_ok=True)

plt.savefig(
    "result/vs_globalvar.png",
    dpi=300,
    bbox_inches="tight"
)

plt.show()

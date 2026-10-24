# 實驗設定
1. datetime計算使用civil_from_days演算法

# 操作方法
`test_time.sh` 是使用 `CLOCK_MONOTONIC` time anchor 的實驗腳本。

`tai/test_time.sh` 是使用 `bpf_ktime_get_tai_ns()` 的實驗腳本；TAI offset 由 `tai_offset_map` 提供，目前值為 37 秒。

## 參數設定
1. SAMPLES: 每組做幾次，可作為腳本的第一個參數傳入

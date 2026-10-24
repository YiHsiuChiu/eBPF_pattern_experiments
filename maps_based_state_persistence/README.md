# 實驗設定
1. map的entry設為4096
2. 每個 sample 對 4096 個 entry 執行操作

# 操作方法
`test_map.sh` 是 map 實驗腳本，量測 lookup、map read、update 與 spinlock update。

`global_var/test_global.sh` 是 global variable 實驗腳本，量測 read 與 update。

## 參數設定
1. SIZES: 寫入payload
2. SAMPLES: 每組做幾次

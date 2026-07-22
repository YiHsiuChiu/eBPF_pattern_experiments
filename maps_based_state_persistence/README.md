# 實驗設定
1. map的entry設為4096
2. 跑一次SAMPLES包含4096次的操作（lookup, update, spinlock update）

# 操作方法
test_map.sh是實驗腳本

## 參數設定
1. SIZES: 寫入payload
2. SAMPLES: 每組做幾次
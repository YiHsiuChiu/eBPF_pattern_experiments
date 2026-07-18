# 實驗設定
1. K為bounded loop上限

# 操作方法
test_operation_loop.sh是實驗腳本

## 選擇實驗
透過run_mode指定實驗，0 = sum、1 = loadbyte、2 = hash、3 = TYPE Boundary

### K Boundary
設定start、end、step，end為K值

### Type Boundary
預設跑u16、u32、u64，可在腳本的types更改
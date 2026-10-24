# 實驗設定
1. K為bounded loop上限

# 操作方法
`test_operation_loop.sh` 是實驗腳本：

```bash
sudo ./test_operation_loop.sh [start] [end] [step] [run_mode]
```

## 選擇實驗
透過 `run_mode` 指定實驗：

- `0` = bounded sum
- `1` = bounded loadbyte
- `2` = bounded hash
- `3` = bounded parse
- `4` = data-dependent loop
- `5` = data-dependent hash
- `6` = data-dependent loadbyte
- `7` = data-dependent parse
- `8` = `bpf_for` sum
- `9` = `bpf_for` loadbyte
- `10` = `bpf_for` hash
- `11` = `bpf_for` parse

### K Boundary
適用於 `run_mode` 0–3。設定 `start`、`end`、`step`，其中迴圈上限 `K` 會依序測試至 `end`。

### Type Boundary
適用於 `run_mode` 4–11。預設測試 `__u16`、`__u32`、`__u64`，可在腳本中的 `types` 修改。

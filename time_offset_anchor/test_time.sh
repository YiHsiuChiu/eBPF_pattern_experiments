#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$SCRIPT_DIR" || exit 1

USER_PROG="./update_boot_time"
SAMPLES="${1:-10000}"

if [ "$EUID" -ne 0 ]; then
  echo "[-] 請使用 sudo 執行此腳本！"
  exit 1
fi

if ! [[ "$SAMPLES" =~ ^[1-9][0-9]*$ ]]; then
    echo "Usage: $0 [positive-sample-count]" >&2
    exit 1
fi

make

"$USER_PROG" -n "$SAMPLES"

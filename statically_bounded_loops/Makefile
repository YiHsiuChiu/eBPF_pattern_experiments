CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -target bpf

# 預設常數 K
K ?= 2000
# 預設變數型態
VARIABLE_TYPE ?= __u16

ARCH := $(shell uname -m | sed 's/x86_64/x86_64-linux-gnu/' | sed 's/aarch64/aarch64-linux-gnu/')
INCLUDES ?= -I/usr/include -I/usr/include/bpf -I/usr/include/$(ARCH)

# 將變數透過 -D 傳遞給 C 原始碼
# 這裡使用 '\"' 幫 VARIABLE_TYPE 加引號，避免 C 語言巨集展開時解析出錯
CFLAGS += -DK=$(K) -DVARIABLE_TYPE='$(VARIABLE_TYPE)'

SRCS := $(wildcard *.bpf.c)
OBJS := $(SRCS:.bpf.c=.bpf.o)

all: $(OBJS)

%.bpf.o: %.bpf.c
	$(CLANG) $(CFLAGS) $(INCLUDES) \
	-c $< -o $@

clean:
	rm -f *.bpf.o

.PHONY: all clean
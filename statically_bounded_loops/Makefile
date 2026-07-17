CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -target bpf

K ?= 2000
# 增加預設值
TEST ?= 0
VARIABLE_TYPE ?= __u32

ARCH := $(shell uname -m | sed 's/x86_64/x86_64-linux-gnu/' | sed 's/aarch64/aarch64-linux-gnu/')
INCLUDES ?= -I/usr/include -I/usr/include/bpf -I/usr/include/$(ARCH)

# 將變數透過 -D 傳遞給 C 原始碼
CFLAGS += -DK=$(K) -DTEST=$(TEST) -DVARIABLE_TYPE=$(VARIABLE_TYPE)

SRCS := $(wildcard *.bpf.c)
OBJS := $(SRCS:.bpf.c=.bpf.o)

all: $(OBJS)

%.bpf.o: %.bpf.c
	$(CLANG) $(CFLAGS) $(INCLUDES) \
	-c $< -o $@

clean:
	rm -f $(OBJS)

.PHONY: all clean
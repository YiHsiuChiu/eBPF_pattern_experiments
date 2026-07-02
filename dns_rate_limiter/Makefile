CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -target bpf

# 動態偵測架構以支援 asm/types.h 的路徑
ARCH := $(shell uname -m | sed 's/x86_64/x86_64-linux-gnu/' | sed 's/aarch64/aarch64-linux-gnu/')
INCLUDES ?= -I/usr/include -I/usr/include/bpf -I/usr/include/$(ARCH)

all: xdp_dns_limiter.bpf.o update_boot_time

xdp_dns_limiter.bpf.o: xdp_dns_limiter.bpf.c
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

update_boot_time: update_boot_time.c
	$(CC) -O2 -Wall $< -o $@ -lbpf

clean:
	rm -f xdp_dns_limiter.bpf.o update_boot_time

.PHONY: all clean

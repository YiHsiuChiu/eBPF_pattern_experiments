CLANG    ?= clang
CC       ?= gcc
CFLAGS   := -O2 -g -Wall

ARCH := $(shell uname -m | sed 's/x86_64/x86_64-linux-gnu/' | sed 's/aarch64/aarch64-linux-gnu/')

PAYLOAD_SIZE ?= 8
SAMPLES ?= 1000

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 \
              -DPAYLOAD_SIZE=$(PAYLOAD_SIZE) \
			  -DSAMPLES=$(SAMPLES) \
              -I/usr/include/bpf \
              -I/usr/include/$(ARCH) \
              -I/usr/include

all: xdp_map_update.bpf.o map_update

xdp_map_update.bpf.o: xdp_map_update.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

map_update: map_update.c
	$(CC) $(CFLAGS) -DSAMPLES=$(SAMPLES) -I. -o $@ $< -lbpf

clean:
	rm -f xdp_map_update.bpf.o map_update

.PHONY: all clean
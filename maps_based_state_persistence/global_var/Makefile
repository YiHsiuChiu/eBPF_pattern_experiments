CLANG    ?= clang
CC       ?= gcc
CFLAGS   := -O2 -g -Wall

ARCH := $(shell uname -m | sed 's/x86_64/x86_64-linux-gnu/' | sed 's/aarch64/aarch64-linux-gnu/')

PAYLOAD_SIZE ?= 8
SAMPLES ?= 2000

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 \
              -DPAYLOAD_SIZE=$(PAYLOAD_SIZE) \
              -DSAMPLES=$(SAMPLES) \
              -I/usr/include/bpf \
              -I/usr/include/$(ARCH) \
              -I/usr/include

all: xdp_global_var.bpf.o global_var

xdp_global_var.bpf.o: xdp_global_var.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

global_var: FORCE global_var.c
	$(CC) $(CFLAGS) -DSAMPLES=$(SAMPLES) -I. -o $@ global_var.c -lbpf

clean:
	rm -f xdp_global_var.bpf.o global_var

.PHONY: all clean FORCE

FORCE:


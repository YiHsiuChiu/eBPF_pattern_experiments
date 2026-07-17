CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -target bpf

K ?= 2000
ARCH := $(shell uname -m | sed 's/x86_64/x86_64-linux-gnu/' | sed 's/aarch64/aarch64-linux-gnu/')
INCLUDES ?= -I/usr/include -I/usr/include/bpf -I/usr/include/$(ARCH)

CFLAGS += -DK=$(K)
SRCS := $(wildcard *.bpf.c)
OBJS := $(SRCS:.bpf.c=.bpf.o)

all: $(OBJS)

%.bpf.o: %.bpf.c
	$(CLANG) $(CFLAGS) $(INCLUDES) \
	-c $< -o $@

clean:
	rm -f $(OBJS)

.PHONY: all clean
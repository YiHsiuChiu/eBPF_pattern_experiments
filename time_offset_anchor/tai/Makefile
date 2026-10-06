CLANG ?= clang
CC ?= gcc

ARCH := $(shell uname -m | sed 's/x86_64/x86_64-linux-gnu/' | sed 's/aarch64/aarch64-linux-gnu/')
INCLUDES ?= -I/usr/include -I/usr/include/bpf -I/usr/include/$(ARCH)

BPF_CFLAGS ?= -O2 -g -Wall -target bpf
BPF_CFLAGS += -DK=$(K) -DVARIABLE_TYPE='$(VARIABLE_TYPE)'

BPF_SRCS := $(wildcard *.bpf.c)
BPF_OBJS := $(BPF_SRCS:.bpf.c=.bpf.o)

USER_CFLAGS ?= -O2 -g -Wall
USER_LDLIBS ?= -lbpf -lelf -lz

USER_SRCS := $(filter-out %.bpf.c,$(wildcard *.c))
USER_BINS := $(USER_SRCS:.c=)

all: $(BPF_OBJS) $(USER_BINS)

$(BPF_OBJS): %.bpf.o: %.bpf.c
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) \
	-c $< -o $@

$(USER_BINS): %: %.c
	$(CC) $(USER_CFLAGS) $(INCLUDES) \
	$< -o $@ $(USER_LDLIBS)

clean:
	rm -f $(BPF_OBJS) $(USER_BINS)

.PHONY: all clean
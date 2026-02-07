# Makefile for katran-decap-core
# Builds BPF objects with BTF CO-RE support and userspace loader/stats tool.
#
# Dependencies: clang, llvm, libbpf-dev, libxdp-dev, bpftool
# No kernel headers needed - vmlinux.h is generated from BTF.

CLANG    ?= clang
LLC      ?= llc
BPFTOOL  ?= bpftool
CC       ?= gcc

# Directories
BUILDDIR  := build
BPF_OUT   := $(BUILDDIR)/bpf
USER_OUT  := $(BUILDDIR)/userspace
INCDIR    := include

# BPF compilation flags
BPF_CFLAGS := -g -O2 -target bpf \
              -Wall -Wno-unused-value -Wno-pointer-sign \
              -Wno-compare-distinct-pointer-types \
              -I$(INCDIR)

# Userspace compilation flags
USER_CFLAGS  := -Wall -O2
USER_LDFLAGS := -lbpf -lelf -lz

# BPF objects
BPF_OBJS := $(BPF_OUT)/decap.bpf.o \
            $(BPF_OUT)/tc_decap.bpf.o \
            $(BPF_OUT)/tc_decap_info.bpf.o \
            $(BPF_OUT)/tc_decap_stats.bpf.o

# Userspace binaries
USER_BINS := $(USER_OUT)/decap_user

# Header dependencies (shared)
COMMON_HDRS := $(INCDIR)/vmlinux.h \
               $(INCDIR)/decap_consts.h \
               $(INCDIR)/decap_structs.h \
               $(INCDIR)/pckt_parsing.h

XDP_HDRS := $(COMMON_HDRS) \
            $(INCDIR)/pckt_encap.h \
            bpf/decap_maps.h

TC_COMMON_HDRS := $(COMMON_HDRS) \
                  tc_bpf/pckt_helpers.h \
                  tc_bpf/tc_decap_kern_helpers.h

# ---- Targets ----

.PHONY: all bpf userspace vmlinux clean

all: bpf userspace

bpf: $(BPF_OBJS)

userspace: $(USER_BINS)

vmlinux: $(INCDIR)/vmlinux.h

clean:
	rm -rf $(BUILDDIR)
	rm -f $(INCDIR)/vmlinux.h

# ---- vmlinux.h generation ----

$(INCDIR)/vmlinux.h:
	@echo "  VMLINUX  $@"
	@mkdir -p $(INCDIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# ---- BPF object compilation ----

$(BPF_OUT):
	@mkdir -p $(BPF_OUT)

# XDP decap (with INLINE_DECAP_GUE)
$(BPF_OUT)/decap.bpf.o: bpf/decap.bpf.c $(XDP_HDRS) | $(BPF_OUT)
	@echo "  BPF      $@"
	$(CLANG) $(BPF_CFLAGS) -DINLINE_DECAP_GUE -c $< -o $@

# TC decap (with INLINE_DECAP_GUE)
$(BPF_OUT)/tc_decap.bpf.o: tc_bpf/tc_decap.bpf.c $(TC_COMMON_HDRS) tc_bpf/tc_decap_maps.h | $(BPF_OUT)
	@echo "  BPF      $@"
	$(CLANG) $(BPF_CFLAGS) -DINLINE_DECAP_GUE -c $< -o $@

# TC decap info
$(BPF_OUT)/tc_decap_info.bpf.o: tc_bpf/tc_decap_info.bpf.c $(TC_COMMON_HDRS) tc_bpf/tc_decap_info_maps.h | $(BPF_OUT)
	@echo "  BPF      $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# TC decap stats (with DECAP_TPR_STATS and DECAP_VIP_STATS)
$(BPF_OUT)/tc_decap_stats.bpf.o: tc_bpf/tc_decap_stats.bpf.c $(TC_COMMON_HDRS) tc_bpf/tc_decap_stats_maps.h | $(BPF_OUT)
	@echo "  BPF      $@"
	$(CLANG) $(BPF_CFLAGS) -DDECAP_TPR_STATS -DDECAP_VIP_STATS -c $< -o $@

# ---- Userspace compilation ----

$(USER_OUT):
	@mkdir -p $(USER_OUT)

$(USER_OUT)/decap_user: userspace/decap_user.c | $(USER_OUT)
	@echo "  CC       $@"
	$(CC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS)

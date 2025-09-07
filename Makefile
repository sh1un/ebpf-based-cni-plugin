# ========================================================================
# Makefile for eBPF CNI Plugin
# ========================================================================

# --- Configuration ---
# Detect architecture for path settings
ARCH := $(shell uname -m | sed 's/x86_64/x86_64/' | sed 's/aarch64/aarch64/')

# Compiler and tools
CC = gcc
CLANG = clang
BPFTOOL = bpftool

# Directories
OUTPUT_DIR = build
SRC_DIR_USER = cmd/ebpfcni
SRC_DIR_BPF = bpf/kernel
DEST_DIR_CNI = /opt/cni/bin

# Source and Object files
BPF_SRC = $(SRC_DIR_BPF)/ebpfcni.bpf.c
USER_SRC = $(SRC_DIR_USER)/main.c
BPF_OBJ = $(OUTPUT_DIR)/ebpfcni.bpf.o
SKEL_HEADER = $(SRC_DIR_USER)/ebpfcni.skel.h
VMLINUX_HEADER = $(OUTPUT_DIR)/vmlinux.h
TARGET_BIN = $(OUTPUT_DIR)/ebpfcni

# --- Compiler and Linker Flags ---

# Flags for Clang (compiling BPF code)
CLANG_FLAGS = \
	-I$(OUTPUT_DIR) \
	-I/usr/include/$(ARCH)-linux-gnu \
	-I/usr/include \
	-g -O2 -target bpf -c

# CFLAGS for GCC (compiling user-space application)
CFLAGS = \
	-I$(OUTPUT_DIR) \
	-I$(SRC_DIR_USER) \
	-I/usr/include/libnl3 \
	-I/usr/include/bpf \
	-g -O2 -Wall

# LDFLAGS for linking user-space application
LDFLAGS = \
-L/usr/lib/$(ARCH)-linux-gnu \
-lbpf -lnl-3 -lnl-route-3 -lnl-genl-3

# --- Build Targets ---

.PHONY: all clean install uninstall

all: $(TARGET_BIN)

# Target: Build the final CNI binary
$(TARGET_BIN): $(USER_SRC) $(SKEL_HEADER)
	@echo "INFO: Compiling CNI binary..."
	@$(CC) $(CFLAGS) -o $@ $(USER_SRC) $(LDFLAGS)
	@echo "SUCCESS: CNI binary compiled at $(TARGET_BIN)"

# Target: Generate the BPF skeleton header
$(SKEL_HEADER): $(BPF_OBJ)
	@echo "INFO: Generating BPF skeleton header..."
	@$(BPFTOOL) gen skeleton $< > $@
	@echo "SUCCESS: Skeleton header generated at $(SKEL_HEADER)"

# Target: Compile the eBPF kernel code
$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_HEADER)
	@echo "INFO: Compiling eBPF code..."
	@$(CLANG) $(CLANG_FLAGS) $< -o $@
	@echo "SUCCESS: eBPF object compiled at $(BPF_OBJ)"

# Target: Generate vmlinux.h for CO-RE
$(VMLINUX_HEADER):
	@echo "INFO: Generating vmlinux.h for CO-RE..."
	@mkdir -p $(OUTPUT_DIR)
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
	@echo "SUCCESS: vmlinux.h generated at $(VMLINUX_HEADER)"

# --- Management Targets ---

# Target: Install the CNI binary
install: all
	@echo "INFO: Installing CNI binary to $(DEST_DIR_CNI)..."
	@sudo mkdir -p $(DEST_DIR_CNI)
	@sudo cp $(TARGET_BIN) $(DEST_DIR_CNI)/
	@echo "SUCCESS: ebpfcni installed."

# Target: Uninstall the CNI binary
uninstall:
	@echo "INFO: Removing CNI binary from $(DEST_DIR_CNI)..."
	@sudo rm -f $(DEST_DIR_CNI)/ebpfcni
	@echo "SUCCESS: ebpfcni uninstalled."

# Target: Clean up all build artifacts
clean:
	@echo "INFO: Cleaning up build artifacts..."
	@rm -rf $(OUTPUT_DIR)
	@rm -f $(SKEL_HEADER)
	@echo "SUCCESS: Cleanup complete."

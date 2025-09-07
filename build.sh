#!/bin/bash
set -e

# Set the PATH to include Homebrew's LLVM installation
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"

# Regenerate eBPF Go bindings
echo "--- Generating eBPF Go bindings ---"
go generate ./cni/plugin

# Cross-compile the CNI plugin for Linux/ARM64
echo "--- Building CNI plugin binary ---"
GOOS=linux GOARCH=arm64 go build -o bin/ebpfcni ./cni/plugin

echo "--- Build complete ---"

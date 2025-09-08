#!/bin/bash
set -e

# Set the PATH to include Homebrew's LLVM installation
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"

# Regenerate eBPF Go bindings
echo "--- Cleaning up old eBPF artifacts ---"
rm -f cni/plugin/bpf_bpf.go cni/plugin/bpf_bpf.o
echo "--- Generating eBPF Go bindings ---"
go generate ./cni/plugin

# Cross-compile binaries for Linux/ARM64
echo "--- Building CNI plugin binary ---"
GOOS=linux GOARCH=arm64 go build -o bin/ebpfcni ./cni/plugin

echo "--- Building endpointctl binary ---"
GOOS=linux GOARCH=arm64 go build -o bin/endpointctl ./cmd/endpointctl

echo "--- Building policyctl binary ---"
GOOS=linux GOARCH=arm64 go build -o bin/policyctl ./cmd/policyctl

echo "--- Build complete ---"

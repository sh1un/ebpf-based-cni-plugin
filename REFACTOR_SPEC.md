# eBPF CNI Plugin Refactoring Specification

## 1. Objective

This document outlines the plan to refactor the existing eBPF-based CNI plugin from a `bash`-scripted implementation to a modern, robust solution using **Golang, `cilium/ebpf`, and CO-RE** (Compile Once - Run Everywhere).

The primary goal is to modernize the technical stack to align with industry best practices, as exemplified by projects like Cilium, while maintaining the current functionality. The refactoring will be performed in-place within the existing repository.

## 2. Current Architecture Analysis

The current implementation consists of three main components:

*   **CNI Plugin (`cni/ebpfcni`)**: A `bash` script responsible for network setup (veth pair, Linux bridge) and attaching a pre-compiled eBPF program using `tc`. It performs rudimentary, non-robust IPAM.
*   **eBPF Program (`bpf/kernel/ebpfcni.bpf.c`)**: A `tc` classifier program that implements a default-deny network policy. It uses a pinned BPF map (`iprules`) to check for allowed traffic between source and destination IPs.
*   **Agent (`k8s/controller/network_policy_agent.sh`)**: A `bash` script (inferred) that watches Kubernetes `NetworkPolicy` resources and updates the `iprules` BPF map accordingly.

## 3. Proposed Refactoring Plan

The refactoring will be executed in two main phases.

### Phase 1: Refactor CNI Plugin to Golang with `cilium/ebpf`

This phase focuses on replacing the `cni/ebpfcni` bash script with a self-contained Go binary. The existing `network_policy_controller.sh` will remain untouched and functional.

**Key Steps:**

1.  **Project Scaffolding**:
    *   Initialize a Go module in the project root: `go mod init github.com/sh1un/ebpf-based-cni-plugin`.
    *   Create a new directory for the CNI plugin: `cni/plugin/`.
    *   Create the main entrypoint file: `cni/plugin/main.go`.

2.  **Integrate Go CNI Libraries**:
    *   Add dependencies for CNI interaction by running `go mod tidy`. This will fetch:
        *   `github.com/containernetworking/cni/pkg/skel`
        *   `github.com/containernetworking/cni/pkg/types`
        *   `github.com/containernetworking/cni/pkg/version`

3.  **Adopt `cilium/ebpf` for CO-RE**:
    *   Add the core eBPF library dependency: `github.com/cilium/ebpf`.
    *   Modify `bpf/kernel/ebpfcni.bpf.c` to be compatible with `cilium/ebpf`'s `bpf2go` tool. This involves:
        *   Including `vmlinux.h` for CO-RE.
        *   Ensuring map definitions use the `struct { ... } __attribute__((packed));` style for keys if they are structs.
        *   Removing hardcoded pinning details from the C code, as this will be handled by the Go code.

4.  **Automate eBPF Compilation with `go:generate`**:
    *   In `cni/plugin/main.go`, add a `//go:generate` directive to run `bpf2go`.
    *   Example: `//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf bpf ../../bpf/kernel/ebpfcni.bpf.c -- -I/path/to/headers`
    *   This command will compile the BPF C code and embed it as Go code (`bpf_bpfel.go`), which can be directly used by the CNI plugin binary.

5.  **Re-implement Network Setup in Go**:
    *   Add the netlink library dependency: `github.com/vishvananda/netlink`.
    *   In `cmdAdd`, write Go code to perform the network setup actions previously done by the bash script.

6.  **Manage eBPF Objects in Go**:
    *   In `cmdAdd`, use the generated Go code from `bpf2go` to load, attach, and pin the eBPF program and maps.

### Phase 2: Refactor Network Policy Agent to Golang (Future Work)

This phase will replace the `network_policy_agent.sh` script with a more robust Go-based agent.

## 4. Expected Outcome

*   **Single Binary Deployment**: The CNI plugin will be a single, statically-linked Go binary.
*   **CO-RE Portability**: The eBPF program will be portable across different kernel versions.
*   **Improved Robustness & Maintainability**: Go provides type safety, better error handling, and easier testing.
*   **Preserved Functionality**: The system's behavior will remain identical after Phase 1.

## 5. Action Plan

Once this specification is approved, please **switch to "Act Mode"** so that I can begin the implementation of Phase 1.

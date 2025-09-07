# eBPF CNI Plugin - Developer's Guide

Welcome to the eBPF CNI Plugin project! This guide will walk you through setting up your development environment, building the project, and testing your changes.

## 1. Project Overview

This project is a Kubernetes CNI (Container Network Interface) plugin built with Golang and eBPF. It uses `cilium/ebpf` for CO-RE (Compile Once - Run Everywhere) eBPF development, allowing for a modern and portable networking solution.

The main components are:
- **Go CNI Plugin**: The core logic that sets up network interfaces for pods.
- **eBPF Program**: A TC (Traffic Control) program that enforces network policies.
- **Kubernetes Controller**: A script that watches `NetworkPolicy` resources and updates the eBPF map.

## 2. Development Environment Setup

This project is developed on an **ARM64 (Apple Silicon) macOS** machine, with testing performed inside an **ARM64 Linux VM** managed by Multipass.

### Prerequisites

- **macOS (ARM64)**: An Apple Silicon Mac (M1, M2, M3, etc.).
- **Homebrew**: The package manager for macOS.
- **Multipass**: For running the Linux VM.
- **Go**: The programming language for the CNI plugin.
- **LLVM**: Required for compiling eBPF C code.

### Step-by-Step Setup

1.  **Install Tools via Homebrew**:
    Open your terminal and run:
    ```bash
    brew install go llvm multipass
    ```

2.  **Configure Multipass VM**:
    a. Launch an ARM64 Ubuntu VM. We recommend using the name `my-instance`.
    ```bash
    multipass launch --name my-instance --cpus 2 --mem 4G --disk 20G
    ```
    b. Mount your local project directory into the VM. This allows code changes on your Mac to be immediately reflected inside the VM.
    ```bash
    # Replace the local path if your project is located elsewhere
    multipass mount /Users/shiun/GitHub/ebpf-based-cni-plugin my-instance:/home/ubuntu/macbook/ebpf-based-cni-plugin
    ```
    c. The VM also needs a single-node Kubernetes cluster. Follow a guide like `k3s` or `microk8s` to set one up inside the VM.

3.  **Set LLVM Path**:
    The eBPF compiler (`bpf2go`) needs to find LLVM tools like `clang` and `llvm-strip`. You must add LLVM to your `PATH`. Add the following line to your shell profile (`~/.zshrc`, `~/.bash_profile`, etc.) and restart your terminal.
    ```bash
    export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
    ```

## 3. Build and Compile Workflow

The build process involves two main steps: generating eBPF Go bindings and cross-compiling the CNI plugin for Linux.

### Step 1: Generate eBPF Bindings

The eBPF C code in `bpf/kernel/ebpfcni.bpf.c` is not compiled directly. Instead, we use `go generate` to create Go code that embeds the compiled eBPF program.

From the project root directory, run:
```bash
go generate ./cni/plugin
```
This command executes the directive in `cni/plugin/main.go`, running `bpf2go` to create `cni/plugin/bpf_bpf.go` and `cni/plugin/bpf_bpf.o`.

> **Note**: If this step fails with an `executable file not found` error, ensure you have completed Step 3 of the environment setup correctly.

### Step 2: Cross-Compile for Linux/ARM64

The CNI plugin must run inside the Linux VM, which has an `arm64` architecture. Therefore, we must cross-compile from macOS.

Run the following command from the project root:
```bash
GOOS=linux GOARCH=arm64 go build -o bin/ebpfcni ./cni/plugin
```
This command produces a Linux-compatible binary at `bin/ebpfcni`.

## 4. Testing the Plugin

With the project directory mounted in the VM, the newly compiled `bin/ebpfcni` is already available inside it.

To test your changes, follow the detailed steps in **`TESTING_GUIDE.md`**. The general workflow is:

1.  **Enter the VM**:
    ```bash
    multipass shell my-instance
    ```

2.  **Run the Deployment Script**:
    The `TESTING_GUIDE.md` provides a comprehensive script to:
    - Stop `kubelet`.
    - Clean up old CNI state and test pods.
    - Copy the new `ebpfcni` binary to `/opt/cni/bin/`.
    - Copy the CNI configuration to `/etc/cni/net.d/`.
    - Restart `kubelet`.
    - Deploy test pods and verify their status.

By following this guide, any new engineer should be able to get their environment running and contribute to the project effectively.

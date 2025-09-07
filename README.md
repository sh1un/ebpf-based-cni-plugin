# eBPF CNI Plugin with libbpf and CO-RE

This project is an eBPF-based CNI (Container Network Interface) plugin designed for Kubernetes. It leverages `libbpf` and CO-RE (Compile Once - Run Everywhere) to create a modern, portable, and efficient networking solution.

The original version was based on shell scripts and `bpftool`. This refactored version is a self-contained C binary that is easier to build, deploy, and maintain.

## Architecture

The plugin consists of two main components:

1.  **eBPF Kernel Program** (`bpf/kernel/ebpfcni.bpf.c`): A program that runs in the Linux kernel, attached to the Traffic Control (TC) hook to inspect and manage network traffic for pods.
2.  **User-space CNI Binary** (`cmd/ebpfcni/main.c`): The CNI plugin executable that Kubernetes invokes. It is responsible for:
    *   Handling CNI commands (`ADD`, `DEL`, `CHECK`, `VERSION`).
    *   Loading, attaching, and managing the eBPF program using `libbpf`.
    *   Setting up network interfaces (e.g., veth pairs) for pods using `libnl`.

## Build Process

The project uses a `Makefile` to automate the build process.

### Prerequisites

Install the necessary build tools and libraries on your build environment (e.g., a Multipass VM running Ubuntu):

```bash
sudo apt update
sudo apt install -y build-essential clang libelf-dev libbpf-dev bpftool libnl-3-dev libnl-genl-3-dev
```

### Build

Simply run `make` to compile the entire project. This command will:
1.  Generate `vmlinux.h` for CO-RE.
2.  Compile the eBPF kernel program.
3.  Generate the BPF skeleton header.
4.  Compile the user-space CNI binary into `build/ebpfcni`.

```bash
make
```

## Installation and Usage

The `Makefile` also provides targets for installation and uninstallation.

1.  **Install the CNI binary**:
    This command copies the compiled binary to `/opt/cni/bin/`.
    ```bash
    sudo make install
    ```

2.  **Create a CNI configuration file**:
    Create `/etc/cni/net.d/10-ebpfcni.conf` with the following content:

    ```json
    {
      "cniVersion": "0.4.0",
      "name": "ebpfcni",
      "type": "ebpfcni"
    }
    ```

3.  **Restart your container runtime** (e.g., `containerd`, `cri-o`) for the changes to take effect.

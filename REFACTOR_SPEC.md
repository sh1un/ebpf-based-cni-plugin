# eBPF CNI Plugin Refactoring Specification

This document outlines the plan to refactor the eBPF-based CNI plugin from its current architecture (Bash scripts, `bpftool`, external user-space helpers) to a modern, integrated solution using `libbpf` and CO-RE (Compile Once - Run Everywhere).

## 1. Current Architecture Analysis

The existing implementation consists of three main, loosely-coupled components:

*   **`cni/ebpfcni` (Bash Script):**
    *   Acts as the CNI plugin entry point.
    *   Handles CNI `ADD`/`DEL` commands.
    *   Performs network setup (Linux bridge, veth pairs) using shell commands (`ip`, `brctl`).
    *   Attaches a **pre-pinned** eBPF TC program to the host-side veth interface using `tc`.
    *   Does not handle eBPF program loading or lifecycle.

*   **`bpf/user/ebpfcni.c` (User-space Helper):**
    *   A simple command-line tool to update a pre-pinned BPF map (`/sys/fs/bpf/iprules`).
    *   It is likely invoked by a separate network policy controller to enforce rules.
    *   It is not part of the CNI execution flow.

*   **`bpf/kernel/ebpfcni.bpf.c` (eBPF Program):**
    *   A TC classifier program.
    *   Inspects ingress packets.
    *   Implements a "default deny" network policy by looking up rules in the `iprules` map.
    *   Depends on an external process to be compiled, loaded, and pinned to the BPF filesystem.

**Limitations of the Current Architecture:**

*   **Poor Portability:** Relies on kernel headers, making it brittle across different kernel versions.
*   **Fragile Deployment:** The process is fragmented. It requires separate steps for compiling the eBPF code, loading/pinning it with `bpftool`, and then running the CNI script which depends on the pinned objects.
*   **High Maintenance Overhead:** Using Bash scripts for network setup and `tc` commands is error-prone and hard to debug, test, and extend.
*   **Decoupled Control Plane:** The CNI plugin and the network policy updater are separate executables, complicating the control loop.

## 2. Proposed Architecture: `libbpf` + CO-RE

The goal is to create a **single, self-contained C binary** (`ebpfcni`) that functions as the CNI plugin and manages the entire lifecycle of the eBPF programs.

**Key Features:**

*   **CNI Plugin Implementation:** The binary will implement the CNI specification, parsing commands (`ADD`, `DEL`, `CHECK`, `VERSION`) and environment variables.
*   **Integrated eBPF Lifecycle Management:** It will use the `libbpf` library to:
    *   Open, load, and verify the eBPF object file.
    *   Attach the eBPF TC program to the correct network interface.
    *   Manage the lifecycle of BPF maps.
*   **CO-RE for Portability:** The eBPF code will be written to be CO-RE compliant, ensuring it can run on different kernel versions without recompilation. This is achieved by using BTF (BPF Type Format) to resolve kernel struct layouts at load time.
*   **Programmatic Network Setup:** All network operations will be performed programmatically using a dedicated C library like **`libnl`**, which provides a comprehensive API for netlink and namespace operations (e.g., `setns()`).
*   **BPF Object Pinning & Path Structure:** To ensure BPF objects persist, they will be pinned to a structured path within the BPF filesystem. This design prevents conflicts and clarifies object scope:
    *   **Global Objects:** Shared maps like `iprules` will be pinned to a global path, e.g., `/sys/fs/bpf/ebpfcni/global/iprules`.
    *   **Per-Interface Objects:** If future designs require per-interface objects, they could be pinned under a path like `/sys/fs/bpf/ebpfcni/ifaces/<ifindex>/...`.
    This structure allows for a stateless CNI plugin and enables external controllers to reliably access shared resources.
*   **BPF Skeleton (`.skel.h`):** We will use `bpftool gen skeleton` to auto-generate a header file from the compiled eBPF object. This provides a clean, type-safe API for the user-space C code to open, load, attach, and interact with the eBPF program and its maps.

## 3. Implementation Steps

1.  **Project Restructuring:**
    *   Create a new directory, e.g., `cmd/ebpfcni/`, to house the new CNI plugin source code.
    *   Create a root `Makefile` to orchestrate the entire build process.

2.  **Update eBPF Kernel Code (`bpf/kernel/ebpfcni.bpf.c`):**
    *   Include `<vmlinux.h>` (generated from kernel BTF) to enable CO-RE and provide type definitions for kernel structures.
    *   Modify map definitions to include a pinning property (e.g., `__uint(pinning, LIBBPF_PIN_BY_NAME);`) to simplify the pinning process with `libbpf`.
    *   Ensure program sections are correctly defined for `libbpf` to identify them.

3.  **Create a `Makefile` and Build Pipeline:**
    *   The `Makefile` will define a clear CI/CD-friendly build process:
        1.  **Generate `vmlinux.h`:** Use `bpftool btf dump` against a kernel image or running kernel to generate the CO-RE header.
        2.  **Build `libbpf`:** It's recommended to include `libbpf` as a submodule and build it from source to guarantee version consistency.
        3.  **Compile eBPF Code:** Use `clang -target bpf` to compile `ebpfcni.bpf.c` into an eBPF object file (`ebpfcni.bpf.o`).
        4.  **Generate Skeleton:** Use `bpftool gen skeleton` to create `ebpfcni.skel.h` from the object file.
        5.  **Compile User-space Binary:** Use `gcc` to compile the CNI main program, linking it against the locally built `libbpf` and `libnl`.
    *   The `Makefile` will also include standard `clean` and `install` targets.

4.  **Develop the New CNI Plugin (`cmd/ebpfcni/main.c`):**
    *   **Entry Point:** The `main` function will parse CNI environment variables and delegate to `cmdAdd`, `cmdDel`, etc.
    *   **`cmdAdd` Function:**
        1.  Check if BPF objects are already pinned at the well-known path (`/sys/fs/bpf/ebpfcni`). If so, re-use them.
        2.  If not pinned, call `ebpfcni_skel__open_and_load()` to open and load the eBPF object.
        3.  **Pin Objects:** Call `bpf_object__pin_maps()` or `bpf_map__pin()` for each map, and `bpf_program__pin()` for the program, to the well-known path. This is critical for lifecycle management.
        4.  Perform network setup (veth, bridge, IPAM) using `libnl`.
        5.  **Attach TC Program:** The skeleton does not auto-attach TC programs. We must explicitly use the `libbpf` TC API.
            *   Create a TC hook: `bpf_tc_hook_create()`.
            *   Attach the eBPF program: `bpf_tc_attach()`, passing the program's file descriptor obtained from the skeleton (`skel->progs.process_tc->prog_fd`).
        6.  Print the CNI result JSON to `stdout`.
    *   **`cmdDel` Function (Refined Cleanup Strategy):**
        1.  Perform network cleanup for the specific pod (e.g., remove the veth pair).
        2.  Detach the TC program from the specific interface using `bpf_tc_detach()` and destroy the hook with `bpf_tc_hook_destroy()`.
        3.  **Crucially, the `DEL` command will NOT remove shared pinned objects (like the global `iprules` map).** The lifecycle of shared resources should be managed by a separate controller or garbage collection mechanism, preventing a single pod deletion from disrupting network policy for all other pods.
    *   **External Controller Interaction:** The network policy controller can now reliably get a file descriptor to the `iprules` map by calling `bpf_obj_get("/sys/fs/bpf/ebpfcni/iprules")` and update it as needed.

5.  **Cleanup:**
    *   Remove the old `cni/ebpfcni` bash script.
    *   Remove the `bpf/user/` directory and its contents.
    *   Update documentation (`README.md`, `INSTALL_GUIDE_ZH_TW.md`) to reflect the new build and installation process.

6.  **Error Handling and Resilience (New Section):**
    *   **Object Re-use:** The plugin must handle cases where maps/programs are already pinned (e.g., after a restart) and re-use them gracefully.
    *   **BTF/CO-RE Requirement:** The plugin will operate on the assumption that the host kernel has BTF enabled. **If BTF is not detected, the plugin will fail explicitly**, returning a CNI error JSON explaining the requirement. A non-CO-RE fallback is out of scope for this refactor due to its complexity.
    *   **CNI Error Reporting:** In case of any failure (`libbpf` error, network setup error), the plugin must print a valid CNI error JSON to `stderr` and exit with a non-zero status code.

7.  **Versioning and Observability (New Section):**
    *   **Plugin Versioning:** The CNI binary will respond to the `CNI_COMMAND=VERSION` command by printing its own version information, conforming to the CNI specification.
    *   **Map Schema Versioning:** To facilitate smoother upgrades and prevent controller/plugin mismatches, a dedicated map (e.g., a global `metadata` map) could be used to store schema versions or other metadata. External controllers should check this metadata before attempting to interact with other maps.

## 4. Benefits of this Refactor

*   **Production-Ready Lifecycle:** Using BPF pinning ensures that network policies and traffic counters persist across CNI process invocations, a critical requirement for production use.
*   **Robustness & Reliability:** A single, compiled binary with explicit error handling is far more robust than a collection of scripts.
*   **Portability (CO-RE):** The CNI plugin will work across a wide range of Linux kernel versions without needing to be recompiled for each one.
*   **Simplified Operations:** Installation and execution are simplified to compiling one binary and placing it in `/opt/cni/bin`. No more manual `bpftool` or `tc` commands during setup.
*   **Improved Performance:** Eliminates the overhead of forking multiple shell processes (`ip`, `brctl`, `jq`, `sed`, `tc`) for every pod creation.
*   **Enhanced Maintainability:** The entire logic is in one place, written in C, and leverages type-safe interfaces (`.skel.h`), making it easier to understand, debug, and extend in the future.

# Cilium MVP - Refactoring Plan (Final)

This document outlines the engineering plan to refactor the existing IP-based CNI plugin into a Cilium-like, identity-based network policy enforcement engine, as specified in the MVP Spec.

---

## Scope & Limitations

- **Single-node cluster, IPv4-only for the MVP.**
- **No conntrack/NAT/LB;** request/response protocols (like TCP or ICMP) require symmetric policy entries.
- **Cross-node and external egress are default-deny** unless endpoints/identities and policies are explicitly provisioned.

---

## Phase 1: Refactor eBPF Core Logic

The goal is to replace the current IP-based filtering with an identity-based lookup mechanism.

**File to be Modified:** `bpf/kernel/ebpfcni.bpf.c`

**Tasks:**

1.  **Define New Global Maps:**
    *   `endpoint_map`: `__u32` (IP) -> `__u32` (Identity). `max_entries = 16384`.
    *   `policy_map`: `struct policy_key` -> `__u8` (Action). `max_entries = 65536`.

2.  **Rewrite TC Program Logic (`process_tc`):**
    *   Early exit with `TC_ACT_OK` for non-IPv4 packets (e.g., ARP).
    *   Look up `src_id` and `dst_id` from `endpoint_map` using packet IPs.
    *   If either identity is not found, drop the packet (`TC_ACT_SHOT`).
    *   Look up the policy in `policy_map`.
    *   If an `allow` entry exists, return `TC_ACT_OK`. Otherwise, drop (`TC_ACT_SHOT`).

3.  **Implementation Notes:**
    *   **L2 / Non-IPv4 Handling:** The tc program MUST early-return `TC_ACT_OK` for non-IPv4 frames (e.g., ARP, IPv6 ND, LLDP). Only IPv4 packets proceed to identity lookups and policy evaluation.
    *   **Policy Symmetry (No Conntrack in MVP):** This MVP does NOT implement conntrack. Any request/response protocol (ICMP echo, TCP handshake, HTTP) REQUIRES symmetric allow rules (both `src->dst` and `dst->src`) to succeed. Otherwise, the reply packet will be dropped.
    *   **Key Layout Safety:** The `policy_map` key struct MUST be shared between eBPF and userspace code from a common header, and guarded with a `static_assert(sizeof(struct policy_key) == 8, "policy_key must be 8 bytes")` to prevent padding mismatches.
    *   **Byte Order:** All Pod IPs must be stored in `endpoint_map` as host-byte order integers. In the eBPF program, IPs extracted from packet headers must be converted with `bpf_ntohl()` before lookup.
    *   **Debugging:** Use `bpf_printk()` to trace packet processing. The `README.md` must show how to view logs via `sudo cat /sys/kernel/debug/tracing/trace_pipe`.

---

## Phase 2: Adapt the CNI Plugin

The CNI plugin's role is simplified to only network setup and attaching the generic eBPF program.

**File to be Modified:** `cni/plugin/main.go`

**Tasks:**

1.  **Globalize BPF Maps:** Ensure `endpoint_map` and `policy_map` are loaded from (or created at) a global path (`/sys/fs/bpf/tc/globals/`) and are not tied to any Pod's lifecycle.
2.  **Simplify CNI Responsibilities:** The plugin's only BPF-related tasks are loading the program, ensuring maps are pinned, and attaching the program to the veth. It will no longer write to maps.

3.  **Implementation Notes:**
    *   **Qdisc Idempotency:** Before attaching filters, ensure `clsact` qdisc exists: `tc qdisc add dev <HOST_VETH> clsact || true`.
    *   **Attach Points (Explicit):** The demo will implement both ingress and egress policy. The program will be attached to:
        *   Host-side veth `INGRESS` (captures Pod Egress traffic).
        *   Host-side veth `EGRESS` (captures Pod Ingress traffic).
    *   **Host Veth Peer Discovery:** The CNI MUST resolve the host-side veth via netlink (as the peer of the container-side veth) instead of using hardcoded names.
    *   **Idempotency:** The `tc filter` command must use `replace` to prevent duplicate filter attachments.

---

## Phase 3: Develop Userspace Management Tools

Create dedicated CLI tools for managing endpoints and policies.

**Files to be Created:** `cmd/endpointctl/main.go`, `cmd/policyctl/main.go`

**Tasks:**

1.  **Create `endpointctl`:**
    *   `add --ip <IP> --identity <ID>`: Upserts an entry in `endpoint_map`.
    *   `del --ip <IP>`: Removes an entry.

2.  **Create `policyctl`:**
    *   `allow --src <ID1> --dst <ID2> [--symmetric]`: Adds allow rule(s) to `policy_map`.
    *   `deny --src <ID1> --dst <ID2> [--symmetric]`: Removes rule(s).

3.  **Implementation Notes:**
    *   **Symmetric Rules Helper:** `policyctl` should provide a `--symmetric` flag to write rules for both `ID1->ID2` and `ID2->ID1`, simplifying setup for request/response protocols.
    *   **Upsert Behavior:** `endpointctl add` must function as an "upsert".
    *   **Input Validation:** Tools must validate inputs (IP format, numeric IDs).
    *   **Map Sizes:** Default capacities (`endpoint_map`: 16384, `policy_map`: 65536) should be used.
    *   **CLI Feedback:** On success, tools should print the current state of the map.

---

## Phase 4: Documentation and Validation

Ensure the project is usable and its functionality can be verified.

**Tasks:**

1.  **Update Build Process:** Modify `build.sh` to compile the new `endpointctl` and `policyctl` binaries.
2.  **Create End-to-End Test Case in `README.md`:**
    1.  Create two pods: `frontend` (IP `10.13.0.2`, ID `1001`) and `backend` (IP `10.13.0.3`, ID `1002`).
    2.  Register endpoints:
        ```bash
        ./endpointctl add --ip 10.13.0.2 --identity 1001
        ./endpointctl add --ip 10.13.0.3 --identity 1002
        ```
    3.  Allow bidirectional traffic for the demo (since no conntrack):
        ```bash
        ./policyctl allow --src 1001 --dst 1002 --symmetric
        ```
    4.  Verify that `ping`/`curl` from `frontend` to `backend` succeeds.
    5.  (Optional) Remove the reverse rule and show that replies are dropped:
        ```bash
        ./policyctl deny --src 1002 --dst 1001
        ```
        Re-run `ping`/`curl`: the request may leave `frontend`, but replies will be dropped.
    6.  Include instructions for observing BPF logs: `sudo cat /sys/kernel/debug/tracing/trace_pipe`.

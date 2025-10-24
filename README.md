# eBPF-based CNI Plugin (Identity-Based)

This project is an eBPF-based CNI plugin for Kubernetes that enforces network policies based on identity, similar to Cilium's model.

## 2025 KubeSummit

👉 **2025 KubeSummit Session**: https://k8s.ithome.com.tw/2025/session-page/4083

## Project Overview

- **CNI Plugin (`./cni/plugin`)**: Sets up the veth pair for Pods and attaches the eBPF TC program.
- **eBPF Program (`./bpf/kernel`)**: An identity-based policy engine attached to the TC (Traffic Control) hook. It filters traffic based on security identities stored in eBPF maps.
- **Management Tools (`./cmd`)**:
  - `endpointctl`: Manages the mapping between Pod IPs and security identities.
  - `policyctl`: Manages network policies between security identities.

## End-to-End Test Case

This guide demonstrates how to set up a simple scenario with two pods, `frontend` and `backend`, and enforce network policies between them.

### Prerequisites

- A running single-node Kubernetes cluster (e.g., inside the Multipass VM).
- The project has been built successfully using `./build.sh`.

### Step 1: Deploy Test Pods

Create two pods, `frontend` and `backend`, which will be used to test connectivity.

```bash
# (Inside the VM)
kubectl apply -f k8s/manifests/test-pods.yaml
```

Wait for the pods to be in the `Running` state and get their IP addresses:

```bash
kubectl get pods -o wide
# NAME       READY   STATUS    RESTARTS   AGE   IP          NODE          NOMINATED NODE   READINESS GATES
# backend    1/1     Running   0          ...   10.13.0.3   my-instance   <none>           <none>
# frontend   1/1     Running   0          ...   10.13.0.2   my-instance   <none>           <none>
```

### Step 2: Register Endpoints

Use `endpointctl` to associate each pod's IP with a unique security identity.

- `frontend` (10.13.0.2) -> ID `1001`
- `backend` (10.13.0.3) -> ID `1002`

```bash
# (Inside the VM, from the project root)
sudo ./bin/endpointctl add --ip 10.13.0.2 --identity 1001
sudo ./bin/endpointctl add --ip 10.13.0.3 --identity 1002
```

### Step 3: Define Network Policy

By default, all traffic is denied. Use `policyctl` to create an "allow" rule. Since this MVP does not have connection tracking, we must create symmetric rules for request/response protocols like TCP or ICMP to work.

```bash
# Allow traffic from frontend (1001) to backend (1002) and vice-versa
sudo ./bin/policyctl allow --src 1001 --dst 1002 --symmetric
```

### Step 4: Verify Connectivity

Now, `ping` or `curl` from the `frontend` pod to the `backend` pod should succeed.

```bash
# Get the frontend pod name
FRONTEND_POD=$(kubectl get pods -l app=frontend -o jsonpath='{.items[0].metadata.name}')

# Ping the backend from the frontend
kubectl exec -it $FRONTEND_POD -- ping -c 3 10.13.0.3
# PING 10.13.0.3 (10.13.0.3) 56(84) bytes of data.
# 64 bytes from 10.13.0.3: icmp_seq=1 ttl=64 time=...
# --- 10.13.0.3 ping statistics ---
# 3 packets transmitted, 3 received, 0% packet loss...
```

### Step 5: (Optional) Test Default-Deny

To demonstrate that the policy is being enforced, remove the return path rule (`backend -> frontend`).

```bash
# Deny traffic from backend (1002) to frontend (1001)
sudo ./bin/policyctl deny --src 1002 --dst 1001
```

Now, re-run the ping test. The ICMP echo request will leave `frontend`, but the reply from `backend` will be dropped by the eBPF program, causing the ping to time out.

```bash
kubectl exec -it $FRONTEND_POD -- ping -c 3 10.13.0.3
# PING 10.13.0.3 (10.13.0.3) 56(84) bytes of data.
# --- 10.13.0.3 ping statistics ---
# 3 packets transmitted, 0 received, 100% packet loss...
```

## Debugging with BPF Logs

You can monitor the eBPF program's decisions in real-time by reading the kernel's trace pipe. This is useful for debugging why a packet was allowed or dropped.

```bash
# (Inside the VM)
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

You will see output like:
```
<...>-54321 [001] .... 1.234567: bpf_trace_printk: TC: HIT from a0d0002 (id=1001) to a0d0003 (id=1002)
<...>-54321 [001] .... 1.234568: bpf_trace_printk: TC: ALLOW id 1001 -> id 1002
<...>-54322 [000] .... 1.234569: bpf_trace_printk: TC: HIT from a0d0003 (id=1002) to a0d0002 (id=1001)
<...>-54322 [000] .... 1.234570: bpf_trace_printk: TC: DENY id 1002 -> id 1001 (no rule)

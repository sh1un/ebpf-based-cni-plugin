#!/usr/bin/env bash
set -e

# This script cleans up resources created for the eBPF CNI plugin testing.
# It needs to be run with sufficient privileges (e.g., sudo) to manage
# system-level resources like TC qdiscs and BPF pins.

echo "--- Starting Cleanup ---"

# 1. Stop the eBPF agent
echo "[1/5] Stopping eBPF agent..."
pkill -f ebpf-agent.sh || echo "Agent not running."

# 2. Delete Kubernetes resources
echo "[2/5] Deleting Kubernetes resources..."
# Delete all resources from the manifests directory, ignoring errors if they don't exist.
kubectl delete -f k8s/manifests/policy-allow-ingress-from-frontend.yaml --ignore-not-found=true
kubectl delete -f k8s/manifests/policy-deny-all.yaml --ignore-not-found=true
kubectl delete -f k8s/manifests/test-pods.yaml --ignore-not-found=true

# A specific command to ensure all network policies are gone, in case they were created manually.
kubectl delete networkpolicies --all --all-namespaces >/dev/null 2>&1 || true


# Wait a moment for pods to terminate
echo "Waiting for pods to be terminated..."
sleep 5

# 3. Clean up eBPF TC qdiscs from network interfaces
echo "[3/5] Cleaning up TC qdiscs..."
# Find all interfaces with a clsact qdisc and delete it.
# This is a common way to detach TC-based BPF programs.
# The output is silenced to avoid errors if no such interfaces are found.
for iface in $(tc qdisc show | grep clsact | awk '{print $5}'); do
    echo "  - Removing clsact qdisc from $iface"
    sudo tc qdisc del dev "$iface" clsact >/dev/null 2>&1 || true
done

# 4. Clean up BPF pin path
BPF_PIN_PATH="/sys/fs/bpf/tc/globals"
echo "[4/5] Cleaning up BPF pin path at ${BPF_PIN_PATH}..."
if [ -d "${BPF_PIN_PATH}" ]; then
    sudo rm -rf "${BPF_PIN_PATH}"
    echo "  - Removed ${BPF_PIN_PATH}"
else
    echo "  - Pin path not found, skipping."
fi

# 5. Clean up agent state directory
STATE_DIR="/var/run/ebpf-agent"
echo "[5/5] Cleaning up agent state directory at ${STATE_DIR}..."
if [ -d "${STATE_DIR}" ]; then
    sudo rm -rf "${STATE_DIR}"
    echo "  - Removed ${STATE_DIR}"
else
    echo "  - State directory not found, skipping."
fi

echo "--- Cleanup Complete ---"

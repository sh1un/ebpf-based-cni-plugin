#!/usr/bin/env bash
set -e

echo "--- Starting Cleanup ---"

# Delete all resources from the manifests directory, ignoring errors if they don't exist.
kubectl delete -f k8s/manifests/policy-allow-client.yaml --ignore-not-found=true
kubectl delete -f k8s/manifests/policy-deny-all.yaml --ignore-not-found=true
kubectl delete -f k8s/manifests/test-pods.yaml --ignore-not-found=true

# Wait a moment for pods to terminate
echo "Waiting for pods to be terminated..."
sleep 5

# 清理舊的 CNI 配置和二進制文件
sudo rm -f /etc/cni/net.d/10-ebpfcni.conf /opt/cni/bin/ebpfcni
sudo rm /sys/fs/bpf/ebpfcni
sudo rm -f /etc/cni/net.d/10-ebpfcni.conf /opt/cni/bin/ebpfcni


# A specific command to ensure all network policies are gone, in case they were created manually.
kubectl delete networkpolicies --all --all-namespaces >/dev/null 2>&1 || true


echo "--- Cleanup Complete ---"

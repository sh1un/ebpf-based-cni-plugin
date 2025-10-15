#!/usr/bin/env bash
set -e

echo "--- Starting Cleanup ---"

# 刪除指定 manifests（若不存在則忽略）
kubectl delete -f k8s/manifests/policy-allow-client.yaml --ignore-not-found=true
kubectl delete -f k8s/manifests/policy-deny-all.yaml --ignore-not-found=true
kubectl delete -f k8s/manifests/test-pods.yaml --ignore-not-found=true

echo "--- Force deleting all pods in default namespace ---"
# 立即強制刪除所有 Pod（不等 grace period）
kubectl delete pod --all -n default --force --grace-period=0 --ignore-not-found=true || true

# 處理卡住的 Terminating Pod（移除 Finalizer）
terminating_pods=$(kubectl get pod -n default --field-selector=status.phase=Terminating -o name 2>/dev/null || true)
if [ -n "$terminating_pods" ]; then
  echo "Patching stuck terminating pods..."
  for pod in $terminating_pods; do
    kubectl patch $pod -n default -p '{"metadata":{"finalizers":null}}' --type=merge || true
  done
fi

echo "--- Deleting all NetworkPolicies in default namespace ---"
kubectl delete networkpolicy --all -n default --ignore-not-found=true || true

# （可選）若你想確保全 cluster 沒有殘留的 NetworkPolicy，也可打開這行
# kubectl delete networkpolicies --all --all-namespaces >/dev/null 2>&1 || true

echo "--- Cleaning up old CNI binaries and BPF state ---"
sudo rm -f /etc/cni/net.d/10-ebpfcni.conf /opt/cni/bin/ebpfcni
sudo rm -rf /sys/fs/bpf/ebpfcni

echo "--- Cleanup Complete --- ✅"

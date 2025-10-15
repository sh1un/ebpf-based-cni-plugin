#!/usr/bin/env bash
set -euo pipefail

echo -e "\033[1;36m--- Starting Cleanup ---\033[0m"

# -------------------------------
# 1. 刪除 K8s 資源
# -------------------------------
echo "--- Deleting manifests (ignore if not found) ---"
kubectl delete -f k8s/manifests/policy-allow-client.yaml --ignore-not-found=true || true
kubectl delete -f k8s/manifests/policy-deny-all.yaml --ignore-not-found=true || true
kubectl delete -f k8s/manifests/test-pods.yaml --ignore-not-found=true || true

echo "--- Force deleting all pods in default namespace ---"
kubectl delete pod --all -n default --force --grace-period=0 --ignore-not-found=true || true

# 處理 stuck 的 Terminating Pod
terminating_pods=$(kubectl get pod -n default --field-selector=status.phase=Terminating -o name 2>/dev/null || true)
if [ -n "$terminating_pods" ]; then
  echo "Patching stuck terminating pods..."
  for pod in $terminating_pods; do
    kubectl patch $pod -n default -p '{"metadata":{"finalizers":null}}' --type=merge || true
  done
fi

echo "--- Deleting all NetworkPolicies in default namespace ---"
kubectl delete networkpolicy --all -n default --ignore-not-found=true || true

# -------------------------------
# 2. Network namespace & veth cleanup
# -------------------------------
echo "--- Cleaning up network namespaces ---"
sudo ip netns | awk '/cni-|ns-/{print $1}' | xargs -r -n1 sudo ip netns delete || true

echo "--- Cleaning up orphan veth interfaces ---"
for dev in $(ls /sys/class/net | grep -E '^veth'); do
  echo "Deleting $dev ..."
  sudo ip link del $dev 2>/dev/null || true
done

# -------------------------------
# 3. Bridge / CNI interface cleanup
# -------------------------------
echo "--- Removing CNI bridges (cni0 / flannel.1 / docker0 / bridge*) ---"
for br in cni0 flannel.1 docker0; do
  if ip link show $br >/dev/null 2>&1; then
    echo "Deleting $br ..."
    sudo ip link set $br down 2>/dev/null || true
    sudo ip link del $br 2>/dev/null || true
  fi
done

# 移除任何自訂 bridge (bridge0, br0 等)
for br in $(ip link show | awk -F: '/bridge0|br0/ {print $2}' | tr -d ' '); do
  echo "Deleting custom bridge: $br ..."
  sudo ip link set $br down 2>/dev/null || true
  sudo ip link del $br 2>/dev/null || true
done

# -------------------------------
# 4. eBPF / tc hooks cleanup
# -------------------------------
if command -v bpftool >/dev/null 2>&1; then
  echo "--- Removing tc hooks from all interfaces ---"
  for dev in $(ls /sys/class/net); do
    sudo tc qdisc del dev $dev clsact 2>/dev/null || true
  done

  echo "--- Cleaning pinned BPF maps/programs ---"
  sudo rm -f /sys/fs/bpf/tc/globals/* 2>/dev/null || true
  sudo rm -rf /sys/fs/bpf/ebpfcni 2>/dev/null || true

  echo "--- Removing orphan sched_cls programs ---"
  sudo bpftool prog show 2>/dev/null | awk '/sched_cls/ {print $1}' | tr -d ':' | \
    xargs -r -n1 sudo bpftool prog delete id 2>/dev/null || true
fi

# -------------------------------
# 5. 清除 CNI 設定檔 & binaries
# -------------------------------
echo "--- Cleaning up old CNI binaries and configs ---"
sudo rm -f /etc/cni/net.d/10-ebpfcni.conf /opt/cni/bin/ebpfcni 2>/dev/null || true

# -------------------------------
# 6. 驗證清理結果
# -------------------------------
echo -e "\n\033[1;32m--- Final Status Check ---\033[0m"
echo "[Network links]"
ip -brief link | grep -E 'bridge|veth|cni' || echo "(clean)"
echo "[Network namespaces]"
sudo ip netns || echo "(clean)"
echo "[BPF objects]"
sudo bpftool prog show 2>/dev/null | grep process_tc || echo "(no eBPF programs left)"
echo "[BPF pin dir]"
sudo ls /sys/fs/bpf/tc/globals 2>/dev/null || echo "(empty)"

echo -e "\n\033[1;32m--- Cleanup Complete --- ✅\033[0m"

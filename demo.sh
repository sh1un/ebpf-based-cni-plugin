#!/usr/bin/env bash
set -e

# This script automates the build, install, and deployment process for testing.


# 2. Clean up old CNI files
echo "[1/3] Cleaning up old CNI files..."
sudo rm -f /etc/cni/net.d/10-ebpfcni.conf /opt/cni/bin/ebpfcni

# 3. Install new CNI files
echo "[2/3] Installing new CNI files..."
sudo cp ./bin/ebpfcni /opt/cni/bin/
sudo cp ./cni/10-ebpfcni.conf /etc/cni/net.d/
echo "  - CNI plugin and config installed."

# 4. Deploy test pods
echo "[3/3] Deploying test pods..."
kubectl apply -f k8s/manifests/test-pods.yaml

echo "--- Demo Setup Complete ---"

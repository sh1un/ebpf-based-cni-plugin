#!/usr/bin/env bash
set -e

# This script automates the build, install, and deployment process for testing.

# 1. Clean up old CNI files
echo "[1/2] Cleaning up old CNI files..."
sudo rm -f /etc/cni/net.d/10-ebpfcni.conf /opt/cni/bin/ebpfcni

# 2. Install new CNI files
echo "[2/2] Installing new CNI files..."
sudo cp ./bin/ebpfcni /opt/cni/bin/
sudo cp ./cni/10-ebpfcni.conf /etc/cni/net.d/
echo "  - CNI plugin and config installed."

echo "--- Demo Setup Complete ---"

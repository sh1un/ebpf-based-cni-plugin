# 查看目前 Node Status
kubectl get no -w

# 配置 CNI Plugin 和 config
./setup.sh

# 開啟新的 Terminal，啟用 ebpf-agent
# 於新的 Terminal 內
cd macbook/ebpf-based-cni-plugin/daemon/
export PATH=$PATH:/home/ubuntu/macbook/ebpf-based-cni-plugin/bin
sudo PATH=$PATH ./ebpf-agent.sh

# 建立 test-pods
kubectl apply -f k8s/manifests/test-pods.yaml

# 查看 BPF maps
sudo bpftool map show

# 查看 endpoint map 裡面有什麼
sudo bpftool map dump pinned /sys/fs/bpf/tc/globals/endpoint_map | jq .

# 用 fronend 向 backend 發出請求
kubectl exec frontend -- curl -s $(kubectl get pod backend -o jsonpath='{.status.podIP}')

# 開新的 terminal 查看 kernel trace buffer
sudo bpftool prog tracelog


# 建立 Network Policy，然後查看 ebpf-agent 是否 Sync
kubectl apply -f k8s/manifests/policy-allow-ingress-from-frontend.yaml

# 查看 Policy Map
sudo bpftool map dump pinned /sys/fs/bpf/tc/globals/policy_map

# 再次用 fronend 向 backend 發出請求，然後查看 tracelog
kubectl exec frontend -- curl -s $(kubectl get pod backend -o jsonpath='{.status.podIP}')

# 用 hacker 向 backend 發出請求，然後查看 tracelog
kubectl exec hacker -- curl -s $(kubectl get pod backend -o jsonpath='{.status.podIP}')

# Clean up
chmod +x force_clean_up_k8s_ebpf.sh
./force_clean_up_k8s_ebpf.sh

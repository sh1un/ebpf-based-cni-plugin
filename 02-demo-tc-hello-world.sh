#產生 vmlinux.h 的指令：
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h

# 編譯 eBPF 程式
clang -O2 -g -target bpf -Iheaders -c bpf/kernel/ebpfcni.bpf.c  -o bpf/kernel/ebpfcni.bpf.o

# Load eBPF 程式
sudo bpftool prog load bpf/kernel/ebpfcni.bpf.o /sys/fs/bpf/ebpfcni

# 把 CNI Plugin 添加 tc 指令，使其能 attach BPF Program 

# 清理舊的 CNI 配置和二進制文件
sudo rm -f /opt/cni/bin/ebpfcni

# 複製 CNI 執行檔
sudo cp cni/ebpfcni /opt/cni/bin/

# 建立一個簡單的 Pod 來測試 CNI
kubectl run nginx --image=nginx

# 查看 attach 什麼 BPF Prog
sudo bpftool net

# 建立一個 netshoot 去發出請求看看
kubectl run netshoot --image=nicolaka/netshoot -- sleep 3600

# 查看 kernel trace buffer
sudo bpftool prog tracelog



# 發出請求
kubectl exec netshoot -- curl -s $(kubectl get pod nginx -o jsonpath='{.status.podIP}')

# Clean up
./force_clean_up_k8s_ebpf.sh

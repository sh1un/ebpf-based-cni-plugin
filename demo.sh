
# 編譯 eBPF 程式
clang -O2 -g -target bpf -I/usr/include/bpf \
  -c bpf/kernel/ebpfcni.bpf.c \
  -o bpf/kernel/ebpfcni.bpf.o


# 編譯 iprules 工具
clang -O2 -g \
  -I./bpf/user \
  -c bpf/user/ebpfcni.c -o ebpfcni.o

clang -O2 -g \
  -I./bpf/user \
  ebpfcni.o -lbpf -o iprules
  
sudo cp iprules k8s/controller/
sudo chmod +x k8s/controller/iprules


# 清理舊的 CNI 配置和二進制文件
sudo rm -f /etc/cni/net.d/10-ebpfcni.conf /opt/cni/bin/ebpfcni

# 確保 CNI 目錄存在
sudo mkdir -p /opt/cni/bin
sudo mkdir -p /etc/cni/net.d

# 複製 CNI 執行檔並賦予執行權限
sudo cp cni/ebpfcni /opt/cni/bin/
sudo chmod +x /opt/cni/bin/ebpfcni

# 複製 CNI 設定檔
sudo cp cni/10-ebpfcni.conf /etc/cni/net.d/
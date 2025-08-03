# 安裝指南：在 Kubernetes 上部署基於 TC 的 eBPF CNI 插件

本指南將引導您在一個已使用 `kubeadm` 初始化的 Single node Kubernetes Cluster (Ubuntu 22.04 LTS) 上，部署一個客製化的、基於 TC (Traffic Control) 的 eBPF CNI 插件，並啟用 Network Policy 功能。

---

## 步驟 1：前置作業 - 安裝依賴與處理頭文件

首先，登入您的 EC2 實例，安裝必要的工具，並解決 eBPF 編譯時的核心頭文件問題。

> 遇到 debconf 提示時，請選擇 "OK" 繼續安裝

```bash
# 更新套件列表
sudo apt-get update

# 安裝必要的工具鏈和函式庫
sudo apt-get install -y clang llvm libelf-dev libbpf-dev libpcap-dev iproute2 jq bridge-utils wget tar build-essential make

# 安裝與當前 AWS 核心版本匹配的頭文件和工具
sudo apt-get install -y linux-headers-$(uname -r) linux-tools-aws

# 建立符號連結以解決 <asm/types.h> 找不到的問題
# 檢查連結是否已存在，避免重複建立
if [ ! -L /usr/include/asm ]; then
  sudo ln -s /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm
fi
```

---

## 步驟 2：下載專案原始碼

```bash
git clone https://github.com/sh1un/ebpf-based-cni-plugin.git
cd ebpf-based-cni-plugin/
```

---

## 步驟 3：編譯 eBPF 程式與 user space 工具

現在，我們需要編譯 eBPF 核心程式，以及用來操作 eBPF map 的 user space 工具。

### 3.1 編譯 eBPF 核心程式

```bash
# 編譯 eBPF 核心程式
clang -O2 -g -target bpf -I/usr/include/bpf \
  -c bpf/kernel/ebpfcni.bpf.c \
  -o bpf/kernel/ebpfcni.bpf.o
```

### 3.2 編譯 user space 工具 (iprules)

這個工具讓我們的 Controller 腳本可以和 eBPF map 互動。

```bash
# 編譯 iprules 工具
clang -O2 -g \
  -I./bpf/user \
  -c bpf/user/ebpfcni.c -o ebpfcni.o

clang -O2 -g \
  -I./bpf/user \
  ebpfcni.o -lbpf -o iprules
  
sudo cp iprules k8s/controller/
sudo chmod +x k8s/controller/iprules
```

---

## 步驟 4：部署 CNI 插件

將 CNI 相關的檔案複製到 Kubernetes 所需的目錄中。

### 4.1 Load eBPF 程式

```bash
# 建立 BPF 檔案系統的掛載點 (如果不存在)
sudo mkdir -p /sys/fs/bpf

# use this command if needed
# sudo rm /sys/fs/bpf/ebpfcni

# Load eBPF 程式
sudo bpftool prog load bpf/kernel/ebpfcni.bpf.o /sys/fs/bpf/ebpfcni
```

### 4.2 複製 CNI 檔案

> 重要提示: 請確保下方 10-ebpfcni.conf 檔案中的 podcidr 欄位與您執行 kubeadm init 時指定的 --pod-network-cidr 參數的子網段相符。例如，若您指定 --pod-network-cidr=10.13.0.0/16，則此處的 podcidr 應為 10.13.0.0/24。

```bash
# 確保 CNI 目錄存在
sudo mkdir -p /opt/cni/bin
sudo mkdir -p /etc/cni/net.d

# 複製 CNI 執行檔並賦予執行權限
sudo cp cni/ebpfcni /opt/cni/bin/
sudo chmod +x /opt/cni/bin/ebpfcni

# 複製 CNI 設定檔
sudo cp cni/10-ebpfcni.conf /etc/cni/net.d/
```

---

## 步驟 5：部署並運行 Network Policy Controller

現在，我們需要運行一個 Controller 來監聽 Kubernetes 的 NetworkPolicy 物件，並將規則同步到 eBPF map。

```bash
# 賦予 Controller 腳本執行權限
chmod +x k8s/controller/network_policy_controller.sh

# 在背景運行 Controller ，並將日誌輸出到檔案
# 使用 nohup 確保即使您登出，Controller 也能繼續運行
sudo nohup ./k8s/controller/network_policy_controller.sh > /var/log/np-controller.log 2>&1 &
```

> 推薦再開一個新的 Terminal，執行 `tail -f /var/log/np-controller.log`

---

## 步驟 6：驗證 Network Policy 功能

在 Controller 運行後，您的 Network Policy 應該就能生效了。

### 6.1 建立 client & server Pods

```bash
kubectl apply -f k8s/manifests/test-pods.yaml
```

### 6.2 驗證是否成功分配 IP address 給 Pods

```bash
kubectl get pod -o wide
```

### 6.3 驗證「預設全部不允許」

因為我們的 eBPF 程式現在預設丟棄所有封包，所以在沒有任何「允許」策略的情況下，連線應該是失敗的。

```bash
SERVER_IP=$(kubectl get po server  -o json | jq -r '.status.podIP')

kubectl exec client -- curl -s --connect-timeout 5 $SERVER_IP
```

```bash
# 查看 NetworkPolicyController logs:
tail -10 /var/log/np-controller.log
```

6.4 驗證「明確允許」Policy

```bash
kubectl apply -f k8s/manifests/policy-allow-client.yaml
```

等待幾秒鐘讓 Controller 反應 (最多 10 秒)。

```bash
# 最終測試連線 (應該會成功！)
kubectl exec client -- curl -s --connect-timeout 5 $SERVER_IP

```

您應該會看到 Nginx 的歡迎頁面。這證明了從 eBPF 數據平面到 Controller 控制平面的完整流程已成功運作。

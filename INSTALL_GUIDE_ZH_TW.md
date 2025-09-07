# 安裝指南：使用 libbpf 與 CO-RE 的 eBPF CNI Plugin

本指南將引導您如何在 Kubernetes 節點 (例如：Ubuntu 22.04 LTS) 上，編譯並部署一個使用 `libbpf` 與 CO-RE 技術的現代化 eBPF CNI Plugin。

---

## 步驟 1：環境準備

在您的建置環境中，安裝必要的編譯工具與函式庫。

```bash
sudo apt update
sudo apt install -y build-essential clang libelf-dev libbpf-dev bpftool libnl-3-dev libnl-genl-3-dev
```

---

## 步驟 2：下載並編譯專案

1.  **下載專案原始碼**

    ```bash
    git clone https://github.com/sh1un/ebpf-based-cni-plugin.git
    cd ebpf-based-cni-plugin/
    ```

2.  **編譯 CNI Plugin**

    專案使用 `Makefile` 來自動化整個建置流程。只需一個指令即可完成所有編譯工作，包含產生 `vmlinux.h`、編譯 eBPF 核心程式、產生 BPF skeleton，以及最終編譯出 CNI 執行檔。

    ```bash
    make
    ```

    編譯成功後，您會在 `build/` 目錄下找到名為 `ebpfcni` 的執行檔。

---

## 步驟 3：部署 CNI Plugin

1.  **安裝 CNI 執行檔**

    `Makefile` 也提供了方便的安裝指令，它會將編譯好的 `ebpfcni` 執行檔複製到 Kubernetes 的 CNI 目錄 (`/opt/cni/bin/`)。

    ```bash
    sudo make install
    ```

2.  **建立 CNI 設定檔**

    在 `/etc/cni/net.d/` 目錄下建立一個設定檔，例如 `10-ebpfcni.conf`。

    ```bash
    sudo mkdir -p /etc/cni/net.d
    ```

    將以下 JSON 內容寫入檔案：

    ```json
    {
      "cniVersion": "0.4.0",
      "name": "ebpfcni",
      "type": "ebpfcni"
    }
    ```

3.  **重啟容器執行環境 (Container Runtime)**

    為了讓新的 CNI Plugin 生效，您需要重啟節點上的容器執行環境，例如 `containerd` 或 `cri-o`。

    ```bash
    # 如果您使用 containerd
    sudo systemctl restart containerd

    # 如果您使用 cri-o
    # sudo systemctl restart crio
    ```

---

## 步驟 4：驗證

部署完成後，您可以透過建立新的 Pod 來驗證 CNI Plugin 是否正常運作。Pod 應該能被成功指派 IP 位址並啟動。

```bash
# 建立一個測試用的 Pod
kubectl run test-pod --image=nginx

# 檢查 Pod 狀態與 IP
kubectl get pod test-pod -o wide

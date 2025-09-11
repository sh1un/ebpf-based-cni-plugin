# CNI Plugin 運作原理：Shell 指令等價轉換

本文件旨在將我們以 Golang 撰寫的 eBPF CNI Plugin 的核心網路設定邏輯，轉換為等價的 Linux Shell 指令。這有助於熟悉 Linux 但不熟悉 Golang 的開發者，透過他們熟悉的指令來理解 CNI Plugin 的實際運作流程。

## 1. 環境變數設定

為了方便說明，我們先定義一些在後續指令中會用到的變數：

```bash
# Pod 的網路命名空間路徑 (由 CRI runtime 提供)
# 範例: /var/run/netns/cni-b8f574a-c108-a1a7-4631-7d233a04848b
export CONTAINER_NS_PATH="<path_to_container_netns>"

# 容器內的網路介面名稱 (由 CNI 設定檔或 runtime 提供)
export IFNAME="eth0"

# CNI Plugin 在主機端建立的 veth 名稱，通常與容器 ID 相關
# 我們的 Plugin 使用 "veth" + 前 8 碼 ContainerID
export HOST_VETH_NAME="veth12345678"

# 網橋名稱
export BRIDGE_NAME="cni0"

# 由 IPAM Plugin 分配到的 IP/Mask
export IP_ADDR="10.22.0.5/24"

# 預設閘道
export GATEWAY="10.22.0.1"

# eBPF TC 程式掛載的路徑
export BPF_PIN_PATH="/sys/fs/bpf/tc/globals"
```

## 2. Bridge (網橋) 設定 (`setupBridge`)

CNI Plugin 首先需要確保有一個網橋存在，用來連接所有容器在主機端的 veth。

**Golang 邏輯**:
- 檢查名為 `cni0` 的網橋是否存在。
- 如果不存在，就建立一個新的網橋。
- 啟用該網橋。

**等價 Shell 指令**:

```bash
# 1. 建立網橋 (如果不存在)
# `ip link add` 如果裝置已存在會報錯，所以可以先檢查或直接刪除
ip link show $BRIDGE_NAME > /dev/null 2>&1 || ip link add name $BRIDGE_NAME type bridge

# 2. 啟用網橋
ip link set $BRIDGE_NAME up
```

## 3. Veth Pair (虛擬網路介面) 設定 (`setupVeth`)

接著，Plugin 會建立一對 veth pair。一端會留在主機端 (Host)，另一端會被移入容器的網路命名空間。

**Golang 邏輯**:
- 建立一個 veth pair (`veth...` <=> `eth0`)。
- 將主機端的 veth (`veth...`) 連接到網橋 `cni0`。
- 啟用主機端的 veth。
- 將容器端的 veth (`eth0`) 移入容器的網路命名空間。
- 進入容器的網路命名空間，並啟用 `eth0`。

**等價 Shell 指令**:

```bash
# 1. 建立 veth pair
ip link add $IFNAME type veth peer name $HOST_VETH_NAME

# 2. 將主機端的 veth 連接到網橋
ip link set $HOST_VETH_NAME master $BRIDGE_NAME

# 3. 啟用主機端的 veth
ip link set $HOST_VETH_NAME up

# 4. 將容器端的 veth 移入容器的網路命名空間
ip link set $IFNAME netns $CONTAINER_NS_PATH

# 5. 進入容器網路命名空間，設定容器內的介面
ip netns exec $CONTAINER_NS_PATH bash -c "
  # 啟用 lo 介面
  ip link set lo up

  # 啟用 eth0 介面
  ip link set $IFNAME up
"
```

## 4. IPAM 與容器網路設定

在設定好 L2 網路後，Plugin 會呼叫 IPAM (IP Address Management) Plugin 來取得 IP 位址，並在容器內設定 L3 網路。

**Golang 邏輯**:
- 執行 IPAM Plugin，取得 IP、Gateway 等資訊。
- 進入容器的網路命名空間。
- 將 IP 位址指派給 `eth0`。
- 設定預設路由 (Default Route)。

**等價 Shell 指令**:

```bash
# 假設 IPAM 已回傳 IP_ADDR 和 GATEWAY
# 進入容器網路命名空間進行設定
ip netns exec $CONTAINER_NS_PATH bash -c "
  # 1. 為 eth0 設定 IP 位址
  ip addr add $IP_ADDR dev $IFNAME

  # 2. 設定預設路由
  ip route add default via $GATEWAY
"
```

## 5. eBPF 核心機制：Map 建立與程式掛載

這是我們 Plugin 的靈魂，它無法直接用 Shell 指令表達，因為牽涉到使用者空間程式與 Linux 核心的互動。以下我們將這個過程拆解說明：

### 步驟 5a: 在 C 程式碼中「定義」Maps

首先，eBPF Maps 的結構、類型、大小等屬性，是在 eBPF 的 C 原始碼 (`bpf/kernel/ebpfcni.bpf.c`) 中被「定義」出來的，像是一個藍圖。

```c
// bpf/kernel/ebpfcni.bpf.c

// endpoint_map: 儲存 Pod IP -> 安全性 ID 的對應
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u32);
} endpoint_map SEC(".maps");

// policy_map: 儲存允許通訊的來源 ID -> 目的 ID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct policy_key);
    __type(value, __u8);
} policy_map SEC(".maps");
```

### 步驟 5b: 使用者空間程式「載入」並「建立」Maps

接著，我們的 Golang CNI Plugin (作為使用者空間程式) 會讀取編譯好的 eBPF 字節碼，解析出上述的 Map 定義，然後透過 `bpf(2)` 系統呼叫，請求核心根據定義**建立 Maps**。這個過程由 `cilium/ebpf` 函式庫的 `loadBpfObjects()` 函式觸發。

### 步驟 5c: 「釘選」(Pinning) Maps 以實現共享與持久化

核心建立的 eBPF Map 預設會隨著建立它的程式結束而消失。為了讓 Map 在所有 Pod 之間共享，並且不受 CNI Plugin 生命週期的影響，我們需要將它「釘選」到 BPF 虛擬檔案系統上。這就像是為核心中的 Map 在檔案系統上建立一個「捷徑」。

**Golang 邏輯 (概念)**:

```go
// pinObject 函式檢查「捷徑」是否存在，若不存在才建立
func pinObject(map, path) {
  // 檢查「捷徑」是否已存在
  if file.Exists(path) {
    // 已存在，代表第一個 Pod 已經釘選過了，直接跳過
    log("Map already pinned, skipping.")
    return
  }
  // 不存在，就建立「捷徑」，將 Map 和路徑綁定
  map.Pin(path)
  log("Successfully pinned map.")
}

// 在 cmdAdd 中呼叫，這個行為是冪等的 (idempotent)
pinObject(objs.EndpointMap, "/sys/fs/bpf/tc/globals/endpoint_map")
pinObject(objs.PolicyMap, "/sys/fs/bpf/tc/globals/policy_map")
pinObject(objs.ProcessTc, "/sys/fs/bpf/tc/globals/tc_prog")
```
這個設計確保了 eBPF Maps 在整個叢集中只會被**建立一次**，之後的所有 CNI 操作都是在存取和更新**同一個**被釘選的 Map。

---

接下來的 Shell 指令，我們就**假設**上述的 Go 程式已經成功執行，並且將 eBPF 程式和 Maps 釘選到了 `$BPF_PIN_PATH` 目錄下。

### 步驟 5d: 掛載 eBPF 程式到網路介面

**等價 Shell 指令**:

```bash
# 1. 確保 BPF Pinning 的目錄存在
mkdir -p $BPF_PIN_PATH

# 2. 在主機端的 veth 上新增 clsact qdisc (佇列規則)
# `clsact` 是一個特殊的 qdisc，專門用來掛載 eBPF filter
# `tc` 指令如果發現已存在，會回報錯誤，但我們可以忽略
tc qdisc add dev $HOST_VETH_NAME clsact

# 4. 將 eBPF 程式掛載到 ingress (入口流量)
tc filter replace dev $HOST_VETH_NAME ingress bpf da pinned $BPF_PIN_PATH/tc_prog

# 5. 將 eBPF 程式掛載到 egress (出口流量)
tc filter replace dev $HOST_VETH_NAME egress bpf da pinned $BPF_PIN_PATH/tc_prog
```

## 6. 清理 (`cmdDel`)

當容器被刪除時，CNI `DEL` 命令會被觸發，Plugin 需要清理先前建立的資源。

**Golang 邏輯**:
- 刪除主機端的 veth 介面 (這會自動刪除另一端的 veth 並將其從網橋上移除)。
- 呼叫 IPAM Plugin 釋放 IP 位址。

**等價 Shell 指令**:

```bash
# 1. 刪除主機端的 veth 介面
# 由於 veth 是成對的，刪除一端會自動移除另一端
ip link del $HOST_VETH_NAME

# 2. (省略) 呼叫 IPAM Plugin 釋放 IP
# 這同樣是執行另一個二進位檔的過程

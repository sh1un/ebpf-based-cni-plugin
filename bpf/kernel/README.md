# eBPF 網路政策程式 (`ebpfcni.bpf.c`)

這份文件旨在以高層次的方式，解釋 `ebpfcni.bpf.c` 這個 eBPF 程式的運作原理。本程式被掛載到網路設備的 TC (Traffic Control) 層，用來實現 Pod 之間的網路隔離政策。

## 功能總覽

此 BPF 程式的核心功能是**基於身份的網路政策執行**。它攔截進出 Pod 的網路封包，並根據預先定義的規則來決定是**允許 (ALLOW)** 還是**丟棄 (DROP)** 該封包。

整個系統採用**預設拒絕 (Default-Deny)** 的策略，也就是說，除非有明確的規則允許通訊，否則所有流量都會被阻擋。

## 核心資料結構 (BPF Maps)

為了實現上述功能，我們使用了兩個 BPF Map 來儲存狀態：

### 1. `endpoint_map`

- **用途**：儲存 Pod IP 位址到其「安全身份 (Security Identity)」的對應關係。安全身份是一個獨一無二的數字 ID，用來代表一個或一組擁有相同標籤 (Label) 的 Pod。
- **好比**：一個公司的員工名錄，你可以用員工的座位號（IP 位址）查到他屬於哪個部門（安全身份 ID）。
- **結構**：
  - `Key`: `Pod 的 IP 位址`
  - `Value`: `安全身份 ID (一個數字)`

```c
// endpoint_map 儲存 Pod IP 位址到其安全身份的對應。
// Key: __u32 (Pod IP)
// Value: __u32 (安全身份 ID)
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u32);
} endpoint_map SEC(".maps");
```

### 2. `policy_map`

- **用途**：儲存被允許的通訊規則。它定義了哪些「來源身份」可以跟哪些「目標身份」通訊。
- **好比**：公司的門禁規則表，上面寫著「IT 部門的員工（來源身份）可以進入機房（目標身份）」。
- **結構**：
  - `Key`: `{ 來源身份 ID, 目標身份 ID }`
  - `Value`: `動作 (例如：1 代表允許)`

```c
// policy_map 儲存允許通訊的規則。
// Key: struct policy_key { u32 來源身份; u32 目標身份; }
// Value: u8 (動作, 例如 1 代表允許)
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct policy_key);
    __type(value, __u8);
} policy_map SEC(".maps");
```

## 程式邏輯

當一個網路封包觸發這個 BPF 程式時，會執行以下邏輯：

### 步驟 1: 預先檢查

我們只關心 IPv4 流量。對於 ARP 或其他非 IP 封包，直接放行，以確保網路基本功能正常。

```c
// 取得封包資料的起始與結束位置
void *data_end = (void *)(long)skb->data_end;
void *data = (void *)(long)skb->data;
struct ethhdr *eth = data;

// 檢查封包長度是否足以包含乙太網路標頭
if (data + sizeof(*eth) > data_end)
{
    return TC_ACT_OK; // 長度不足，直接放行
}
// 如果協定不是 IP (例如 ARP)，直接放行
if (eth->h_proto != bpf_htons(ETH_P_IP))
{
    return TC_ACT_OK;
}
```

### 步驟 2: 識別來源與目標

從封包中解析出來源與目標 IP，並用它們去 `endpoint_map` 中查找對應的安全身份 ID。

```c
// 解析 IP 標頭
struct iphdr *iph = data + sizeof(*eth);
if (data + sizeof(*eth) + sizeof(*iph) > data_end)
{
    return TC_ACT_OK; // 長度不足，直接放行
}

// 取得來源與目標 IP
__u32 src_ip = bpf_ntohl(iph->saddr);
__u32 dst_ip = bpf_ntohl(iph->daddr);

// 查詢來源 IP 的身份
__u32 *src_id = bpf_map_lookup_elem(&endpoint_map, &src_ip);
if (!src_id)
{
    // 在 map 中找不到，代表是未知的來源，丟棄封包
    return TC_ACT_SHOT;
}

// 查詢目標 IP 的身份
__u32 *dst_id = bpf_map_lookup_elem(&endpoint_map, &dst_ip);
if (!dst_id)
{
    // 在 map 中找不到，代表是未知的目標，丟棄封包
    return TC_ACT_SHOT;
}
```

### 步驟 3: 執行政策

根據查到的兩個身份 ID，去 `policy_map` 中查詢是否存在允許的規則。

```c
// 組合出 policy_map 的查詢 key
struct policy_key pkey = {
    .src_id = *src_id,
    .dst_id = *dst_id,
};

// 查詢是否存在允許的規則
__u8 *action = bpf_map_lookup_elem(&policy_map, &pkey);
if (action && *action == ACTION_ALLOW)
{
    // 找到允許規則，放行封包
    return TC_ACT_OK;
}

// 預設拒絕：沒有找到任何允許規則，因此丟棄封包
return TC_ACT_SHOT;
```

---

## 補充：eBPF TC 程式極簡範例

對於剛接觸 eBPF 的開發者，這裡提供一個最基礎的 TC BPF 程式範例。它的功能非常單純：

1.  解析收到的網路封包，判斷是否為 IPv4。
2.  如果是，就透過 `bpf_printk` 印出來源與目的 IP 位址（這些訊息可以透過 `cat /sys/kernel/debug/tracing/trace_pipe` 查看）。
3.  無論如何，最後都無條件放行 (`TC_ACT_OK`) 所有封包。

這個範例有助於理解 TC BPF 程式的基本結構與運作方式。

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

// 定義 TC 程式的 section
SEC("tc")
int simple_tc_parser(struct __sk_buff *skb)
{
    // 取得封包資料的起始與結束位置
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;


    // 檢查是否為 IPv4 封包
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_SHOT; // 不是 IPv4，DROP
    }


    // 印出封包資訊
    bpf_printk("TC: Got a packet from 0x%x to 0x%x",
               bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr));

    // 條件放行所有封包
    return TC_ACT_OK;
}
```

產生 vmlinux.h 的指令:

```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h
```

編譯 C 為 eBPF bytecode 的指令:

```bash
clang -O2 -g -target bpf -Iheaders -c bpf/kernel/ebpfcni.bpf.c  -o bpf/kernel/ebpfcni.bpf.o
```

Load eBPF 程式:

```bash
sudo rm /sys/fs/bpf/ebpfcni
sudo bpftool prog load bpf/kernel/ebpfcni.bpf.o /sys/fs/bpf/ebpfcni
```

- BPF 文件：https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SCHED_CLS/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

char _license[] SEC("license") = "GPL";

// 定義 TC 程式的 section
SEC("tc")
int simple_tc_parser(struct __sk_buff *skb)
{
    // 取得封包資料的起始與結束位置
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    struct iphdr *iph = data + sizeof(*eth);

    // 邊界檢查，避免讀超過封包長度
    if ((void *)iph + sizeof(*iph) > data_end)
        return TC_ACT_SHOT;

    // 印出封包資訊
    bpf_printk("TC: Got a packet from 0x%x to 0x%x",
               bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr));

    // 條件放行所有封包
    return TC_ACT_OK;
}
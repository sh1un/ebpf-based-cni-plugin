#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>

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

    // 檢查邊界
    if ((void *)iph + sizeof(*iph) > data_end)
    {
        return TC_ACT_SHOT;
    }

    // 檢查是否為 IPv4 封包
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return TC_ACT_OK; // 不是 IPv4，放行
    }

    // 印出封包資訊
    bpf_printk("TC: Got a packet from 0x%x to 0x%x",
               bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr));

    // 放行封包
    return TC_ACT_OK;
}

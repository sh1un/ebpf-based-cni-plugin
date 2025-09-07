#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf/bpf_tc_consts.h"

char _license[] SEC("license") = "GPL";

struct ip_rule
{
    __u32 src_ip;
    __u32 dst_ip;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ip_rule);
    __type(value, __u32);
} iprules SEC(".maps");

SEC("tc")
int process_tc(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
    {
        return TC_ACT_OK;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return TC_ACT_OK;
    }

    struct iphdr *iph = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*iph) > data_end)
    {
        return TC_ACT_OK;
    }

    // Key is in network byte order, directly from the packet
    struct ip_rule rule = {
        .src_ip = iph->saddr,
        .dst_ip = iph->daddr,
    };

    __u32 *action;
    action = bpf_map_lookup_elem(&iprules, &rule);
    if (action)
    {
        if (*action == 1)
        { // 1 = allow
            return TC_ACT_OK;
        }
        else
        { // 0 = deny
            return TC_ACT_SHOT;
        }
    }

    // Default deny
    return TC_ACT_SHOT;
}

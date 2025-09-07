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

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32); // local_ip
} local_cfg SEC(".maps");

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

    // --- Ingress Policy Logic ---
    // Only apply policy if the destination IP is the local Pod's IP.
    __u32 key = 0;
    __u32 *local_ip = bpf_map_lookup_elem(&local_cfg, &key);
    if (!local_ip)
    {
        // If local_ip is not configured, allow all traffic to avoid black-holing.
        return TC_ACT_OK;
    }

    // The IP addresses in the packet are in network byte order (big-endian).
    // The local_ip from the map is in host byte order (little-endian on x86).
    // We must convert the packet's destination IP to host byte order for a correct comparison.
    if (bpf_ntohl(iph->daddr) != *local_ip)
    {
        // Not our packet, let it pass.
        return TC_ACT_OK;
    }

    // Key is in network byte order, directly from the packet
    struct ip_rule rule = {
        .src_ip = iph->saddr,
        .dst_ip = iph->daddr,
    };

    bpf_printk("LOOKUP ifindex=%d src=%x dst=%x\n", skb->ifindex, rule.src_ip, rule.dst_ip);

    __u32 *action;
    action = bpf_map_lookup_elem(&iprules, &rule);
    if (action)
    {
        if (*action == 1)
        { // 1 = allow
            bpf_printk("ALLOW ifindex=%d %x -> %x\n", skb->ifindex, rule.src_ip, rule.dst_ip);
            return TC_ACT_OK;
        }
        else
        { // 0 = deny
            bpf_printk("DENY ifindex=%d %x -> %x\n", skb->ifindex, rule.src_ip, rule.dst_ip);
            return TC_ACT_SHOT;
        }
    }

    // Default deny
    bpf_printk("DENY (default) ifindex=%d %x -> %x\n", skb->ifindex, rule.src_ip, rule.dst_ip);
    return TC_ACT_SHOT;
}

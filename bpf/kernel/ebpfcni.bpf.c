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
    bpf_printk("TC PROG HIT: ifindex=%d\n", skb->ifindex);
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

    // --- Host-Order IP Conversion & Comparison ---
    // Convention: All comparisons are done in host byte order.
    __u32 pkt_saddr_host = bpf_ntohl(iph->saddr);
    __u32 pkt_daddr_host = bpf_ntohl(iph->daddr);
    __u32 local_ip_host = *local_ip;

    bpf_printk("CHECK local match: pkt_daddr_host=%x local_ip_host=%x (host order)\n", pkt_daddr_host, local_ip_host);
    if (pkt_daddr_host != local_ip_host)
    {
        // Not our packet, let it pass.
        bpf_printk("NOT local pod, allow. pkt_daddr_host=%x, local_ip_host=%x\n", pkt_daddr_host, local_ip_host);
        return TC_ACT_OK;
    }

    bpf_printk("LOCAL pod traffic, check iprules...\n");

    // --- Policy Lookup ---
    // Key is constructed in host byte order.
    struct ip_rule rule = {
        .src_ip = pkt_saddr_host,
        .dst_ip = pkt_daddr_host,
    };

    bpf_printk("LOOKUP (host order) ifindex=%d src=%x dst=%x\n", skb->ifindex, rule.src_ip, rule.dst_ip);

    __u32 *action;
    action = bpf_map_lookup_elem(&iprules, &rule);
    if (action)
    {
        bpf_printk("DEBUG: Found rule in iprules map with value: %d\n", *action);
        if (*action == 1)
        { // 1 = allow
            bpf_printk("ALLOW (host order) ifindex=%d %x -> %x\n", skb->ifindex, rule.src_ip, rule.dst_ip);
            return TC_ACT_OK;
        }
        else
        { // 0 = deny
            bpf_printk("DENY (host order) ifindex=%d %x -> %x\n", skb->ifindex, rule.src_ip, rule.dst_ip);
            return TC_ACT_SHOT;
        }
    }
    else
    {
        bpf_printk("NO rule, DEFAULT DENY (host order) %x -> %x\n", rule.src_ip, rule.dst_ip);
        return TC_ACT_SHOT;
    }

    // Fallback deny, should not be reached.
    return TC_ACT_SHOT;
}

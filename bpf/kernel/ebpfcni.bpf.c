#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf/bpf_tc_consts.h"
#include "api.h"

#define ACTION_ALLOW 1

char _license[] SEC("license") = "GPL";

// endpoint_map stores the mapping from a Pod's IP address to its security identity.
// Key: __u32 (Pod IP in host-byte order)
// Value: __u32 (Security Identity)
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u32);
} endpoint_map SEC(".maps");

// policy_map stores the allowed communication paths between security identities.
// Key: struct policy_key { __u32 src_id; __u32 dst_id; }
// Value: __u8 (Action, e.g., 1 for allow)
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct policy_key);
    __type(value, __u8);
} policy_map SEC(".maps");

SEC("tc")
int process_tc(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    // 1. L2 / Non-IPv4 Handling
    // Immediately allow non-IPv4 traffic (e.g., ARP, IPv6 Neighbor Discovery).
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

    // 2. Identity Lookup
    // Convert packet IPs to host-byte order for map lookups.
    __u32 src_ip = bpf_ntohl(iph->saddr);
    __u32 dst_ip = bpf_ntohl(iph->daddr);

    __u32 *src_id = bpf_map_lookup_elem(&endpoint_map, &src_ip);
    if (!src_id)
    {
        bpf_printk("TC: DROP src IP %x not in endpoint_map\n", src_ip);
        return TC_ACT_SHOT;
    }

    __u32 *dst_id = bpf_map_lookup_elem(&endpoint_map, &dst_ip);
    if (!dst_id)
    {
        bpf_printk("TC: DROP dst IP %x not in endpoint_map\n", dst_ip);
        return TC_ACT_SHOT;
    }

    bpf_printk("TC: HIT from %x (id=%u) to %x (id=%u)\n", src_ip, *src_id, dst_ip, *dst_id);

    // 3. Policy Enforcement
    struct policy_key pkey = {
        .src_id = *src_id,
        .dst_id = *dst_id,
    };

    __u8 *action = bpf_map_lookup_elem(&policy_map, &pkey);
    if (action && *action == ACTION_ALLOW)
    {
        bpf_printk("TC: ALLOW id %u -> id %u\n", pkey.src_id, pkey.dst_id);
        return TC_ACT_OK;
    }

    // Default-deny: If no explicit allow rule is found, drop the packet.
    bpf_printk("TC: DENY id %u -> id %u (no rule)\n", pkey.src_id, pkey.dst_id);
    return TC_ACT_SHOT;
}

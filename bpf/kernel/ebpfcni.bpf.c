#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// Manually define constants to avoid header conflicts with vmlinux.h
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define ETH_P_IP 0x0800

#define MAX_ENTRIES 1024

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} counter SEC(".maps");

struct ip_pair
{
    __u32 saddr;
    __u32 daddr;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct ip_pair);
    __type(value, int);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} iprules SEC(".maps");

SEC("tc")
int process_tc(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;

    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end)
        return TC_ACT_OK;

    bpf_printk("tc: got packet from %x to %x", bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr));

    __u32 src_ip_key = iph->saddr;
    __u64 *value;

    value = bpf_map_lookup_elem(&counter, &src_ip_key);
    if (value)
    {
        (*value)++;
    }
    else
    {
        __u64 one = 1;
        bpf_map_update_elem(&counter, &src_ip_key, &one, BPF_NOEXIST);
    }

    // Logic for blocking traffic conditionally

    // The key is the pair source-addr IP and the value is a boolean 0/no allow 1/allowed
    struct ip_pair ip_pair_key;
    ip_pair_key.saddr = bpf_ntohl(iph->saddr);
    ip_pair_key.daddr = bpf_ntohl(iph->daddr);
    int *value_ip_pair;

    value_ip_pair = bpf_map_lookup_elem(&iprules, &ip_pair_key);
    if (value_ip_pair)
    {
        // Rule exists, check if it's an allow (1) or deny (0) rule
        if (*value_ip_pair == 1)
        {
            return TC_ACT_OK; // Allow
        }
        else
        {
            return TC_ACT_SHOT; // Deny
        }
    }

    // Default action: if no rule is found, drop the packet.
    // The controller is responsible for adding rules.
    return TC_ACT_SHOT;
}
char _license[] SEC("license") = "GPL";

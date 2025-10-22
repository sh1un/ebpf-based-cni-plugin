#ifndef __EBPFCNI_API_H
#define __EBPFCNI_API_H

// PolicyKey defines the key for the policy map.
// It uses explicit padding to ensure a fixed size and prevent compiler-dependent variations.
struct policy_key
{
    unsigned int src_id;
    unsigned int dst_id;
};

#endif /* __EBPFCNI_API_H */

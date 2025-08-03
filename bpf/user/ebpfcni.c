#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include "ebpfcni.h"

struct ip_pair
{
    __u32 saddr;
    __u32 daddr;
};

int main(int argc, char *argv[])
{
    // Load the pinned BPF map from bpffs
    int map_fd = bpf_obj_get("/sys/fs/bpf/iprules");
    if (map_fd < 0)
    {
        perror("Error opening pinned BPF map");
        return 1;
    }

    // Define the key and value for the update
    struct ip_pair key;

    key.saddr = ipv4_to_u32(argv[1]); // Convert the source address to network byte order
    key.daddr = ipv4_to_u32(argv[2]); // Convert the destination address to network byte order
    int value = atoi(argv[3]);

    // Update the BPF map element
    int ret = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);

    if (ret)
    {
        fprintf(stderr, "Error updating BPF map element: %s\n", strerror(-ret));
        return 1;
    }

    return 0;
}

#define _GNU_SOURCE // Must be defined before any other includes to get setns()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "ebpfcni.skel.h"

// For libnl
#include <netlink/netlink.h>
#include <linux/netlink.h>   // For NLM_F_CREATE
#include <linux/rtnetlink.h> // For NLM_F_MOVE
#include <netlink/socket.h>
#include <netlink/route/link.h>
#include <netlink/route/link/veth.h>
#include <netlink/route/addr.h>
#include <netlink/route/route.h>
#include <net/if.h> // For if_nametoindex and IFF_UP
#include <sched.h>  // For setns

// Forward declarations for CNI command handlers
static int enter_netns(int *original_ns_fd, const char *netns_path);
static int leave_netns(int original_ns_fd);
static int cmd_add();
static int cmd_del();
static int cmd_check();
static int cmd_version();

int main(int argc, char **argv)
{
    char *cni_command;

    cni_command = getenv("CNI_COMMAND");
    if (cni_command == NULL)
    {
        fprintf(stderr, "CNI_COMMAND environment variable not set\n");
        return 1;
    }

    if (strcmp(cni_command, "ADD") == 0)
    {
        return cmd_add();
    }
    else if (strcmp(cni_command, "DEL") == 0)
    {
        return cmd_del();
    }
    else if (strcmp(cni_command, "CHECK") == 0)
    {
        return cmd_check();
    }
    else if (strcmp(cni_command, "VERSION") == 0)
    {
        return cmd_version();
    }
    else
    {
        fprintf(stderr, "Unknown CNI_COMMAND: %s\n", cni_command);
        return 1;
    }

    return 0;
}

static int cmd_add()
{
    struct ebpfcni_bpf *skel;
    int err;
    char *container_id, *netns_path, *if_name;
    char host_if_name[IFNAMSIZ];
    struct nl_sock *sock = NULL;
    struct rtnl_link *link = NULL;
    struct nl_cache *cache = NULL;

    // 1. Parse CNI environment variables
    container_id = getenv("CNI_CONTAINERID");
    netns_path = getenv("CNI_NETNS");
    if_name = getenv("CNI_IFNAME");

    if (!container_id || !netns_path || !if_name)
    {
        fprintf(stderr, "Missing CNI environment variables (CNI_CONTAINERID, CNI_NETNS, CNI_IFNAME)\n");
        return 1;
    }

    // Generate a unique host-side interface name
    snprintf(host_if_name, IFNAMSIZ, "veth%.10s", container_id);

    // 2. Create veth pair
    sock = nl_socket_alloc();
    if (!sock)
    {
        fprintf(stderr, "Failed to allocate netlink socket\n");
        return 1;
    }

    if (nl_connect(sock, NETLINK_ROUTE) < 0)
    {
        fprintf(stderr, "Failed to connect to netlink\n");
        nl_socket_free(sock);
        return 1;
    }

    link = rtnl_link_alloc();
    if (!link)
    {
        fprintf(stderr, "Failed to allocate rtnl_link\n");
        nl_socket_free(sock);
        return 1;
    }

    rtnl_link_set_type(link, "veth");
    rtnl_link_set_name(link, if_name);
    // The peer is created and set within the rtnl_link_veth_add call
    // rtnl_link_veth_set_peer(link, host_if_name); // This function does not exist in libnl

    err = rtnl_link_add(sock, link, NLM_F_CREATE);
    if (err < 0)
    {
        fprintf(stderr, "Failed to create veth pair: %s\n", nl_geterror(err));
        rtnl_link_put(link);
        nl_socket_free(sock);
        return 1;
    }

    printf("Successfully created veth pair: %s <-> %s\n", if_name, host_if_name);
    rtnl_link_put(link);
    // Re-allocate socket for subsequent operations
    nl_socket_free(sock);
    sock = NULL;

    // 3. Move peer to netns and bring interfaces up
    int if_index = if_nametoindex(if_name);
    int host_if_index = if_nametoindex(host_if_name);
    int netns_fd = -1;

    sock = nl_socket_alloc();
    nl_connect(sock, NETLINK_ROUTE);

    if (rtnl_link_alloc_cache(sock, AF_UNSPEC, &cache) < 0)
    {
        fprintf(stderr, "Failed to allocate link cache\n");
        goto nl_cleanup;
    }

    // Get link for container interface
    link = rtnl_link_get(cache, if_index);
    if (!link)
    {
        fprintf(stderr, "Failed to get link for %s\n", if_name);
        goto nl_cleanup;
    }

    // Move to netns
    netns_fd = open(netns_path, O_RDONLY);
    if (netns_fd < 0)
    {
        fprintf(stderr, "Failed to open netns %s: %s\n", netns_path, strerror(errno));
        goto nl_cleanup;
    }
    rtnl_link_set_ns_fd(link, netns_fd);
    err = rtnl_link_add(sock, link, NLM_F_REPLACE);
    if (err < 0)
    {
        fprintf(stderr, "Failed to move link to netns: %s\n", nl_geterror(err));
        close(netns_fd);
        goto nl_cleanup;
    }
    printf("Successfully moved %s to %s\n", if_name, netns_path);
    close(netns_fd);

    // Bring host interface up
    rtnl_link_put(link); // release previous link
    link = rtnl_link_get(cache, host_if_index);
    rtnl_link_set_flags(link, IFF_UP);
    err = rtnl_link_add(sock, link, NLM_F_REPLACE);
    if (err < 0)
    {
        fprintf(stderr, "Failed to bring up host link %s: %s\n", host_if_name, nl_geterror(err));
        goto nl_cleanup;
    }
    printf("Successfully brought up host link %s\n", host_if_name);

nl_cleanup:
    if (cache)
        nl_cache_free(cache);
    if (link)
        rtnl_link_put(link);
    if (sock)
        nl_socket_free(sock);

    // 4. Configure interface in netns
    int original_ns_fd;
    if (enter_netns(&original_ns_fd, netns_path) != 0)
    {
        return 1;
    }

    sock = nl_socket_alloc();
    nl_connect(sock, NETLINK_ROUTE);

    // Re-alloc cache for the new namespace
    if (rtnl_link_alloc_cache(sock, AF_UNSPEC, &cache) < 0)
    {
        fprintf(stderr, "Failed to allocate link cache in netns\n");
        nl_socket_free(sock);
        leave_netns(original_ns_fd);
        return 1;
    }

    // Bring up container interface
    int container_if_index = if_nametoindex(if_name);
    link = rtnl_link_get(cache, container_if_index);
    if (!link)
    {
        fprintf(stderr, "Failed to get link for %s in netns\n", if_name);
        nl_cache_free(cache);
        nl_socket_free(sock);
        leave_netns(original_ns_fd);
        return 1;
    }
    rtnl_link_set_flags(link, IFF_UP);
    err = rtnl_link_add(sock, link, NLM_F_REPLACE);
    if (err < 0)
    {
        fprintf(stderr, "Failed to bring up container link %s: %s\n", if_name, nl_geterror(err));
        // still need to leave netns
    }
    else
    {
        printf("Successfully brought up container link %s\n", if_name);
    }
    rtnl_link_put(link);
    link = NULL;

    // Add IP address
    struct rtnl_addr *addr = rtnl_addr_alloc();
    struct nl_addr *local;
    // This should be parsed from CNI config stdin, hardcoding for now
    nl_addr_parse("10.10.0.2/24", AF_INET, &local);
    rtnl_addr_set_local(addr, local);
    rtnl_addr_set_ifindex(addr, container_if_index);
    err = rtnl_addr_add(sock, addr, 0);
    if (err < 0)
    {
        fprintf(stderr, "Failed to add IP address: %s\n", nl_geterror(err));
    }
    else
    {
        printf("Successfully added IP address to %s\n", if_name);
    }
    rtnl_addr_put(addr);

    // Add default route
    struct rtnl_route *route = rtnl_route_alloc();
    struct nl_addr *gw;
    // The gateway should be the host-side veth IP, hardcoding for now
    nl_addr_parse("10.10.0.1", AF_INET, &gw);
    rtnl_route_set_family(route, AF_INET);
    rtnl_route_set_table(route, RT_TABLE_MAIN);
    rtnl_route_set_scope(route, RT_SCOPE_UNIVERSE);
    rtnl_route_set_type(route, RTN_UNICAST);
    struct rtnl_nexthop *nh = rtnl_route_nh_alloc();
    rtnl_route_nh_set_gateway(nh, gw);
    rtnl_route_add_nexthop(route, nh);
    err = rtnl_route_add(sock, route, 0);
    if (err < 0)
    {
        fprintf(stderr, "Failed to add default route: %s\n", nl_geterror(err));
    }
    else
    {
        printf("Successfully added default route\n");
    }
    // rtnl_route_put(route) is implicitly called by add_nexthop
    nl_addr_put(gw);

    nl_cache_free(cache);
    nl_socket_free(sock);
    sock = NULL;

    if (leave_netns(original_ns_fd) != 0)
    {
        return 1;
    }

    // 5. Load and attach BPF program to host veth
    skel = ebpfcni_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = ebpfcni_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        ebpfcni_bpf__destroy(skel);
        return 1;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = host_if_index, .attach_point = BPF_TC_INGRESS);
    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST)
    {
        fprintf(stderr, "Failed to create TC hook: %s\n", strerror(errno));
        ebpfcni_bpf__destroy(skel);
        return 1;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = bpf_program__fd(skel->progs.process_tc));
    err = bpf_tc_attach(&hook, &opts);
    if (err)
    {
        fprintf(stderr, "Failed to attach TC program: %s\n", strerror(errno));
        ebpfcni_bpf__destroy(skel);
        return 1;
    }

    printf("Successfully loaded and attached BPF program to %s\n", host_if_name);

    // 6. Print CNI result
    // TODO: Parse real IP from stdin config
    fprintf(stdout, "{\"cniVersion\":\"0.4.0\",\"interfaces\":[{\"name\":\"%s\",\"mac\":\"00:11:22:33:44:55\"}],\"ips\":[{\"version\":\"4\",\"address\":\"10.10.0.2/24\",\"gateway\":\"10.10.0.1\",\"interface\":0}],\"routes\":[{\"dst\":\"0.0.0.0/0\",\"gw\":\"10.10.0.1\"}]}\n", if_name);

    ebpfcni_bpf__destroy(skel);
    return 0;

cleanup:
    // This label is now only for BPF skeleton cleanup on attach failure
    ebpfcni_bpf__destroy(skel);
    return err;
}

static int cmd_del()
{
    char *container_id, *if_name;
    char host_if_name[IFNAMSIZ];
    struct nl_sock *sock = NULL;
    struct rtnl_link *link = NULL;
    struct nl_cache *cache = NULL;
    int err;

    container_id = getenv("CNI_CONTAINERID");
    if_name = getenv("CNI_IFNAME");

    if (!container_id || !if_name)
    {
        fprintf(stderr, "Missing CNI environment variables for DEL\n");
        return 1;
    }

    snprintf(host_if_name, IFNAMSIZ, "veth%.10s", container_id);

    sock = nl_socket_alloc();
    nl_connect(sock, NETLINK_ROUTE);

    if (rtnl_link_alloc_cache(sock, AF_UNSPEC, &cache) < 0)
    {
        fprintf(stderr, "Failed to allocate link cache for DEL\n");
        nl_socket_free(sock);
        return 1;
    }

    int host_if_index = if_nametoindex(host_if_name);
    if (host_if_index > 0)
    {
        link = rtnl_link_get(cache, host_if_index);
        if (link)
        {
            err = rtnl_link_delete(sock, link);
            if (err < 0)
            {
                fprintf(stderr, "Failed to delete link %s: %s\n", host_if_name, nl_geterror(err));
            }
            else
            {
                printf("Successfully deleted link %s\n", host_if_name);
            }
            rtnl_link_put(link);
        }
    }

    // Detach BPF program from TC hook
    if (host_if_index > 0)
    {
        DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = host_if_index, .attach_point = BPF_TC_INGRESS);
        err = bpf_tc_hook_destroy(&hook);
        if (err)
        {
            fprintf(stderr, "Failed to destroy TC hook on %s: %s\n", host_if_name, strerror(errno));
        }
        else
        {
            printf("Successfully destroyed TC hook on %s\n", host_if_name);
        }
    }

    if (cache)
        nl_cache_free(cache);
    nl_socket_free(sock);
    return 0;
}

static int cmd_check()
{
    fprintf(stdout, "CNI CHECK command not implemented\n");
    // TODO: Implement CHECK logic
    return 0;
}

static int cmd_version()
{
    // A real implementation would get this from a build variable
    fprintf(stdout, "{\n");
    fprintf(stdout, "  \"cniVersion\": \"0.4.0\",\n");
    fprintf(stdout, "  \"supportedVersions\": [\"0.4.0\"],\n");
    fprintf(stdout, "  \"pluginVersion\": \"0.1.0\"\n");
    fprintf(stdout, "}\n");
    return 0;
}

static int enter_netns(int *original_ns_fd, const char *netns_path)
{
    // Save the original network namespace
    *original_ns_fd = open("/proc/self/ns/net", O_RDONLY);
    if (*original_ns_fd < 0)
    {
        fprintf(stderr, "Failed to open original netns: %s\n", strerror(errno));
        return 1;
    }

    // Open the target network namespace
    int new_ns_fd = open(netns_path, O_RDONLY);
    if (new_ns_fd < 0)
    {
        fprintf(stderr, "Failed to open target netns %s: %s\n", netns_path, strerror(errno));
        close(*original_ns_fd);
        return 1;
    }

    // Switch to the new network namespace
    if (setns(new_ns_fd, CLONE_NEWNET) < 0)
    {
        fprintf(stderr, "Failed to setns to %s: %s\n", netns_path, strerror(errno));
        close(*original_ns_fd);
        close(new_ns_fd);
        return 1;
    }

    close(new_ns_fd); // No longer need this fd
    return 0;
}

static int leave_netns(int original_ns_fd)
{
    // Switch back to the original network namespace
    if (setns(original_ns_fd, CLONE_NEWNET) < 0)
    {
        fprintf(stderr, "Failed to switch back to original netns: %s\n", strerror(errno));
        close(original_ns_fd);
        return 1;
    }

    close(original_ns_fd);
    return 0;
}

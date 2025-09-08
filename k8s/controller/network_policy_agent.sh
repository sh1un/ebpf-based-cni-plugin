#!/bin/bash

ERR_LOG="/tmp/network_policy_controller.err.log"
# Clear the log file at the start of the script
> "$ERR_LOG"

# =================================================================
# !! TECH-DEBT WARNING !!
#
# This script has been temporarily modified to support a per-Pod BPF
# map architecture, which was introduced during the Phase 1 Go CNI
# plugin refactoring. This is a short-term solution to maintain
# functionality.
#
# The long-term goal is to align with Cilium's design philosophy by
# using a centralized BPF map managed by a Go-based controller.
#
# TODO for Phase 2:
# 1. Refactor the CNI plugin to use a single, global BPF map for policies.
# 2. Replace this entire script with a Go-based controller.
# 3. The new controller will manage the centralized map.
# =================================================================

# Function to convert IP address to a hex representation suitable for bpftool
ip_to_hex() {
    ip=$1
    # To store a value in host order on a little-endian machine, the bytes
    # for bpftool must be provided in little-endian order.
    # For an IP A.B.C.D, this means the hex bytes should be D C B A.
    IFS=. read -r i1 i2 i3 i4 <<< "$ip"
    printf "%02x %02x %02x %02x" "$i4" "$i3" "$i2" "$i1"
}

# Function to update a BPF map for a specific pod
update_map() {
    local map_path=$1
    local src_ip=$2
    local dst_ip=$3
    local value=$4

    # Defensively check for empty inputs
    if [ -z "$map_path" ] || [ -z "$src_ip" ] || [ -z "$dst_ip" ]; then
        echo "SKIP: invalid args map=$map_path src=$src_ip dst=$dst_ip" >> "$ERR_LOG"
        return
    fi

    local max_retries=5
    local retry_interval=1

    # Retry loop to wait for the map to be pinned by the CNI plugin
    for ((i=0; i<max_retries; i++)); do
        if sudo test -e "$map_path"; then
            break
        fi
        echo "Waiting for map $map_path to appear... (attempt $((i+1))/$max_retries)" >> "$ERR_LOG"
        sleep $retry_interval
    done

    if ! sudo test -e "$map_path"; then
        echo "Map not found at $map_path after $max_retries retries, skipping update." >> "$ERR_LOG"
        return
    fi

    local src_hex=$(ip_to_hex "$src_ip")
    local dst_hex=$(ip_to_hex "$dst_ip")

    local value_hex="00 00 00 00"
    if [ "$value" -eq 1 ]; then
        value_hex="01 00 00 00"
    fi

    echo "EXEC: bpftool map update pinned $map_path key hex $src_hex $dst_hex value hex $value_hex" >> "$ERR_LOG"

    if sudo bpftool map update pinned "$map_path" key hex $src_hex $dst_hex value hex $value_hex >>"$ERR_LOG" 2>&1; then
        sudo bpftool map lookup pinned "$map_path" key hex $src_hex $dst_hex >>"$ERR_LOG" 2>&1
        echo "VERIFIED: src=$src_ip dst=$dst_ip v=$value_hex written to $map_path" >> "$ERR_LOG"
    else
        echo "UPDATE_FAIL: src=$src_ip dst=$dst_ip v=$value_hex map=$map_path" >> "$ERR_LOG"
    fi
}

while true; do
    echo "--- Starting Network Policy Sync Cycle ---"

    pods_info=$(kubectl get pods -o jsonpath='{range .items[?(@.status.podIP)]}{.status.podIP}{" "}{.metadata.uid}{"\n"}{end}')
    all_pod_ips=$(echo "$pods_info" | awk '{print $1}')
    echo "DEBUG: Found pods:"
    echo "$pods_info"

    network_policies=$(kubectl get networkpolicies.networking.k8s.io -o json)

    echo "Applying allow rules based on network policies..."
    echo "$network_policies" | jq -c '.items[]' | while read -r policy; do

        pod_selector=$(echo "$policy" | jq -r '.spec.podSelector.matchLabels | to_entries | .[] | "\(.key)=\(.value)"' | tr '\n' ',' | sed 's/,$//')
        echo "DEBUG: Destination pod selector: $pod_selector"
        dest_ips=$(kubectl get pods -l "$pod_selector" -o jsonpath='{range .items[*]}{.status.podIP}{"\n"}{end}')
        echo "DEBUG: Destination IPs: $(echo $dest_ips | tr '\n' ' ')"

        echo "$policy" | jq -c '.spec.ingress[0].from[]?' | while read -r from_rule; do
            if [ -z "$from_rule" ] || [ "$from_rule" == "null" ]; then
                continue
            fi

            ingress_pod_selector=$(echo "$from_rule" | jq -r '.podSelector.matchLabels | to_entries | .[] | "\(.key)=\(.value)"' | tr '\n' ',' | sed 's/,$//')
            echo "DEBUG: Source pod selector: $ingress_pod_selector"
            source_ips=$(kubectl get pods -l "$ingress_pod_selector" -o jsonpath='{range .items[*]}{.status.podIP}{"\n"}{end}')
            echo "DEBUG: Source IPs: $(echo $source_ips | tr '\n' ' ')"

            for src_ip in $source_ips; do
                for dest_ip in $dest_ips; do
                    if [ -z "$src_ip" ] || [ -z "$dest_ip" ]; then continue; fi

                    # --- Destination Pod ---
                    dest_pod_uid=$(echo "$pods_info" | awk -v ip="$dest_ip" '$1==ip {print $2}')
                    if [ -n "$dest_pod_uid" ]; then
                        dest_map_path="/sys/fs/bpf/tc/globals/iprules_$dest_pod_uid"
                        echo "  ALLOW: $src_ip -> $dest_ip (map $dest_map_path)"
                        update_map "$dest_map_path" "$src_ip" "$dest_ip" 1
                    else
                        echo "SKIP: no UID for dest_ip=$dest_ip" >> "$ERR_LOG"
                    fi

                    # --- Source Pod ---
                    src_pod_uid=$(echo "$pods_info" | awk -v ip="$src_ip" '$1==ip {print $2}')
                    if [ -n "$src_pod_uid" ]; then
                        src_map_path="/sys/fs/bpf/tc/globals/iprules_$src_pod_uid"
                        echo "  ALLOW: $dest_ip -> $src_ip (map $src_map_path return traffic)"
                        update_map "$src_map_path" "$dest_ip" "$src_ip" 1
                    else
                        echo "SKIP: no UID for src_ip=$src_ip" >> "$ERR_LOG"
                    fi
                done
            done
        done
    done

    echo "--- Sync Cycle Finished ---"
    echo "DEBUG ls /sys/fs/bpf/tc/globals ----" >> "$ERR_LOG"
    sudo ls -l /sys/fs/bpf/tc/globals >> "$ERR_LOG" 2>&1

    sleep 10
done

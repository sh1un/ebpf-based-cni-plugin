#!/usr/bin/env bash
set -uo pipefail

# ===== Config =====
INTERVAL="${INTERVAL:-5}"                         # seconds
BPF_PIN_PATH="${BPF_PIN_PATH:-/sys/fs/bpf/tc/globals}"
STATE_DIR="${STATE_DIR:-/var/run/ebpf-agent}"    # stores assigned identities & cached edges
IDENTITY_MODE="${IDENTITY_MODE:-labels}"    # incremental | labels
SYMMETRIC_DEFAULT="${SYMMETRIC_DEFAULT:-true}"  # true: also write reverse allow for demo

mkdir -p "${STATE_DIR}/pods" "${STATE_DIR}/policies"

log() { echo "[ebpf-agent] $(date +'%F %T') $*"; }

need_bin() {
  command -v "$1" >/dev/null 2>&1 || { echo "FATAL: missing binary: $1"; exit 1; }
}

for bin in kubectl jq endpointctl policyctl sha1sum; do need_bin "$bin"; done

# ===== Identity helpers =====
# Incremental counter persisted to file
COUNTER_FILE="${STATE_DIR}/identity_counter"
init_counter() { [[ -f "$COUNTER_FILE" ]] || echo "1000" > "$COUNTER_FILE"; }
next_identity() {
  local n
  n="$(cat "$COUNTER_FILE")"
  echo $((n+1)) > "$COUNTER_FILE"
  echo "$n"
}

# Compute uint32 from sorted labels (label-based mode)
labels_to_u32() {
  # stdin: JSON labels object, ex: {"app":"frontend","tier":"fe"}
  # output: uint32 decimal (sha1 -> first 8 hex -> uint32)
  local hex
  hex="$(jq -rc 'to_entries|sort_by(.key)|map("\(.key)=\(.value)")|join(";")' \
        | sha1sum | awk '{print $1}' | cut -c1-8)"
  printf "%d\n" "0x${hex}"
}

assign_identity() {
  local uid="$1" labels_json="$2" ns="$3"
  local idfile="${STATE_DIR}/pods/${uid}.id"

  local id
  if [[ "$IDENTITY_MODE" == "labels" ]]; then
    # According to labels and namespace to compute identity
    local labels_with_ns
    labels_with_ns="$(jq -c --arg ns "$ns" '. + {"k8s:namespace":$ns}' <<<"$labels_json")"
    id="$(labels_to_u32 <<<"$labels_with_ns")"
    echo "$id" > "$idfile"   # overwrite each time
  else
    # incremental mode: only assign once per-uid
    if [[ -f "$idfile" ]]; then
      cat "$idfile"
      return 0
    fi
    id="$(next_identity)"
    echo "$id" > "$idfile"
  fi

  echo "$id"
}


# ===== Pod sync → endpoint_map =====
sync_pods() {
  log "syncing pods..."
  # Build current set snapshot
  local current_file="${STATE_DIR}/pods/current.list"
  : > "$current_file"

  kubectl get pods -A -o json \
  | jq -r '
      .items[]
      | select(.status.podIP != null and .spec.hostNetwork != true)
      | select(.status.phase=="Running")
      | [
          .metadata.uid,
          .metadata.namespace,
          .metadata.name,
          .status.podIP,
          (.metadata.labels // {})
        ] | @base64
    ' \
  | while read -r row; do
      local uid ns name ip labels_b64 labels_json id
      uid="$(echo "$row" | base64 -d | jq -r '.[0]')"
      ns="$(echo "$row" | base64 -d | jq -r '.[1]')"
      name="$(echo "$row" | base64 -d | jq -r '.[2]')"
      ip="$(echo "$row" | base64 -d | jq -r '.[3]')"
      labels_json="$(echo "$row" | base64 -d | jq -c '.[4]')"

      id="$(assign_identity "$uid" "$labels_json" "$ns")"
      echo "${uid}:${ip}:${id}" >> "$current_file"

      # Upsert endpoint_map
      if endpointctl add --ip "$ip" --identity "$id" >/dev/null 2>&1; then
        log "endpoint upsert ok  ns=$ns pod=$name ip=$ip id=$id"
      else
        log "WARN endpointctl add failed  ns=$ns pod=$name ip=$ip id=$id"
      fi
    done

  # Garbage collect endpoints (pods removed)
  # Compare saved files (*.id) to current list
  for idfile in "${STATE_DIR}/pods/"*.id; do
    [[ -e "$idfile" ]] || continue
    local uid base ip id
    base="$(basename "$idfile")"
    uid="${base%.id}"
    grep -q "^${uid}:" "$current_file" && continue
    # We lost this pod; attempt to delete its endpoint by last-known IP (if cached)
    local cache="${STATE_DIR}/pods/${uid}.lastip"
    if [[ -f "$cache" ]]; then
      ip="$(cat "$cache")"
      if [[ -n "${ip:-}" ]]; then
        policyctl >/dev/null 2>&1  # noop ensure path exists
        endpointctl del --ip "$ip" >/dev/null 2>&1 || true
        log "endpoint deleted for uid=$uid ip=$ip"
      fi
    fi
    rm -f "$idfile" "$cache"
  done

  # Update last-known IP cache
  while IFS=: read -r uid ip id; do
    echo "$ip" > "${STATE_DIR}/pods/${uid}.lastip"
  done < <(cut -d: -f1,2,3 "$current_file")
}

# ===== NetworkPolicy sync → policy_map =====
# MVP: only supports same-namespace Ingress, .spec.podSelector + .spec.ingress[].from[].podSelector
# Records edges per-NP for GC.
np_key() { echo "$1:$2"; }  # ns:name

sync_policies() {
  log "syncing networkpolicies..."
  # Track all seen NPs this round for GC
  local seen="${STATE_DIR}/policies/seen.list"
  : > "$seen"

  kubectl get networkpolicies -A -o json \
  | jq -r '
      .items[] | @base64
    ' \
  | while read -r row; do
      local ns name spec dst_selector src_selectors
      ns="$(echo "$row" | base64 -d | jq -r '.metadata.namespace')"
      name="$(echo "$row" | base64 -d | jq -r '.metadata.name')"
      spec="$(echo "$row" | base64 -d | jq -c '.spec')"
      echo "$(np_key "$ns" "$name")" >> "$seen"

      # Extract dst selector (podSelector of the policy)
      dst_selector="$(jq -r -c '.podSelector.matchLabels // {}' <<<"$spec")"

      # Build label selector string "k=v,k2=v2"
      to_sel() { jq -r 'to_entries|map("\(.key)=\(.value)")|join(",")'; }

      # Resolve dst uids within same ns
      local dst_uids
      dst_uids="$(kubectl get pods -n "$ns" -l "$(echo "$dst_selector" | to_sel)" -o jsonpath='{.items[*].metadata.uid}')"

      # For each ingress.from.podSelector
      jq -c '.ingress[]? | .from[]? | .podSelector.matchLabels // {}' <<<"$spec" \
      | while read -r src_sel_json; do
          local src_uids
          src_uids="$(kubectl get pods -n "$ns" -l "$(echo "$src_sel_json" | to_sel)" -o jsonpath='{.items[*].metadata.uid}')"

          for du in $dst_uids; do
            [[ -f "${STATE_DIR}/pods/${du}.id" ]] || continue
            local dst_id; dst_id="$(cat "${STATE_DIR}/pods/${du}.id")"
            for su in $src_uids; do
              [[ -f "${STATE_DIR}/pods/${su}.id" ]] || continue
              local src_id; src_id="$(cat "${STATE_DIR}/pods/${su}.id")"

              # Write allow (and optional symmetric for demo)
              if policyctl allow --src "$src_id" --dst "$dst_id" >/dev/null 2>&1; then
                log "policy allow src=$src_id -> dst=$dst_id (np=$ns/$name)"
                echo "${src_id},${dst_id}" >> "${STATE_DIR}/policies/${ns}_${name}.edges.tmp"
                if [[ "$SYMMETRIC_DEFAULT" == "true" ]]; then
                  policyctl allow --src "$dst_id" --dst "$src_id" >/dev/null 2>&1 || true
                  echo "${dst_id},${src_id}" >> "${STATE_DIR}/policies/${ns}_${name}.edges.tmp"
                fi
              else
                log "WARN policyctl allow failed src=$src_id dst=$dst_id (np=$ns/$name)"
              fi
            done
          done
        done

      # Commit temp edges list atomically
      local edgef="${STATE_DIR}/policies/${ns}_${name}.edges"
      mv -f "${edgef}.tmp" "$edgef" 2>/dev/null || true
    done

  # GC: remove edges for NPs that no longer exist
  for f in "${STATE_DIR}/policies/"*.edges; do
    [[ -e "$f" ]] || continue
    local base ns_name
    base="$(basename "$f" .edges)"
    ns_name="${base//_/:}"    # ns:name
    if ! grep -qx "$ns_name" "$seen"; then
      # delete all edges for this NP
      while IFS=, read -r s d; do
        policyctl deny --src "$s" --dst "$d" >/dev/null 2>&1 || true
        log "policy removed src=$s dst=$d (np=$ns_name deleted)"
      done < "$f"
      rm -f "$f"
    fi
  done
}

# ===== Main loop =====
init_counter
log "starting ebpf-agent (shell) interval=${INTERVAL}s mode=${IDENTITY_MODE} symmetric=${SYMMETRIC_DEFAULT}"
while true; do
  sync_pods
  sync_policies
  sleep "${INTERVAL}"
done

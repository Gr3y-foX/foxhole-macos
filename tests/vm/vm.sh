#!/bin/bash
# Host-side helper for ad-hoc work in the Tart test VM.
#
# Usage:  bash tests/vm/vm.sh up             boot foxhole-test (no-op if running)
#         bash tests/vm/vm.sh push           copy the working tree to ~/foxhole
#         bash tests/vm/vm.sh ssh 'cmd ...'  run a command in the VM
#         bash tests/vm/vm.sh down           stop the VM
#         bash tests/vm/vm.sh reset          recreate foxhole-test from foxhole-clean
# Env:    FOXHOLE_VM_NET=bridged  boot with --net-bridged=en0 (real internet)
set -euo pipefail

if [[ "$(sysctl -n sysctl.proc_translated 2>/dev/null)" == "1" ]]; then
    exec arch -arm64 /bin/bash "$0" "$@"
fi

export PATH="$HOME/.local/bin:$PATH"
export TART_HOME="${TART_HOME:-/Volumes/Disc Samsung T7/vm - backups/macos_vm}"
VM="foxhole-test"
CLEAN="${FOXHOLE_VM_BASE:-foxhole-clean}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o PubkeyAuthentication=no -o LogLevel=ERROR -o ServerAliveInterval=10)

[[ -d "$TART_HOME" ]] || { echo "TART_HOME not found: $TART_HOME (SSD unplugged?)"; exit 1; }

NET_ARGS=(); IP_ARGS=()
if [[ "${FOXHOLE_VM_NET:-nat}" == "bridged" ]]; then
    NET_ARGS=(--net-bridged="${FOXHOLE_VM_BRIDGE:-en0}"); IP_ARGS=(--resolver arp)
fi
vm_ip() { tart ip "$VM" ${IP_ARGS[@]+"${IP_ARGS[@]}"} --wait "${1:-5}" 2>/dev/null; }
ssh_vm() { sshpass -p admin ssh "${SSH_OPTS[@]}" "admin@$(vm_ip)" "$@"; }

case "${1:-}" in
    up)
        if ! tart list 2>/dev/null | awk -v vm="$VM" '$2 == vm && $NF == "running"' | grep -q .; then
            nohup tart run --no-graphics --no-audio --no-clipboard ${NET_ARGS[@]+"${NET_ARGS[@]}"} "$VM" >/dev/null 2>&1 &
        fi
        IP=$(vm_ip 120)
        for _ in $(seq 1 40); do nc -z -G2 "$IP" 22 2>/dev/null && break; sleep 3; done
        echo "VM ${VM} at ${IP}"
        ;;
    push)
        ssh_vm 'rm -rf ~/foxhole && mkdir -p ~/foxhole'
        (cd "$REPO" && { git ls-files -z; git ls-files -z --others --exclude-standard tests; } \
            | xargs -0 tar -cf -) | ssh_vm 'tar -xf - -C ~/foxhole'
        echo "pushed working tree to ~/foxhole"
        ;;
    ssh)
        shift
        ssh_vm "$@"
        ;;
    down)
        # graceful first: an abrupt stop can lose the last file operations
        ssh_vm 'sync; sudo shutdown -h now' >/dev/null 2>&1 || true
        for _ in $(seq 1 30); do
            tart list 2>/dev/null | awk -v vm="$VM" '$2 == vm && $NF == "running"' | grep -q . || exit 0
            sleep 2
        done
        tart stop "$VM" 2>/dev/null || true
        ;;
    reset)
        tart stop "$VM" 2>/dev/null || true
        tart delete "$VM" 2>/dev/null || true
        tart clone "$CLEAN" "$VM"
        tart set "$VM" --cpu 4 --memory 4096
        echo "recreated ${VM} from ${CLEAN}"
        ;;
    *)
        sed -n '2,9p' "$0"; exit 1
        ;;
esac

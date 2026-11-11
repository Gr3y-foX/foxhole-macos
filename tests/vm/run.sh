#!/bin/bash
# Host-side runner: boots the Tart test VM, copies the repo's tracked files
# (working tree, so uncommitted edits are included), runs vmtest.sh inside,
# saves the log and stops the VM.
#
# Usage:  bash tests/vm/run.sh [--reset]
#   --reset   recreate foxhole-test from foxhole-clean before running
#
# Env:   FOXHOLE_VM_NET=bridged   boot with --net-bridged=en0 (real internet)
#        FOXHOLE_VM_BASE=foxhole-brew   base image for --reset (default foxhole-clean; -brew has Homebrew)
#
# Needs: tart, sshpass, VM image admin/admin (Cirrus Labs vanilla image).
set -euo pipefail

# Tart cannot start macOS VMs from a Rosetta (x86_64) process, e.g. an
# Intel-only bash in /usr/local/bin. Re-exec with the native /bin/bash.
if [[ "$(sysctl -n sysctl.proc_translated 2>/dev/null)" == "1" ]]; then
    exec arch -arm64 /bin/bash "$0" "$@"
fi

export PATH="$HOME/.local/bin:$PATH"
export TART_HOME="${TART_HOME:-/Volumes/Disc Samsung T7/vm - backups/macos_vm}"
VM="foxhole-test"
CLEAN="${FOXHOLE_VM_BASE:-foxhole-clean}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_DIR="${REPO}/docs/testing/logs"
LOG="${LOG_DIR}/vm-test-$(date +%Y-%m-%d_%H%M%S).log"
mkdir -p "$LOG_DIR"
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o PubkeyAuthentication=no -o LogLevel=ERROR -o ServerAliveInterval=10)

[[ -d "$TART_HOME" ]] || { echo "TART_HOME not found: $TART_HOME (SSD unplugged?)"; exit 1; }
command -v sshpass >/dev/null || { echo "sshpass missing"; exit 1; }

if [[ "${1:-}" == "--reset" ]]; then
    tart stop "$VM" 2>/dev/null || true
    tart delete "$VM" 2>/dev/null || true
    tart clone "$CLEAN" "$VM"
    tart set "$VM" --cpu 4 --memory 4096
fi

# FOXHOLE_VM_NET=bridged gives the VM real internet (default NAT is blocked by a
# host VPN kill switch such as Mullvad Lockdown). It then has a LAN address.
NET_ARGS=(); IP_ARGS=(--wait 120)
if [[ "${FOXHOLE_VM_NET:-nat}" == "bridged" ]]; then
    NET_ARGS=(--net-bridged="${FOXHOLE_VM_BRIDGE:-en0}"); IP_ARGS=(--resolver arp --wait 120)
fi
tart run --no-graphics --no-audio --no-clipboard ${NET_ARGS[@]+"${NET_ARGS[@]}"} "$VM" >/dev/null 2>&1 &
# Graceful stop: an abrupt `tart stop` can lose the last file operations (e.g. the
# final cleanup), leaving the next run with stale state.
stop_vm() {
    ssh_vm 'sync; sudo shutdown -h now' >/dev/null 2>&1 || true
    for _ in $(seq 1 30); do
        tart list 2>/dev/null | awk -v vm="$VM" '$2 == vm && $NF == "running"' | grep -q . || return 0
        sleep 2
    done
    tart stop "$VM" >/dev/null 2>&1 || true
}
trap stop_vm EXIT

IP=$(tart ip "$VM" "${IP_ARGS[@]}")
echo "VM ${VM} at ${IP}; waiting for SSH..."
for _ in $(seq 1 30); do
    nc -z -G2 "$IP" 22 2>/dev/null && break
    sleep 3
done

ssh_vm() { sshpass -p admin ssh "${SSH_OPTS[@]}" "admin@${IP}" "$@"; }

ssh_vm 'rm -rf ~/foxhole && mkdir -p ~/foxhole'
# Tracked files plus not-yet-committed files under tests/
(cd "$REPO" && { git ls-files -z; git ls-files -z --others --exclude-standard tests; } \
    | xargs -0 tar -cf -) | ssh_vm 'tar -xf - -C ~/foxhole'
# Also keep a copy inside the VM, so the log survives a dropped SSH session
ssh_vm 'bash ~/foxhole/tests/vm/vmtest.sh > ~/vmtest.log 2>&1; echo "vmtest exit: $?" >> ~/vmtest.log; cat ~/vmtest.log' 2>&1 \
    | tr -d '\r' | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' | tee "$LOG" || true
echo "ssh exit: ${PIPESTATUS[0]}" | tee -a "$LOG"

# Phase 2: vmtest.sh left the lock on. Reboot and check that it comes back by itself.
echo "Rebooting the VM for the after-reboot phase..." | tee -a "$LOG"
ssh_vm 'sync; sudo shutdown -r now' >/dev/null 2>&1 || true
sleep 20
UP=0
for _ in $(seq 1 60); do
    IP=$(tart ip "$VM" "${IP_ARGS[@]}" 2>/dev/null || true)
    if [[ -n "$IP" ]] && nc -z -G2 "$IP" 22 2>/dev/null && ssh_vm true 2>/dev/null; then UP=1; break; fi
    sleep 3
done
if [[ "$UP" == 1 ]]; then
    ssh_vm 'bash ~/foxhole/tests/vm/vmtest.sh --after-reboot > ~/vmtest2.log 2>&1; echo "vmtest phase 2 exit: $?" >> ~/vmtest2.log; cat ~/vmtest2.log' 2>&1 \
        | tr -d '\r' | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' | tee -a "$LOG" || true
else
    echo "  FAIL: VM did not come back after the reboot (phase 2 not run)" | tee -a "$LOG"
fi

echo "Log saved: ${LOG}"

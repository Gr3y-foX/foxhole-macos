#!/bin/bash
# Host-side runner: boots the Tart test VM, copies the repo's tracked files
# (working tree, so uncommitted edits are included), runs vmtest.sh inside,
# saves the log and stops the VM.
#
# Usage:  bash tests/vm/run.sh [--reset]
#   --reset   recreate foxhole-test from foxhole-clean before running
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
CLEAN="foxhole-clean"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOG_DIR="${REPO}/docs/testing"
LOG="${LOG_DIR}/vm-test-$(date +%Y-%m-%d_%H%M%S).log"
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

tart run --no-graphics --no-audio --no-clipboard "$VM" >/dev/null 2>&1 &
trap 'tart stop "$VM" >/dev/null 2>&1 || true' EXIT

IP=$(tart ip "$VM" --wait 120)
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

echo "Log saved: ${LOG}"

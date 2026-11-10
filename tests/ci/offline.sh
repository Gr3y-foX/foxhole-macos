#!/bin/bash
# Offline checks for the netlib: nothing here touches the system (sudo is shimmed
# and every path points into a temp dir). Runs locally and in CI.
#   bash tests/ci/offline.sh
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
chk() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# shellcheck source=../../mac-hardening-netlib.sh
source "$REPO/mac-hardening-netlib.sh"
set +e

echo "== anchor rendering"
# sudo shim: render the anchor into $T instead of /etc/pf.anchors
sudo() {
    case "$1" in
        mkdir) return 0 ;;
        install) cp "${@: -2:1}" "$T/anchor.rules" ;;
        *) "$@" ;;
    esac
}
prepare_pf_dns_lock_anchor >/dev/null 2>&1
chk "anchor rendered" '[[ -s "$T/anchor.rules" ]]'
chk "passes utun0..utun15 explicitly (PF has no utun+ wildcard)" \
    '[[ "$(grep -c "^pass .* on { utun0 .*utun15 }" "$T/anchor.rules")" == 2 ]] && ! grep -q "utun+" "$T/anchor.rules"'
chk "blocks 53 and 853 on physical interfaces only" \
    '[[ "$(grep -c "^block out quick on {" "$T/anchor.rules")" == 4 ]] && ! grep -E "^block" "$T/anchor.rules" | grep -vq " on {"'
chk "default mode doh: Quad9 passes tcp 443 only, before the blocks" \
    '[[ "$(grep -c "^pass out quick proto tcp to .* port 443$" "$T/anchor.rules")" == 4 ]] && ! grep -q "proto { udp tcp } to 9" "$T/anchor.rules" && [[ "$(grep -n "9\.9\.9\.9" "$T/anchor.rules" | head -1 | cut -d: -f1)" -lt "$(grep -n "^block" "$T/anchor.rules" | head -1 | cut -d: -f1)" ]]'
FOXHOLE_DNS_MODE=plain prepare_pf_dns_lock_anchor >/dev/null 2>&1
chk "mode plain: Quad9 on any port" '[[ "$(grep -c "^pass out quick proto { udp tcp } to " "$T/anchor.rules")" == 4 ]]'
FOXHOLE_DNS_MODE=vpn prepare_pf_dns_lock_anchor >/dev/null 2>&1
chk "mode vpn: no Quad9 exception, blocks remain" '! grep -q "9\.9\.9\." "$T/anchor.rules" && [[ "$(grep -c "^block out quick on {" "$T/anchor.rules")" == 4 ]]'
chk "unknown mode is rejected" '! (FOXHOLE_DNS_MODE=bogus _choose_dns_mode >/dev/null 2>&1)'
prepare_pf_dns_lock_anchor >/dev/null 2>&1
if pfctl -h >/dev/null 2>&1 && [[ "$(uname)" == Darwin ]] && command -v pfctl >/dev/null; then
    if /usr/bin/sudo -n true 2>/dev/null; then
        chk "pfctl -nf accepts the anchor" '/usr/bin/sudo -n pfctl -nf "$T/anchor.rules" 2>/dev/null'
    else
        echo "  SKIP: pfctl -nf (no passwordless sudo)"
    fi
fi

echo "== toggle script"
awk "/<< 'SCRIPT'\$/{f=1;next} /^SCRIPT\$/{f=0} f" "$REPO/mac-hardening-netlib.sh" > "$T/toggle.sh"
chk "extracted proxy-toggle.sh parses" '/bin/bash -n "$T/toggle.sh"'
chk "VPN check matches (Connected) exactly, not (Disconnected)" 'grep -qF "grep -F \"(Connected)\"" "$T/toggle.sh"'
chk "no CIDR forward rules for Privoxy" '! grep -qE "^forward +[0-9.]+/[0-9]+ " "$REPO/mac-hardening-netlib.sh"'

echo "== ask()"
chk "ask: default N without a tty" '[[ "$(ask q ANS </dev/null >/dev/null 2>&1; echo "$ANS")" == N ]]'
chk "ask: FOXHOLE_ASSUME_YES=1 answers y" '[[ "$(FOXHOLE_ASSUME_YES=1 ask q ANS </dev/null >/dev/null 2>&1; echo "$ANS")" == y ]]'
chk "no eval in the netlib" '! grep -nE "(^|[^a-z_])eval " "$REPO/mac-hardening-netlib.sh" | grep -v "^[0-9]*:[[:space:]]*#"'

echo "== PF lock enable/disable order (v0.17.4)"
sed -n '/^enable_pf_dns_lock() {/,/^}/p' "$REPO/mac-hardening-netlib.sh" > "$T/enable.fn"
sed -n '/^disable_pf_dns_lock() {/,/^}/p' "$REPO/mac-hardening-netlib.sh" > "$T/disable.fn"
chk "enable: synchronous start precedes the boot daemon install" \
    '[[ "$(grep -n "helper\" start" "$T/enable.fn" | head -1 | cut -d: -f1)" -lt "$(grep -n "_install_pf_launchdaemon" "$T/enable.fn" | head -1 | cut -d: -f1)" ]]'
chk "enable: no status poll loop left" '! grep -q "sleep 0.5" "$T/enable.fn"'
chk "disable: anchor flushed before the helper re-install" \
    '[[ "$(grep -n "F all" "$T/disable.fn" | head -1 | cut -d: -f1)" -lt "$(grep -n "_install_pf_helper" "$T/disable.fn" | head -1 | cut -d: -f1)" ]]'

echo "== restore.sh teardown (v0.17.4, audit F1)"
awk "/<<'RESTORE'\$/{f=1;next} /^RESTORE\$/{f=0} f" "$REPO/mac-hardening-netlib.sh" > "$T/restore.sh"
chk "restore.sh parses" '/bin/bash -n "$T/restore.sh"'
chk "restore.sh boots out the lock daemon and removes its plist" \
    'grep -q "launchctl bootout" "$T/restore.sh" && grep -q "rm -f \"\$LOCK_PLIST\"" "$T/restore.sh"'
chk "restore.sh flushes only the foxhole anchor" \
    'grep -q "pfctl -a \"\$LOCK_ANCHOR\" -F all" "$T/restore.sh" && ! grep -v "^#" "$T/restore.sh" | grep -qE "pfctl -(d|f) "'
chk "restore.sh releases only our token (pfctl -X on the token file)" \
    'grep -q "pfctl -X \"\$LOCK_REF\"" "$T/restore.sh" && grep -q "LOCK_TOKEN=\"/var/db/foxhole/pf.token\"" "$T/restore.sh"'

echo "== no stale design"
chk "no dnscrypt-proxy formula in the installer" '! grep -q "\"dnscrypt-proxy\"" "$REPO/mac-hardening-install.sh"'
chk "installer does not run the Tor profile stub" '! grep -q "bash \"\$SCRIPT_DIR/profile-paranoid-tor.sh\"" "$REPO/mac-hardening-install.sh"'
chk "no launchctl load/unload left in the netlib" '! grep -qE "launchctl (un)?load" "$REPO/mac-hardening-netlib.sh"'
chk "pf.conf is never written by enable (only the legacy cleanup touches it)" \
    '[[ "$(grep -c "tee -a \"\$PF_CONF\"\|tee -a /etc/pf.conf" "$REPO/mac-hardening-netlib.sh")" == 0 ]]'

echo
echo "RESULT: ${PASS} passed, ${FAIL} failed"
[[ $FAIL -eq 0 ]]

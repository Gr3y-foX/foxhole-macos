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
chk "Quad9 whitelist comes before the blocks" \
    '[[ "$(grep -n "9\.9\.9\.9" "$T/anchor.rules" | head -1 | cut -d: -f1)" -lt "$(grep -n "^block" "$T/anchor.rules" | head -1 | cut -d: -f1)" ]]'
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

echo "== no stale design"
chk "no dnscrypt-proxy formula in the installer" '! grep -q "\"dnscrypt-proxy\"" "$REPO/mac-hardening-install.sh"'
chk "no launchctl load/unload left in the netlib" '! grep -qE "launchctl (un)?load" "$REPO/mac-hardening-netlib.sh"'
chk "pf.conf is never written by enable (only the legacy cleanup touches it)" \
    '[[ "$(grep -c "tee -a \"\$PF_CONF\"\|tee -a /etc/pf.conf" "$REPO/mac-hardening-netlib.sh")" == 0 ]]'

echo
echo "RESULT: ${PASS} passed, ${FAIL} failed"
[[ $FAIL -eq 0 ]]

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
        mkdir|chown|chmod|mv|rm) return 0 ;;
        tee) cat > "$T/anchor.rules" ;;
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
    '[[ "$(grep -n "HELPER\" start" "$T/enable.fn" | head -1 | cut -d: -f1)" -lt "$(grep -n "_install_pf_launchdaemon" "$T/enable.fn" | head -1 | cut -d: -f1)" ]]'
chk "enable: status is checked again after the boot daemon install" \
    '[[ "$(grep -n "HELPER\" status" "$T/enable.fn" | tail -1 | cut -d: -f1)" -gt "$(grep -n "_install_pf_launchdaemon" "$T/enable.fn" | head -1 | cut -d: -f1)" ]]'
chk "enable: every failure path after the start rolls back" '[[ "$(grep -c "_pf_lock_rollback" "$T/enable.fn")" == 3 ]]'
chk "enable: the order check above found both lines" \
    'grep -q "HELPER\" start" "$T/enable.fn" && grep -q "_install_pf_launchdaemon" "$T/enable.fn"'
chk "enable: prepared rules are promoted only after the confirmation and the guard (F5)" \
    '[[ "$(grep -n "mv -f \"\$PF_LOCK_RULES_NEW\"" "$T/enable.fn" | head -1 | cut -d: -f1)" -gt "$(grep -n "_pf_main_has_apple_anchor" "$T/enable.fn" | head -1 | cut -d: -f1)" ]] && grep -q "mv -f \"\$PF_LOCK_RULES_NEW\"" "$T/enable.fn"'
sed -n '/^prepare_pf_dns_lock_anchor() {/,/^}/p' "$REPO/mac-hardening-netlib.sh" > "$T/prepare.fn"
chk "prepare never writes the live rules file (F5)" \
    'grep -q "PF_ANCHOR=\"\$PF_LOCK_RULES_NEW\"" "$T/prepare.fn" && ! grep -q "\$PF_LOCK_RULES\"" "$T/prepare.fn"'
chk "disable: anchor flushed before the helper re-install" \
    '[[ "$(grep -n "F all" "$T/disable.fn" | head -1 | cut -d: -f1)" -lt "$(grep -n "_install_pf_helper" "$T/disable.fn" | head -1 | cut -d: -f1)" ]]'

echo "== v0.17.4 static fixes (audit F10-F16)"
awk "/<<'HELPER'\$/{f=1;next} /^HELPER\$/{f=0} f" "$REPO/mac-hardening-netlib.sh" > "$T/helper.sh"
chk "helper parses" '/bin/bash -n "$T/helper.sh"'
chk "helper flushes the anchor on every start failure (F11)" \
    '[[ "$(grep -c "start_failed \"" "$T/helper.sh")" == 3 ]] && grep -q "held_token >/dev/null || pf -a \"\$ANCHOR\" -F all" "$T/helper.sh"'
chk "helper is not empty and has all four actions" \
    '[[ "$(grep -cE "^    (start|boot|stop|status)\)" "$T/helper.sh")" == 4 ]]'
chk "helper has no temp file and never touches the main ruleset" \
    '! grep -q mktemp "$T/helper.sh" && ! grep -qE "pfctl +-d|-f +/etc/pf\.conf" "$T/helper.sh"'
chk "helper status requires the com.apple/* anchor in the main ruleset (F8)" \
    'grep -q "rules_loaded && held_token >/dev/null && main_has_anchor" "$T/helper.sh"'
chk "helper boot retries are bounded (F8)" 'grep -q "\"\$N\" -ge 5" "$T/helper.sh"'
sed -n '/^_install_pf_launchdaemon() {/,/^}/p' "$REPO/mac-hardening-netlib.sh" > "$T/ld.fn"
awk "/<< 'EOF'\$/{f=1;next} /^EOF\$/{f=0} f" "$T/ld.fn" > "$T/pf.plist"
chk "LaunchDaemon plist is well-formed and runs the helper's boot action" \
    'plutil -lint "$T/pf.plist" >/dev/null 2>&1 && grep -q "<string>boot</string>" "$T/pf.plist" && grep -q "<string>${PF_LOCK_HELPER}</string>" "$T/pf.plist" && grep -q "<string>${PF_LOCK_LABEL}</string>" "$T/pf.plist"'
chk "LaunchDaemon writer reports failure to its caller (F3)" '[[ "$(grep -c "return 1" "$T/ld.fn")" -ge 3 ]]'
chk "no user-owned staging files left in the PF lock code (F14)" \
    '[[ "$(grep -c "mktemp" "$REPO/mac-hardening-netlib.sh")" == 1 ]] && grep -q "TMP_HOSTS=\$(mktemp)" "$REPO/mac-hardening-netlib.sh"'
chk "vpn_daily offers a backup snapshot (F17)" 'grep -q "create_net_backup" "$REPO/vpn_daily.sh"'
chk "helper releases the reference if the token cannot be saved (F12)" \
    'grep -q "cannot write \$TOKEN_FILE; PF reference released" "$T/helper.sh"'
chk "menu and vpn_daily guard enable_pf_dns_lock (F13)" \
    'grep -q "enable_pf_dns_lock || warn" "$REPO/mac-hardening-netlib.sh" && grep -q "enable_pf_dns_lock || warn" "$REPO/vpn_daily.sh"'
chk "reset runs each step in a subshell (F16)" \
    'grep -q "( disable_pf_dns_lock )" "$REPO/mac-hardening-netlib.sh" && grep -q "( disable_hosts_blocklist )" "$REPO/mac-hardening-netlib.sh"'
chk "legacy pf.conf reload asks first (F10)" \
    'grep -q "Reload the main PF ruleset now" "$REPO/mac-hardening-netlib.sh"'

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

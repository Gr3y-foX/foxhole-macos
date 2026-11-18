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
chk "anchor has no pass rule in any mode (a quick pass runs before a kill switch, F9)" \
    '( for m in doh plain vpn; do FOXHOLE_DNS_MODE=$m prepare_pf_dns_lock_anchor >/dev/null 2>&1; grep -qE "^[[:space:]]*pass" "$T/anchor.rules" && exit 1; [[ "$(grep -c "^block out quick on {" "$T/anchor.rules")" == 4 ]] || exit 1; done; true )'
chk "blocks 53 and 853 on physical interfaces only" \
    '[[ "$(grep -c "^block out quick on {" "$T/anchor.rules")" == 4 ]] && ! grep -E "^block" "$T/anchor.rules" | grep -vq " on {"'
chk "default mode doh: no Quad9 rule (443 is never blocked; no pass ahead of a kill switch, F9)" \
    '! grep -v "^#" "$T/anchor.rules" | grep -q "9\.9\.9\.\|149\.112\|foxhole_quad9" && [[ "$(grep -c "^block out quick on { .* } proto { udp tcp } to any port \(53\|853\)$" "$T/anchor.rules")" == 2 ]]'
FOXHOLE_DNS_MODE=plain prepare_pf_dns_lock_anchor >/dev/null 2>&1
chk "mode plain: Quad9 left out of the 53/853 blocks via a table, no pass rule (F9)" \
    'grep -q "^table <foxhole_quad9> const { 9\.9\.9\.9 149\.112\.112\.112 9\.9\.9\.11 149\.112\.112\.11 }$" "$T/anchor.rules" && [[ "$(grep -c "^block out quick on { .* } proto { udp tcp } to ! <foxhole_quad9> port \(53\|853\)$" "$T/anchor.rules")" == 2 ]] && ! grep "^pass" "$T/anchor.rules" | grep -q "9\.9\.9\.\|foxhole_quad9"'
chk "no mode has a pass rule that names an address (F9)" \
    '( for m in doh plain vpn; do FOXHOLE_DNS_MODE=$m prepare_pf_dns_lock_anchor >/dev/null 2>&1; grep "^pass" "$T/anchor.rules" | grep -q " to [0-9<]" && exit 1; done; true )'
FOXHOLE_DNS_MODE=plain prepare_pf_dns_lock_anchor >/dev/null 2>&1
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
chk "LaunchDaemon plist re-runs the helper every 60 s and keeps RunAtLoad (N1)" \
    'grep -q "<key>StartInterval</key>" "$T/pf.plist" && grep -A1 "<key>StartInterval</key>" "$T/pf.plist" | grep -q "<integer>60</integer>" && grep -A1 "<key>RunAtLoad</key>" "$T/pf.plist" | grep -q "<true/>"'
chk "helper boot: silent fast path (rules loaded + token held) comes before the retry loop (N1)" \
    'sed -n "/^    boot)/,/^        ;;/p" "$T/helper.sh" > "$T/boot.case"; [[ "$(grep -n "rules_loaded && held_token >/dev/null" "$T/boot.case" | head -1 | cut -d: -f1)" -ge 1 ]] && [[ "$(grep -n "rules_loaded && held_token >/dev/null" "$T/boot.case" | head -1 | cut -d: -f1)" -lt "$(grep -n "until do_start" "$T/boot.case" | head -1 | cut -d: -f1)" ]] && sed -n "/rules_loaded && held_token >\/dev\/null/,/fi/p" "$T/boot.case" | head -3 | grep -q "exit 0"'
chk "helper boot: the fast path does not log and does not look at main_has_anchor" \
    '! sed -n "/rules_loaded && held_token >\/dev\/null/,/^        fi/p" "$T/boot.case" | grep -qE "echo|main_has_anchor|do_start"'
chk "helper boot: the success log line tests grep for is unchanged" \
    'grep -q "boot: rules loaded into \$ANCHOR, PF reference held (try \$N)" "$T/helper.sh"'
chk "LaunchDaemon writer reports failure to its caller (F3)" '[[ "$(grep -c "return 1" "$T/ld.fn")" -ge 3 ]]'
chk "no user-owned staging files left in the PF lock code (F14)" \
    '[[ "$(grep -c "mktemp" "$REPO/mac-hardening-netlib.sh")" == 1 ]] && grep -q "TMP_HOSTS=\$(mktemp)" "$REPO/mac-hardening-netlib.sh"'
sed -n '/^update_hosts() {/,/^}/p' "$REPO/mac-hardening-netlib.sh" > "$T/hosts.fn"
chk "hosts download is validated and applied from a root-owned copy" \
    'grep -q "install -m 644 -o root -g wheel \"\$TMP_HOSTS\" \"\$STAGED\"" "$T/hosts.fn" && grep -q "cat \"\$STAGED\"" "$T/hosts.fn" && ! grep -q "cat \"\$TMP_HOSTS\"" "$T/hosts.fn"'
chk "hosts: a failed commit lookup does not end the script" 'grep -q "cut -c1-7) || true" "$T/hosts.fn"'
chk "helper directory must be root-only writable" 'grep -q "is not root-only writable" "$REPO/mac-hardening-netlib.sh"'
chk "helper and proxy toggle both use the root-only directory check" \
    'sed -n "/^_install_pf_helper() {/,/^}/p" "$REPO/mac-hardening-netlib.sh" | grep -q _require_root_dir && sed -n "/^enable_privoxy_vpn_autoswitch() {/,/^}/p" "$REPO/mac-hardening-netlib.sh" | grep -q _require_root_dir'
chk "proxy toggle lives in /usr/local/libexec; the old /usr/local/bin copy is removed" \
    'grep -q "<string>/usr/local/libexec/proxy-toggle.sh</string>" "$REPO/mac-hardening-netlib.sh" && ! grep -q "<string>/usr/local/bin/proxy-toggle.sh</string>" "$REPO/mac-hardening-netlib.sh" && [[ "$(grep -c "PROXY_TOGGLE_LEGACY\"" "$REPO/mac-hardening-netlib.sh")" -ge 2 ]]'
# F7: run the helper's interface merge on a sample rules file (networksetup stubbed)
mkdir -p "$T/f7"
printf 'pass quick on lo0 all\nblock out quick on { en0 en9 } proto { udp tcp } to any port 53\n' > "$T/f7/rules"
printf '#!/bin/bash\nprintf "Hardware Port: Wi-Fi\\nDevice: en0\\nHardware Port: USB\\nDevice: en5\\nHardware Port: Bad\\nDevice: en1;rm\\n"\n' > "$T/f7/networksetup"
chmod +x "$T/f7/networksetup"
sed -n "/^    IFACES=\$( {/,/sed 's\/ \$\/\/')\$/p" "$T/helper.sh" \
    | sed -e "s#/usr/sbin/networksetup#$T/f7/networksetup#" -e "s#\"\$RULES\"#\"$T/f7/rules\"#" > "$T/f7/merge.sh"
F7=$(bash -c "$(cat "$T/f7/merge.sh"); echo \"\$IFACES\"")
chk "F7: interface list = union of live and file lists, unsafe names dropped (got: $F7)" '[[ "$F7" == "en0 en5 en9" ]]'
(
    stat() { echo "${FAKE_STAT:-}"; }   # stands in for both the owner and the mode query
    tee() { cat >/dev/null; }
    sudo() { case "$1" in tee) cat >/dev/null ;; *) return 0 ;; esac; }
    FAKE_STAT=root; _install_pf_helper >/dev/null 2>&1
)
# shellcheck disable=SC2034  # used inside the single-quoted chk string (eval)
RC_OWNER=$?
chk "helper install refuses when the directory check fails" '[[ $RC_OWNER -ne 0 ]]'
chk "vpn_daily offers a backup snapshot (F17)" 'grep -q "create_net_backup" "$REPO/vpn_daily.sh"'
chk "helper releases the reference if the token cannot be saved (F12)" \
    'grep -q "cannot write \$TOKEN_FILE; PF reference released" "$T/helper.sh"'
chk "menu and vpn_daily guard enable_pf_dns_lock (F13)" \
    'grep -q "enable_pf_dns_lock || warn" "$REPO/mac-hardening-netlib.sh" && grep -q "enable_pf_dns_lock || warn" "$REPO/vpn_daily.sh"'
chk "reset runs each step in a subshell (F16)" \
    'grep -q "( disable_pf_dns_lock )" "$REPO/mac-hardening-netlib.sh" && grep -q "( disable_hosts_blocklist )" "$REPO/mac-hardening-netlib.sh"'
chk "legacy pf.conf reload asks first (F10)" \
    'grep -q "Reload the main PF ruleset now" "$REPO/mac-hardening-netlib.sh"'

echo "== foreign anchors and the unattended legacy reload (D7, audit F10)"
# The real _pf_legacy_cleanup edits /etc/pf.conf, which this file never touches. The
# decision it takes is in _pf_foreign_anchors and _pf_confirm_main_reload: test those
# with pfctl (behind sudo) and ask stubbed.
(
    sudo() { case "$1" in pfctl) shift; pfctl_stub "$@" ;; *) return 0 ;; esac; }
    pfctl_stub() {
        case "$*" in
            "-sr") printf '%s\n' 'scrub-anchor "com.apple/*" all fingerprints' 'anchor "com.apple/*" all' 'anchor "mullvad" all' \
                       'anchor "com.hardening.dnsleak" all' 'anchor "we ird;$(id)"' 'block drop all' ;;
            *) echo "UNEXPECTED pfctl $*" >> "$T/pfctl.calls" ;;
        esac
    }
    _pf_foreign_anchors > "$T/foreign.out"
)
chk "foreign anchors: lists mullvad, drops com.apple/* and the legacy anchor, ignores non-anchor lines" \
    '[[ "$(sed -n 1p "$T/foreign.out")" == mullvad ]]'
chk "foreign anchors: untrusted characters are replaced, nothing is executed" \
    '[[ "$(sed -n 2p "$T/foreign.out")" == "we?ird???id?" ]] && [[ "$(wc -l < "$T/foreign.out" | tr -d " ")" == 2 ]]'
(
    sudo() { case "$1" in pfctl) shift; [[ "$*" == "-sr" ]] && printf '%s\n' 'anchor "com.apple/*" all' 'anchor "com.hardening.dnsleak" all' ;; esac; return 0; }
    _pf_foreign_anchors > "$T/foreign2.out"
)
chk "foreign anchors: stock ruleset has none" '[[ ! -s "$T/foreign2.out" ]]'
(
    export FOXHOLE_ASSUME_YES=1
    sudo() { case "$1" in pfctl) shift; [[ "$*" == "-sr" ]] && printf '%s\n' 'anchor "com.apple/*" all' 'anchor "mullvad" all' ;; esac; return 0; }
    ask() { echo ASK_CALLED >> "$T/unattended.out"; printf -v "$2" '%s' y; }
    _pf_confirm_main_reload >> "$T/unattended.out" 2>&1
    echo "rc=$?" >> "$T/unattended.out"
)
chk "unattended + foreign anchor: reload refused (rc 1), names the anchor, ask() never called" \
    'grep -q "^rc=1$" "$T/unattended.out" && grep -q "mullvad" "$T/unattended.out" && grep -q "Unattended run" "$T/unattended.out" && ! grep -q ASK_CALLED "$T/unattended.out"'
(
    export FOXHOLE_ASSUME_YES=1
    sudo() { case "$1" in pfctl) shift; [[ "$*" == "-sr" ]] && printf '%s\n' 'anchor "com.apple/*" all' 'anchor "com.hardening.dnsleak" all' ;; esac; return 0; }
    _pf_confirm_main_reload > "$T/unattended2.out" 2>&1
    echo "rc=$?" >> "$T/unattended2.out"
)
chk "unattended + stock ruleset only: reload allowed (rc 0)" 'grep -q "^rc=0$" "$T/unattended2.out"'
(
    unset FOXHOLE_ASSUME_YES
    sudo() { case "$1" in pfctl) shift; [[ "$*" == "-sr" ]] && printf '%s\n' 'anchor "com.apple/*" all' 'anchor "mullvad" all' ;; esac; return 0; }
    ask() { echo ASK_CALLED >> "$T/interactive.out"; printf -v "$2" '%s' N; }
    _pf_confirm_main_reload >> "$T/interactive.out" 2>&1
    echo "rc=$?" >> "$T/interactive.out"
)
chk "interactive + foreign anchor: the old warning and the question stay, a 'no' skips (rc 1)" \
    'grep -q "including a VPN kill switch" "$T/interactive.out" && grep -q ASK_CALLED "$T/interactive.out" && grep -q "^rc=1$" "$T/interactive.out"'
(
    unset FOXHOLE_ASSUME_YES
    sudo() { case "$1" in pfctl) shift; [[ "$*" == "-sr" ]] && printf '%s\n' 'anchor "com.apple/*" all' 'anchor "mullvad" all' ;; esac; return 0; }
    ask() { printf -v "$2" '%s' y; }
    _pf_confirm_main_reload > "$T/interactive2.out" 2>&1
    echo "rc=$?" >> "$T/interactive2.out"
)
chk "interactive + 'yes': reload allowed (rc 0)" 'grep -q "^rc=0$" "$T/interactive2.out"'
sed -n '/^_pf_legacy_cleanup() {/,/^}/p' "$REPO/mac-hardening-netlib.sh" > "$T/legacy.fn"
chk "legacy cleanup: pfctl -f on the main ruleset sits behind _pf_confirm_main_reload, and the skip message stays" \
    '[[ "$(grep -n "_pf_confirm_main_reload" "$T/legacy.fn" | head -1 | cut -d: -f1)" -ge 1 ]] && [[ "$(grep -n "_pf_confirm_main_reload" "$T/legacy.fn" | head -1 | cut -d: -f1)" -lt "$(grep -n "sudo pfctl -f \"\$PF_CONF\"" "$T/legacy.fn" | head -1 | cut -d: -f1)" ]] && grep -q "Reload skipped" "$T/legacy.fn" && [[ "$(grep -c "pfctl -f" "$T/legacy.fn")" == 1 ]]'

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

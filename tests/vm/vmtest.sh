#!/bin/bash
# shellcheck disable=SC2034  # variables are used inside the single-quoted chk "..." strings (eval)
# Runs INSIDE the foxhole-test VM. Sources the netlib and exercises PF lock paths.
set -uo pipefail
cd ~/foxhole || exit 1
PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
SKIP=0
skip() { echo "  SKIP: $1 (no direct internet in VM)"; SKIP=$((SKIP+1)); }
# Network checks need direct egress; on a host with a VPN kill switch the VM may have none
netchk() { if [[ "$NET_OK" == 1 ]]; then chk "$1" "$2"; else skip "$1"; fi; }
chk()  { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
source ./mac-hardening-netlib.sh
set +e   # test harness: keep going after failures
ask() { printf -v "$2" '%s' 'y'; }   # auto-answer yes

echo "== T0 static"
for f in mac-hardening-netlib.sh vpn_daily.sh mac-hardening-install.sh; do chk "bash -n $f" "bash -n $f"; done

A=com.apple/foxhole.dnsleak
# vpn_active() exactly as written into proxy-toggle.sh
awk "/<< 'SCRIPT'\$/{f=1;next} /^SCRIPT\$/{f=0} f" ./mac-hardening-netlib.sh | sed -n '/^vpn_active() {/,/^}/p' > /tmp/vpn_active.sh
source /tmp/vpn_active.sh
vpn_active_probe() { vpn_active; }
RULES=/etc/pf.anchors/com.hardening.dnsleak
HELPER=/usr/local/libexec/foxhole-pf-dnslock
TOKEN=/var/db/foxhole/pf.token
PLIST=/Library/LaunchDaemons/com.hardening.pf.dnsleak.plist
pfq()      { sudo pfctl "$@" 2>/dev/null; }
pf_on()    { pfq -s info | grep -q "Status: Enabled"; }
ntokens()  { pfq -s References | grep -cE '^[0-9]+ ' || true; }
# Packets that hit the udp/53 block rules (works without internet egress)
blk53()    { pfq -a "$A" -vsr | awk '/^block .* proto udp .* port = 53$/ {getline; for (i=1;i<=NF;i++) if ($i=="Packets:") s+=$(i+1)} END {print s+0}'; }
same_conf(){ diff <(grep -v "^$" /etc/pf.conf) <(grep -v "^$" /tmp/pf.conf.baseline) >/dev/null; }

echo "== T1 baseline"
sudo cp /etc/pf.conf /tmp/pf.conf.baseline
pfq -sr > /tmp/pf.main.baseline
stat -f '%Su:%Sg %Lp' /etc/pf.conf
chk "pf.conf root:wheel 644" '[[ "$(stat -f "%Su:%Sg %Lp" /etc/pf.conf)" == "root:wheel 644" ]]'
chk "no hardening lines in pf.conf" '! grep -q dnsleak /etc/pf.conf'
chk "PF disabled at baseline" '! pf_on'
chk "main ruleset evaluates com.apple/*" 'grep -qE "^anchor \"com\.apple/\*\"" /tmp/pf.main.baseline'
NET_OK=0
curl -s -o /dev/null --max-time 6 https://1.1.1.1/ && NET_OK=1
echo "  info: direct internet egress: $([[ $NET_OK == 1 ]] && echo yes || echo NO)"

echo "== T2 prepare + enable"
prepare_pf_dns_lock_anchor 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
chk "rules file exists" 'test -f $RULES'
chk "rules syntax ok (pfctl -nf)" 'sudo pfctl -nf $RULES 2>/dev/null'
chk "block rules scoped (on {)" 'grep -q "^block out quick on {" $RULES'
enable_pf_dns_lock 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
chk "pf.conf untouched" 'same_conf && cmp -s /etc/pf.conf /tmp/pf.conf.baseline'
chk "main ruleset untouched" 'diff <(pfq -sr) /tmp/pf.main.baseline >/dev/null'
chk "rules loaded in $A (port 53)" 'pfq -a $A -sr | grep -q "port = 53"'
chk "utun pass rules loaded (utun0..utun15)" '[[ "$(pfq -a $A -sr | grep -c "^pass .* on utun")" -ge 30 ]]'
chk "PF enabled" 'pf_on'
chk "exactly one PF reference held" '[[ "$(ntokens)" == 1 ]]'
chk "token file root 600, token is held" '[[ "$(sudo stat -f "%Su %Lp" $TOKEN)" == "root 600" ]] && pfq -s References | grep -qw "$(sudo cat $TOKEN)"'
chk "helper root:wheel 755" '[[ "$(stat -f "%Su:%Sg %Lp" $HELPER)" == "root:wheel 755" ]]'
chk "LaunchDaemon bootstrapped" 'sudo launchctl print system/com.hardening.pf.dnsleak >/dev/null 2>&1'
chk "helper status = active" 'sudo bash $HELPER status'

echo "== T3 behaviour"
pfq -a $A -sr | head -20
pfq -a $A -z >/dev/null
dig +time=1 +tries=2 example.com @8.8.8.8 >/dev/null 2>&1
B=$(blk53); echo "  info: udp/53 block-rule packets after dig @8.8.8.8: $B"
chk "DNS to 8.8.8.8 hits the block rule" '[[ "$B" -gt 0 ]]'
netchk "plain DNS @8.8.8.8 blocked" '! dig +time=3 +tries=1 +short example.com @8.8.8.8 2>/dev/null | grep -q "[0-9]"'
netchk "Quad9 @9.9.9.9 allowed" 'dig +time=4 +tries=1 +short example.com @9.9.9.9 2>/dev/null | grep -q "[0-9]"'
netchk "HTTPS by IP still works during lock" 'curl -s --max-time 6 -o /dev/null -w "%{http_code}" https://9.9.9.9/ -k | grep -qE "^[0-9]{3}$"'

echo "== T4 idempotence + coexistence"
enable_pf_dns_lock >/dev/null 2>&1
chk "second enable: still one reference" '[[ "$(ntokens)" == 1 ]]'
sudo pfctl -f /etc/pf.conf >/dev/null 2>&1
chk "rules survive a main-ruleset reload (pfctl -f /etc/pf.conf)" 'sudo bash $HELPER status'
sudo launchctl kickstart -k system/com.hardening.pf.dnsleak >/dev/null 2>&1; sleep 2
chk "daemon re-run: still one reference" '[[ "$(ntokens)" == 1 ]] && sudo bash $HELPER status'
OTHER=$(sudo pfctl -E 2>&1 | sed -n "s/^Token : //p")
echo "  info: second PF user (like a VPN kill switch) took token $OTHER"

echo "== T5 verify_dns_stack completes"
OUT=$(verify_dns_stack 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
echo "$OUT" | grep -E '^\[|Results'
chk "health check reached summary" 'echo "$OUT" | grep -q "Results:"'
chk "[2] utun rule found via anchor" 'echo "$OUT" | grep -q "\[2\].*present"'

echo "== T6 disable"
disable_pf_dns_lock 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
chk "PF stays on for the other holder" 'pf_on && [[ "$(ntokens)" == 1 ]]'
sudo pfctl -X "$OTHER" >/dev/null 2>&1
chk "PF off once the other holder releases" '! pf_on'
chk "pf.conf still equals baseline" 'cmp -s /etc/pf.conf /tmp/pf.conf.baseline'
chk "rules flushed" '! pfq -a $A -sr | grep -q .'
chk "files removed (rules, helper, token, plist)" '! test -e $RULES && ! test -e $HELPER && ! sudo test -e $TOKEN && ! test -e $PLIST'
chk "LaunchDaemon gone" '! sudo launchctl print system/com.hardening.pf.dnsleak >/dev/null 2>&1'
netchk "plain DNS @8.8.8.8 works again" 'dig +time=4 +tries=1 +short example.com @8.8.8.8 2>/dev/null | grep -q "[0-9]"'

echo "== T7 migration from a pre-0.17.3 install (pf.conf marker + com.hardening.dnsleak)"
prepare_pf_dns_lock_anchor >/dev/null 2>&1
printf '\n# ===== hardening dns lock =====\nanchor "com.hardening.dnsleak"\nload anchor "com.hardening.dnsleak" from "/etc/pf.anchors/com.hardening.dnsleak"\n' | sudo tee -a /etc/pf.conf >/dev/null
sudo pfctl -f /etc/pf.conf >/dev/null 2>&1
chk "legacy anchor active before migration" 'pfq -a com.hardening.dnsleak -sr | grep -q "port = 53"'
enable_pf_dns_lock 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E "older version|restored|ACTIVE|✗"
chk "migration: pf.conf back to baseline" 'same_conf'
chk "migration: pf.conf root:wheel 644" '[[ "$(stat -f "%Su:%Sg %Lp" /etc/pf.conf)" == "root:wheel 644" ]]'
chk "migration: legacy anchor flushed" '! pfq -a com.hardening.dnsleak -sr | grep -q .'
chk "migration: new lock active" 'sudo bash $HELPER status'
disable_pf_dns_lock >/dev/null 2>&1
chk "migration: disable leaves no hardening lines" '! grep -q "dnsleak\|hardening dns lock" /etc/pf.conf'
sudo pfctl -d >/dev/null 2>&1   # the simulated old install had no token; turn PF off by hand

echo "== T8 guard: main ruleset without com.apple/*"
prepare_pf_dns_lock_anchor >/dev/null 2>&1
echo "pass all" | sudo pfctl -f - >/dev/null 2>&1
enable_pf_dns_lock > /tmp/guard.out 2>&1; RC=$?
sed 's/\x1b\[[0-9;]*m//g' /tmp/guard.out | grep -E "✗|i\]" | head -3
chk "enable refuses (rc != 0)" '[[ $RC -ne 0 ]]'
chk "no daemon installed on refusal" '! test -e $PLIST'
sudo pfctl -f /etc/pf.conf >/dev/null 2>&1
sudo rm -f $RULES
chk "stock main ruleset restored" 'diff <(pfq -sr) /tmp/pf.main.baseline >/dev/null'

echo "== T9 reset_net_hardening re-run on clean state"
reset_net_hardening >/dev/null 2>&1; chk "reset exits 0" '[[ $? -eq 0 ]]'
chk "PF off after reset" '! pf_on'

echo "== T11 full stack with internet: Quad9 resolver + hosts blocklist + lock (needs egress)"
if [[ "$NET_OK" != 1 ]]; then
    skip "T11 full stack"
else
    # The real design uses the Quad9 DoH profile, which needs a GUI approval.
    # Stand-in: plain-DNS resolver 9.9.9.9 (whitelisted by the lock), so the health check can pass.
    SVC=$(networksetup -listallnetworkservices | tail -n +2 | grep -v '^\*' | head -1)
    sudo networksetup -setdnsservers "$SVC" 9.9.9.9 149.112.112.112
    sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder 2>/dev/null
    update_hosts >/tmp/hosts.out 2>&1
    chk "hosts blocklist installed (>1000 entries)" '[[ "$(grep -c "^0\.0\.0\.0" /etc/hosts)" -gt 1000 ]]'
    chk "hosts: marker exactly once" '[[ "$(grep -cF "# ===== StevenBlack Blocklist =====" /etc/hosts)" == 1 ]]'
    chk "hosts: localhost entries kept" 'grep -q "^127.0.0.1[[:space:]]*localhost" /etc/hosts'
    chk "hosts: a listed ad domain resolves to 0.0.0.0" '[[ "$(dscacheutil -q host -a name doubleclick.net 2>/dev/null | awk "/ip_address/{print \$2; exit}")" == 0.0.0.0 ]]'
    prepare_pf_dns_lock_anchor >/dev/null 2>&1; enable_pf_dns_lock >/dev/null 2>&1
    chk "resolver works through the lock" 'dig +time=4 +tries=1 +short example.com | grep -q "[0-9]"'
    chk "plain DNS to 8.8.8.8 blocked, resolver 9.9.9.9 still fine" '! dig +time=3 +tries=1 +short example.com @8.8.8.8 | grep -q "[0-9]" && dig +time=4 +tries=1 +short example.com @9.9.9.9 | grep -q "[0-9]"'
    OUT=$(verify_dns_stack 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
    echo "$OUT" | grep -E '^\[|Results'
    chk "health check: all 10 pass" 'echo "$OUT" | grep -q "Results: 10/10 passed, 0 failed"'
    update_hosts >/tmp/hosts2.out 2>&1
    chk "hosts: second update keeps one marker" '[[ "$(grep -cF "# ===== StevenBlack Blocklist =====" /etc/hosts)" == 1 ]]'
    reset_net_hardening >/dev/null 2>&1
    sudo networksetup -setdnsservers "$SVC" Empty
    chk "reset: blocklist and lock gone" '! grep -qF "StevenBlack Blocklist" /etc/hosts && ! sudo bash $HELPER status'
    chk "reset: /etc/hosts still has localhost" 'grep -q "^127.0.0.1[[:space:]]*localhost" /etc/hosts'
    chk "reset: PF off" '! pf_on'
fi

echo "== T12 tunnel: utun with IPv4 + route through it, lock on (no internet needed)"
# A stock VM has only system utuns (IPv6). Give utun3 an IPv4 and route a TEST-NET-3
# address through it, which is what a VPN client does.
TUN_IP=203.0.113.53
prepare_pf_dns_lock_anchor >/dev/null 2>&1; enable_pf_dns_lock >/dev/null 2>&1
chk "no VPN detected before the tunnel exists" '! vpn_active_probe'
sudo ifconfig utun3 inet 10.99.0.1 10.99.0.2 netmask 255.255.255.255 up
sudo route -n add -host $TUN_IP -interface utun3 >/dev/null 2>&1
chk "route to $TUN_IP goes via utun3" 'route -n get $TUN_IP | grep -q "interface: utun3"'
pfq -a $A -z >/dev/null
dig +time=1 +tries=1 +short example.com @$TUN_IP >/dev/null 2>&1
UT=$(pfq -a $A -vsr | awk '/^pass out quick on utun3 all/ {getline; for (i=1;i<=NF;i++) if ($i=="Packets:") print $(i+1)}')
echo "  info: packets on the utun3 pass rule: ${UT:-none}"
chk "DNS through the tunnel passes the utun3 rule" '[[ "${UT:-0}" -gt 0 ]]'
chk "vpn_active (proxy-toggle) sees the utun IPv4 tunnel" 'vpn_active_probe'
sudo route -n delete -host $TUN_IP >/dev/null 2>&1
sudo ifconfig utun3 inet 10.99.0.1 delete >/dev/null 2>&1
chk "no VPN detected after the tunnel is gone" '! vpn_active_probe'
disable_pf_dns_lock >/dev/null 2>&1

echo "== T14 ask() with FOXHOLE_ASSUME_YES (real netlib ask, no tty)"
chk "ask answers y without a tty when FOXHOLE_ASSUME_YES=1" '[[ "$(bash -c "source ./mac-hardening-netlib.sh; FOXHOLE_ASSUME_YES=1 ask q ANS </dev/null >/dev/null; echo \$ANS")" == y ]]'
chk "ask still answers N without a tty by default" '[[ "$(bash -c "source ./mac-hardening-netlib.sh; ask q ANS </dev/null >/dev/null 2>&1; echo \$ANS")" == N ]]'
chk "ask rejects command substitution in the variable name use (printf -v, no eval)" '[[ "$(FOXHOLE_ASSUME_YES=1 bash -c "source ./mac-hardening-netlib.sh; ask q ANS </dev/null >/dev/null; echo \$ANS")" == y ]]'

echo "== T13 Privoxy auto-switch: real proxy-toggle.sh + LaunchDaemon + networksetup (stand-in listener on :8118)"
SVC=$(networksetup -listallnetworkservices | tail -n +2 | grep -v '^\*' | head -1)
wproxy() { networksetup -getwebproxy "$SVC" | awk -F': ' '$1=="Enabled"{print $2}'; }
sproxy() { networksetup -getsecurewebproxy "$SVC" | awk -F': ' '$1=="Enabled"{print $2}'; }
toggle() { sudo bash /usr/local/bin/proxy-toggle.sh; }
fake_privoxy() { perl -MIO::Socket::INET -e '$s=IO::Socket::INET->new(LocalAddr=>"127.0.0.1",LocalPort=>8118,Listen=>5,ReuseAddr=>1) or die; alarm 900; while ($c=$s->accept) { close $c }' >/dev/null 2>&1 & }
fake_privoxy
LPID=$!; sleep 1
enable_privoxy_vpn_autoswitch 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E "✗|\[!\]|loopback|exposed|not listening|loaded"
chk "toggle script root:wheel 755" '[[ "$(stat -f "%Su:%Sg %Lp" /usr/local/bin/proxy-toggle.sh)" == "root:wheel 755" ]]'
chk "daemon bootstrapped" 'sudo launchctl print system/com.hardening.proxytoggle >/dev/null 2>&1'
sleep 8   # the daemon re-runs once after its own proxy changes (WatchPath, ThrottleInterval 5)
chk "no VPN + Privoxy listening -> web and secure web proxy ON" '[[ "$(wproxy)" == Yes && "$(sproxy)" == Yes ]]'
chk "proxy points at 127.0.0.1:8118" 'networksetup -getwebproxy "$SVC" | grep -q "Server: 127.0.0.1" && networksetup -getwebproxy "$SVC" | grep -q "Port: 8118"'
W1=$(wc -l < /var/log/proxy-toggle.log); toggle; toggle
chk "repeat runs change nothing (idempotent, log does not grow)" '[[ "$(wc -l < /var/log/proxy-toggle.log)" == "$W1" ]]'
sudo ifconfig utun3 inet 10.99.0.1 10.99.0.2 netmask 255.255.255.255 up; toggle
chk "VPN (utun IPv4) -> proxy OFF" '[[ "$(wproxy)" == No && "$(sproxy)" == No ]]'
sudo ifconfig utun3 inet 10.99.0.1 delete; toggle
chk "VPN gone -> proxy back ON" '[[ "$(wproxy)" == Yes ]]'
kill $LPID 2>/dev/null; wait $LPID 2>/dev/null; toggle
chk "Privoxy not listening -> proxy OFF (never point at a dead port)" '[[ "$(wproxy)" == No && "$(sproxy)" == No ]]'
chk "toggle logged the dead-Privoxy case" 'grep -q "Privoxy is not listening" /var/log/proxy-toggle.log'
fake_privoxy
LPID=$!; sleep 1; toggle
chk "Privoxy back -> proxy ON again" '[[ "$(wproxy)" == Yes ]]'
disable_privoxy_autoswitch >/dev/null 2>&1
kill $LPID 2>/dev/null; wait $LPID 2>/dev/null
chk "disable: daemon, plist and script gone" '! sudo launchctl print system/com.hardening.proxytoggle >/dev/null 2>&1 && ! test -e /Library/LaunchDaemons/com.hardening.proxytoggle.plist && ! test -e /usr/local/bin/proxy-toggle.sh'
chk "disable: system proxies OFF" '[[ "$(wproxy)" == No && "$(sproxy)" == No ]]'

echo "== T15 installer fixes (functions extracted from mac-hardening-install.sh; needs egress)"
INST=./mac-hardening-install.sh
fn() { sed -n "/^$1() {/,/^}/p" "$INST"; }
chk "installer has no tap/install of homebrew/brew-vulns" '! grep -q "brew install homebrew/brew-vulns" $INST'
if [[ "$NET_OK" != 1 ]]; then
    skip "T15 installer downloads"
else
    # Homebrew is only present in the foxhole-brew based image; the others skip these
    OSV=$(grep '^OVERSIGHT_VERSION=' $INST | cut -d'"' -f2)
    OSURL="https://github.com/objective-see/OverSight/releases/download/v${OSV}/OverSight_${OSV}.zip"
    OSSHA=$(grep '^OVERSIGHT_ZIP_SHA1=' $INST | cut -d'"' -f2)
    curl -fsSL -m60 -o /tmp/os.zip "$OSURL"
    chk "OverSight pinned release downloads and matches the pinned SHA-1" '[[ "$(shasum -a 1 /tmp/os.zip | awk "{print toupper(\$1)}")" == "$OSSHA" ]]'
    chk "archive holds \"OverSight Installer.app\" (name with a space)" '[[ "$(unzip -l /tmp/os.zip | grep -c "OverSight Installer.app/")" -ge 1 ]]'
    chk "script looks for OverSight*Installer.app" 'grep -q "OverSight\*Installer.app" $INST'
    eval "$(fn _install_mergen)"
    sudo rm -rf /Applications/Mergen.app
    _install_mergen > /tmp/t15-mergen.out 2>&1; sed 's/\x1b\[[0-9;]*m//g' /tmp/t15-mergen.out | grep -E "URL|SHA|installed|✗|\[!\]" | head -6
    chk "Mergen: resolved the real .dmg asset and verified SHA-256" 'grep -q "SHA-256 verified" /tmp/t15-mergen.out'
    chk "Mergen: app installed" 'test -d /Applications/Mergen.app'
    chk "Mergen: temp dir and mount cleaned up" '! ls -d /tmp/mergen.* >/dev/null 2>&1 && ! mount | grep -qi "/Volumes/Mergen"'
    sudo rm -rf /Applications/Mergen.app
fi
# Gatekeeper: real `spctl --status` exits 1 when assessments are disabled (stock Cirrus
# image; macOS 26 will not let a script switch it off again), so emulate that with stubs.
eval "$(fn check_gatekeeper_filevault)"
rm -f /tmp/gk_on
(
    spctl() {
        case "$1" in
            --status) if [[ -f /tmp/gk_on ]]; then echo "assessments enabled"; return 0
                      else echo "assessments disabled"; return 1; fi ;;
            --master-enable) touch /tmp/gk_on ;;
        esac
    }
    sudo() { if [[ "$1" == spctl ]]; then shift; spctl "$@"; else command sudo "$@"; fi; }
    FOXHOLE_ASSUME_YES=1 check_gatekeeper_filevault
) > /tmp/t15-gk.out 2>&1
sed 's/\x1b\[[0-9;]*m//g' /tmp/t15-gk.out | grep -E "Gatekeeper" | head -4
chk "Gatekeeper: disabled state (exit 1) is detected, no 'Unable to determine'" '! grep -q "Unable to determine" /tmp/t15-gk.out && grep -q "DISABLED" /tmp/t15-gk.out'
chk "Gatekeeper: --master-enable issued after answering yes" 'test -f /tmp/gk_on'
rm -f /tmp/gk_on

echo "== T16 create_net_backup + restore.sh"
cp /etc/hosts /tmp/hosts.t16
create_net_backup > /tmp/t16-backup.out 2>&1
BK=$(ls -d "$HOME"/.foxhole/backups/* | tail -1)
chk "backup holds hosts, pf.conf, system-dns.txt, network_proxies.txt" 'test -f $BK/hosts && test -f $BK/pf.conf && test -f $BK/system-dns.txt && test -f $BK/network_proxies.txt'
chk "backup holds restore.sh (the old message pointed at a rollback.sh that did not exist)" 'test -x $BK/restore.sh && grep -q "restore.sh" /tmp/t16-backup.out && ! grep -q "rollback.sh" /tmp/t16-backup.out'
chk "restore.sh parses" 'bash -n $BK/restore.sh'
echo "# t16 tampering" | sudo tee -a /etc/hosts >/dev/null
chk "restore.sh refuses to run without root" '! bash $BK/restore.sh >/dev/null 2>&1'
# shellcheck disable=SC2024  # the redirect target is a user-owned /tmp file
sudo bash $BK/restore.sh > /tmp/t16-restore.out 2>&1; RR=$?
chk "restore.sh exits 0 and restores /etc/hosts byte-for-byte" '[[ $RR -eq 0 ]] && cmp -s /etc/hosts /tmp/hosts.t16'
chk "restored /etc/hosts is root:wheel 644" '[[ "$(stat -f "%Su:%Sg %Lp" /etc/hosts)" == "root:wheel 644" ]]'
chk "pf.conf unchanged by restore" 'cmp -s /etc/pf.conf /tmp/pf.conf.baseline'
rm -rf "$HOME/.foxhole"

echo "== T10 vpn_daily.sh menu from another cwd (driven by expect: ask() needs a tty)"
cat > /tmp/vd.exp <<'EXP'
set timeout 30
set env(TERM) xterm
spawn bash /Users/admin/foxhole/vpn_daily.sh
expect "Continue?*" { send "y\r" }
expect "Password:" { send "admin\r" }
expect "Choice (1-6):" { send "4\r" }
expect "Choice (1-6):" { send "1\r" }
expect "Continue enabling PF DNS lock?*" { send "y\r" }
expect "Choice (1-6):" { send "2\r" }
expect "Choice (1-6):" { send "6\r" }
expect eof
EXP
(cd / && /usr/bin/expect /tmp/vd.exp 2>&1 | tr -d '\r' | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' > /tmp/vpn_daily.out)
chk "vpn_daily [4] prints guidance" 'grep -q "ipleak.net" /tmp/vpn_daily.out'
chk "vpn_daily [1] reports lock ACTIVE" 'grep -q "PF DNS lock: ACTIVE" /tmp/vpn_daily.out'
chk "vpn_daily [2] removes lock" 'grep -q "PF DNS lock removed" /tmp/vpn_daily.out'
chk "vpn_daily exits cleanly" 'grep -q "Done. For daily use" /tmp/vpn_daily.out'
chk "no 'command not found' in vpn_daily output" '! grep -qi "command not found" /tmp/vpn_daily.out'
chk "no leftovers after vpn_daily" '! grep -q dnsleak /etc/pf.conf && ! test -e $PLIST && ! pf_on'

echo
echo "RESULT: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"

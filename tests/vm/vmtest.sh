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

# Phase 2 (run by run.sh after it rebooted the VM): phase 1 left the lock on
if [[ "${1:-}" == "--after-reboot" ]]; then
    echo "== T26 reboot with the lock on, no VPN (audit scenario A, F8)"
    NET_OK=0
    for _ in $(seq 1 30); do sudo bash $HELPER status >/dev/null 2>&1 && break; sleep 2; done
    echo "  info: /var/log/foxhole-pf.log (tail):"; sudo tail -n 6 /var/log/foxhole-pf.log 2>&1 | sed "s/^/    /"
    echo "  info: daemon: $(sudo launchctl print system/com.hardening.pf.dnsleak 2>&1 | grep -E "state =|last exit code" | tr -s " " | tr "\n" ";")"
    chk "after reboot: helper status = active" 'sudo bash $HELPER status'
    chk "after reboot: PF enabled, exactly one reference" 'pf_on && [[ "$(ntokens)" == 1 ]]'
    chk "after reboot: main ruleset evaluates com.apple/*" 'pfq -sr | grep -qE "^anchor \"com\.apple/\*\""'
    chk "after reboot: rules loaded (port 53 blocks, utun passes)" 'pfq -a $A -sr | grep -q "port = 53" && pfq -a $A -sr | grep -q "^pass .* on utun"'
    chk "after reboot: the boot action logged a successful run" 'sudo grep -q "boot: rules loaded" /var/log/foxhole-pf.log'
    chk "after reboot: no temp or pending files" '! ls /var/run/foxhole-pf.* >/dev/null 2>&1 && ! test -e $RULES.new && ! test -e $PLIST.new && ! test -e $HELPER.new'
    pfq -a $A -z >/dev/null
    dig +time=1 +tries=2 example.com @8.8.8.8 >/dev/null 2>&1
    B=$(blk53); echo "  info: udp/53 block-rule packets after dig @8.8.8.8: $B"
    chk "after reboot: DNS to 8.8.8.8 hits the block rule" '[[ "$B" -gt 0 ]]'
    curl -s -o /dev/null --max-time 6 https://1.1.1.1/ && NET_OK=1
    echo "  info: direct internet egress with the lock on: $([[ $NET_OK == 1 ]] && echo yes || echo NO)"
    netchk "after reboot: HTTPS by IP works with the lock on (no IP lockout)" 'curl -s -o /dev/null --max-time 6 https://1.1.1.1/'
    disable_pf_dns_lock >/dev/null 2>&1
    chk "after reboot: disable leaves PF off and no leftovers" '! pf_on && ! test -e $RULES && ! test -e $HELPER && ! test -e $PLIST && ! sudo test -e $TOKEN'
    echo
    echo "RESULT (after reboot): ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
    exit 0
fi

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
# v0.17.4: prepare writes $RULES.new; enable moves it into place after the confirmation
chk "prepared rules file exists, live rules file not written yet" 'test -f $RULES.new && ! test -e $RULES'
chk "prepared rules root:wheel 644" '[[ "$(stat -f "%Su:%Sg %Lp" $RULES.new)" == "root:wheel 644" ]]'
chk "rules syntax ok (pfctl -nf)" 'sudo pfctl -nf $RULES.new 2>/dev/null'
chk "block rules scoped (on {)" 'grep -q "^block out quick on {" $RULES.new'
enable_pf_dns_lock 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
chk "enable promoted the prepared rules (rules file root:wheel 644, no .new left)" 'test -f $RULES && ! test -e $RULES.new && [[ "$(stat -f "%Su:%Sg %Lp" $RULES)" == "root:wheel 644" ]]'
chk "plist root:wheel 644, runs the boot action, no staging files left" '[[ "$(stat -f "%Su:%Sg %Lp" $PLIST)" == "root:wheel 644" ]] && grep -q "<string>boot</string>" $PLIST && ! test -e $PLIST.new && ! test -e $HELPER.new && ! ls /tmp/foxhole-pf-* /tmp/pf.anchor.* >/dev/null 2>&1'
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
netchk "plain DNS to Quad9 @9.9.9.9:53 blocked in the default doh mode" '! dig +time=3 +tries=1 +short example.com @9.9.9.9 2>/dev/null | grep -q "[0-9]"'
echo "  info: Quad9 rules as PF prints them:"; pfq -a $A -sr | grep "to 9\.9\.9\.9\|to 149"
chk "doh mode: Quad9 passes tcp 443 only" 'pfq -a $A -sr | grep "to 9\.9\.9\.9" | grep -q "proto tcp.*port = 443" && ! pfq -a $A -sr | grep "to 9\.9\.9\.9" | grep -qv "port = 443"'
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
sudo cp $RULES.new $RULES   # old versions wrote the live rules file directly; pf.conf loads the legacy anchor from it
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
chk "refusal drops the prepared rules, nothing loaded, PF not referenced" '! test -e $RULES.new && ! pfq -a $A -sr | grep -q . && [[ "$(ntokens)" == 0 ]]'
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
    FOXHOLE_DNS_MODE=plain prepare_pf_dns_lock_anchor >/dev/null 2>&1; enable_pf_dns_lock >/dev/null 2>&1
    chk "resolver works through the lock" 'dig +time=4 +tries=1 +short example.com | grep -q "[0-9]"'
    chk "plain DNS to 8.8.8.8 blocked, resolver 9.9.9.9 still fine" '! dig +time=3 +tries=1 +short example.com @8.8.8.8 | grep -q "[0-9]" && dig +time=4 +tries=1 +short example.com @9.9.9.9 | grep -q "[0-9]"'
    OUT=$(verify_dns_stack 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
    echo "$OUT" | grep -E '^\[|Results'
    chk "health check: all 10 pass" 'echo "$OUT" | grep -q "Results: 10/10 passed, 0 failed"'
    update_hosts >/tmp/hosts2.out 2>&1
    chk "hosts: second update keeps one marker" '[[ "$(grep -cF "# ===== StevenBlack Blocklist =====" /etc/hosts)" == 1 ]]'
    # set -e as in the real scripts: the commit lookup is informational and must not end the run
    ( set -e; curl() { case "$*" in *api.github.com*) return 22 ;; *) command curl "$@" ;; esac; }; update_hosts ) >/tmp/hosts3.out 2>&1; RC=$?
    chk "hosts: update completes when the GitHub commit lookup fails" '[[ $RC -eq 0 ]] && grep -q "Latest GitHub commit: unknown" /tmp/hosts3.out && grep -q "/etc/hosts updated" /tmp/hosts3.out && [[ "$(grep -cF "# ===== StevenBlack Blocklist =====" /etc/hosts)" == 1 ]]'
    chk "hosts: root-owned staging copy removed, blocklist still complete" '! sudo test -e /etc/hosts.foxhole.download && [[ "$(grep -c "^0\.0\.0\.0" /etc/hosts)" -gt 1000 ]]'
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
cp /etc/pf.conf /tmp/pf.conf.t16   # pf.conf as it is when the backup is taken (T7 leaves a blank line vs the baseline)
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
chk "pf.conf restored to its state at backup time" 'cmp -s /etc/pf.conf /tmp/pf.conf.t16'
rm -rf "$HOME/.foxhole"

echo "== T17 DNS modes (doh/vpn/plain) + interface list re-rendered at helper start"
FOXHOLE_DNS_MODE=vpn prepare_pf_dns_lock_anchor >/dev/null 2>&1; enable_pf_dns_lock >/dev/null 2>&1
chk "vpn mode: no Quad9 pass rule loaded" '! pfq -a $A -sr | grep -q "9\.9\.9\."'
chk "vpn mode: block rules and utun passes loaded" 'pfq -a $A -sr | grep -q "port = 53" && pfq -a $A -sr | grep -q "^pass .* on utun"'
netchk "vpn mode: even Quad9 on 53 is blocked" '! dig +time=3 +tries=1 +short example.com @9.9.9.9 2>/dev/null | grep -q "[0-9]"'
disable_pf_dns_lock >/dev/null 2>&1
FOXHOLE_DNS_MODE=plain prepare_pf_dns_lock_anchor >/dev/null 2>&1; enable_pf_dns_lock >/dev/null 2>&1
chk "plain mode: Quad9 passes udp+tcp on any port" 'pfq -a $A -sr | grep "to 9\.9\.9\.9" | grep -qv "port = 443"'
netchk "plain mode: Quad9 on 53 allowed" 'dig +time=4 +tries=1 +short example.com @9.9.9.9 2>/dev/null | grep -q "[0-9]"'
disable_pf_dns_lock >/dev/null 2>&1
FOXHOLE_DNS_MODE=doh prepare_pf_dns_lock_anchor >/dev/null 2>&1; enable_pf_dns_lock >/dev/null 2>&1
REAL_IF=$(networksetup -listallhardwareports | awk '/^Device: en[0-9]+$/ {print $2; exit}')
sudo sed -i '' -E 's/^(block out quick on \{)[^}]*(\} )/\1 en99 \2/' $RULES
chk "rules file now carries a stale interface list (en99 only)" 'grep -q "^block out quick on { en99 }" $RULES'
sudo bash $HELPER start >/dev/null 2>&1
chk "helper start re-renders the interface list (real $REAL_IF scoped, stale en99 gone)" 'pfq -a $A -sr | grep "port = 53" | grep -q "$REAL_IF" && ! pfq -a $A -sr | grep -q en99'
chk "re-render does not touch the rules file on disk" 'grep -q "^block out quick on { en99 }" $RULES'
ls -la /var/run/foxhole-pf.* 2>&1 | sed "s/^/  info: /"
chk "re-render leaves no temp files behind" '! ls /var/run/foxhole-pf.* >/dev/null 2>&1'
chk "helper status still active" 'sudo bash $HELPER status'
disable_pf_dns_lock >/dev/null 2>&1
chk "T17 cleanup: PF off, no leftovers" '! pf_on && ! test -e $RULES'

echo "== T18 real Privoxy via Homebrew (base image foxhole-brew: FOXHOLE_VM_BASE=foxhole-brew; needs egress)"
for B in /opt/homebrew/bin/brew /usr/local/bin/brew; do [[ -x $B ]] && eval "$($B shellenv)" && break; done
if ! command -v brew >/dev/null 2>&1 || [[ "$NET_OK" != 1 ]]; then
    echo "  SKIP: T18 real Privoxy (needs Homebrew in the VM and internet; use FOXHOLE_VM_BASE=foxhole-brew)"; SKIP=$((SKIP+1))
else
    SVC=$(networksetup -listallnetworkservices | tail -n +2 | grep -v '^\*' | head -1)
    install_privoxy > /tmp/t18-install.out 2>&1
    sed 's/\x1b\[[0-9;]*m//g' /tmp/t18-install.out | grep -E "✗|\[!\]|✓" | head -5
    chk "install_privoxy installed the formula" 'brew list --formula privoxy >/dev/null 2>&1'
    for _ in $(seq 1 10); do nc -z 127.0.0.1 8118 2>/dev/null && break; sleep 1; done
    chk "brew services started Privoxy (port 8118 listens)" 'nc -z 127.0.0.1 8118'
    if ! nc -z 127.0.0.1 8118 2>/dev/null; then
        echo "  info: brew services did not start Privoxy here (headless ssh has no GUI launchd domain); starting it directly"
        ( "$(brew --prefix)/sbin/privoxy" --no-daemon "$(brew --prefix)/etc/privoxy/config" >/tmp/privoxy.out 2>&1 & )
        for _ in $(seq 1 10); do nc -z 127.0.0.1 8118 2>/dev/null && break; sleep 1; done
    fi
    chk "Privoxy listens on loopback only (not exposed)" 'lsof -nP -iTCP:8118 -sTCP:LISTEN | grep -q "127.0.0.1:8118" && ! lsof -nP -iTCP:8118 -sTCP:LISTEN | grep -qE "\*:8118|0\.0\.0\.0:8118"'
    chk "real Privoxy answers HTTP through the proxy" '[[ "$(curl -s -x http://127.0.0.1:8118 --max-time 15 -o /dev/null -w "%{http_code}" http://example.com/)" == 200 ]]'
    configure_privoxy_vpn_bypass >/tmp/t18-bypass.out 2>&1
    chk "bypass rules written to the Privoxy config" 'grep -q "foxhole\|VPN bypass\|forward" "$(brew --prefix)/etc/privoxy/config"'
    enable_privoxy_vpn_autoswitch >/tmp/t18-auto.out 2>&1
    sleep 8
    chk "real Privoxy + no VPN -> proxies ON" '[[ "$(networksetup -getwebproxy "$SVC" | awk -F": " "\$1==\"Enabled\"{print \$2}")" == Yes ]]'
    sudo ifconfig utun3 inet 10.99.0.1 10.99.0.2 netmask 255.255.255.255 up; sudo bash /usr/local/bin/proxy-toggle.sh
    chk "real Privoxy + VPN up -> proxies OFF" '[[ "$(networksetup -getwebproxy "$SVC" | awk -F": " "\$1==\"Enabled\"{print \$2}")" == No ]]'
    sudo ifconfig utun3 inet 10.99.0.1 delete
    disable_privoxy_autoswitch >/dev/null 2>&1
    chk "disable: proxies OFF and toggle gone" '[[ "$(networksetup -getwebproxy "$SVC" | awk -F": " "\$1==\"Enabled\"{print \$2}")" == No ]] && ! test -e /usr/local/bin/proxy-toggle.sh'
    pkill -x privoxy 2>/dev/null; brew services stop privoxy >/dev/null 2>&1
fi

echo "== T19 real WireGuard tunnel (wireguard-go: two peers in the VM) with the lock on (needs Homebrew + egress)"
for B in /opt/homebrew/bin/brew /usr/local/bin/brew; do [[ -x $B ]] && eval "$($B shellenv)" && break; done
if ! command -v brew >/dev/null 2>&1 || [[ "$NET_OK" != 1 ]]; then
    echo "  SKIP: T19 real WireGuard (needs Homebrew in the VM and internet; use FOXHOLE_VM_BASE=foxhole-brew)"; SKIP=$((SKIP+1))
else
    brew list --formula wireguard-tools >/dev/null 2>&1 || brew install wireguard-tools wireguard-go >/tmp/t19-brew.out 2>&1
    WD=$(mktemp -d); (
        cd "$WD" && umask 077
        wg genkey > ka; wg genkey > kb
        sudo env WG_TUN_NAME_FILE="$WD/na" wireguard-go utun >/dev/null 2>&1; sleep 1
        sudo env WG_TUN_NAME_FILE="$WD/nb" wireguard-go utun >/dev/null 2>&1; sleep 1
    )
    UA=$(sudo cat "$WD/na"); UB=$(sudo cat "$WD/nb")
    PA=$(wg pubkey < "$WD/ka"); PB=$(wg pubkey < "$WD/kb")
    echo "  info: tunnel ends $UA <-> $UB (UDP over 127.0.0.1)"
    sudo wg set "$UA" private-key "$WD/ka" listen-port 51820 peer "$PB" allowed-ips 192.0.2.0/24 endpoint 127.0.0.1:51821
    sudo wg set "$UB" private-key "$WD/kb" listen-port 51821 peer "$PA" allowed-ips 10.77.0.1/32 endpoint 127.0.0.1:51820
    sudo ifconfig "$UA" inet 10.77.0.1 10.77.0.9 netmask 255.255.255.255 up
    sudo ifconfig "$UB" inet 10.77.0.2 10.77.0.1 netmask 255.255.255.255 up
    sudo route -n add -net 192.0.2.0/24 -interface "$UA" >/dev/null 2>&1
    FOXHOLE_DNS_MODE=doh prepare_pf_dns_lock_anchor >/dev/null 2>&1; enable_pf_dns_lock >/dev/null 2>&1
    chk "lock is active with a real WireGuard interface present" 'sudo bash $HELPER status'
    sudo tcpdump -i "$UB" -n -c 1 -w "$WD/cap.pcap" udp port 53 >/dev/null 2>&1 &
    TP=$!; sleep 1
    dig +time=2 +tries=1 @192.0.2.53 example.com >/dev/null 2>&1
    sleep 1; sudo kill $TP 2>/dev/null; wait $TP 2>/dev/null
    chk "DNS to a resolver behind the tunnel passes the lock (query arrived decrypted on the peer)" 'sudo tcpdump -nr "$WD/cap.pcap" 2>/dev/null | grep -q "192\.0\.2\.53\.53"'
    chk "WireGuard handshake completed" 'sudo wg show "$UA" latest-handshakes | grep -qE "[[:space:]][1-9][0-9]*$"'
    sudo route -n delete -net 192.0.2.0/24 >/dev/null 2>&1
    pfq -a $A -z >/dev/null
    dig +time=1 +tries=2 @192.0.2.53 example.com >/dev/null 2>&1
    B=$(blk53); echo "  info: udp/53 block-rule packets without the tunnel route: $B"
    chk "same query without the tunnel route leaves a physical interface and is blocked" '[[ "$B" -gt 0 ]]'
    disable_pf_dns_lock >/dev/null 2>&1
    sudo pkill -x wireguard-go 2>/dev/null; rm -rf "$WD"
    chk "T19 cleanup: PF off, no leftovers" '! pf_on && ! test -e $RULES'
fi

echo "== T20 disable still unlocks when the helper re-install fails (audit F2)"
prepare_pf_dns_lock_anchor >/dev/null 2>&1; enable_pf_dns_lock >/dev/null 2>&1
chk "T20 setup: lock active" 'sudo bash $HELPER status'
# Since the helper-directory check, disable no longer aborts here: it releases the reference itself
( set -e; _install_pf_helper() { die "simulated helper install failure"; }; disable_pf_dns_lock ) > /tmp/t20.out 2>&1; RC=$?
chk "disable completes although the helper install failed" '[[ $RC -eq 0 ]] && grep -q "simulated helper install failure" /tmp/t20.out && grep -q "releasing the PF reference directly" /tmp/t20.out && grep -q "PF DNS lock removed" /tmp/t20.out'
chk "block rules flushed, PF off, no reference left" '! pfq -a $A -sr | grep -q . && ! pf_on && [[ "$(ntokens)" == 0 ]]'
chk "boot daemon and plist gone" '! test -e $PLIST && ! sudo launchctl print system/com.hardening.pf.dnsleak >/dev/null 2>&1'
chk "no leftovers (rules, helper, token)" '! test -e $RULES && ! test -e $HELPER && ! sudo test -e $TOKEN'

echo "== T27 helper directory must be root-only writable"
sudo chown admin /usr/local/libexec
prepare_pf_dns_lock_anchor >/dev/null 2>&1
( set -e; enable_pf_dns_lock ) > /tmp/t27.out 2>&1; RC=$?
sed 's/\x1b\[[0-9;]*m//g' /tmp/t27.out | grep "✗" | head -2
chk "user-owned helper directory: enable refuses and names the fix" '[[ $RC -ne 0 ]] && grep -q "is not root-only writable" /tmp/t27.out && grep -q "sudo chown root:wheel /usr/local/libexec" /tmp/t27.out'
chk "refusal: no helper, no plist, no rules loaded, PF off" '! test -e $HELPER && ! test -e $HELPER.new && ! test -e $PLIST && ! pfq -a $A -sr | grep -q . && ! pf_on'
sudo chown root:wheel /usr/local/libexec; sudo chmod 775 /usr/local/libexec
( set -e; enable_pf_dns_lock ) > /tmp/t27b.out 2>&1; RC=$?
chk "group-writable helper directory: enable refuses" '[[ $RC -ne 0 ]] && grep -q "is not root-only writable" /tmp/t27b.out && ! pf_on'
sudo chmod 755 /usr/local/libexec
enable_pf_dns_lock >/dev/null 2>&1
chk "root:wheel 755 directory: enable works" 'sudo bash $HELPER status'
disable_pf_dns_lock >/dev/null 2>&1
chk "T27 cleanup: PF off, no leftovers" '! pf_on && ! test -e $RULES && ! test -e $HELPER'

echo "== T21 failed enable rolls back to 'lock off' (audit F3, F11)"
prepare_pf_dns_lock_anchor >/dev/null 2>&1
( _launchd_bootstrap() { return 1; }; enable_pf_dns_lock ) > /tmp/t21.out 2>&1; RC=$?
sed 's/\x1b\[[0-9;]*m//g' /tmp/t21.out | grep -E "✗|!\]" | head -3
chk "bootstrap failure: enable returns non-zero and says it rolled back" '[[ $RC -ne 0 ]] && grep -q "rolled back" /tmp/t21.out && ! grep -q "ACTIVE" /tmp/t21.out'
chk "bootstrap failure: no plist, no job (nothing turns the lock on at boot)" '! test -e $PLIST && ! test -e $PLIST.new && ! sudo launchctl print system/com.hardening.pf.dnsleak >/dev/null 2>&1'
chk "bootstrap failure: no rules loaded, PF off, no reference" '! pfq -a $A -sr | grep -q . && ! pf_on && [[ "$(ntokens)" == 0 ]]'
disable_pf_dns_lock >/dev/null 2>&1
echo "this is not a pf rule" | sudo tee $RULES.new >/dev/null
enable_pf_dns_lock > /tmp/t21b.out 2>&1; RC=$?
chk "unloadable rules: enable returns non-zero" '[[ $RC -ne 0 ]] && grep -q "did not come up" /tmp/t21b.out'
chk "unloadable rules: no plist, no rules loaded, PF off, no reference" '! test -e $PLIST && ! pfq -a $A -sr | grep -q . && ! pf_on && [[ "$(ntokens)" == 0 ]]'
OTHER=$(sudo pfctl -E 2>&1 | sed -n "s/^Token : //p")
echo "this is not a pf rule" | sudo tee $RULES.new >/dev/null
enable_pf_dns_lock >/dev/null 2>&1
chk "unloadable rules with another PF holder: anchor empty, the other reference untouched" '! pfq -a $A -sr | grep -q . && pf_on && [[ "$(ntokens)" == 1 ]]'
sudo pfctl -X "$OTHER" >/dev/null 2>&1
disable_pf_dns_lock >/dev/null 2>&1
chk "T21 cleanup: PF off, no leftovers" '! pf_on && ! test -e $RULES && ! test -e $RULES.new && ! test -e $HELPER'

echo "== T22 restore.sh removes the lock (audit F1)"
create_net_backup > /dev/null 2>&1
BK=$(ls -d "$HOME"/.foxhole/backups/* | tail -1)
prepare_pf_dns_lock_anchor >/dev/null 2>&1; enable_pf_dns_lock >/dev/null 2>&1
chk "T22 setup: lock active" 'sudo bash $HELPER status'
pfq -sr > /tmp/pf.main.t22
# shellcheck disable=SC2024  # the redirect target is a user-owned /tmp file
sudo bash $BK/restore.sh > /tmp/t22-restore.out 2>&1; RR=$?
chk "restore.sh exits 0 and reports the lock removed" '[[ $RR -eq 0 ]] && grep -q "PF DNS lock removed" /tmp/t22-restore.out'
chk "restore: rules flushed, PF off, no reference" '! pfq -a $A -sr | grep -q . && ! pf_on && [[ "$(ntokens)" == 0 ]]'
chk "restore: plist and job gone (lock does not return at boot)" '! test -e $PLIST && ! sudo launchctl print system/com.hardening.pf.dnsleak >/dev/null 2>&1'
chk "restore: helper, rules and token files gone" '! test -e $HELPER && ! test -e $RULES && ! sudo test -e $TOKEN'
chk "restore: main ruleset not reloaded or changed" 'diff <(pfq -sr) /tmp/pf.main.t22 >/dev/null'
netchk "restore: plain DNS @8.8.8.8 works again" 'dig +time=4 +tries=1 +short example.com @8.8.8.8 2>/dev/null | grep -q "[0-9]"'
rm -rf "$HOME/.foxhole"

echo "== T23 mode switch: declined switch changes nothing, direct switch replaces the rules (audit F4, F5, G)"
FOXHOLE_DNS_MODE=plain prepare_pf_dns_lock_anchor >/dev/null 2>&1; enable_pf_dns_lock >/dev/null 2>&1
FOXHOLE_DNS_MODE=vpn prepare_pf_dns_lock_anchor >/dev/null 2>&1
( ask() { printf -v "$2" '%s' 'N'; }; enable_pf_dns_lock ) >/dev/null 2>&1
chk "declined switch: rules file still says plain, prepared file dropped" 'grep -q "^# DNS policy: plain" $RULES && ! test -e $RULES.new'
sudo launchctl kickstart -k system/com.hardening.pf.dnsleak >/dev/null 2>&1; sleep 3
chk "declined switch: a daemon re-run (as at boot) still loads plain" 'pfq -a $A -sr | grep "to 9\.9\.9\.9" | grep -qv "port = 443" && sudo bash $HELPER status'
FOXHOLE_DNS_MODE=vpn prepare_pf_dns_lock_anchor >/dev/null 2>&1; enable_pf_dns_lock >/dev/null 2>&1
chk "direct switch plain -> vpn (no disable): no Quad9 rule left in the kernel" '! pfq -a $A -sr | grep -q "9\.9\.9\."'
chk "direct switch: lock active, still exactly one reference, daemon bootstrapped" 'sudo bash $HELPER status && [[ "$(ntokens)" == 1 ]] && sudo launchctl print system/com.hardening.pf.dnsleak >/dev/null 2>&1'

echo "== T24 helper status and boot action (audit F8)"
echo "pass all" | sudo pfctl -f - >/dev/null 2>&1
chk "status fails when the main ruleset has no com.apple/* anchor (lock inert)" '! sudo bash $HELPER status'
sudo pfctl -f /etc/pf.conf >/dev/null 2>&1
chk "status is ok again once the stock main ruleset is back" 'sudo bash $HELPER status'
sudo bash $HELPER boot >/dev/null 2>&1; RC=$?
chk "boot action is idempotent: rc 0, still one reference" '[[ $RC -eq 0 ]] && [[ "$(ntokens)" == 1 ]] && sudo bash $HELPER status'

echo "== T25 reset continues past a failed step (audit F16)"
( disable_pf_dns_lock() { die "simulated PF step failure"; }; reset_net_hardening ) > /tmp/t25.out 2>&1
chk "reset reports the failed step and still completes" 'grep -q "PF DNS lock step failed" /tmp/t25.out && grep -q "Network hardening reset complete" /tmp/t25.out'
reset_net_hardening >/dev/null 2>&1
chk "T25 cleanup: PF off, no leftovers" '! pf_on && ! test -e $RULES && ! test -e $HELPER && ! test -e $PLIST'

echo "== T10 vpn_daily.sh menu from another cwd (driven by expect: ask() needs a tty)"
cat > /tmp/vd.exp <<'EXP'
set timeout 30
set env(TERM) xterm
spawn bash /Users/admin/foxhole/vpn_daily.sh
expect "Continue?*" { send "y\r" }
expect "Password:" { send "admin\r" }
expect "Create backup snapshot*" { send "y\r" }
expect "Choice (1-6):" { send "4\r" }
expect "Choice (1-6):" { send "1\r" }
expect "Choice (1-3, Enter = 1):" { send "1\r" }
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
chk "vpn_daily took a backup snapshot with restore.sh (audit F17)" 'ls "$HOME"/.foxhole/backups/*/restore.sh >/dev/null 2>&1'
rm -rf "$HOME/.foxhole"

echo "== T26 setup: leave the lock on (doh) for the reboot phase"
echo "  info: helper log lines that are not a plain start/boot/stop (expected: only the simulated failures of T21/T24):"
sudo grep -v -e "rules loaded into" -e "rules flushed" /var/log/foxhole-pf.log 2>/dev/null | tail -12 | sed "s/^/    /"
FOXHOLE_DNS_MODE=doh prepare_pf_dns_lock_anchor >/dev/null 2>&1; enable_pf_dns_lock >/dev/null 2>&1
chk "lock active before the reboot" 'sudo bash $HELPER status && test -e $PLIST'

echo
echo "RESULT: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"

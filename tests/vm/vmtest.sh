#!/bin/bash
# Runs INSIDE the foxhole-test VM. Sources the netlib and exercises PF lock paths.
set -uo pipefail
cd ~/foxhole
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
chk "utun pass rule loaded" 'pfq -a $A -sr | grep -q utun'
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

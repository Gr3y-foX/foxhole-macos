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

echo "== T1 baseline"
sudo cp /etc/pf.conf /tmp/pf.conf.baseline
BASE_SUM=$(shasum /etc/pf.conf | cut -d' ' -f1)
stat -f '%Su:%Sg %Lp' /etc/pf.conf
chk "pf.conf root:wheel 644" '[[ "$(stat -f "%Su:%Sg %Lp" /etc/pf.conf)" == "root:wheel 644" ]]'
chk "no hardening lines in pf.conf" '! grep -q dnsleak /etc/pf.conf'
NET_OK=0
curl -s -o /dev/null --max-time 6 https://1.1.1.1/ && NET_OK=1
echo "  info: direct internet egress: $([[ $NET_OK == 1 ]] && echo yes || echo NO)"

echo "== T2 prepare + enable"
prepare_pf_dns_lock_anchor 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
chk "anchor file exists" 'test -f /etc/pf.anchors/com.hardening.dnsleak'
chk "anchor syntax ok (pfctl -nf)" 'sudo pfctl -nf /etc/pf.anchors/com.hardening.dnsleak 2>/dev/null'
chk "anchor block rules scoped (on {)" 'grep -q "^block out quick on {" /etc/pf.anchors/com.hardening.dnsleak'
grep '^block' /etc/pf.anchors/com.hardening.dnsleak | head -2
enable_pf_dns_lock 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
chk "pf.conf has marker" 'grep -qF "# ===== hardening dns lock =====" /etc/pf.conf'
chk "pf.conf root:wheel 644 after enable" '[[ "$(stat -f "%Su:%Sg %Lp" /etc/pf.conf)" == "root:wheel 644" ]]'
chk "pf enabled" 'sudo pfctl -s info 2>/dev/null | grep -q "Status: Enabled"'
chk "anchor rules loaded (port 53)" 'sudo pfctl -a com.hardening.dnsleak -sr 2>/dev/null | grep -q "port = 53"'
chk "utun pass rule loaded" 'sudo pfctl -a com.hardening.dnsleak -sr 2>/dev/null | grep -q utun'
chk "LaunchDaemon plist exists" 'test -f /Library/LaunchDaemons/com.hardening.pf.dnsleak.plist'

echo "== T3 behaviour"
sudo pfctl -a com.hardening.dnsleak -sr 2>/dev/null | head -20
netchk "plain DNS @8.8.8.8 blocked" '! dig +time=3 +tries=1 +short example.com @8.8.8.8 2>/dev/null | grep -q "[0-9]"'
netchk "Quad9 @9.9.9.9 allowed" 'dig +time=4 +tries=1 +short example.com @9.9.9.9 2>/dev/null | grep -q "[0-9]"'
netchk "HTTPS by IP still works during lock" 'curl -s --max-time 6 -o /dev/null -w "%{http_code}" https://9.9.9.9/ -k | grep -qE "^[0-9]{3}$"'
echo "  info: system resolver (expected to FAIL without DoH profile):"
dig +time=3 +tries=1 +short example.com 2>&1 | head -2

echo "== T4 idempotence (enable again)"
enable_pf_dns_lock >/dev/null 2>&1
chk "marker appears exactly once" '[[ "$(grep -cF "# ===== hardening dns lock =====" /etc/pf.conf)" == "1" ]]'
chk "load anchor appears exactly once" '[[ "$(grep -c "load anchor \"com.hardening.dnsleak\"" /etc/pf.conf)" == "1" ]]'

echo "== T5 verify_dns_stack completes"
OUT=$(verify_dns_stack 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
echo "$OUT" | grep -E '^\[|Results'
chk "health check reached summary" 'echo "$OUT" | grep -q "Results:"'
chk "[2] utun rule found via anchor" 'echo "$OUT" | grep -q "\[2\].*present"'

echo "== T6 disable"
disable_pf_dns_lock 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
chk "no hardening lines left in pf.conf" '! grep -q "dnsleak\|hardening dns lock" /etc/pf.conf'
chk "pf.conf root:wheel 644 after disable" '[[ "$(stat -f "%Su:%Sg %Lp" /etc/pf.conf)" == "root:wheel 644" ]]'
chk "anchor file removed" '! test -f /etc/pf.anchors/com.hardening.dnsleak'
chk "plist removed" '! test -f /Library/LaunchDaemons/com.hardening.pf.dnsleak.plist'
chk "anchor rules flushed" '! sudo pfctl -a com.hardening.dnsleak -sr 2>/dev/null | grep -q .'
chk "pf.conf content equals baseline (ignoring blank lines)" 'diff <(grep -v "^$" /etc/pf.conf) <(grep -v "^$" /tmp/pf.conf.baseline) >/dev/null'
netchk "plain DNS @8.8.8.8 works again" 'dig +time=4 +tries=1 +short example.com @8.8.8.8 2>/dev/null | grep -q "[0-9]"'

echo "== T7 reset_net_hardening re-run on clean state"
reset_net_hardening >/dev/null 2>&1; chk "reset exits 0" '[[ $? -eq 0 ]]'

echo "== T8 vpn_daily.sh menu from another cwd (driven by expect: ask() needs a tty)"
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
chk "vpn_daily [2] removes lock" 'grep -q "marker and anchor lines removed" /tmp/vpn_daily.out'
chk "vpn_daily exits cleanly" 'grep -q "Done. For daily use" /tmp/vpn_daily.out'
chk "no 'command not found' in vpn_daily output" '! grep -qi "command not found" /tmp/vpn_daily.out'
chk "no leftovers after vpn_daily" '! grep -q dnsleak /etc/pf.conf'

echo
echo "RESULT: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"

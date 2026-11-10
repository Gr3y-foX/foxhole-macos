# PF DNS-lock lockout audit — report

Scope: `mac-hardening-netlib.sh` v0.17.3 on `debug` (`80f2847`), PF lock start, stop,
boot and recovery paths, scenarios A–J of `docs/dev/AUDIT_PF_LOCKOUT.md` plus extras.
Read-only audit: no product or test file was changed, nothing was run against host
PF, launchd, network config or `/etc`. All line numbers are `mac-hardening-netlib.sh`
unless another file is named, and were read from the file at this commit.

Callers were confirmed with `grep -rn` over the repo's `*.sh` files (GitNexus does not
resolve shell calls): the PF functions are called only from the netlib menu
(L1133–1134, L1153), `vpn_daily.sh` (L73–74, L80, L114) and the test files.

One fact shapes most findings: the netlib runs under `set -euo pipefail` (L2) and
`vpn_daily.sh` inherits it by sourcing (vpn_daily.sh:38). Any unguarded non-zero
status inside a function ends the whole menu process.

## 1. Summary

| Severity | Count | Findings |
|---|---|---|
| lockout | 6 | F1, F2, F3, F5, F6, F11 |
| leak | 6 | F4, F7, F8, F9, F10, F14 |
| cosmetic | 5 | F12, F13, F15, F16, F17 |

"Lockout" here means DNS is blocked when the user does not expect it, or stays blocked
after the user tried to remove the lock. No path was found that cuts IP connectivity:
the anchor only blocks ports 53 and 853 on `en*` interfaces (L352–355).

F14 (temp-file staging) is a local privilege question, not a traffic leak. It is filed
under "leak" as the closest of the three classes.

**Most dangerous: F1, `mac-hardening-netlib.sh:188` (`restore.sh` body, written by
`_write_restore_script` L169).** The backup's `restore.sh` is the advertised safety
net (L164, `docs/dev/CHECKPOINT.md` D2), but it does not stop the lock, flush the
anchor, release the PF reference or remove the LaunchDaemon plist. A user who is
locked out of DNS and runs it sees "[+] restored" lines, still has no DNS, and still
has none after a reboot. It happens on every run, not only on an error path.
F2 is the runner-up: it is rarer, but there the disable path itself fails.

## 2. Findings

| ID | Scenario | Location | What happens | User-visible impact | Severity | Minimal fix |
|---|---|---|---|---|---|---|
| F1 | F | L188–193 (restore body), L164, L174–175 | `restore.sh` restores `hosts`, `pf.conf`, `resolver` only. `pf.conf` is never edited by 0.17.3, so for the lock it is a no-op. The anchor rules stay loaded, the token stays held, the plist stays in `/Library/LaunchDaemons`. | Restore reports success, DNS stays blocked, and the lock comes back at every boot. | lockout | Add lock teardown to `restore.sh` (snippet 2.1). |
| F2 | E, H | L586 before L587; exits at L367, L449 | `disable_pf_dns_lock` boots the daemon out (L582), removes the plist (L583), then re-installs the helper *before* it stops the lock. If `mktemp /tmp/...` fails (L367, `set -e`) or `install` fails (`die`, L449), the process exits with the rules still loaded and the reference still held. | Disable and reset both abort with an error. DNS stays blocked until reboot (plist is gone, so a reboot clears it). Re-running disable fails the same way. | lockout | Flush the anchor with plain `pfctl` before anything that can fail (snippet 2.2). |
| F3 | I, H | L574–576, L531–541 | `_launchd_bootstrap` failure only warns (L576; the `a && b \|\| c` form returns 0). On a first enable nothing has run `start`, so the status poll fails and `enable_pf_dns_lock` returns 1 (L540). Helper and plist stay on disk; nothing rolls back. | "PF DNS lock did not come up", the menu exits (F13). At the next boot launchd loads the plist and the lock turns on, in a session where the user believes it is off. | lockout (delayed) | In `enable_pf_dns_lock`, run `sudo /bin/bash "$PF_LOCK_HELPER" start` directly and check its status; treat the daemon as boot persistence only. On failure remove the plist (snippet 2.3). |
| F4 | G, I | L532–536; helper L400, L441 | On a re-enable (mode switch) with a failed bootstrap, or a failed bootout followed by a failed bootstrap, `start` never re-runs. `status` only checks "some rule with port 53 is loaded and the token is held", which the *old* rules satisfy. | "launchctl bootstrap failed" then "PF DNS lock: ACTIVE ✓". The kernel still has the old mode, e.g. the `plain` Quad9 any-port exception after switching to `vpn`. The daemon is not loaded until reboot. | leak | Same as F3: synchronous `start`, which reloads the anchor from the new file (helper L419/L421). |
| F5 | G | L1133–1134, vpn_daily.sh:73–74; L502–506, L523 | `prepare_pf_dns_lock_anchor` rewrites the rules file (L357) before `enable_pf_dns_lock` asks for confirmation (L502). Answering "N", or the `com.apple/*` guard refusing (L523), leaves the new mode on disk with the old one in the kernel. | With the lock already on: declining a `doh`→`vpn` switch still makes the next boot (or daemon restart) apply `vpn`, so DNS works only through a tunnel from then on. | lockout (delayed) | Ask before writing: move the confirmation into the callers ahead of `prepare`, or have `prepare` write to `${PF_LOCK_RULES}.new` and let `enable` `mv` it into place after the confirmation and the guard. |
| F6 | A, B | L346–348, L352–355 | The block is on every `en*` interface for every destination. In `vpn` mode there is no exception, so a VPN client that must resolve its server name before the tunnel exists cannot. In every mode, a captive-portal network (hotel, airport) cannot serve its DHCP-provided DNS. | No name resolution on a fresh network or after boot until the lock is disabled. IP connectivity is intact. Recovery through menu [2] works offline. | lockout (by design, soft) | Say so in the L500–501 warning and in vpn_daily [4] ("to join a captive network or bootstrap a VPN by hostname, disable the lock first"). No rule change proposed. |
| F7 | A | helper L409–412 | At `start` the interface list in the block rules is *replaced* by what `networksetup` reports at that moment. If only part of the hardware is enumerated at boot, or a dongle present at enable time is unplugged at boot, the loaded list is narrower than the file. | Plain DNS leaves on the interface missing from the list until the next `start`. No message. | leak | Use the union of the file's list and the live list (snippet 2.4). T17's "stale en99 gone" assertion then has to change: that is a product decision (D2), not a test bug. |
| F8 | A | plist L547–569 (no `KeepAlive`); helper L403–431 vs L514 | (a) If `start` exits 1 at boot, launchd does not retry. (b) `start` and `status` never check that the main ruleset evaluates `anchor "com.apple/*"`; only `enable` does (L514). | (a) After a reboot the lock is off with no notice except a line in `/var/log/foxhole-pf.log`. (b) With a custom or replaced main ruleset the lock is inert while `status` exits 0. | leak | (a) Bounded retry inside `start` (e.g. 5 tries, `sleep 2`) rather than `KeepAlive`. (b) In `start`, log a warning when `/sbin/pfctl -sr` has no `anchor "com.apple/*"` line; make `status` fail on it. |
| F9 | B, D | L316, L322–323, L327, L336, L343 | All pass rules in the anchor are `quick` and three have no interface: icmp6 (L327), Quad9 tcp 443 (L336), Quad9 any port (L343). `quick` in an anchor ends evaluation of the whole ruleset, so they pre-empt any block rules a VPN kill switch placed after `anchor "com.apple/*"`. None of them is needed for the lock in `doh` mode: the blocks only match 53/853 on `en*`. | With a kill switch active and the tunnel down, traffic to Quad9 (443, or any port in `plain`), all ICMPv6, and anything on another `utun` can leave despite the kill switch. | leak (needs a real kill switch to confirm rule order) | Keep only what the blocks need: drop rules [1]–[3] and the `doh` Quad9 rule, and scope the `plain` exception: `pass out quick on { IFACES } proto { udp tcp } to <ip> port { 53 853 }`. Offline checks and T3/T17 need updating with it. |
| F10 | D, F | L490 (from L511 and L591); L174–175 | `_pf_legacy_cleanup` reloads the main ruleset with `pfctl -f /etc/pf.conf` when the pre-0.17.3 marker is present. The `restore.sh` header tells the user to run the same command. Both replace whatever a VPN kill switch loaded into the main ruleset. The lock itself survives the reload (T4, vmtest.sh:81–82), so the hint does nothing for recovery. | Kill-switch rules are silently dropped: once on migration, and whenever a user follows the restore hint. | leak | L490: warn and ask before the reload when `pfctl -s References` shows another holder. L174–175: delete the hint (0.17.3 never edits `pf.conf`) or reword it to "only if no VPN kill switch is active". |
| F11 | C, H | helper L419/L421 then L424–426 | `start` loads the rules first and takes the PF reference second. If `pfctl -E` fails or prints no token, it exits 1 with the rules still in the anchor. | If another program already has PF enabled, the DNS block is live while `status`, `enable` and the log all say the lock failed. Menu [2] clears it. | lockout (recoverable) | On the "no token" path flush before exit: `pf -a "$ANCHOR" -F all >/dev/null`. |
| F12 | C | helper L424–428, L434–437; L593–594 | The token write (L428) is unchecked and not atomic with `-E`. If the write fails, `start` is killed between L424 and L428, the `Token :` parse (L425) fails, or the token file is deleted, the reference is orphaned. A later `start` takes a second one; `stop` cannot release either (L434). | After disable PF stays enabled and L594 says "another program holds a reference". Rules are flushed, so no block. Cleared by reboot or `sudo pfctl -d`. | cosmetic | Check the write and release on failure: `( umask 077; echo "$TOKEN" > "$TOKEN_FILE" ) \|\| { pf -X "$TOKEN"; exit 1; }`. Reword L594 to "a PF reference is still held (ours may have been lost)". |
| F13 | H | L523, L540 → L1134, vpn_daily.sh:74 | `enable_pf_dns_lock` returns 1 on the guard and on "did not come up". The callers do not guard the call, so `set -e` ends the menu. | The script exits right after the error, so the user is no longer in the menu that offers disable/reset. | cosmetic | In both menus: `enable_pf_dns_lock \|\| warn "PF DNS lock was not enabled"`. |
| F14 | J | L546–571 (plist), L367–448 (helper), L297–357 (rules), L480–486 (pf.conf) | Content that root will run or load is staged in a file owned by the invoking user, then copied with `sudo install`. Another process of the same user can rewrite it in between. For the plist the window contains a `sudo` call (`_launchd_bootout`, L570), so it can be as long as a password prompt. Plist and helper give root code execution; rules and pf.conf give control of PF. Detail in 2.5. | None in normal use. A same-user process without the sudo password could become root during enable or disable. | leak (integrity) | Stream the static heredocs straight to root, as `enable_privoxy_vpn_autoswitch` already does at L887: `sudo tee "${PF_LOCK_PLIST}.new" >/dev/null <<'EOF'`, then `sudo chown root:wheel`, `sudo chmod 644`, `sudo mv -f`. Same for the helper (mode 755). |
| F15 | J | L357–359 | When `install` fails, `die` runs before `rm -f "$TMP"`. L449 and L572 do remove theirs. | A `pf.anchor.XXXXXX` file (rules text, no secret) stays in `/tmp`. | cosmetic | `\|\| { rm -f "$TMP"; die "..."; }` as at L449. |
| F16 | E, H | L1059–1061; L483, L484, L487 | `reset_net_hardening` runs three disables in sequence with no guards. Any exit in the first (F2, or a `die` in `_pf_legacy_cleanup`) skips the Privoxy and hosts steps. | Reset stops half-way; the proxy-toggle daemon and hosts blocklist stay. | cosmetic | `disable_pf_dns_lock \|\| warn "..."` for each step, after F2 removes the `die` exits from the PF step. |
| F17 | F | vpn_daily.sh (no call); L110–112; L498 | `create_net_backup` is called only from the netlib menu (L1105). `vpn_daily.sh` never snapshots, and `enable_pf_dns_lock` does not either, against the CLAUDE.md convention. The backup saves `pf.anchor.dnsleak` (L110–112) but nothing ever reads it back. | VPN Daily users have no `restore.sh` at all. | cosmetic | Call `create_net_backup` once in `vpn_daily.sh` before the menu, as L1103–1109 does. Use the saved anchor in `restore.sh` (snippet 2.1) or stop saving it. |

### 2.1 F1: `restore.sh` teardown (bash 3.2, no eval, runs as root)

To be added before the `dscacheutil` line (L194). It never touches the main ruleset.
If the backup holds `pf.anchor.dnsleak`, the lock existed when the snapshot was taken,
so the rules file is restored and the lock is left alone.

```bash
# PF DNS lock (v0.17.3 layout). Anchor-scoped: the main ruleset is not touched.
LOCK_ANCHOR="com.apple/foxhole.dnsleak"
LOCK_LABEL="com.hardening.pf.dnsleak"
LOCK_HELPER="/usr/local/libexec/foxhole-pf-dnslock"
LOCK_TOKEN="/var/db/foxhole/pf.token"
if [[ -f "${DIR}/pf.anchor.dnsleak" ]]; then
    restore pf.anchor.dnsleak /etc/pf.anchors/com.hardening.dnsleak
    echo "[i] PF DNS lock was configured at backup time; left as it is."
else
    launchctl bootout "system/${LOCK_LABEL}" 2>/dev/null
    rm -f "/Library/LaunchDaemons/${LOCK_LABEL}.plist"
    /sbin/pfctl -a "$LOCK_ANCHOR" -F all >/dev/null 2>&1
    if [[ -s "$LOCK_TOKEN" ]]; then
        T="$(cat "$LOCK_TOKEN")"
        case "$T" in
            ''|*[!0-9]*) ;;
            *) /sbin/pfctl -X "$T" >/dev/null 2>&1 ;;
        esac
    fi
    rm -f "$LOCK_TOKEN" "$LOCK_HELPER" /etc/pf.anchors/com.hardening.dnsleak
    echo "[+] PF DNS lock removed (anchor flushed, boot daemon removed)"
fi
```

### 2.2 F2: flush before the helper re-install

In `disable_pf_dns_lock`, directly after L583:

```bash
    # Flush first: nothing below may leave the rules loaded if it fails
    sudo pfctl -a "$PF_LOCK_ANCHOR" -F all >/dev/null 2>&1 || true
```

Better still, use the installed helper when it exists and re-install only when it is
missing: `[[ -f "$PF_LOCK_HELPER" ]] || _install_pf_helper`.

### 2.3 F3/F4: synchronous start in `enable_pf_dns_lock`

Replacing the poll at L530–541:

```bash
    if sudo /bin/bash "$PF_LOCK_HELPER" start >/dev/null \
       && sudo /bin/bash "$PF_LOCK_HELPER" status; then
        log "PF DNS lock: ACTIVE ✓ (anchor ${PF_LOCK_ANCHOR})"
    else
        err "PF DNS lock did not come up. Log: /var/log/foxhole-pf.log"
        _launchd_bootout "$PF_LOCK_LABEL"
        sudo rm -f "$PF_LOCK_PLIST" || true
        sudo /bin/bash "$PF_LOCK_HELPER" stop >/dev/null || true
        return 1
    fi
```

`start` is idempotent for the reference (helper L423), so the daemon's own
`RunAtLoad` run next to it is harmless (T4, vmtest.sh:83–84).

### 2.4 F7: union of interface lists in the helper

Replacing helper L409–412. `sort -u` output contains only `en<N>` names, because both
inputs are filtered by the same pattern, so the `sed` replacement stays safe.

```bash
        LIVE=$(/usr/sbin/networksetup -listallhardwareports 2>/dev/null \
            | awk '/^Device: en[0-9]+$/ {print $2}')
        FILED=$(sed -n -E 's/^block out quick on \{([^}]*)\} .*/\1/p' "$RULES" \
            | tr ' ' '\n' | grep -E '^en[0-9]+$')
        IFACES=$(printf '%s\n%s\n' "$LIVE" "$FILED" | grep -E '^en[0-9]+$' \
            | sort -u | tr '\n' ' ' | sed 's/ $//')
```

### 2.5 Scenario J: each `mktemp` call

None of the five is inside the root-run helper. The helper heredoc (L369–446) has no
`mktemp` and passes rules on stdin (L413, L419), so the CLAUDE.md rule "no temp files
in root-run helpers" holds as written. The installer-side calls are outside the
letter of that rule; three of them break its intent.

| Line | Function | Path | Created as | Becomes | Swap possible | Left behind | Covered by the rule |
|---|---|---|---|---|---|---|---|
| L297 | `prepare_pf_dns_lock_anchor` | `/tmp/pf.anchor.XXXXXX` | invoking user, 0600 | root-owned PF rules file, loaded at boot | Same user only, between L356 and L357. Result: arbitrary anchor rules (weakened lock, F9-style bypass). No code execution. | Yes, when `install` fails (F15) or the process is killed. | No (not the helper). |
| L367 | `_install_pf_helper` | `/tmp/foxhole-pf-helper.XXXXXX` | invoking user, 0600 | script run by root from `sudo` and at every boot | Same user only, between L368 and L448. Result: root code execution, persistent. | Only if killed between L367 and L450; both exit paths remove it. | No by the letter; yes by intent (F14). |
| L480 | `_pf_legacy_cleanup` | `$TMPDIR/tmp.XXXXXX` (per-user dir) | invoking user, 0600 | `/etc/pf.conf`, then loaded (L490) | Same user only, between L482 and L486. Result: arbitrary main ruleset. Legacy installs only. | No: removed at L483, L487, L488. | No. |
| L546 | `_install_pf_launchdaemon` | `/tmp/foxhole-pf-plist.XXXXXX` | invoking user, 0600 | root LaunchDaemon plist, bootstrapped at once (L574) | Same user only, between L547 and L571. The window includes `sudo launchctl bootout` (L570), so a sudo password prompt keeps it open. Result: root code execution. | Only if killed between L546 and L573. | No by the letter; yes by intent (F14). |
| L649 | `update_hosts` | `$TMPDIR/tmp.XXXXXX` | invoking user, 0600 | appended to `/etc/hosts` (L690–691) | Same user only, between the validation (L655) and the append. Result: arbitrary hosts entries. | Yes, on any `set -e` exit between L663 and L691 (see section 5, note 9). | No (not PF, not a helper). |

Is `/tmp` safe for the staging step? Against other users, yes: `mktemp` creates the
file with `O_EXCL`, mode 0600 and a random name, and `/tmp` is sticky. Against other
processes of the same user, no, and that is the user whose sudo rights the script
borrows. If the whole script is run under `sudo`, the files are root-owned and the
issue goes away. Since both heredocs are static, no staging file is needed at all.

Related: `sudo mkdir -p "$(dirname "$PF_LOCK_HELPER")"` (L365) does not check who
owns `/usr/local/libexec`. If that directory already exists and is user-writable
(Intel Homebrew layouts make parts of `/usr/local` user-owned), the root-run helper
can be replaced after install. Same for `/usr/local/bin/proxy-toggle.sh` (L771, L785).
Proposed: after `mkdir`, refuse to continue unless `stat -f '%Su' <dir>` is `root`.

## 3. Ruled out

| Scenario | Verdict | Line that makes it safe |
|---|---|---|
| A: hard lockout after reboot with no VPN | Safe. Only ports 53/853 on `en*` are blocked; DHCP, mDNS, HTTPS and SSH are untouched. In `doh` mode DNS works through the profile. | L352–355 (the only `block` rules); L336 |
| A: daemon runs before the network is up | Does not matter for rule matching: rules name interfaces, they do not need them to exist (T17 loads `en99`, vmtest.sh:291–294). An empty `networksetup` result falls back to the file. Real boot order: needs VM. | helper L411–417, L421 |
| B: tunnel on `utun16+`, `ipsec0`, `ppp0`, `tun0` is blocked | Safe. The blocks are scoped to `en[0-9]+` only, so a tunnel outside the pass list is simply not matched. The `utun0–15` pass rules are not what keeps tunnels working. | L244–245, L352–355; helper L409–410 |
| B: `utun` that appears after boot | Safe if PF binds names lazily, as the `en99` case suggests. Not proven for a tunnel created after the rules load: needs VM. | L322–323 |
| C: enable twice, disable once | Safe. A second `start` sees the held token and does not call `-E` again (T4, vmtest.sh:79–84). | helper L423 |
| C: stale token file after reboot or crash | Safe. The token must still appear in `pfctl -s References`, otherwise a new one is taken. | helper L396 |
| C: disable twice | Safe. No token, nothing to release. | helper L434 |
| D: `stop` reloads or flushes the main ruleset | Safe. The flush is anchor-scoped and `-X` releases only our token. There is no `pfctl -d` and no `-f /etc/pf.conf` in the helper. Exception outside the helper: F10. | helper L433, L435 |
| E: reset leaves a plist that re-enables the lock | Safe. Bootout and plist removal come first and bootout cannot abort the function. If `sudo` itself fails at L583 the state is unchanged and consistent. | L582–583, L454 |
| E: reset on a system with no lock | Safe (T9, vmtest.sh:130–132). | L587–588 |
| G: stale Quad9 exception after a normal mode switch | Safe on the normal path: the rules file is replaced whole and `pfctl -f` on the anchor replaces its ruleset. Existing states for Quad9 expire on their own. Not covered by a test (T17 disables between modes). Failure path: F4. | L357; helper L419/L421 |
| H: `sed` re-render injection | Safe. `IFACES` only ever holds names matching `en[0-9]+`. | helper L410, L412 |
| H: exit between `prepare` steps, in `_choose_dns_mode`, in `ask` | Safe: all exits happen before the first write. | L275, L282, L502–506 |
| H: exit between bootout (L570) and bootstrap (L574) on re-enable | Safe: the old plist is still on disk, so the daemon returns at boot; the kernel state is untouched. | L571–572 |
| I: PF referenced with no daemon | Harmless: rules and reference stay consistent and the plist on disk loads at boot. The misleading messages are F3/F4. | L571, helper L423 |
| J: temp file inside the root-run helper | None. | helper L369–446, L413, L419 |
| `launchctl load`/`unload` anywhere | None; only L454 and L461 call `launchctl`. | L454, L461 |

## 4. Proposed checks (not applied)

### 4.1 Offline, for `tests/ci/offline.sh`

Written without `eval` so they stand alone; `ok`/`bad`, `$T`, `$REPO` are the file's
own.

```bash
echo "== anchor per mode (exact rule sets)"
for MODE in doh vpn plain; do
    FOXHOLE_DNS_MODE="$MODE" prepare_pf_dns_lock_anchor >/dev/null 2>&1
    cp "$T/anchor.rules" "$T/anchor.$MODE"
    if grep -q "^# DNS policy: ${MODE}\$" "$T/anchor.$MODE"; then ok "$MODE: policy comment"; else bad "$MODE: policy comment"; fi
    N443=$(grep -c '^pass out quick proto tcp to .* port 443$' "$T/anchor.$MODE")
    NANY=$(grep -c '^pass out quick proto { udp tcp } to ' "$T/anchor.$MODE")
    case "$MODE" in
        doh)   WANT="4 0" ;;
        vpn)   WANT="0 0" ;;
        plain) WANT="0 4" ;;
    esac
    if [[ "$N443 $NANY" == "$WANT" ]]; then ok "$MODE: Quad9 rules = $WANT"; else bad "$MODE: Quad9 rules = $N443 $NANY, want $WANT"; fi
    if [[ "$(grep -c '^block ' "$T/anchor.$MODE")" == 4 ]]; then ok "$MODE: 4 block rules"; else bad "$MODE: 4 block rules"; fi
done
# Render order plain -> vpn above proves no stale exception survives a rewrite
if grep -q '9\.9\.9\.\|149\.112\.' "$T/anchor.vpn"; then bad "vpn after plain: stale Quad9 line"; else ok "vpn after plain: no stale Quad9 line"; fi

echo "== LaunchDaemon writer"
sed -n '/^_install_pf_launchdaemon() {/,/^}/p' "$REPO/mac-hardening-netlib.sh" > "$T/ld.fn"
# "launchctl" also appears in the warn text, so match the call forms only
if grep -qE 'sudo launchctl|launchctl (un)?load' "$T/ld.fn"; then bad "writer calls launchctl directly or load/unload"; else ok "writer uses only _launchd_bootout/_launchd_bootstrap"; fi
awk "/<< 'EOF'\$/{f=1;next} /^EOF\$/{f=0} f" "$T/ld.fn" > "$T/pf.plist"
if plutil -lint "$T/pf.plist" >/dev/null 2>&1; then ok "plist is well-formed"; else bad "plist is well-formed"; fi
if grep -q "<string>${PF_LOCK_LABEL}</string>" "$T/pf.plist" \
   && grep -q "<string>${PF_LOCK_HELPER}</string>" "$T/pf.plist"; then ok "plist label and helper path match the constants"; else bad "plist label/helper drift"; fi

echo "== helper"
awk "/<<'HELPER'\$/{f=1;next} /^HELPER\$/{f=0} f" "$REPO/mac-hardening-netlib.sh" > "$T/helper.sh"
if /bin/bash -n "$T/helper.sh"; then ok "helper parses"; else bad "helper parses"; fi
if grep -q 'mktemp' "$T/helper.sh"; then bad "helper uses mktemp"; else ok "helper has no temp file"; fi
if grep -qE 'pfctl +-d|-f +/etc/pf\.conf' "$T/helper.sh"; then bad "helper touches the main ruleset"; else ok "helper never disables PF or reloads pf.conf"; fi
if grep -E -- '-F +all' "$T/helper.sh" | grep -qv -- '-a "\$ANCHOR"'; then bad "unscoped flush"; else ok "every flush is anchor-scoped"; fi
if grep -q "^ANCHOR=\"${PF_LOCK_ANCHOR}\"\$" "$T/helper.sh" \
   && grep -q "^RULES=\"${PF_LOCK_RULES}\"\$" "$T/helper.sh" \
   && grep -q "^TOKEN_FILE=\"${PF_LOCK_TOKEN}\"\$" "$T/helper.sh"; then ok "helper constants match the netlib"; else bad "helper constants drift"; fi
```

`plutil -lint` on a file in the temp dir is read-only. On a non-macOS runner that
check must be skipped. Further static checks worth adding once the fixes land: in
`disable_pf_dns_lock` the bootout line precedes the plist removal, which precedes
the first line that can exit; `restore.sh` (extract between `<<'RESTORE'` and
`RESTORE`) parses and contains the anchor teardown.

### 4.2 VM sections, for `tests/vm/vmtest.sh`

A reboot cannot happen inside one `vmtest.sh` run. Proposed: a `--phase` argument,
with `tests/vm/run.sh` rebooting the VM between phase 1 and phase 2.

| Section | Setup | Action | Expected | Product bug vs test bug |
|---|---|---|---|---|
| T20 (A) reboot, no VPN | Phase 1: `prepare` + `enable` in `doh` mode; record `ntokens`. | Reboot. Phase 2, before any netlib call. | `helper status` exits 0; exactly one reference; main ruleset has `anchor "com.apple/*"`; `blk53` counts a `dig @8.8.8.8`; `curl https://1.1.1.1/` still works (`netchk`); `/var/log/foxhole-pf.log` has one `start:` line for this boot. | If `launchctl print system/com.hardening.pf.dnsleak` shows the job ran with a non-zero last exit status, it is the product (F8). If the job is absent, check that phase 1 left the plist: then it is the test. Wait up to 30 s before asserting; a fixed short sleep would be a test bug. |
| T21 (B) tunnel names | Lock on. | Create a `wireguard-go` tunnel *after* enable and note its name; route TEST-NET-3 through it; `dig`. Repeat with the route on an interface outside `utun0–15` (create tunnels until the name passes 15, or use `feth0` from `ifconfig feth0 create`). Then reboot and repeat the first case. | The query reaches the peer (as T19, vmtest.sh:355–359); `blk53` stays 0 for it. | Read `pfctl -a $A -vsr` counters: if the packet hit a `block` rule the product is wrong (the "ruled out" claim for B fails). If no counter moved at all, the route was not in place: test bug. |
| T22 (C) reference accounting | Lock on, a second holder as in T4 (vmtest.sh:85). | (1) `sudo rm` the token file, run `disable`. (2) Fresh enable, then run a copy of the helper whose `/sbin/pfctl` is replaced by a stub that fails `-E` only, with the second holder active. (3) Two `start` runs at once in the background. | (1) Rules flushed; one extra reference remains: documents F12, and after the fix the message names it. (2) Before the F11 fix the anchor still has rules: expected failure that proves F11; after the fix the anchor is empty. (3) `ntokens` minus the other holder is 1. | For (2), confirm the stub was really used (it logs its arguments). If `ntokens` is off by one everywhere, re-check the `ntokens` regex against `pfctl -s References` output first, as with the earlier PF-text test bugs. |
| T23 (E) reset order | Lock on, daemon bootstrapped. | (1) `reset_net_hardening`, then reboot. (2) Lock on again; delete the helper; reset. (3) Lock on again; in a subshell define `mktemp() { return 1; }`, then call `disable_pf_dns_lock`. | (1) After reboot: no plist, no job, `! pf_on`, anchor empty. (2) Same end state. (3) Before the F2 fix the subshell exits non-zero and `pfq -a $A -sr` still shows `port = 53`: this proves F2. After the fix the anchor is empty even though the helper install failed. | In (3) check that the subshell really exited inside `_install_pf_helper` (the log has no "PF DNS lock removed"). If it reached that line the override did not take effect: test bug. |
| T24 (F) restore with the lock on | `create_net_backup`, then `prepare` + `enable`. | `sudo bash restore.sh`. | Today: `helper status` still 0 and the plist still present, which records F1. After the fix: anchor empty, no plist, `! pf_on`, main ruleset equal to `/tmp/pf.main.baseline`. | A diff in the main ruleset after restore means the script reloaded `pf.conf`: product bug. |
| T25 (G) direct mode switch | Lock on in `plain`. | `FOXHOLE_DNS_MODE=vpn prepare` + `enable`, with no disable in between. | No `9.9.9.` line in `pfq -a $A -sr`; one reference. | If a Quad9 line remains, check `launchctl print` for the job's last run: no run means F4, a run means the helper did not reload. |
| T26 (I) bootstrap failure | Clean state. | Override `_launchd_bootstrap() { return 1; }` in the test shell; `prepare` + `enable`. | Today: enable returns 1 and the plist stays on disk (records F3). After the fix: either the lock is ACTIVE through the synchronous start, or no plist and no rules remain. | The override must be defined after sourcing the netlib; otherwise the real function runs and the test proves nothing. |

## 5. Not verified, and what would settle it

1. **Boot order (A).** Whether `com.hardening.pf.dnsleak` runs before or after
   Apple's own `pfctl -f /etc/pf.conf` at boot, and whether a child anchor loaded
   first survives that first load. T4 only proves survival of a reload on a running
   system. Settled by T20. A read of `/System/Library/LaunchDaemons/com.apple.pfctl.plist`
   would show what Apple runs; it was not read here because of the "nothing that
   touches launchd" rule.
2. **`pfctl -E` during early boot (A, C).** Whether it can fail before PF is ready.
   Settled by T20 plus the log line count over several reboots.
3. **Late-created tunnels (B).** PF binding to an interface name created after the
   rules were loaded. Settled by T21.
4. **Kill-switch rule order (F9, F10).** Where Mullvad or another client puts its
   rules relative to `anchor "com.apple/*"`, and whether it re-applies them after a
   main-ruleset reload. Needs the real-Mullvad test already listed as open in
   CHECKPOINT; compare `pfctl -sr` with the client connected, lock on and off.
5. **`-F all` scope on macOS (D).** That `pfctl -a <anchor> -F all` leaves states and
   the main ruleset alone on this macOS build. Read from the helper and from pfctl's
   documented behaviour, not measured. Settled by adding
   `diff <(pfq -sr) /tmp/pf.main.baseline` after T6's disable.
6. **Here-strings in the helper (J).** bash 3.2 implements `<<<` with a short-lived
   temp file in `$TMPDIR` or `/tmp` (helper L387, L413, L419, L425). If that
   directory is not writable when the daemon runs at boot, L425 would lose the token
   after `-E` succeeded (F12) and L413 would fall back to the file. Settled by T20's
   log check; replacing `<<<` with pipes (`printf '%s\n' "$OUT" | sed ...`) removes
   the question.
7. **Dormant main rules.** `pfctl -E` makes whatever is in the main ruleset live. If
   a previous tool left block rules loaded with PF disabled, enabling the lock would
   activate them. The L514 guard only checks that the `com.apple/*` anchor is there.
   Not reproducible without a VM scenario; a `pfctl -sr | grep -c '^block'` notice
   before enable would surface it.
8. **Bootstrap EIO timing (I).** Whether three tries one second apart are enough on
   slow hardware. Only VM evidence exists (suite green).
9. **Outside the PF scope, seen while checking L649:** in `update_hosts`, L666–668
   assigns `LATEST_COMMIT` from a pipeline that starts with `curl -f`. Under
   `pipefail` + `set -e` a GitHub API failure (rate limit, offline) exits the script
   there, after the download and before `/etc/hosts` is touched, and leaves
   `$TMP_HOSTS` behind. The `${LATEST_COMMIT:-unknown}` at L669 shows a failure was
   meant to be tolerated. Not counted in the findings. Fix: append `|| true` to the
   pipeline.

## 6. Commands run

All by the auditing session itself. No subagent was used: the file is 1180 lines and
was read in full directly, so the four optional lookups were done inline.

| # | Command (cwd = repo root unless noted) | Result |
|---|---|---|
| 1 | `git branch --show-current`, `git log --oneline -3`, `git worktree list`, `git status --short` | `debug` at `80f2847`; untracked: `.DS_Store`, `.claude/`, `free-claude-code/`, the brief |
| 2 | `ls docs/dev` | brief and notes present |
| 3 | `wc -l mac-hardening-netlib.sh vpn_daily.sh tests/ci/offline.sh tests/vm/vmtest.sh` | 1180 / 135 / 69 / 395 |
| 4 | `grep -n '^[a-zA-Z_][a-zA-Z0-9_]*()' mac-hardening-netlib.sh` | function start lines; matches the brief's list |
| 5 | `grep -n 'mktemp' mac-hardening-netlib.sh` | L297, L367, L480, L485 (comment), L546, L649 |
| 6 | `bash -n mac-hardening-netlib.sh` | exit 0, no output (parse only, the file is not executed) |
| 7 | `shellcheck -S warning mac-hardening-netlib.sh` | exit 0, no output |
| 8 | `grep -rn` for the PF, launchd and backup function names over `*.sh` | callers as listed at the top of this report |
| 9 | `grep -n 'launchctl\|pfctl -d\|pfctl -f\|-F all' mac-hardening-netlib.sh` | L433, L454, L461, L490, L495, L519 (plus comments L28, L175, L493, L576) |
| 10 | `grep -n` for boot/token/limit words in `docs/testing/reports/vm-test-report-2026-11-04.md` | no reboot test in the suite; open items: real Mullvad, DoH image |
| 11 | `grep -n 'restore.sh\|create_net_backup'` in `README.md`, `docs/changelog/v0.17.3.md`, `docs/testing/README.md` | no match |
| 12 | Full reads (file viewer, no execution): the brief, `CLAUDE.md`, `docs/dev/CHECKPOINT.md`, `docs/dev/NEXT_SESSION.md`, `mac-hardening-netlib.sh`, `vpn_daily.sh`, `tests/ci/offline.sh`, `tests/vm/vmtest.sh` | — |

Not run: `tests/ci/offline.sh`, any `pfctl`, `launchctl`, `networksetup`, `scutil`
or `route` command, the installer, either menu, the VM suite. Nothing under `/etc`,
`/Library/LaunchDaemons` or `/System` was read or written.

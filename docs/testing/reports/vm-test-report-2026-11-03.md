# VM test report — 2026-11-03

**Branch:** `debug` (v0.17.2) + uncommitted `port = 53` fix
**VM:** Tart `foxhole-test`, cloned from `foxhole-clean` (Cirrus Labs `macos-tahoe-vanilla`, macOS 26.6.2, arm64, 4 CPU / 4 GB)
**Host:** macOS 26.7.1, Mullvad VPN connected with Lockdown Mode on
**How to re-run:** `bash tests/vm/run.sh --reset` (logs land in this folder)

## Result

| Run | Log | Passed | Failed | Skipped |
|---|---|---|---|---|
| 1 (ad-hoc, before fixes) | `../logs/vm-test-2026-11-03_run1.log` | 27 | 5 | — |
| 2 (`tests/vm/run.sh`) | `../logs/vm-test-2026-11-03_153313.log` | 31 | 0 | 4 |

Run 1's 5 failures were 3 network checks (no egress, see below) and 2 harness problems (`vpn_daily.sh` fed through a pipe). Run 2 skips the network checks when the VM has no egress and drives `vpn_daily.sh` through `expect`.

## Verified

- Anchor is written `root:wheel 644`, passes `pfctl -nf`, block rules scoped to `en0 en1`.
- Enable: one marker + one `anchor`/`load anchor` pair, also after a second enable; PF on; rules loaded; utun pass rule present; LaunchDaemon installed.
- Disable: no hardening lines left, `pf.conf` still `root:wheel 644` and equal to the original (blank lines aside), anchor file + plist gone, anchor rules flushed.
- `verify_dns_stack` runs to the summary under `set -e`.
- `reset_net_hardening` exits 0 on a clean system.
- `vpn_daily.sh` run from `/`: guidance, enable (reports ACTIVE), disable, exit; no `command not found`, no leftovers.

## Bugs found

| # | Where | Problem | Status |
|---|---|---|---|
| B1 | `enable_pf_dns_lock` | Post-enable check grepped `port 53`; `pfctl` prints `port = 53`, so it always said "verify manually". | Fixed (uncommitted) |

## Not covered (environment limits)

- **No direct internet in the VM.** Ping/HTTPS by IP fail even with the lock off; DNS via the host gateway works. Most likely cause: host Mullvad Lockdown Mode blocking NAT traffic from `bridge100`. Skipped: plain DNS blocked/allowed, Quad9 reachability, HTTPS during lock.
- **No Quad9 DoH profile** in the VM, so health checks [1] [3]–[6] fail by design and system DNS stops while the lock is on.
- **No real VPN tunnel** (utun interfaces exist but carry no traffic).
- **No hosts blocklist / Privoxy / base installer** runs.

## Observations for the host

- **Rosetta bash.** `bash` on the host PATH is `/usr/local/bin/bash` (Intel-only 5.3 from an old Intel Homebrew). Scripts started with `bash script.sh` run translated: `uname -m` says `x86_64` and Tart refuses to start VMs. `tests/vm/run.sh` re-execs natively; the foxhole scripts themselves do not.
- **PF reload vs. Mullvad.** `pfctl -f /etc/pf.conf` replaces the main ruleset; pfctl itself warns it can flush rules added by others. Mullvad uses PF, so enabling the lock on the host may disable its kill switch until Mullvad reapplies it. Not verified.
- **PF left enabled** after disable; macOS ships with PF off.

## Next improvements (prioritized)

### P1 — host safety (before anyone runs this on a real Mac)
1. **Rosetta guard** in `mac-hardening-install.sh`, `mac-hardening-netlib.sh`, `vpn_daily.sh`: if `sysctl.proc_translated` is 1, re-exec with `arch -arm64 /bin/bash`. Otherwise arch and Homebrew-prefix detection can be wrong.
2. **Stop replacing the main PF ruleset.** Try loading the rules into a child of Apple's wildcard anchor (`pfctl -a com.apple/foxhole.dnsleak -f <file>`). The default `pf.conf` already evaluates `com.apple/*`, so no `pf.conf` edit and no `pfctl -f /etc/pf.conf` would be needed, which avoids clobbering Mullvad's rules. Verify in the VM first.
3. **Restore PF's previous state.** Enable with `pfctl -E` (returns a reference token), store the token, release it with `pfctl -X <token>` on disable, so PF goes back off if it was off.
4. **Modern launchd calls:** `launchctl bootstrap system` / `bootout system` instead of deprecated `load` / `unload`.

### P2 — test coverage
5. **VM egress:** pause Mullvad Lockdown during a run, or try `tart run --net-softnet` / `--net-bridged`, so the 4 skipped checks run.
6. **DoH profile image:** boot once with graphics, install and approve the Quad9 `.mobileconfig`, clone as `foxhole-doh`. Then health checks [1]–[6] mean something; check whether [1] (`scutil --dns` for `9.9.9.9`) actually detects a DoH profile.
7. **Real tunnel:** WireGuard (`wireguard-tools` + `wireguard-go`) in the VM to prove DNS works through `utun` with the lock on. Needs item 5.
8. **Extend `vmtest.sh`:** hosts blocklist add/remove, Privoxy auto-switch, base installer.

### P3 — quality
9. **`FOXHOLE_ASSUME_YES=1`** so `ask` can answer yes without a tty (tests and automation without `expect`).
10. **CI:** GitHub Actions macOS runner with `bash -n`, shellcheck and the offline anchor/rollback tests.
11. Filter `pfctl` noise (`No ALTQ support`, `-f` warning) or show it only on failure.
12. **Before merging to `main`:** commit B1 + `tests/`, submit the PR, decide on `debug_netlib/`, point CLAUDE.md's testing section at `tests/vm/run.sh`.

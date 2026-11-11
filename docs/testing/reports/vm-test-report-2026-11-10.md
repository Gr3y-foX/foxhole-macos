# VM test report — 2026-11-10 (v0.17.4, lockout audit fixes)

Final fresh-VM run (`FOXHOLE_VM_BASE=foxhole-brew FOXHOLE_VM_NET=bridged`, `tests/vm/run.sh --reset`):
**159 passed / 0 failed / 0 skipped**, then **12 / 0 / 0 after a reboot** (`../logs/vm-test-2026-11-10_195917.log`).
Offline: `tests/ci/offline.sh` 42/42. Lint: `bash -n` and `shellcheck -S warning` clean.
The clean image (no Homebrew) was not run this time.

| Area | Result |
|---|---|
| T1–T19 (existing suite) | pass. T2 now also checks the prepared-rules flow (`<rules>.new` promoted by enable), owner and mode of the rules file and plist, the `boot` action in the plist, and that no staging files are left. T8 checks that a refused enable drops the prepared rules. |
| T10 `vpn_daily.sh` driven by expect | pass (answers the new backup prompt; a snapshot with `restore.sh` exists afterwards) |
| T20 (new, F2) disable with a failing helper re-install | pass: the function aborts, the block rules and the boot daemon are gone anyway; a second disable completes |
| T21 (new, F3, F11) failed enable | pass: bootstrap failure and unloadable rules both end with no plist, no rules, PF off, no reference; with another PF holder its reference is untouched |
| T22 (new, F1) `restore.sh` with the lock on | pass: rules flushed, PF off, plist/job/helper/rules/token gone, main ruleset unchanged, plain DNS works again |
| T23 (new, F4, F5) mode switch | pass: a declined `plain`→`vpn` switch leaves `plain` on disk and after a daemon re-run; a direct switch leaves no Quad9 rule, one reference |
| T24 (new, F8) helper `status` and `boot` | pass: `status` fails while the main ruleset has no `com.apple/*` anchor; `boot` is idempotent |
| T25 (new, F16) reset with a failing step | pass: the failure is reported and the reset completes |
| T26 (new, scenario A) reboot with the lock on, no VPN | pass: the LaunchDaemon's `boot` action succeeded on the first try, one PF reference, the stock main ruleset is loaded, DNS to 8.8.8.8 hits the block rule, HTTPS by IP works, disable leaves nothing behind |

## Update 2026-11-11

Fresh run after the helper-directory check, the disable fallback and the `update_hosts`
changes: **166 passed / 0 failed / 0 skipped**, then **12 / 0 / 0 after a reboot**
(`../logs/vm-test-2026-11-11_005737.log`). Offline 46/46.

- T20 changed with the product: disable now completes when the helper install fails
  (it releases the PF reference itself), so the test expects rc 0 and no leftovers.
- T27 (new): enable refuses a user-owned or group-writable `/usr/local/libexec`, loads
  nothing, and works again with root:wheel 755.
- T11: `update_hosts` completes under `set -e` when the GitHub commit lookup fails; the
  root-owned staging copy is removed.

## The earlier run today

`../logs/vm-test-2026-11-10_195315.log`: 157 / 2 failed (after reboot 12 / 0).

- **T7 "legacy anchor active before migration": test bug.** The simulated pre-0.17.3
  install loads its anchor from the live rules file, which `prepare` no longer writes.
  The test now copies the prepared file into place, as an old install would have it.
- **T17 "vpn mode: block rules and utun passes loaded": product side, cause not proven.**
  Right after `enable_pf_dns_lock` returned, the anchor read back empty; a second later
  the rules were there. Enable now returns while the daemon's `RunAtLoad` run is still
  reloading the anchor, and the first version of the F11 fix flushed the anchor on any
  failed load. Two changes followed: a failed reload keeps the loaded rules when our
  reference is held, and enable waits for the daemon's first run and re-checks `status`.
  The helper's error line was not captured, so whether the flush or a busy `pfctl` read
  in the test caused it is not settled. It did not recur in the final run.

## Not covered

- Scenario B: a tunnel on an interface outside `utun0–15`, or created after boot
  (proposed T21 of the audit report).
- A real VPN kill switch next to the lock (F9, F10): needs real Mullvad.
- Reference accounting with a lost token file, two `start` runs at once (audit T22).
- `pfctl -E` failing at boot: not reproducible in the VM; the `boot` retry is only
  checked for the success path.
- A real DoH profile image, GUI-only installer casks (as before).

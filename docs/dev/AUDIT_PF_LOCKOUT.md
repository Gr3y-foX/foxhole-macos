# Task brief: PF DNS-lock lockout audit

Guide rails and task for a stronger reasoning model working on foxhole-macos.
Read this whole file before touching anything. Repo rules are in `CLAUDE.md`
(root); this file narrows them for this task.

## 1. Context

foxhole-macos hardens macOS and changes **live system state**. The PF DNS lock
(`mac-hardening-netlib.sh`, v0.17.3) can cut the user's network if it goes
wrong. Recovery of a locked-out machine is the main thing to verify.

Relevant pieces:

- Anchor `com.apple/foxhole.dnsleak`, rules file `/etc/pf.anchors/com.hardening.dnsleak`.
- Helper `/usr/local/libexec/foxhole-pf-dnslock start|stop|status`, shared by
  the enable/disable paths and the boot LaunchDaemon.
- PF enabled by reference token (`pfctl -E` / `-X`).
- LaunchDaemon managed with `bootstrap`/`bootout` (never `load`/`unload`).
- `reset_net_hardening` (cleanup path) and `create_net_backup` (writes `restore.sh`).
- VPN tunnels must keep passing: `utun0`–`utun15` listed explicitly (PF on
  macOS has no `utun+` wildcard). Blocks are scoped to physical interfaces.
- `FOXHOLE_DNS_MODE`: `doh` (default), `vpn`, `plain`.

## 2. Guide rails (hard rules)

1. **No host execution.** Do not run the installer, the netlib menu, or any
   `pfctl`, `networksetup`, `launchctl`, `scutil` or `route` command on the host.
   All live testing happens in the Tart VM through `tests/vm/`.
2. **Read-only first pass.** Do not edit product code (`mac-hardening-*.sh`,
   `vpn_daily.sh`) in this task. Output is a report and proposed checks only.
3. **Do not weaken a check to get green.** If a test fails, decide whether the
   test or the product is wrong, and say which with evidence.
4. **Stay on `debug`.** No push to `main`, no PR actions. Do not commit unless
   the user asks. Never commit `.DS_Store`, `.claude/`, `.gitnexus/`,
   `free-claude-code/`.
5. **Secrets.** Never write a Mullvad account number, a key, or any credential
   to files, git, logs or memory.
6. **Bash 3.2.** Any suggested code must work on macOS stock bash 3.2 (no
   associative arrays, `${var,,}`, or `mapfile`). Quote all variables; no `eval`;
   no untrusted input in `sudo`, `sh -c`, XML or plist strings.
7. **Impact before edit.** Per `CLAUDE.md`, GitNexus `impact` on shell functions
   usually returns `UNKNOWN`. Confirm callers with `grep -rn` over `*.sh` and say
   you did so. Treat `UNKNOWN` as unresolved, not safe.
8. **Language.** Reply to the user in the language they write in (Russian or
   English). Code comments and any commit text are in English.
9. **No model identifiers** in any repo artifact (files, commits, PR text).

## 3. Orientation (do this first, in order)

1. Read `docs/dev/CHECKPOINT.md`, then `docs/dev/NEXT_SESSION.md`.
2. Read `CLAUDE.md`: the "Conventions" bullet "PF lock design (v0.17.3)" and the "Testing" section.
3. Read `docs/testing/reports/vm-test-report-2026-11-04.md` for the latest VM results.
4. Known locations in `mac-hardening-netlib.sh` (v0.17.3, verify with `grep -n`
   before citing; line numbers drift):
   - `create_net_backup()` ~l.95; saves pf.conf, the anchor rules file, hosts, resolver.
   - `_write_restore_script()` ~l.169; `restore.sh` restores hosts, pf.conf, resolver only.
   - `prepare_pf_dns_lock_anchor()` ~l.279; `_install_pf_helper()` ~l.364 (helper body
     is the heredoc there, `start|stop|status`).
   - `enable_pf_dns_lock()` ~l.498; `_install_pf_launchdaemon()` ~l.544 (writes
     `/Library/LaunchDaemons/com.hardening.pf.dnsleak.plist` via `mktemp /tmp/...`).
   - `disable_pf_dns_lock()` ~l.579.
   - `_launchd_bootout()` / `_launchd_bootstrap()` ~l.453–466 (bootstrap retries 3×
     with `sleep 1`; the comment cites an EIO right after bootout).
   - `reset_net_hardening()` ~l.1057 (calls PF, Privoxy and hosts disables; no restore).
   - The Privoxy/proxy-toggle LaunchDaemon (`com.hardening.proxytoggle`) is a separate
     daemon; it is in scope only where it interacts with the PF lock on reset.
5. Read `tests/vm/vmtest.sh` section list (T0–T19) and `tests/ci/offline.sh`.

## 4. The task

Audit the PF DNS lock **start, stop, boot and recovery** paths for lockout
scenarios. For each scenario, decide: does the code recover, and what does the
user see?

Scenarios to cover (add others you find):

- A. Reboot with the lock enabled and **no VPN** up at boot. Can the user reach
  the network after login? Does the LaunchDaemon run before or after the network
  is available, and does that matter?
- B. Reboot with the lock enabled and a **VPN up** whose tunnel uses an interface
  name outside `utun0`–`utun15`, or a name that appears after boot. Is the tunnel
  blocked?
- C. `pfctl -E` fails, or reference-token accounting gets out of balance
  (enable twice, disable once; `start` run during a crash). Is PF left enabled
  with no way to release it through the helper?
- D. `stop` run while another VPN kill switch owns the main ruleset. Does the
  helper reload or flush the main ruleset? (It must not, per the design.)
- E. `reset_net_hardening` run in the wrong order (before `stop`, or with the
  LaunchDaemon still bootstrapped). Does reset leave a plist that re-enables the
  lock on the next boot?
- F. Restore from `restore.sh`. Known gap to confirm: it restores hosts, pf.conf
  and resolver, but **not** the anchor rules file (`pf.anchor.dnsleak`, saved by
  `create_net_backup`) or the LaunchDaemon plist. Decide whether a restore can
  leave the lock active after reboot, and whether the `pfctl -f` reload hint in
  `restore.sh` can touch the main ruleset.
- G. The `doh`/`vpn`/`plain` mode switch while the lock is on. Is the old anchor
  content fully replaced, or can a stale Quad9 exception survive?
- H. Any `set -euo pipefail` path that exits between two steps that must be paired.
I. Bootstrap failure after bootout (the retry loop in `_launchd_bootstrap` ends
   with `return 1`). Does the caller then leave the daemon absent, the lock
   active, or PF referenced with no daemon?
J. Temp file in a root-run path: `_install_pf_launchdaemon` writes its plist to
   `mktemp /tmp/foxhole-pf-plist.XXXXXX`. `CLAUDE.md` forbids temp files in
   root-run helpers. Check whether the file can be swapped or left behind, and
   whether `/tmp` is a safe place for a root-owned plist staging step.

For each finding give: **scenario, file:line, what happens, user-visible impact,
severity (lockout / leak / cosmetic), and the minimal fix you would propose.**

## 5. Proposed checks (write, do not run on host)

Propose, do not apply:

- Offline checks for `tests/ci/offline.sh`: rendered-anchor assertions for each
  DNS mode, and a check that the LaunchDaemon writer never emits `load`/`unload`.
- VM sections for `tests/vm/vmtest.sh` for the scenarios that need a real
  reboot or real PF (A, B, C, E). Describe each as: setup, action, expected result,
  and how to tell a product bug from a test bug.

Put proposed checks in the report, not in the test files.

## 6. Deliverable

Create **one** report at `docs/dev/AUDIT_PF_LOCKOUT_REPORT.md` with:

1. Summary: number of findings by severity, and the single most dangerous one.
2. Findings table: scenario, location, impact, severity, proposed fix.
3. Ruled out: scenarios you checked and found safe, with the reason.
4. Proposed checks (section 5).
5. What you could not verify without the host or a VM, and what would settle it.
6. Commands you ran (read-only only: `grep`, `sed -n`, `bash -n` on a copy, `shellcheck`).

Keep the report factual. Quote code by `file:line`. Do not claim a scenario is
safe without naming the line that makes it safe.

## 7. Stop conditions

Stop and ask the user before:

- Any command that touches the host's PF, launchd, network config or `/etc`.
- Any edit to product scripts.
- Any push, commit, or PR action.

If a scenario needs a real reboot or real PF to decide, do not guess. Mark it
"needs VM" in the report and move on. Finished parts are useful even if the
whole audit is not complete.

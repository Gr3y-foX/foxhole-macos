# Checkpoint — 2026-11-11 (resume here)

Read first: this file, then `SESSION_PLAN.md` (checkpoint list CP0–CP10), then `NEXT_SESSION.md` for background.

## 2026-11-10: lockout audit and v0.17.4

- Audit: brief `AUDIT_PF_LOCKOUT.md`, report `AUDIT_PF_LOCKOUT_REPORT.md` (17 findings, F1–F17).
- **Branch `private-all`** (new, pushed to origin; the user wants all work to land there first, then be filtered to `debug` and later `main`). `debug` and `main` are still at `80f2847`; PR #1 is untouched. Note: a branch in the same GitHub repo is as visible as the repo itself.
- v0.17.4 fixes F1–F6, F8, F10–F17: see `../changelog/v0.17.4.md`. Done 2026-11-11 (2nd round, backup tag `backup/pre-f7-toggle-2026-11-11`): F7 interface union (D2 revised by the user's go-ahead), proxy toggle moved to `/usr/local/libexec`, `private-all` merged into `debug` (updates PR #1). Open: **F9** (`quick` pass rules vs a VPN kill switch: needs real Mullvad). Done 2026-11-11: helper-directory ownership check, disable fallback, `update_hosts` root-owned staging and tolerant commit lookup.
- VM: 167/0/0 plus 12/0/0 after a reboot (run of 2026-11-11, 2nd round) on the Homebrew image, `../testing/reports/vm-test-report-2026-11-10.md`. `run.sh` now has a reboot phase (T26). Offline 49/49.
- One T17 failure in the first run of the day has no proven cause (report, "The earlier run today"). If "block rules and utun passes loaded" fails again right after an enable, read `/var/log/foxhole-pf.log` in the VM before anything else.
- GitNexus CLI does not load on this Mac (x86_64 native module on arm64): callers were confirmed with `grep -rn`. Repair: `node /usr/local/lib/node_modules/gitnexus/node_modules/@ladybugdb/core/install.js`, then re-run `analyze`.
- Next: decide F7; real Mullvad test for F9/F10; cherry-pick or merge `private-all` into `debug` when the user says so (that updates PR #1).

---

# Checkpoint — 2026-11-04 night

## State
- Docs layout (reorganised 2026-11-05): `docs/changelog/` (release notes), `docs/testing/` (README, `reports/`, `logs/`), `docs/dev/` (these working notes, PR text, CLAUDE.md draft), `docs/archive/`. Index: `docs/README.md`. `tests/vm/run.sh` now writes logs to `docs/testing/logs/`.
- PR #1 could not be retitled by the session (GitHub integration returned 403); paste the title/body from `docs/dev/PR-1-text.md` by hand.
- Branch `debug`, remote `origin` = `git@github-foxhole:Gr3y-foX/foxhole-macos.git` (SSH works; run `ssh`/`git push` outside the sandbox, the sandbox blocks DNS).
- Done: CP0, CP1, CP3, CP4, D2, D4, CP8 (GitNexus re-indexed, detect-changes low), README + report + changelog, T18 real Privoxy, T19 real WireGuard. CLAUDE.md rewritten for v0.17.3 and the docs layout (2026-11-05). Open: retitle PR #1 by hand (`PR-1-text.md`), real Mullvad / DoH tests.
- PR `debug` → `main`: **PR #1 is already open** (created by the user 2026-11-03; title still "fix(netlib): v0.16 — Phase 1+2 audit fixes", so the old notes saying "no PR exists" were stale). Every push to `debug` updates it. Ask the user before changing its title/body; the text below is the suggested new one. PR text: title `v0.17.3: PF DNS lock in com.apple/* child anchor, installer fixes, VM test suite`; body from `docs/changelog/v0.17.3.md` + VM result + open items.
- CI: green on `debug` since the billing lock was lifted (lint push + pull_request runs).

## User decisions (CP2, answered 2026-11-04)
- **D1:** make it configurable. DNS modes via `FOXHOLE_DNS_MODE` or a menu prompt: `doh` (default, Quad9 on tcp 443 only), `vpn` (no Quad9 exception, DNS only through the tunnel; the user's own Mullvad setup with Quad9 inside the VPN), `plain` (Quad9 any port, old behaviour).
- **D2:** yes. Helper `start` re-renders the physical-interface list at boot, falls back to the rules file as written. **Revised 2026-11-11 (F7):** union of the live list and the file's list. Test in the VM before shipping; `create_net_backup` (writes `restore.sh`) is the safety net.
- **D3:** keep the `sudo pfctl -d` message, no auto-disable (my recommendation; user left it to me).
- **D4:** done: `debug_netlib/` moved to `docs/archive/debug_netlib/`.
- **R1:** remote already switched to `foxhole-macos` by the user.

## Work done since the last checkpoint
- `mac-hardening-netlib.sh`: DNS modes, interface re-render in the boot helper (stdin, no temp file); `mac-hardening-install.sh`: Tor profile option marked planned; tests: offline 17/17, VM T17 + T18, `FOXHOLE_VM_BASE`.

## VM result
- Homebrew image (`FOXHOLE_VM_BASE=foxhole-brew`): 125/0/0, `vm-test-2026-11-04_234847.log` (T18 real Privoxy, T19 real WireGuard). Clean image: 112/0/1 (T18 skipped), `vm-test-2026-11-04_233206.log`. The temp-file flake is gone (rules go to pfctl on stdin).

## Next steps (in order)
1. (done) D1/D2/D4, README, report, changelog, GitNexus (CP8), T18 real Privoxy, installer Tor option.
2. (done) CLAUDE.md updated (layout, commands, PF design, DNS modes, testing, working notes; GitNexus stats refreshed). Its GitNexus block is auto-generated: after the next `analyze` the numbers may change again. The `.claude/skills` table there still points at untracked files: commit the skills or drop the table.
3. PR #1: retitle it by hand with `docs/dev/PR-1-text.md` (the session connection gets 403 on edits); then decide on merge and on `subscribe_pr_activity`.
4. CI: `lint` is green on push and pull_request for `5afa8fb`, `e7ae7dd`, `c4984a2` (checked via the public API 2026-11-04 night); re-check after new pushes.
5. Optional: GUI-cask timeout in the installer (only affects headless VMs); real Mullvad test (needs the user, see below); `foxhole-doh` image (GUI click).

## Mullvad account (privacy)
The user gave a Mullvad account number for a VM-only test. It is deliberately **not stored anywhere** (not in files, git, logs or memory). Ask the user again when the test is wanted; pass it to `mullvad account login` over stdin inside the VM only. The VM needs the Mullvad CLI installed first (brew cask), and an account has a device limit.

## Environment notes
- Tart VMs on the SSD `Disc Samsung T7`: `foxhole-test` (work), `foxhole-clean` (base for `--reset`), `foxhole-brew` (clean + Homebrew + CLT).
- Shut the VM down gracefully (`tests/vm/vm.sh down`, `run.sh` does it).
- Host rules: no `pfctl`/`launchctl`/`networksetup`/installer runs on the host. Work only on `debug`. No PR unasked.
- The sandbox blocks DNS and `mktemp` in the system temp dir: run `ssh`, `git push` and `tests/ci/offline.sh` with the sandbox disabled (they don't change the system).
- Commit footer: the Co-Authored-By line from the session's system reminder. Never commit `.DS_Store`, `.claude/`, `free-claude-code/`.

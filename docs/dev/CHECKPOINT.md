# Checkpoint — 2026-11-04 night (resume here)

Read first: this file, then `SESSION_PLAN.md` (checkpoint list CP0–CP10), then `NEXT_SESSION.md` for background.

## State
- Docs layout (reorganised 2026-11-05): `docs/changelog/` (release notes), `docs/testing/` (README, `reports/`, `logs/`), `docs/dev/` (these working notes, PR text, CLAUDE.md draft), `docs/archive/`. Index: `docs/README.md`. `tests/vm/run.sh` now writes logs to `docs/testing/logs/`.
- PR #1 could not be retitled by the session (GitHub integration returned 403); paste the title/body from `docs/dev/PR-1-text.md` by hand.
- Branch `debug`, remote `origin` = `git@github-foxhole:Gr3y-foX/foxhole-macos.git` (SSH works; run `ssh`/`git push` outside the sandbox, the sandbox blocks DNS).
- Done: CP0, CP1, CP3, CP4, D2, D4, CP8 (GitNexus re-indexed, detect-changes low), README + report + changelog, T18 real Privoxy, T19 real WireGuard. CLAUDE.md rewritten for v0.17.3 and the docs layout (2026-11-05). Open: retitle PR #1 by hand (`PR-1-text.md`), real Mullvad / DoH tests.
- PR `debug` → `main`: **PR #1 is already open** (created by the user 2026-11-03; title still "fix(netlib): v0.16 — Phase 1+2 audit fixes", so the old notes saying "no PR exists" were stale). Every push to `debug` updates it. Ask the user before changing its title/body; the text below is the suggested new one. PR text: title `v0.17.3: PF DNS lock in com.apple/* child anchor, installer fixes, VM test suite`; body from `docs/changelog/v0.17.3.md` + VM result + open items.
- CI: green on `debug` since the billing lock was lifted (lint push + pull_request runs).

## User decisions (CP2, answered 2026-11-04)
- **D1:** make it configurable. DNS modes via `FOXHOLE_DNS_MODE` or a menu prompt: `doh` (default, Quad9 on tcp 443 only), `vpn` (no Quad9 exception, DNS only through the tunnel; the user's own Mullvad setup with Quad9 inside the VPN), `plain` (Quad9 any port, old behaviour).
- **D2:** yes. Helper `start` re-renders the physical-interface list at boot, falls back to the rules file as written. Test in the VM before shipping; `create_net_backup` (writes `restore.sh`) is the safety net.
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

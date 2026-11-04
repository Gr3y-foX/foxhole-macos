# Checkpoint — 2026-11-04 night (resume here)

Read first: this file, then `SESSION_PLAN.md` (checkpoint list CP0–CP10), then `NEXT_SESSION.md` for background.

## State
- Branch `debug`, remote `origin` = `git@github-foxhole:Gr3y-foX/foxhole-macos.git` (SSH works; run `ssh`/`git push` outside the sandbox, the sandbox blocks DNS).
- Done: CP0, CP1, CP3, CP4, D2, D4, CP8 (GitNexus re-indexed, detect-changes low), README + report + changelog, T18 real Privoxy. Open: CP7 CLAUDE.md text (draft in `CLAUDE_MD_DRAFT.md`, needs the user), CP9 PR decision.
- PR `debug` → `main`: not opened. Open only if the user asks. PR text: title `v0.17.3: PF DNS lock in com.apple/* child anchor, installer fixes, VM test suite`; body from `docs/v 0.17/netlib_v0.17.3.md` + VM result + open items.
- CI: the user says billing is fixed but the account has no credit (free plan). Re-check `lint` runs once pushed.

## User decisions (CP2, answered 2026-11-04)
- **D1:** make it configurable. DNS modes via `FOXHOLE_DNS_MODE` or a menu prompt: `doh` (default, Quad9 on tcp 443 only), `vpn` (no Quad9 exception, DNS only through the tunnel; the user's own Mullvad setup with Quad9 inside the VPN), `plain` (Quad9 any port, old behaviour).
- **D2:** yes. Helper `start` re-renders the physical-interface list at boot, falls back to the rules file as written. Test in the VM before shipping; `create_net_backup` (writes `restore.sh`) is the safety net.
- **D3:** keep the `sudo pfctl -d` message, no auto-disable (my recommendation; user left it to me).
- **D4:** done: `debug_netlib/` moved to `docs/archive/debug_netlib/`.
- **R1:** remote already switched to `foxhole-macos` by the user.

## Work done since the last checkpoint
- `mac-hardening-netlib.sh`: DNS modes, interface re-render in the boot helper (stdin, no temp file); `mac-hardening-install.sh`: Tor profile option marked planned; tests: offline 17/17, VM T17 + T18, `FOXHOLE_VM_BASE`.

## VM result
- Homebrew image (`FOXHOLE_VM_BASE=foxhole-brew`): 120/0/0, `vm-test-2026-11-04_232844.log`. Clean image: 112/0/1 (T18 skipped), `vm-test-2026-11-04_233206.log`. The temp-file flake is gone (rules go to pfctl on stdin).

## Next steps (in order)
1. (done) D1/D2/D4, README, report, changelog, GitNexus (CP8), T18 real Privoxy, installer Tor option.
2. CP7 rest: show the user `docs/testing/CLAUDE_MD_DRAFT.md` (new "Commands"/"Testing" text for CLAUDE.md) and apply only if they agree; ask about the stale GitNexus stats (7373 symbols) and the `.claude/skills` table in CLAUDE.md.
3. CP9: ask whether to open the PR `debug` → `main` (text above; check for a PR template first; offer `subscribe_pr_activity` afterwards).
4. CI: re-check the `lint` workflow on GitHub (billing/credit question with the user).
5. Optional: real WireGuard in `foxhole-brew` (marginal: T12 already covers PF with a real utun); GUI-cask timeout in the installer (only affects headless VMs); real Mullvad test (needs the user, see below); `foxhole-doh` image (GUI click).

## Mullvad account (privacy)
The user gave a Mullvad account number for a VM-only test. It is deliberately **not stored anywhere** (not in files, git, logs or memory). Ask the user again when the test is wanted; pass it to `mullvad account login` over stdin inside the VM only. The VM needs the Mullvad CLI installed first (brew cask), and an account has a device limit.

## Environment notes
- Tart VMs on the SSD `Disc Samsung T7`: `foxhole-test` (work), `foxhole-clean` (base for `--reset`), `foxhole-brew` (clean + Homebrew + CLT).
- Shut the VM down gracefully (`tests/vm/vm.sh down`, `run.sh` does it).
- Host rules: no `pfctl`/`launchctl`/`networksetup`/installer runs on the host. Work only on `debug`. No PR unasked.
- The sandbox blocks DNS and `mktemp` in the system temp dir: run `ssh`, `git push` and `tests/ci/offline.sh` with the sandbox disabled (they don't change the system).
- Commit footer: the Co-Authored-By line from the session's system reminder. Never commit `.DS_Store`, `.claude/`, `free-claude-code/`.

# Checkpoint — 2026-11-04 night (resume here)

Read first: this file, then `SESSION_PLAN.md` (checkpoint list CP0–CP10), then `NEXT_SESSION.md` for background.

## State
- Branch `debug`, remote `origin` = `git@github-foxhole:Gr3y-foX/foxhole-macos.git` (SSH works; run `ssh`/`git push` outside the sandbox, the sandbox blocks DNS).
- CP0, CP1, CP3, CP4 and D2 are done. See `git log` for the head; D4 (archive `debug_netlib/`) and CP7-CP9 are open.
- PR `debug` → `main`: not opened. Open only if the user asks. PR text: title `v0.17.3: PF DNS lock in com.apple/* child anchor, installer fixes, VM test suite`; body from `docs/v 0.17/netlib_v0.17.3.md` + VM result + open items.
- CI: the user says billing is fixed but the account has no credit (free plan). Re-check `lint` runs once pushed.

## User decisions (CP2, answered 2026-11-04)
- **D1:** make it configurable. DNS modes via `FOXHOLE_DNS_MODE` or a menu prompt: `doh` (default, Quad9 on tcp 443 only), `vpn` (no Quad9 exception, DNS only through the tunnel; the user's own Mullvad setup with Quad9 inside the VPN), `plain` (Quad9 any port, old behaviour).
- **D2:** yes. Helper `start` re-renders the physical-interface list at boot, falls back to the rules file as written. Test in the VM before shipping; `create_net_backup` (writes `restore.sh`) is the safety net.
- **D3:** keep the `sudo pfctl -d` message, no auto-disable (my recommendation; user left it to me).
- **D4:** move `debug_netlib/` to `docs/archive/` (not done yet).
- **R1:** remote already switched to `foxhole-macos` by the user.

## Work in the commit "feat(netlib): DNS modes + interface re-render" (CP4 + D2 done)
- `mac-hardening-netlib.sh`: `_choose_dns_mode`, mode-aware rule [4] in `prepare_pf_dns_lock_anchor`, interface re-render in the helper `start` heredoc.
- `tests/ci/offline.sh`: tests for the three modes + invalid mode. Offline suite: **16 passed / 0 failed**. `bash -n` + `shellcheck -S warning` clean.
- `tests/vm/vmtest.sh`: T3 now expects plain DNS to 9.9.9.9 blocked in `doh` mode; T11 uses `FOXHOLE_DNS_MODE=plain` (its resolver is a plain-DNS stand-in); new **T17** (modes + interface re-render with a stale `en99` list), placed before T10.
- Fresh-VM run: **112 passed / 0 failed / 0 skipped** (`docs/testing/vm-test-2026-11-04_231847.log`). Earlier runs found and fixed test bugs only (PF prints `inet proto tcp ... port = 443`; vpn_daily [1] now shows the mode prompt, T10 answers it).

## VM result
- 112/0/0, log `docs/testing/vm-test-2026-11-04_231847.log`. One earlier run had a one-off T17 failure ("temp file left in /var/run/foxhole-pf.*"); not reproduced. If it returns, suspect the boot LaunchDaemon `start` still running right after enable.

## Next steps (in order)
1. (done) D1/D2 committed and pushed.
2. D4: `git mv debug_netlib docs/archive/debug_netlib`, fix references (`grep -rn debug_netlib`), commit, push.
3. CP7 docs: README vs code (DNS modes, `FOXHOLE_DNS_MODE`), draft the new CLAUDE.md "Testing" text and **show it to the user before editing**, tick PLAN.md, consolidated test report, drop stale claims.
4. CP8 GitNexus: `node .gitnexus/run.cjs analyze --index-only`, then `detect-changes --scope compare --base-ref main` (bash = UNKNOWN; confirm callers with `grep -rn`).
5. CP9: ask whether to open the PR.
6. Optional (CP10): real Privoxy / WireGuard in the `foxhole-brew` VM; real Mullvad test in the VM.

## Mullvad account (privacy)
The user gave a Mullvad account number for a VM-only test. It is deliberately **not stored anywhere** (not in files, git, logs or memory). Ask the user again when the test is wanted; pass it to `mullvad account login` over stdin inside the VM only. The VM needs the Mullvad CLI installed first (brew cask), and an account has a device limit.

## Environment notes
- Tart VMs on the SSD `Disc Samsung T7`: `foxhole-test` (work), `foxhole-clean` (base for `--reset`), `foxhole-brew` (clean + Homebrew + CLT).
- Shut the VM down gracefully (`tests/vm/vm.sh down`, `run.sh` does it).
- Host rules: no `pfctl`/`launchctl`/`networksetup`/installer runs on the host. Work only on `debug`. No PR unasked.
- The sandbox blocks DNS and `mktemp` in the system temp dir: run `ssh`, `git push` and `tests/ci/offline.sh` with the sandbox disabled (they don't change the system).
- Commit footer: the Co-Authored-By line from the session's system reminder. Never commit `.DS_Store`, `.claude/`, `free-claude-code/`.

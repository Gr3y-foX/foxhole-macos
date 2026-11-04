# Next session plan — foxhole-macos (`debug` branch, v0.17.3)

## Context
Long session on 2026-11-03 took `debug` from v0.17.2 to v0.17.3:
- PF DNS lock moved into the `com.apple/foxhole.dnsleak` child anchor. `/etc/pf.conf` is no longer edited.
- PF is enabled with a `pfctl -E` token and released on disable.
- One helper, `/usr/local/libexec/foxhole-pf-dnslock`, is used by enable, disable and boot. launchd calls use `bootstrap`/`bootout`.
- Many bugs were found by running the scripts in a Tart VM instead of only reading them.

The goal of the next session: close the unverified work, get the user's 4 design decisions, finish merge prep, and open the PR `debug` → `main` **only when the user asks**.

## Status update — 2026-11-04 night (overrides everything below where they differ)
Read `CHECKPOINT.md` first, then `SESSION_PLAN.md`. Summary:
- Pushed over SSH (`origin` = `git@github-foxhole:Gr3y-foX/foxhole-macos.git`; run `ssh`/`git push` outside the sandbox).
- D1 done: `FOXHOLE_DNS_MODE` = `doh` (default, Quad9 tcp 443 only) / `vpn` / `plain`. D2 done: boot helper re-renders interfaces (rules via `pfctl -f -`, no temp file). D3: keep the `sudo pfctl -d` message. D4 done: `debug_netlib/` is in `docs/archive/`.
- VM suite: 120/0/0 on the Homebrew image (`FOXHOLE_VM_BASE=foxhole-brew`, includes T18 real Privoxy), 112/0/1 on the clean image. Offline 17/17.
- Installer option [2] (Tor profile) is now marked "planned" and does not run the stub.
- Still open: CP7 (review `docs/testing/CLAUDE_MD_DRAFT.md`, apply to CLAUDE.md if the user agrees; stale GitNexus stats and `.claude/skills` table in CLAUDE.md), CP9 (PR only if asked), CI (account billing), real Mullvad / WireGuard / DoH image (need the user; the Mullvad account number must never be stored).

## State at the end of the session (checked read-only)
- **Branch:** `debug` is in sync with `origin/debug` at `531695d`. There are 25 commits ahead of `main`; `main` is still at v0.16.1.
- **Working tree:** only the user's own `CLAUDE.md` / `AGENTS.md` changes, which are a GitNexus section refresh. Don't touch them. Untracked: `.DS_Store`, `.claude/`, `free-claude-code/`.
- **Last green VM run:** 93 passed / 0 failed / 0 skipped (`docs/testing/vm-test-2026-11-03_193350.log`, run with `FOXHOLE_VM_NET=bridged`).
- **Unverified commit `f59538b`:**
  - `create_net_backup` now writes `restore.sh` via `_write_restore_script` in `mac-hardening-netlib.sh`. The old message pointed at a `rollback.sh` that doesn't exist.
  - T16 in `tests/vm/vmtest.sh` covers it, but **has never run**.
- **CI:** `.github/workflows/lint.yml` and `tests/ci/offline.sh` exist (offline tests pass 13/13 locally). The workflow has **never been seen running on GitHub**.
- **Pushing:** the Intel Homebrew `/usr/local/bin/git` (Rosetta) hangs on github.com. `arch -arm64 /usr/bin/git push -u origin debug` works.
- **Remote:** GitHub says the repo moved to `https://github.com/Gr3y-foX/foxhole-macos.git`, but the remote still points at `macos-sec-harder-26`.
- **Stale plan items:** `docs/testing/PLAN.md` still has two open items that are already done or obsolete:
  - "run.sh --reset produced no log": fixed by the graceful shutdown in `e240e12`.
  - Step 1b "VM: Privoxy menu [3]": T13 covers the toggle; only the real Privoxy binary is still open.
- **Test order:** `vmtest.sh` sections run in this order: T0–T9, T11, T12, T14, T13, T15, T16, then T10 last (vpn_daily via expect).

## Step 1: Verify and close what's open (no design changes)
1. **Preconditions:** SSD `Disc Samsung T7` mounted, Mullvad as usual.
2. **Run the suite on a clean VM:** `FOXHOLE_VM_NET=bridged bash tests/vm/run.sh --reset`. T16 must pass, and the total should be about 101/0/0.
   - If T16 fails: fix `_write_restore_script` / T16, re-run, then commit `fix(netlib): …`.
   - If green: amend nothing. Commit the new log plus a PLAN/CHECKPOINT tick (`test: T16 green`).
3. **Push:** `arch -arm64 /usr/bin/git push -u origin debug`. Verify with `git ls-remote origin debug`.
4. **CI:** check that the `lint` workflow ran for the push. There is no gh auth, so use the GitHub web UI or ask the user. If it fails on the `macos-latest` runner (bash path, shellcheck version, `networksetup` in `prepare_pf_dns_lock_anchor`), fix it in `tests/ci/offline.sh` or the workflow.
5. **Ask the user:** should I switch the remote URL to `Gr3y-foX/foxhole-macos`? The command is `git remote set-url origin …`.

## Step 2: User decisions (ask with AskUserQuestion at the start), then implement
| # | Question | Recommendation | Where |
|---|---|---|---|
| D1 | Quad9 whitelist passes any port, so plain DNS on :53 to 9.9.9.9 leaves outside the VPN | Restrict to `port 443` (DoH). T11's plain-DNS stand-in then needs a DoH image or a different stand-in | `prepare_pf_dns_lock_anchor` rule [4]; T3/T11; `tests/ci/offline.sh` |
| D2 | Block rules cover only interfaces present at enable time | Have the helper's `start` re-render the interface list at boot, and document re-enabling after adding a NIC. Unscoped blocks would also catch `ipsec0`/`ppp0` VPNs. | helper heredoc in `_install_pf_helper`; `_physical_ifaces` |
| D3 | Old (≤0.17.2) installs keep PF on after migration (no token) | Keep the current message (`sudo pfctl -d`); don't auto-disable | `_pf_legacy_cleanup` |
| D4 | `debug_netlib/` (7 tracked files, incl. old `netlib-simple.sh`) | Move to `docs/archive/` or delete before the merge | repo tree, README |

For each change: `bash -n`, `shellcheck -S warning`, a new or adjusted VM test, the full suite, a changelog note in `docs/v 0.17/netlib_v0.17.3.md` (or bump to 0.17.4 if released separately), commit, push.

## Step 3: Merge prep
- **Docs:** check that README sections match the code: PF lock, Privoxy, hosts, installer notes, `FOXHOLE_ASSUME_YES`, `tests/vm/run.sh`, `FOXHOLE_VM_NET=bridged`.
- **CLAUDE.md "Commands / Testing" section:** still describes the old pf.conf testing. Propose the text to the user. It's their file and it has uncommitted edits, so ask first.
- **PLAN.md:** tick the stale items and add a summary line.
- **Test report:** write one consolidated `docs/testing/vm-test-report-<date>.md` (like the 2026-11-03 one). Optionally prune the 13 logs to the meaningful ones.
- **GitNexus:** `node .gitnexus/run.cjs analyze --index-only`, then `detect-changes --scope compare --base-ref main`. Bash functions are not indexed (impact = UNKNOWN), so suggest a `.gitnexusignore` for `free-claude-code/` to the user.
- **PR (only on the user's go):**
  - Title and body come from `CHECKPOINT.md` lines 11–13. Check for a PR template first, and end the body with the attribution line.
  - After creating it, ask whether to subscribe to PR activity.

## Step 4: Optional coverage (if tokens remain; order by value)
1. **Real Privoxy in the VM:** clone `foxhole-brew` → `foxhole-test`, run netlib menu [3] / `install_privoxy`, check that `brew services` starts it and that T13 passes against the real daemon. Note: `run.sh --reset` clones `foxhole-clean` (no brew). Consider adding a `FOXHOLE_VM_BASE=foxhole-brew` option to `run.sh`/`vm.sh`.
2. **Real WireGuard tunnel:** `brew install wireguard-tools wireguard-go` in `foxhole-brew`, a loopback or peer config, then DNS through the tunnel with the lock on.
3. **Real Mullvad side by side:** this needs the user on the host. Run `vpn_daily.sh` [1] with Mullvad connected, check that the kill switch still works, then [2]. So far this was only simulated with a second `pfctl -E` holder.
4. **DoH profile image `foxhole-doh`:** needs a GUI click in the VM. It would let T11 use real DoH and resolve D1.
5. **Installer:** add a timeout around cask installers that need a GUI (BlockBlock hangs headless). `profile-paranoid-tor.sh` is still a header-only stub, but installer option [2] runs it, so either warn or hide that option.

## Rules carried over
- **Branch:** work only on `debug`. Never push to `main`, and no PR without an explicit ask.
- **Host safety:** no `pfctl` / `launchctl` / `networksetup` / installer runs on the host. All system-changing tests go in the VM. Stop the VM gracefully (`vm.sh down` / `run.sh`).
- **Shell rules:** bash 3.2, `printf -v` (no eval), resolve brew via `resolve_brew_prefix`, idempotent changes with a marker or rollback, version header and changelog for behaviour changes.
- **Repo rules:** GitNexus impact/detect-changes before edits and commits (bash = UNKNOWN, so confirm with grep). Don't commit `.DS_Store`, `.gitnexus/`, `free-claude-code/`.
- **Host shell:** the host shell is zsh (no word-splitting of `$VAR` commands). Use `perl -e 'alarm N; exec @ARGV'` as a timeout. The VM has no Python (only Perl), and sourcing the netlib turns on `set -e`.

## Verification (how to know the session succeeded)
- `FOXHOLE_VM_NET=bridged bash tests/vm/run.sh --reset` → 0 failed, 0 skipped, log committed.
- `bash tests/ci/offline.sh` → all pass. The GitHub `lint` workflow is green on `debug`.
- `git ls-remote origin debug` equals `git rev-parse HEAD`.
- `CHECKPOINT.md` and `PLAN.md` are updated, with no open item left unexplained. The PR is opened only if the user asked.

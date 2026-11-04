# Session plan: foxhole-macos `debug` (v0.17.3), started 2026-11-04

This is my own working file for this session. Tick each box as it lands and write the commit hash next to it.
Background: `NEXT_SESSION.md` (status block at the top), `CHECKPOINT.md` (partly stale), `PLAN.md`.

## Loop at every checkpoint
**Run → Check → Continue.** Each checkpoint has 4 parts:
- **Run:** what I do.
- **Check:** how I know it worked.
- **Stop if:** when I halt and ask the user.
- **Continue:** where to go next.

After each checkpoint, write one line in the **Log** at the bottom. If the session dies, resume from the last ticked box.

## Starting state (read-only, 2026-11-04)
- **Branch:** `debug` at `a1c62a4`. The local `origin/debug` ref is `c3ffa61`, so **1 commit is not pushed** (the GitNexus ignore / AGENTS symlink / checkpoint commit). This ref may be stale: confirm with `git ls-remote`.
- **Commits ahead of `main`:** 32. `main` is still v0.16.1. Netlib header says v0.17.3. Changelog: `docs/changelog/v0.17.3.md`.
- **Tests:** last fresh-VM suite was 100/0/0, including T16 (`vm-test-2026-11-03_233425.log`). `tests/ci/offline.sh` passed 13/13 locally.
- **CI:** blocked by the GitHub billing lock. This is not a code problem.
- **Remote:** `origin` still points at `macos-sec-harder-26`, but GitHub says the repo moved to `foxhole-macos`.
- **Working tree:** clean apart from untracked `.DS_Store`, `.claude/`, `free-claude-code/`. Never commit those.

## Rules I must keep
- **Branch:** only `debug`. No push to `main`. No PR unless the user asks.
- **Host:** never run `pfctl`, `launchctl`, `networksetup`, the installer or the netlib menu on the host. System tests go in the Tart VM only, and I shut it down gracefully.
- **After every edit:** `bash -n` and `shellcheck -S warning`. Keep bash 3.2 compatibility and use `printf -v` (never `eval`).
- **Before editing a function:** run GitNexus impact. Bash functions resolve as `UNKNOWN`, so confirm callers with `grep -rn` over `*.sh` and say so.
- **Before every commit:** GitNexus `detect-changes`.
- **Push:** `arch -arm64 /usr/bin/git push -u origin debug`. Never use `/usr/local/bin/git`, which hangs.
- **Commit footer:** end each commit message with the Co-Authored-By line from the system reminder.
- **Behaviour changes:** add a changelog note and a version header bump.

---

## CP0: Sync check (read-only)
- [ ] **Run:**
  - `git status`
  - `git fetch origin debug`
  - `git rev-parse HEAD origin/debug`
  - `git ls-remote origin debug`
- [ ] **Check:**
  - Local is ahead by exactly `a1c62a4` and nothing remote is new.
  - The SSD `Disc Samsung T7` is mounted (needed for the VM).
- **Stop if:** the remote has commits I don't have. Then ask before any rebase or merge.
- **Continue:** CP1.

## CP1: Push the unpushed commit
- [ ] **Run:** `arch -arm64 /usr/bin/git push -u origin debug`
- [ ] **Check:** `git ls-remote origin debug` equals `git rev-parse HEAD`.
- **Stop if:** the push hangs or is rejected. Retry with backoff 2s/4s/8s/16s, then report.
- **Continue:** CP2.

## CP2: Ask the user (one AskUserQuestion, all at once)
- [ ] Ask these, with my recommendation first:
  - **D1:** Restrict the Quad9 whitelist to `port 443` (DoH only)? *Recommend: yes.*
  - **D2:** Should the helper `start` re-render the physical-interface list at boot? *Recommend: yes, plus a doc note to re-enable after adding a NIC.*
  - **D3:** Old ≤0.17.2 installs keep PF on after migration. *Recommend: keep the `sudo pfctl -d` message, no auto-disable.*
  - **D4:** What to do with `debug_netlib/`? *Recommend: move it to `docs/archive/`.*
  - **R1:** Switch `origin` to `Gr3y-foX/foxhole-macos`? *Recommend: yes.*
- [ ] **Check:** every answer is written into the Log.
- **Stop if:** the user wants to think it over. Then do CP7 (docs, which has no design impact) and wait.
- **Continue:** CP3 (only the items the user approved).

## CP3: R1, remote URL (if approved)
- [ ] **Run:** `git remote set-url origin https://github.com/Gr3y-foX/foxhole-macos.git`
- [ ] **Check:** `git remote -v`, then `arch -arm64 /usr/bin/git ls-remote origin debug` still equals HEAD.
- **Continue:** CP4.

## CP4: D1, Quad9 limited to port 443 (if approved)
- [ ] **Run:**
  - Run impact on `prepare_pf_dns_lock_anchor` and grep its callers.
  - Edit rule [4] to add `port 443`.
  - Update T3/T11 in `tests/vm/vmtest.sh`. T11's plain-DNS stand-in no longer passes, so choose one: assert that :53 to Quad9 is **blocked** (this becomes a new negative test), and keep the DoH path checked with `curl https://dns.quad9.net/dns-query`.
  - Update `tests/ci/offline.sh` if it greps rule text.
- [ ] **Check:**
  - `bash -n` and `shellcheck` pass.
  - Generate the anchor with `sudo` stubbed, then `pfctl -nvf <anchor>` (syntax only, no load).
  - `bash tests/ci/offline.sh` passes.
- **Stop if:** T11 loses all positive DNS coverage. Then ask whether a DoH VM image (`foxhole-doh`) is worth building now.
- **Continue:** CP5 (I batch the VM run in CP6).

## CP5: D2 / D3 / D4 (each only if approved)
- [ ] **D2:**
  - Run impact on `_install_pf_helper` and `_physical_ifaces`.
  - The helper heredoc `start` re-renders the iface list before loading the anchor.
  - Add a VM test: add a fake interface or recheck after reboot, if that's feasible. Otherwise document why it isn't covered.
- [ ] **D3:** most likely no code change. Only confirm the message text in `_pf_legacy_cleanup`.
- [ ] **D4:**
  - `git mv debug_netlib docs/archive/debug_netlib`.
  - Fix the references in `CLAUDE.md`, the README and `NEXT_SESSION.md`. Check with `grep -rn debug_netlib`.
- [ ] **Check:**
  - `bash -n` and `shellcheck` on all scripts.
  - `offline.sh` passes.
  - Changelog: add to `netlib_v0.17.3.md`, or bump to 0.17.4 (header plus a new doc) if D1/D2 count as a separate release. *Default: stay at 0.17.3, since it isn't merged yet.*
- **Continue:** CP6.

## CP6: Full VM suite (only if CP4 or CP5 changed code)
- [ ] **Run:** `FOXHOLE_VM_NET=bridged bash tests/vm/run.sh --reset`
- [ ] **Check:** 0 failed / 0 skipped. The total is about 100 or more, plus the new tests. The log is copied into `docs/testing/logs/`.
- **Stop if:** something fails twice for the same reason after one fix attempt. Then report it with the log excerpt.
- [ ] **Commit:** one commit per decision. Examples:
  - `fix(netlib): restrict Quad9 whitelist to DoH port 443`
  - `fix(netlib): re-render physical ifaces at helper start`
  - `chore: archive debug_netlib/`
  - `test: VM suite green after D1/D2`

  Run `detect-changes` before each commit, then push as in CP1.
- **Continue:** CP7.

## CP7: Merge-prep docs
- [ ] **README:** check that these sections match the code: PF lock in a child anchor (no pf.conf edit), Privoxy autoswitch, hosts, installer notes, `FOXHOLE_ASSUME_YES`, `tests/vm/run.sh`, `FOXHOLE_VM_NET=bridged`.
- [ ] **CLAUDE.md "Testing without touching the system":** it still describes the old pf.conf testing. **Draft the new text and show it to the user before editing.** It's their file.
- [ ] **CLAUDE.md:** ask about the stale GitNexus stats (7373 symbols) and the `.claude/skills` table, which points at untracked files.
- [ ] **PLAN.md:** tick the done or obsolete items and add a summary line.
- [ ] **CHECKPOINT.md:** rewrite it so it's no longer stale. Its "Next" list still says push/T16, and it still says "nothing pushed".
- [ ] **Test report:** write a consolidated `docs/testing/reports/vm-test-report-2026-11-04.md`. Ask before pruning old logs.
- [ ] **Check:** `grep` for stale claims: `rollback.sh`, `pf.conf` edit, `dnscrypt`, `utun+`.
- [ ] **Commit:** `docs: …`, then push.
- **Continue:** CP8.

## CP8: GitNexus and the pre-merge diff
- [ ] **Run:**
  - `node .gitnexus/run.cjs analyze --index-only`
  - `node .gitnexus/run.cjs detect-changes --scope compare --base-ref main --repo .`
- [ ] **Check:** not `partial` and not `truncated`. If it is either, re-run.
- [ ] **Check:** summarise the affected areas for the user. Bash functions show as `UNKNOWN`, so name the touched scripts from `git diff --stat main..debug`.
- **Continue:** CP9.

## CP9: Hand-off or PR
- [ ] Ask: "Open the PR `debug` → `main` now?"
- [ ] **If yes:**
  - Check for a PR template.
  - Title: `v0.17.3: PF DNS lock in com.apple/* child anchor, installer fixes, VM test suite`.
  - Body: the changelog summary, the VM result, and the open items (CI billing lock, real Mullvad/Privoxy/WireGuard not tested).
  - End the body with the attribution line.
  - Then ask whether to subscribe to PR activity.
- [ ] **If no:** update `NEXT_SESSION.md` and `CHECKPOINT.md`, commit and push.
- **Done when:**
  - HEAD equals `origin/debug`.
  - The suite is green.
  - The docs aren't stale.
  - Every open item is either decided or written down with its reason.

## CP10: Optional coverage (only if time and tokens remain, in this order)
1. **Real Privoxy in the VM:**
   - `tart clone foxhole-brew foxhole-test`.
   - Run `install_privoxy`, then T13 against the real daemon.
   - Maybe add a `FOXHOLE_VM_BASE` option to `run.sh`/`vm.sh`.
2. **Real WireGuard in `foxhole-brew`:** DNS through the tunnel with the lock on.
3. **Installer:** add a timeout around GUI casks (BlockBlock hangs). Hide or warn on option [2] (`profile-paranoid-tor.sh` is a stub).
4. **Needs the user at the Mac:** real Mullvad side by side, and the `foxhole-doh` image (needs a GUI click).

## Blocked, outside my control
- **CI:** the GitHub billing lock. After the owner fixes it, re-run `lint` on `debug` and check the Linux and macOS jobs.

## Plan vs done (end of 2026-11-04 session)
| CP | Planned | Result |
|---|---|---|
| CP0 sync check | git state, SSD | done; local was 1 commit ahead |
| CP1 push | native git push | done after the SSH key and email setting were fixed by the user (`origin` is now SSH `github-foxhole`) |
| CP2 decisions | ask D1-D4, R1 | done: D1 configurable, D2 yes (test in VM first), D3 my call (keep message), D4 archive, R1 done by the user |
| CP3 remote URL | `set-url` | done by the user (SSH alias) |
| CP4 D1 | Quad9 port 443 | done, as three modes `doh` / `vpn` / `plain` (more than planned: the user wanted options) |
| CP5 D2/D3/D4 | interface re-render, message, archive | D2 done (stdin instead of a temp file after a flake), D3 no code change, D4 done |
| CP6 VM suite | full run, commits | done: 125/0/0 (Homebrew image), 112/0/1 (clean image); several test-side fixes on the way |
| CP7 docs | README, CLAUDE.md, PLAN, report | README, changelog, PLAN, CHECKPOINT, NEXT_SESSION, report done; **CLAUDE.md text is only a draft** (`CLAUDE_MD_DRAFT.md`, needs the user) |
| CP8 GitNexus | re-index, compare to main | done (risk low, not partial) |
| CP9 PR | ask first | **not done**: PR #1 already exists (old v0.16 title); retitle only with the user's OK |
| CP10 optional | Privoxy, WireGuard, cask timeout, Mullvad, DoH | real Privoxy (T18) and real WireGuard (T19) done; installer Tor option marked planned; cask timeout skipped (headless-VM only); Mullvad and DoH image need the user |

Extras not in the plan: CI found green after the billing fix, `FOXHOLE_VM_BASE`, offline checks 17/17, `restore.sh` unchanged, PR #1 discovered.

## Log
- 2026-11-04: plan written (read-only session: no code changed, nothing committed).
- 2026-11-04 night: CP0-CP8 and most of CP10 done; open: CLAUDE.md text, PR #1 retitle, Mullvad/DoH tests (all need the user).

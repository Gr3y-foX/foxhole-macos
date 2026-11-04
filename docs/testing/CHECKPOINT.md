# Checkpoint — 2026-11-04 (resume here)

## Done this session (local only, nothing pushed)
- **Session start:** `debug` at `c3ffa61`, in sync with GitHub. Local VM suite last green: 100/0/0 (`vm-test-2026-11-03_233425.log`, includes T16).
- **`.gitnexusignore`** added with `free-claude-code/`. GitNexus reads it (checked in its source). Re-index: 7,406 nodes → 319 nodes, so the unrelated clone is out.
- **`AGENTS.md`** is now a symlink to `CLAUDE.md`. The two files were byte-identical, so no content was lost. Agents that read `AGENTS.md` directly still get the full text.
- **`CLAUDE.md`** (GitNexus section):
  - the "warn the user before editing" rule for HIGH/CRITICAL risk is explicit again, and says to report callers, affected processes and risk level;
  - new note: bash functions usually resolve as `UNKNOWN`, so confirm callers with `grep -rn` over the `*.sh` files and say so.
- **`NEXT_SESSION.md`:** status section added at the top (T16 green, push works with native git, CI blocked by billing, remote URL still open, D1–D4 still open).
- **Lint:** `bash -n` on all scripts and `shellcheck -S warning` clean.

## Not done (needs your answer or GitHub)
- **CI:** still blocked by GitHub's billing lock on the account. Nothing to fix in the workflow.
- **Decisions D1–D4** (Quad9 port 443, interfaces added later, old-install PF message, `debug_netlib/`): not decided.
- **Remote URL:** still `macos-sec-harder-26`; the repo moved to `foxhole-macos`.
- **GitNexus stats** in `CLAUDE.md` still say 7373 symbols. They were generated with the unrelated clone included. Re-generating them would rewrite your block, so I left it for you to decide.
- **`.claude/skills` table** in `CLAUDE.md` points at untracked files. Commit the skills or drop the table: your call.
- **Real Mullvad test**, real Privoxy and WireGuard in the VM, DoH profile image: need you at the Mac or more time.

## Your uncommitted edits
- The GitNexus refresh you had in `CLAUDE.md`/`AGENTS.md` is included in this local commit, together with my changes, because the two files are now one. Revert that hunk if you didn't want it committed.

## Branch / PR state
- Work branch: `debug`. `main` is still v0.16.1. **Never push to main; work only on `debug`.**
- CI status: all `lint` runs fail before any step starts: GitHub says the account is locked due to a billing issue (owner must fix; check via https://api.github.com/repos/Gr3y-foX/foxhole-macos/actions/runs). Workflow now has a Linux shellcheck job and a separate macOS job.
- Latest fresh-VM suite: 100 passed / 0 failed / 0 skipped (`vm-test-2026-11-03_233425.log`, includes T16). Remote `debug` was at `f59538b` when this section was written; see `git log` for the current head.
  - `e6730f3` fix(install): OverSight/Mergen downloads, brew vulns, Gatekeeper, SSH-aware firewall (VM suite 93/0/0)
  - `548c6e5` docs: plan and checkpoint after the installer run
  - `f59538b` WIP: `restore.sh` in net backups + T16 test (T16 NOT run in the VM yet)
- GitHub says the repo moved to `https://github.com/Gr3y-foX/foxhole-macos.git`. Update the remote when convenient; pushes to the old URL still work for now.
- Push problem: the Intel Homebrew `git` (`/usr/local/bin/git`, Rosetta) hangs on github.com; `curl` works. Apple's native `arch -arm64 /usr/bin/git push -u origin debug` connects. Use that, or retry later.
- **No PR opened.** Open one only when asked. PR text (ready to paste):
  - Title: `v0.17.3: PF DNS lock in com.apple/* child anchor, installer fixes, VM test suite`
  - Body: what changed (see `docs/v 0.17/netlib_v0.17.3.md`); VM suite `tests/vm/run.sh` 93 passed / 0 failed / 0 skipped with `FOXHOLE_VM_NET=bridged`; open items below.

## What was done (short)
- v0.17.3: DNS lock lives in `com.apple/foxhole.dnsleak`; `/etc/pf.conf` never edited; PF enabled via `pfctl -E` token and released on disable; helper `/usr/local/libexec/foxhole-pf-dnslock`; `launchctl bootstrap/bootout`.
- Found and fixed by running real tests in the VM: no `utun+` wildcard in PF (now `utun0-15`); `proxy-toggle.sh` never written on clean Apple Silicon (`/usr/local/bin` missing); Privoxy VPN detection matched "(Disconnected)"; hosts update removed old list before download; installer: OverSight/Mergen URLs 404, brew-vulns tap archived, Gatekeeper `spctl` exit code, firewall step cuts incoming SSH.
- Test infra: `FOXHOLE_VM_NET=bridged` (real internet in the VM); graceful VM shutdown; `tests/vm/vm.sh`; `tests/ci/offline.sh`; `.github/workflows/lint.yml` (not yet seen running on GitHub); `FOXHOLE_ASSUME_YES=1`.

## Uncommitted / unverified
- Nothing in the code is unverified now: `restore.sh` + T16 passed on a fresh VM (100/0/0). Only `CLAUDE.md`/`AGENTS.md` are modified (the user's own edits).

## Environment
- Tart VMs: `foxhole-test` (work), `foxhole-clean` (base), `foxhole-brew` (clean + Homebrew + CLT). `run.sh --reset` clones `foxhole-clean`, so brew-dependent work needs `tart clone foxhole-brew foxhole-test` first.
- SSD `Disc Samsung T7` must be mounted. Shut the VM down gracefully (`vm.sh down` / `run.sh` do `sync; shutdown -h now`).
- Known flake: the SSH control-master/firewall experiment hung; the installer's BlockBlock cask needs a GUI and hangs headless.

## Open questions for the user
- Quad9 whitelist passes any port (plain DNS to 9.9.9.9:53 outside the VPN). Restrict to 443?
- Block rules cover only interfaces present at enable time. Change?
- Old installs (≤0.17.2) keep PF on after migration (no token). Script says `sudo pfctl -d`.
- Leave `debug_netlib/`, or delete before merge?

## Next (in order)
1. Push: `arch -arm64 /usr/bin/git push -u origin debug`.
2. Run T16 in the VM (`FOXHOLE_VM_NET=bridged bash tests/vm/run.sh --reset`); commit if green.
3. Ask the user whether to open the PR (text above).
4. Check the `lint.yml` run on GitHub once the PR or branch is visible.

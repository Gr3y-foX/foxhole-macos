# Checkpoint — 2026-11-03 (resume here)

## Branch / PR state
- Work branch: `debug`. `main` is still v0.16.1. **Never push to main; work only on `debug`.**
- Remote `debug` is at `f59538b`, in sync with local. Pushed commits:
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
- `mac-hardening-netlib.sh`: `create_net_backup` now writes `restore.sh` into the backup dir (old message pointed to a non-existent `rollback.sh`). Syntax and shellcheck OK, not run.
- `tests/vm/vmtest.sh`: T16 tests that restore. Not run. Run: `FOXHOLE_VM_NET=bridged bash tests/vm/run.sh --reset`.

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

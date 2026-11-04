# Checkpoint — 2026-11-03 night (resume here)

## State
- Branch `debug` pushed at `841c492` (v0.17.3). `main` is still v0.16.1. **Work only on `debug`.** No PR exists (checked via GitHub API); create one only when the user asks.
- Uncommitted on purpose: `CLAUDE.md`, `AGENTS.md` (the user's own edits — don't touch). Untracked: `.DS_Store`, `.claude/`, `free-claude-code/`, three partial logs `vm-test-…_1706*/1708*/1709*.log` (runs cut off by SSH drops).
- Work plan with checkboxes: `docs/testing/PLAN.md`. Changelogs: `docs/v 0.17/netlib_v0.17.2-changes.md` (second pass), `docs/v 0.17/netlib_v0.17.3.md`.
- Last VM runs: **64 pass / 0 fail / 0 skip** with `FOXHOLE_VM_NET=bridged` (`vm-test-2026-11-03_181300.log`, `_181523.log`). Without bridged mode the VM has no egress and 4 internet checks skip (49/0/4).

## What was done this session
1. Housekeeping: confirmed B1 (`port = 53`) and the Rosetta guard were already committed (`77c92e6`); tested the guard with a throwaway script; moved the guard above the "Do not run as root" comment in the installer.
2. Offline bug sweep (`01552ba`), found by reading the code and testing with stubbed `scutil`/`ifconfig`/`nc`/`networksetup`/`curl`:
   - proxy-toggle `vpn_active` matched "(Disconnected)" → proxy never turned on; now exact "(Connected)" + `utun` with IPv4 (Mullvad/ClearVPN/OpenVPN), Tailscale ignored.
   - `set_proxy` idempotent (writes touched its own WatchPath); never enables proxy while Privoxy isn't listening; `install_privoxy` now starts it (`brew services`).
   - Privoxy exposure check used `0.0.0.0.8118` (macOS prints `*.8118`); bypass `forward` rules were CIDR (unsupported) → URL patterns; `disable_privoxy_autoswitch` also turns system proxies off.
   - `update_hosts` downloads + validates (≥1000 entries) before touching `/etc/hosts`.
   - Installer: dropped `dnscrypt-proxy` from `SECURITY_FORMULAS`, `ask` uses `printf -v`, script names fixed. shellcheck `-S warning` clean for install/netlib/vpn_daily.
3. v0.17.3 (`841c492`), plan items 1.2–1.4, researched in the VM first:
   - Rules load into `com.apple/foxhole.dnsleak` (child of the stock `com.apple/*` anchor) — `/etc/pf.conf` never edited, main ruleset never reloaded (Mullvad-safe).
   - PF enabled with `pfctl -E` token (`/var/db/foxhole/pf.token`), released with `pfctl -X` on disable → PF returns to its prior state, stays on if another holder exists.
   - Helper `/usr/local/libexec/foxhole-pf-dnslock start|stop|status` is the single path for enable/disable/boot daemon.
   - `launchctl bootstrap/bootout system` for PF and Privoxy daemons (`_launchd_bootout`, `_launchd_bootstrap` with retry).
   - Enable refuses if the main ruleset has no `anchor "com.apple/*"`; `_pf_legacy_cleanup` migrates old pf.conf-marker installs.
   - `tests/vm/vmtest.sh` rewritten (T1–T10: counter-based block check, coexistence, migration, guard, reboot-independent); new `tests/vm/vm.sh` (up/push/ssh/down/reset). Reboot test done manually: daemon re-applies the lock with a new token.

## Environment (Tart VM)
- Tart 2.41.1 in `~/.local/tart`, symlink `~/.local/bin/tart`. `TART_HOME="/Volumes/Disc Samsung T7/vm - backups/macos_vm"` (SSD must be plugged in).
- VMs: `foxhole-test` (work copy), `foxhole-clean` (untouched). Login `admin`/`admin`, `sudo -n` works. Host shell is zsh (no word-splitting; use functions, not `$V`), host `bash` on PATH is Intel-only → use `bash` via `arch -arm64` (scripts re-exec).
- `bash tests/vm/run.sh --reset` = full test; `bash tests/vm/vm.sh up|push|ssh '…'|down|reset` = ad hoc.
- Default NAT mode has no internet (host Mullvad Lockdown). **Use `FOXHOLE_VM_NET=bridged bash tests/vm/run.sh [--reset]`** (`--net-bridged=en0`, VM gets a LAN IP, `tart ip --resolver arp`). Stop the VM gracefully (`vm.sh down` / `run.sh` do `sync; shutdown -h now`) — `tart stop` alone lost the last file ops.

## Open questions for the user
- Quad9 whitelist passes any port (plain DNS to 9.9.9.9 :53 leaks outside the VPN) → restrict to 443?
- Block rules cover only interfaces present at enable time (USB NIC added later is unblocked) → change?
- Old (≤0.17.2) installs: PF stays on after migration (no token); script prints `sudo pfctl -d`.

## Next (see PLAN.md)
1. WireGuard tunnel test in the VM (`brew install wireguard-tools wireguard-go`, loopback-style config) → DNS through `utun+` with lock on; real `vpn_active` check.
2. Privoxy auto-switch with real Privoxy in the VM (brew), installer areas in `vmtest.sh`.
3. Real DoH profile image `foxhole-doh` (GUI approval; optional — T11 uses a Quad9 plain-DNS stand-in).
5. Step 3: `FOXHOLE_ASSUME_YES`, CI, `BASE_SUM` lint, decide `debug_netlib/`, CLAUDE.md testing section → `tests/vm/run.sh`, refresh GitNexus (`node .gitnexus/run.cjs analyze --index-only`).

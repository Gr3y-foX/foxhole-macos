# Work plan — v0.17.2 → merge (started 2026-11-03)

Working list for the agent. Source: `CHECKPOINT.md` + `vm-test-report-2026-11-03.md`.
Tick items as they land; note the commit hash.

Rules: no `pfctl` / `launchctl` / `networksetup` / installer runs on the host.
`bash -n` + `shellcheck` after every edit. GitNexus `detect-changes` before every commit.
Don't touch the user's uncommitted `CLAUDE.md` / `AGENTS.md`.

## Step 0 — housekeeping
- [x] B1 (`port = 53` ACTIVE check) is committed — `77c92e6` (report said uncommitted; it's stale)
- [x] Commit `tests/vm/run.sh` log-copy change + this plan (see Log)
- [x] PR debug→main: none exists (checked 2026-11-03 via GitHub API) — the form was never submitted; create only when the user asks

## Step 1 — P1 host safety
- [x] 1.1 Rosetta guard in install, netlib, vpn_daily — `77c92e6`
  - [x] Guard verified on the host with a throwaway script (x86_64 shell → re-exec → arm64)
  - [x] VM re-run after `77c92e6`: 31 pass / 0 fail / 4 skip — `vm-test-2026-11-03_171053.log` (VM is native arm64, so the guard is a no-op there; the x86_64 path is covered by the host test)
  - [x] Installer: moved the guard above the `# Do not run as root` comment it had split from its check
- [ ] 1.2 Load rules into `com.apple/foxhole.dnsleak` (`pfctl -a … -f`), no `pf.conf` edit, no `pfctl -f /etc/pf.conf`
  - offline: `pfctl -nvf` on the generated anchor; VM: enable/disable + Mullvad-style coexistence
  - keep rollback for installs that still have the old `pf.conf` marker block
- [ ] 1.3 `pfctl -E` token stored under `~/.foxhole/` (or `/var/db/foxhole/`), `pfctl -X <token>` on disable
- [ ] 1.4 `launchctl bootstrap|bootout system` instead of `load|unload` (netlib lines ~316, 347, 612–630)
- [ ] Version bump + note in `docs/v 0.17/` once 1.2–1.4 change behaviour

## Step 1b — offline bug sweep (2026-11-03, SSD unplugged)
- [x] proxy-toggle `vpn_active`: `(Disconnected)` matched → proxy never ON; + utun/IPv4 detection (Mullvad)
- [x] proxy-toggle `set_proxy` idempotent (own WatchPath re-trigger)
- [x] proxy-toggle: no proxy ON while Privoxy is down; `install_privoxy` starts the service
- [x] Privoxy exposure check (`*.8118` format), bypass `forward` patterns (no CIDR)
- [x] `disable_privoxy_autoswitch` turns proxies off
- [x] `update_hosts` download + validate before editing `/etc/hosts`
- [x] Installer: drop dnscrypt-proxy, `ask` without eval, script names
- [x] shellcheck `-S warning` clean (install, netlib, vpn_daily)
- [ ] VM: run Privoxy menu [3] + toggle with a real Privoxy (needs SSD)
- [ ] Open question for the user: Quad9 whitelist passes **any port** (incl. plain DNS :53 to 9.9.9.9 outside the VPN); restrict to 443 (DoH)?
- [ ] Open question: block rules only cover interfaces present at enable time; a USB/Thunderbolt NIC added later is not blocked until re-enable

## Step 2 — P2 VM coverage (needs SSD + user)
- [ ] VM egress (pause Mullvad Lockdown or `tart run --net-softnet`) → 4 skipped checks
- [ ] `foxhole-doh` image with the Quad9 DoH profile → health checks [1], [3]–[6]
- [ ] WireGuard tunnel in the VM
- [ ] `vmtest.sh`: hosts blocklist, Privoxy auto-switch, base installer

## Step 3 — P3 quality / merge prep
- [ ] `FOXHOLE_ASSUME_YES=1` for `ask`
- [x] Shellcheck warnings in shipped scripts (SC2229, SC2155, SC2034); `BASE_SUM` in tests/vm/vmtest.sh still open
- [ ] CI: GitHub Actions macOS runner with `bash -n` + shellcheck + offline anchor tests
- [ ] Decide on `debug_netlib/`; point CLAUDE.md testing section at `tests/vm/run.sh` (after the user's own edits are in)
- [ ] Refresh GitNexus index; PR debug→main (only when the user asks)

## Log
- 2026-11-03: plan written; Step 0 / 1.1 checked. Logs 170637/170811/170950 are runs cut off by a dropped SSH session (left untracked); 171053 is the good one.
- 2026-11-03 evening: user unplugged the SSD; did the offline bug sweep (Step 1b). Details: `docs/v 0.17/netlib_v0.17.2-changes.md` → Second pass.
- Next: 1.2 (`com.apple/foxhole.dnsleak` anchor) offline prototype; VM checks when the SSD is back.

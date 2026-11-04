# Work plan — v0.17.2 → merge (started 2026-11-03)

Working list for the agent. Source: `CHECKPOINT.md` + `vm-test-report-2026-11-03.md`.
Tick items as they land; note the commit hash.

Rules: no `pfctl` / `launchctl` / `networksetup` / installer runs on the host.
`bash -n` + `shellcheck` after every edit. GitNexus `detect-changes` before every commit.
Don't touch the user's uncommitted `CLAUDE.md` / `AGENTS.md`.

## Step 0 — housekeeping
- [x] B1 (`port = 53` ACTIVE check) is committed — `77c92e6` (report said uncommitted; it's stale)
- [x] Commit `tests/vm/run.sh` log-copy change + this plan (see Log)
- [ ] Check whether PR debug→main exists (network to github.com failed from the host on 2026-11-03; retry / ask the user)

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

## Step 2 — P2 VM coverage (needs SSD + user)
- [ ] VM egress (pause Mullvad Lockdown or `tart run --net-softnet`) → 4 skipped checks
- [ ] `foxhole-doh` image with the Quad9 DoH profile → health checks [1], [3]–[6]
- [ ] WireGuard tunnel in the VM
- [ ] `vmtest.sh`: hosts blocklist, Privoxy auto-switch, base installer

## Step 3 — P3 quality / merge prep
- [ ] `FOXHOLE_ASSUME_YES=1` for `ask`
- [ ] Shellcheck warnings: SC2229 in `ask` (netlib:54, intentional — add disable comment), SC2155 (netlib:366, 447), SC2034 (`PRIVOXY_PORT`, `BASE_SUM`)
- [ ] CI: GitHub Actions macOS runner with `bash -n` + shellcheck + offline anchor tests
- [ ] Decide on `debug_netlib/`; point CLAUDE.md testing section at `tests/vm/run.sh` (after the user's own edits are in)
- [ ] Refresh GitNexus index; PR debug→main (only when the user asks)

## Log
- 2026-11-03: plan written; Step 0 / 1.1 checked. Logs 170637/170811/170950 are runs cut off by a dropped SSH session (left untracked); 171053 is the good one.
- Next: 1.2 (`com.apple/foxhole.dnsleak` anchor) — prototype offline, then VM.

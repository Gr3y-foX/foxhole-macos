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
- [x] 1.2 Load rules into `com.apple/foxhole.dnsleak` (`pfctl -a … -f`), no `pf.conf` edit, no `pfctl -f /etc/pf.conf`
  - offline: `pfctl -nvf` on the generated anchor; VM: enable/disable + Mullvad-style coexistence
  - keep rollback for installs that still have the old `pf.conf` marker block
  - VM research 2026-11-03 (clean VM, macOS 26.6.2): stock main ruleset has `anchor "com.apple/*"` (loaded at boot by `com.apple.pfctl`, PF off);
    a child `com.apple/foxhole.dnsleak` is evaluated (block-rule packet counters rise), survives `pfctl -f /etc/pf.conf`;
    `pfctl -E` tokens outlive the process, are ref-counted with other holders, vanish at reboot.
  - Design: helper `/usr/local/libexec/foxhole-pf-dnslock start|stop|status` (single code path for enable/disable/boot);
    token in `/var/db/foxhole/pf.token`; LaunchDaemon runs `helper start`; enable aborts if main ruleset lacks `com.apple/*`;
    `_pf_legacy_cleanup` removes the old pf.conf marker block once.
- [x] 1.3 `pfctl -E` token stored under `~/.foxhole/` (or `/var/db/foxhole/`), `pfctl -X <token>` on disable
- [x] 1.4 `launchctl bootstrap|bootout system` instead of `load|unload` (netlib lines ~316, 347, 612–630)
- [x] Version bump → 0.17.3 + `docs/changelog/v0.17.3.md`
  - [x] VM: `run.sh --reset` 49/0/4 (logs 175310, 175751); reboot test: lock re-applied at boot with a new token
  - [ ] Real Mullvad on the host side-by-side (simulated with a 2nd `pfctl -E` holder only)
  - [x] `run.sh --reset` right after a VM reboot once produced no log — fixed by the graceful shutdown (`e240e12`)

## Step 1b — offline bug sweep (2026-11-03, SSD unplugged)
- [x] proxy-toggle `vpn_active`: `(Disconnected)` matched → proxy never ON; + utun/IPv4 detection (Mullvad)
- [x] proxy-toggle `set_proxy` idempotent (own WatchPath re-trigger)
- [x] proxy-toggle: no proxy ON while Privoxy is down; `install_privoxy` starts the service
- [x] Privoxy exposure check (`*.8118` format), bypass `forward` patterns (no CIDR)
- [x] `disable_privoxy_autoswitch` turns proxies off
- [x] `update_hosts` download + validate before editing `/etc/hosts`
- [x] Installer: drop dnscrypt-proxy, `ask` without eval, script names
- [x] shellcheck `-S warning` clean (install, netlib, vpn_daily)
- [x] Privoxy toggle + LaunchDaemon tested in the VM (T13, stand-in listener); real Privoxy binary still open (Step 2)
- [ ] Open question for the user: Quad9 whitelist passes **any port** (incl. plain DNS :53 to 9.9.9.9 outside the VPN); restrict to 443 (DoH)?
- [ ] Open question: block rules only cover interfaces present at enable time; a USB/Thunderbolt NIC added later is not blocked until re-enable

## Step 2 — P2 VM coverage
- [x] VM egress: `FOXHOLE_VM_NET=bridged` (`--net-bridged=en0`, VM gets a LAN address; ARP resolver for `tart ip`). Default NAT stays blocked by host Mullvad Lockdown; `--net-softnet` needs the `softnet` binary + host sudo (not available non-interactively).
  - 4 skipped internet checks now run: 8.8.8.8 blocked, Quad9 allowed, HTTPS ok, DNS works again after disable.
- [x] T11 full stack: Quad9 plain-DNS resolver (stand-in for the DoH profile, which needs GUI approval) + hosts blocklist (77k entries) + lock → health check **10/10**; hosts update/idempotence/reset.
- [x] `run.sh`/`vm.sh down`: graceful shutdown (`sync; shutdown -h now`) — abrupt `tart stop` lost the last file ops and left stale lock state for the next run. Two consecutive runs: 64/0/0 each.
- [ ] Real DoH profile image `foxhole-doh` (needs GUI click in the VM: boot with graphics) — still only the plain-DNS stand-in
- [x] Tunnel test **without WireGuard** (T12): IPv4 on system `utun3` + a TEST-NET-3 host route through it → DNS passes the `utun3` rule, `vpn_active` sees the VPN. Found: PF has no `utun+` wildcard → explicit `utun0-15`. A real WireGuard run needs brew (→ Xcode CLT) in the VM; deferred.
- [x] T13 real `proxy-toggle.sh` + LaunchDaemon + networksetup with a stand-in listener (found: `/usr/local/bin` missing on clean Apple Silicon → script never written)
- [x] T14 `FOXHOLE_ASSUME_YES`
- [x] Base installer run end to end in the VM (`foxhole-brew` image = clean + Homebrew + CLT): 6 findings fixed (see `docs/changelog/v0.17.3.md`, "Installer run"), T15 tests
- [x] Real Privoxy binary in the VM: T18 (8/8, `FOXHOLE_VM_BASE=foxhole-brew`, 2026-11-04). [x] Real WireGuard in the VM: T19 (5/5, wireguard-go, 2026-11-04)
- [ ] BlockBlock cask installer needs a GUI session (hangs headless) — maybe add a timeout around cask installs

- [x] `create_net_backup` writes `restore.sh` (the old message pointed at a non-existent `rollback.sh`); T16 green — fresh-VM run 100/0/0 (`vm-test-2026-11-03_233425.log`)

## Step 3 — P3 quality / merge prep
- [x] `FOXHOLE_ASSUME_YES=1` for `ask` (netlib + installer; T14, `tests/ci/offline.sh`)
- [x] Shellcheck warnings in shipped scripts (SC2229, SC2155, SC2034); `BASE_SUM` removed
- [x] CI: `.github/workflows/lint.yml` runs green on GitHub since 2026-11-04 (Linux shellcheck job + macOS job; push and pull_request).
- [x] `debug_netlib/` archived to `docs/archive/debug_netlib/` (2026-11-04); [ ] point CLAUDE.md testing section at `tests/vm/run.sh` (after the user's own edits are in)
- [ ] Refresh GitNexus index; PR debug→main (only when the user asks)

## Log
- 2026-11-03: plan written; Step 0 / 1.1 checked. Logs 170637/170811/170950 are runs cut off by a dropped SSH session (left untracked); 171053 is the good one.
- 2026-11-03 evening: user unplugged the SSD; did the offline bug sweep (Step 1b). Details: `docs/changelog/v0.17.2.md` → Second pass.
- 2026-11-03 night: SSD back. Step 1.2–1.4 done ("big guy"): VM research → helper/token design → 49/0/4 + reboot test. New `tests/vm/vm.sh` for ad-hoc VM work.
- 2026-11-03 night: Step 2 egress + T11 done (64/0/0 twice). Next: WireGuard/Privoxy tests, then Step 3.
- 2026-11-03 (next day session): T16 verified (first run found a test-side pf.conf assertion; fixed). Fresh-VM suite 100/0/0. Pushed.

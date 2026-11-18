# Testing

The scripts change live system state (PF, `/etc/hosts`, proxies, LaunchDaemons), so system-changing tests run **only inside a Tart VM**, never on your Mac.

| What | How | Touches the system? |
|---|---|---|
| Syntax and lint | `bash -n <script>` and `shellcheck -S warning mac-hardening-*.sh vpn_daily.sh tests/ci/offline.sh tests/vm/*.sh` | no |
| Offline checks | `bash tests/ci/offline.sh` (renders the PF anchor in all three DNS modes with `sudo` stubbed; also runs in CI, see `.github/workflows/lint.yml`) | no |
| Full VM suite | `FOXHOLE_VM_NET=bridged bash tests/vm/run.sh --reset` (needs the SSD with the Tart images, `tart`, `sshpass`) | VM only |
| Ad-hoc work in the VM | `bash tests/vm/vm.sh up\|push\|ssh '<cmd>'\|down\|reset` | VM only |

Environment variables: `FOXHOLE_VM_NET=bridged` (real internet in the VM), `FOXHOLE_VM_BASE=foxhole-brew` (start from the image with Homebrew; enables the real Privoxy test T18 and the real WireGuard test T19) or `FOXHOLE_VM_BASE=foxhole-mullvad` (the Mullvad app installed and logged in, LAN sharing allowed; enables the real Mullvad test T28), `FOXHOLE_ASSUME_YES=1` and `FOXHOLE_DNS_MODE=doh|vpn|plain` (unattended runs).

Each run saves its log to [`logs/`](logs/). Latest result: [`reports/vm-test-report-2026-11-18.md`](reports/vm-test-report-2026-11-18.md) (v0.17.6, image foxhole-mullvad, bridged: 216 passed / 0 failed / 0 skipped, plus 12 / 0 / 0 after a reboot). Previous: [`reports/vm-test-report-2026-11-12.md`](reports/vm-test-report-2026-11-12.md) (real Mullvad, v0.17.5: 192 / 1 / 0, plus 12 / 0 / 0 after a reboot; the failure was the open N1). Earlier reports: [`reports/vm-test-report-2026-11-10.md`](reports/vm-test-report-2026-11-10.md) (v0.17.4, 167 / 0 / 0 on the Homebrew image), [`reports/vm-test-report-2026-11-04.md`](reports/vm-test-report-2026-11-04.md), [`reports/vm-test-report-2026-11-03.md`](reports/vm-test-report-2026-11-03.md); the latter's logs sit in [`logs/`](logs/) with the `2026-11-03` prefix.

T28 (real Mullvad) connects Mullvad, turns its kill switch on (lockdown mode, tunnel down) and checks the lock in all three DNS modes next to it (audit F9), the F10 reload prompt (interactive, and unattended with `FOXHOLE_ASSUME_YES=1`, where the reload must be skipped because of Mullvad's anchor), and what happens when Mullvad disconnects (it runs `pfctl -d`; the lock must be active again within 90 s, thanks to the daemon's 60 s re-run). It ends with Mullvad disconnected and lockdown off. Without a logged-in Mullvad it is skipped.

T29 needs no internet: it turns PF off with `pfctl -d` (what Mullvad does on disconnect) and checks that the daemon brings the lock back within 90 s with exactly one reference, that idle 60 s re-runs add nothing to `/var/log/foxhole-pf.log`, and that after a disable nothing brings the lock back (it waits 65 s twice). T30 needs no internet either: a stand-in anchor `fakevpn` is added to the stock main ruleset and a legacy pf.conf marker is appended; an unattended enable (`FOXHOLE_ASSUME_YES=1`) must skip the main-ruleset reload, keep `fakevpn`, and still restore pf.conf. T2/T12/T17/T26 check that the anchor has no pass rules (audit F9); T12 also checks that DNS routed through a `utun` interface does not touch the block rules.

Not covered yet: a real DoH profile (the VM uses a plain-DNS Quad9 stand-in).

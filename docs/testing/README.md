# Testing

The scripts change live system state (PF, `/etc/hosts`, proxies, LaunchDaemons), so system-changing tests run **only inside a Tart VM**, never on your Mac.

| What | How | Touches the system? |
|---|---|---|
| Syntax and lint | `bash -n <script>` and `shellcheck -S warning mac-hardening-*.sh vpn_daily.sh tests/ci/offline.sh tests/vm/*.sh` | no |
| Offline checks | `bash tests/ci/offline.sh` (renders the PF anchor in all three DNS modes with `sudo` stubbed; also runs in CI, see `.github/workflows/lint.yml`) | no |
| Full VM suite | `FOXHOLE_VM_NET=bridged bash tests/vm/run.sh --reset` (needs the SSD with the Tart images, `tart`, `sshpass`) | VM only |
| Ad-hoc work in the VM | `bash tests/vm/vm.sh up\|push\|ssh '<cmd>'\|down\|reset` | VM only |

Environment variables: `FOXHOLE_VM_NET=bridged` (real internet in the VM), `FOXHOLE_VM_BASE=foxhole-brew` (start from the image with Homebrew; enables the real Privoxy test T18 and the real WireGuard test T19) or `FOXHOLE_VM_BASE=foxhole-mullvad` (the Mullvad app installed and logged in, LAN sharing allowed; enables the real Mullvad test T28), `FOXHOLE_ASSUME_YES=1` and `FOXHOLE_DNS_MODE=doh|vpn|plain` (unattended runs).

Each run saves its log to [`logs/`](logs/). Latest result: [`reports/vm-test-report-2026-11-12.md`](reports/vm-test-report-2026-11-12.md) (real Mullvad, image foxhole-mullvad, v0.17.5 with the F9 fix: 192 passed / 1 failed / 0 skipped, plus 12 / 0 / 0 after a reboot; the failure is the open N1). Previous: [`reports/vm-test-report-2026-11-10.md`](reports/vm-test-report-2026-11-10.md) (v0.17.4, 167 / 0 / 0 on the Homebrew image). `run.sh` reboots the VM after the main run and runs `vmtest.sh --after-reboot` (T26: the lock must come back by itself). Earlier reports: [`reports/vm-test-report-2026-11-04.md`](reports/vm-test-report-2026-11-04.md), [`reports/vm-test-report-2026-11-03.md`](reports/vm-test-report-2026-11-03.md); the latter's logs sit in [`logs/`](logs/) with the `2026-11-03` prefix.

T28 (real Mullvad) connects Mullvad, turns its kill switch on (lockdown mode, tunnel down) and checks the lock in all three DNS modes next to it (audit F9), the F10 reload prompt, and what happens when Mullvad disconnects. It ends with Mullvad disconnected and lockdown off. Without a logged-in Mullvad it is skipped.

Not covered yet: a real DoH profile (the VM uses a plain-DNS Quad9 stand-in).

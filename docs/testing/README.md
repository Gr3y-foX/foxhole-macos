# Testing

The scripts change live system state (PF, `/etc/hosts`, proxies, LaunchDaemons), so system-changing tests run **only inside a Tart VM**, never on your Mac.

| What | How | Touches the system? |
|---|---|---|
| Syntax and lint | `bash -n <script>` and `shellcheck -S warning mac-hardening-*.sh vpn_daily.sh tests/ci/offline.sh tests/vm/*.sh` | no |
| Offline checks | `bash tests/ci/offline.sh` (renders the PF anchor in all three DNS modes with `sudo` stubbed; also runs in CI, see `.github/workflows/lint.yml`) | no |
| Full VM suite | `FOXHOLE_VM_NET=bridged bash tests/vm/run.sh --reset` (needs the SSD with the Tart images, `tart`, `sshpass`) | VM only |
| Ad-hoc work in the VM | `bash tests/vm/vm.sh up\|push\|ssh '<cmd>'\|down\|reset` | VM only |

Environment variables: `FOXHOLE_VM_NET=bridged` (real internet in the VM), `FOXHOLE_VM_BASE=foxhole-brew` (start from the image with Homebrew; enables the real Privoxy test T18 and the real WireGuard test T19), `FOXHOLE_ASSUME_YES=1` and `FOXHOLE_DNS_MODE=doh|vpn|plain` (unattended runs).

Each run saves its log to [`logs/`](logs/). Latest result: [`reports/vm-test-report-2026-11-04.md`](reports/vm-test-report-2026-11-04.md) (125 passed / 0 failed / 0 skipped on the Homebrew image). Earlier report: [`reports/vm-test-report-2026-11-03.md`](reports/vm-test-report-2026-11-03.md); its logs sit in [`logs/`](logs/) with the `2026-11-03` prefix.

Not covered yet: real Mullvad side by side with the lock, a real DoH profile (the VM uses a plain-DNS Quad9 stand-in).

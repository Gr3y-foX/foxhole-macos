# VM test report — 2026-11-04 (v0.17.3 + DNS modes)

Final fresh-VM runs (`FOXHOLE_VM_NET=bridged`, `tests/vm/run.sh --reset`): **125 passed / 0 failed / 0 skipped** on the Homebrew image (`FOXHOLE_VM_BASE=foxhole-brew`, `vm-test-2026-11-04_234847.log`); **112 / 0 / 1 skipped** on the clean image (`vm-test-2026-11-04_233206.log`, T18 needs Homebrew).
Offline: `tests/ci/offline.sh` 16/16. Lint: `bash -n` and `shellcheck -S warning` clean.

| Area | Result |
|---|---|
| T1–T9 PF lock: enable, behaviour, idempotence, health check, disable, migration, guard, reset | pass (doh mode is the default now: plain DNS to 9.9.9.9 is blocked, tcp 443 passes) |
| T10 `vpn_daily.sh` driven by expect | pass (answers the new mode prompt) |
| T11 full stack (plain-DNS stand-in via `FOXHOLE_DNS_MODE=plain`) + hosts blocklist | pass, health check 10/10 |
| T12 tunnel stand-in, T13 Privoxy toggle (stand-in listener), T14 `ask()`, T15 installer fixes, T16 backups + `restore.sh` | pass |
| T17 (new) DNS modes and boot-time interface re-render (stale `en99` list replaced by the real `en0`; rules file untouched; rules go to `pfctl -f -` on stdin, no temp file) | pass |
| T18 (new) real Privoxy from Homebrew: install, `brew services` start, loopback only, HTTP through the proxy, VPN bypass, auto-switch ON/OFF, disable | pass (8/8) |
| T19 (new) real WireGuard (`wireguard-go`, two peers in the VM over 127.0.0.1) with the lock on: a DNS query routed into the tunnel arrives decrypted on the peer, handshake completes; the same query without the tunnel route leaves a physical interface and hits the block rule | pass (5/5) |

Test-side fixes during the day (no product bug): PF prints the rule as `inet proto tcp ... port = 443`; `vpn_daily` option [1] shows the mode prompt.
An earlier temp-file approach in the boot helper left a file in `/var/run` in 2 of 3 runs; replaced by stdin, no temp file (see the changelog).

Not covered (needs the user or more setup): real Mullvad side by side, a DoH profile image, GUI-only installer casks.

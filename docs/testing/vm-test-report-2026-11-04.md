# VM test report — 2026-11-04 (v0.17.3 + DNS modes)

Final fresh-VM run: **112 passed / 0 failed / 0 skipped** (`vm-test-2026-11-04_231847.log`, `FOXHOLE_VM_NET=bridged`, `tests/vm/run.sh --reset`).
Offline: `tests/ci/offline.sh` 16/16. Lint: `bash -n` and `shellcheck -S warning` clean.

| Area | Result |
|---|---|
| T1–T9 PF lock: enable, behaviour, idempotence, health check, disable, migration, guard, reset | pass (doh mode is the default now: plain DNS to 9.9.9.9 is blocked, tcp 443 passes) |
| T10 `vpn_daily.sh` driven by expect | pass (answers the new mode prompt) |
| T11 full stack (plain-DNS stand-in via `FOXHOLE_DNS_MODE=plain`) + hosts blocklist | pass, health check 10/10 |
| T12 tunnel stand-in, T13 Privoxy toggle (stand-in listener), T14 `ask()`, T15 installer fixes, T16 backups + `restore.sh` | pass |
| T17 (new) DNS modes and boot-time interface re-render (stale `en99` list replaced by the real `en0`; rules file untouched; no temp files) | pass |

Test-side fixes during the day (no product bug): PF prints the rule as `inet proto tcp ... port = 443`; `vpn_daily` option [1] shows the mode prompt.
One earlier run had a one-off T17 failure (a leftover `/var/run/foxhole-pf.*` temp file); it did not repeat. If it returns, suspect the boot LaunchDaemon `start` running right after enable.

Not covered (needs the user or more setup): real Mullvad side by side, real Privoxy and WireGuard in the VM, a DoH profile image, GUI-only installer casks.

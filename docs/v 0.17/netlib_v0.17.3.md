# netlib v0.17.3 — PF DNS lock without touching /etc/pf.conf

Branch `debug`, 2026-11-03. Covers plan items 1.2–1.4.

## Why

v0.17.2 appended an `anchor`/`load anchor` block to `/etc/pf.conf` and ran
`pfctl -f /etc/pf.conf`. That replaces the **main ruleset**, which other PF users
(Mullvad and other VPN kill switches) also write to. It also turned PF on with
`pfctl -e` and never turned it off again.

## What changed

| Area | v0.17.2 | v0.17.3 |
|---|---|---|
| Where rules live | own anchor `com.hardening.dnsleak`, hooked into `/etc/pf.conf` | `com.apple/foxhole.dnsleak`, a child of the `com.apple/*` anchor the stock `/etc/pf.conf` already evaluates |
| `/etc/pf.conf` | edited (marker block) | never edited |
| Main ruleset | reloaded on enable and disable | never reloaded (except once when migrating an old install) |
| Turning PF on | `pfctl -e`, left on after disable | `pfctl -E` reference token in `/var/db/foxhole/pf.token`; disable releases it with `pfctl -X`, so PF is off again unless another program holds a reference |
| Boot | LaunchDaemon ran `pfctl -e -f /etc/pf.conf; pfctl -a … -f …` | LaunchDaemon runs `foxhole-pf-dnslock start` (same helper as enable/disable) |
| launchd | `launchctl load/unload` | `launchctl bootstrap/bootout system` (PF and Privoxy daemons) |
| Safety check | none | enable refuses if the main ruleset does not evaluate `com.apple/*` (the rules would never apply) |
| Old installs | — | `_pf_legacy_cleanup` removes the old marker block (backup kept), reloads `pf.conf` once and flushes the old anchor |

## Verified in the VM (macOS 26.6.2, `foxhole-test`)

- Stock state: PF off, `com.apple.pfctl` loads `/etc/pf.conf` at boot, main ruleset has `anchor "com.apple/*"`.
- The child anchor is evaluated: DNS to 8.8.8.8 increments the udp/53 block-rule packet counter.
- The rules survive `pfctl -f /etc/pf.conf`. Tokens outlive the process that took them and are ref-counted with other holders.
- `tests/vm/run.sh --reset`: 49 passed, 0 failed, 4 skipped (internet checks; the VM has no egress). Logs `vm-test-2026-11-03_175310.log` and `_175751.log` (final tree).
- Reboot: after `shutdown -r` the LaunchDaemon re-loaded the rules and took a new token, and `helper status` reported active.

## Not covered

- Coexistence with a real Mullvad install (simulated with a second `pfctl -E` holder).
- Traffic checks through a real tunnel (the VM has no egress).
- Older installs enabled PF with `pfctl -e`, which has no token. Migration leaves PF on and prints how to turn it off. `pfctl -d` would also disable PF for every other user, so it is not run automatically.

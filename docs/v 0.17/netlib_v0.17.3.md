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

## Found later the same night — `utun+` is not a PF wildcard

A temporary `block out quick on utun+ …` rule in the VM matched nothing, while the same rule on `utun3`
or on a list `{ utun0 … utun5 }` blocked a DNS query routed through `utun3`. So the anchor's
`pass … on utun+` rule (present since v0.17.1) never matched. It was harmless because the block rules only
cover physical `en*` interfaces, but the "tunnels always pass" guarantee and health check [2] rested on a dead rule.
The anchor now passes an explicit `utun0`–`utun15` list. T12 builds a tunnel in the VM (IPv4 on `utun3`,
test address routed through it) and checks that DNS through it hits the `utun3` pass rule and that
`vpn_active` reports a VPN.

## Found by T13 — `proxy-toggle.sh` was never written on a clean Apple Silicon Mac

`/usr/local/bin` does not exist there (only Intel Homebrew creates it). `sudo tee /usr/local/bin/proxy-toggle.sh`
failed silently, the daemon was bootstrapped for a script that was not there, and the function still printed
"LaunchDaemon loaded". Now the directory is created and a failed write stops the function.
T13 runs the real generated toggle against the VM's `networksetup` with a stand-in listener on `127.0.0.1:8118`:
ON without VPN, OFF with a `utun` IPv4 tunnel, back ON, OFF while nothing listens, idempotent repeats, clean disable.
Suite: 81 passed, 0 failed, 0 skipped.

## Installer run in the VM (`mac-hardening-install.sh`, Homebrew installed, `FOXHOLE_ASSUME_YES=1`)

The base installer had never been run end to end. Findings and fixes:

| Step | Problem | Fix |
|---|---|---|
| Firewall | Stealth mode + "allow signed" off make the application firewall drop **incoming SSH**, including open sessions (the VM became unreachable; no allow rule for `sshd` helped) | Warn and ask to skip when port 22 is listening |
| OverSight | `objective-see.org/downloads/OverSight.zip` is a 404; the page auto-detect returns old zips; the app is named `OverSight Installer.app` (space) but the script looked for `OverSight_Installer.app`; predictable `/tmp` paths | Pinned GitHub release `v2.4.0` (its SHA-1 matches the one already in the script), `find -name "OverSight*Installer.app"`, `mktemp -d` |
| brew-vulns | `homebrew/brew-vulns` is archived (merged into Homebrew); `brew install homebrew/brew-vulns/brew-vulns` fails | Check the built-in `brew vulns`, `brew update` if missing |
| Mergen | `releases/latest/download/Mergen.dmg` is a 404 (asset is `Mergen-2.3.dmg`) | Resolve the asset via the API, verify against `SHA256SUMS.txt`, parse the mount point, `mktemp -d` |
| Gatekeeper | `if GK=$(spctl --status)` – `spctl` exits 1 when disabled, so the disabled case printed "Unable to determine" and never offered to enable | Do not test the exit code |
| BlockBlock cask | Its installer needs a GUI session and waited forever in the headless VM (not a script bug) | – |
| Other | `OS`/`Mergen` prompts and `brew` subprocesses read from stdin; piped answers are eaten – use `FOXHOLE_ASSUME_YES` | – |

T15 covers the OverSight pin and archive layout, the Mergen install with checksum, and the Gatekeeper case
(stubbed `spctl`, because macOS 26 does not let a script switch Gatekeeper off again).
Suite: 93 passed, 0 failed, 0 skipped.

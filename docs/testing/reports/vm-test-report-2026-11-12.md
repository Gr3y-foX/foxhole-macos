# VM test report — 2026-11-12: real Mullvad (T28)

Image: `foxhole-mullvad` (clone of `foxhole-test`, Mullvad app 2026.5 logged in, LAN sharing allow, auto-connect and lockdown off, no Homebrew). Network: bridged to Wi-Fi `en0` (iPhone hotspot). Command:

```bash
FOXHOLE_VM_BASE=foxhole-mullvad FOXHOLE_VM_NET=bridged bash tests/vm/run.sh --reset
```

| Run | Log | Result |
|---|---|---|
| Baseline, T28 gate broken (skipped) | `../logs/vm-test-2026-11-12_114712.log` | 167 / 0 / 1, after reboot 12 / 0 / 0 |
| With T28 (v0.17.4) | `../logs/vm-test-2026-11-12_115624.log` | 186 / 5 / 0, after reboot 12 / 0 / 0 |
| With the F9 fix (v0.17.5) | `../logs/vm-test-2026-11-12_120927.log` | **192 / 1 / 0**, after reboot 12 / 0 / 0. Only N1 fails. |

## How Mullvad uses PF (measured in the VM)

- Connected or blocking, Mullvad loads its own main ruleset: `anchor "com.apple/*"` **then** `anchor "mullvad"`. Our anchor `com.apple/foxhole.dnsleak` is evaluated first, so any `quick` pass in it ends evaluation before Mullvad's kill switch.
- Mullvad enables PF with `pfctl -e` (no reference) and, when it disconnects with lockdown off, removes its anchor and runs `pfctl -d`.
- Lockdown on + disconnected: its anchor passes only LAN, DHCP, its relay API (`45.83.223.196:443`, root only) and blocks everything else (`block return out quick all`, `block drop quick all`).
- A main-ruleset reload (`pfctl -f /etc/pf.conf`) under lockdown drops `anchor "mullvad"`; Mullvad still reports "blocked" and had not restored its rules after 30 s, while 1.1.1.1 answered. This is why F10's prompt matters.

## T28 failures (product, not test)

| Check | Finding |
|---|---|
| kill switch + lock doh: HTTPS to Quad9 stays blocked | **F9 confirmed.** `pass out quick proto tcp to 9.9.9.9 port 443` (no interface) passes on `en0` before Mullvad's block. |
| kill switch + lock plain: HTTPS / DNS :53 to Quad9 stays blocked | **F9 confirmed**, worse: plain DNS to Quad9 leaves outside the tunnel. |
| kill switch + lock vpn | passes: no Quad9 exception, nothing leaks. |
| lock still active after Mullvad disconnects | **New (N1).** Mullvad's `pfctl -d` turns PF off and clears all references; our lock is inert (helper `status` fails, DNS to 8.8.8.8 works) until the next boot or enable. Not in the audit. |

Passed: lock next to a connected Mullvad (DNS through the tunnel, HTTPS by IP), Mullvad's anchor kept on enable and disable, disable leaves PF on for Mullvad, F10 decline keeps the kill switch, cleanup.

## Other failure

- T17 `plain mode: Quad9 on 53 allowed` (one `dig`, one try). Passed in the baseline run on the same image minutes earlier; T17 runs before T28, so the new section cannot cause it. Likely a hotspot DNS timeout; not proven. If it repeats, give the check a second try and log `dig` output.

## Not tested / notes

- `FOXHOLE_ASSUME_YES=1` answers the F10 reload prompt with yes, which drops Mullvad's kill switch in unattended runs. Not a check yet; a product decision.
- ICMPv6 and "other utun" bypass parts of F9 are not measured (no IPv6 on the hotspot).
- T28 leaves Mullvad disconnected with lockdown off. The test never sees or prints the account number.

## After the F9 fix (v0.17.5)

`../../changelog/v0.17.5.md`: no Quad9 pass rules in any mode; `plain` leaves Quad9 out of the 53/853 blocks with `table <foxhole_quad9>` instead. Run `vm-test-2026-11-12_120927.log`: all six F9 checks pass in all three modes, T3/T17/T23 pass with the new rule text, the table is flushed on disable and gone after a mode switch. Remaining failure: N1 (Mullvad's disconnect turns PF off). T17 "Quad9 on 53 allowed" passed this time.

An earlier attempt of this run (no log) failed at the first SSH login: `--reset` gives the clone a new MAC and a new hotspot address, and the VM refused `admin` once right after boot. The re-run went through; if it repeats, `run.sh` should retry the first login.

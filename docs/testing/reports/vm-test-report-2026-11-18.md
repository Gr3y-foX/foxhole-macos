# VM test report — 2026-11-18: netlib v0.17.6 (D5, D6, D7)

Version: `mac-hardening-netlib.sh` v0.17.6 (header line 7). Changes: `../../changelog/v0.17.6.md`.

- D5: the LaunchDaemon re-runs `boot` every 60 s (fixes N1 from the 2026-11-12 report).
- D6: the anchor has no pass rules (rest of F9).
- D7: an unattended migration does not reload the main ruleset over a foreign anchor (F10).

Image: `foxhole-mullvad` (clone of `foxhole-test`, Mullvad app logged in, no Homebrew). The log headers do not name the image; the T28 section title in `../logs/vm-test-2026-11-18_150037.log` does (`base image foxhole-mullvad`).

| Run | Log | Network | Result |
|---|---|---|---|
| 1 | `../logs/vm-test-2026-11-18_144716.log` | NAT, host on a phone hotspot; no internet in the VM (log T1: `direct internet egress: NO`) | **149 / 1 / 12**, after reboot 11 / 0 / 1 |
| 2 | no log | bridged | Never started: the VM refused the first `admin` SSH login right after boot (second time after 2026-11-12). Fixed: `run.sh` and `vm.sh` wait for a working login (30 tries, 3 s apart); `run.sh` has `ConnectTimeout=10`. |
| 3 | `../logs/vm-test-2026-11-18_150037.log` | bridged to Wi-Fi `en0` (log T1: `direct internet egress: yes`) | **216 / 0 / 0**, after reboot **12 / 0 / 0** |
| T12 only | no log | — | 9 / 0 (reported by the main session; unverified here) |

Command for run 3 (as in the 2026-11-12 report):

```bash
FOXHOLE_VM_BASE=foxhole-mullvad FOXHOLE_VM_NET=bridged bash tests/vm/run.sh --reset
```

Run 1 used the same image without `FOXHOLE_VM_NET=bridged` (per the main session; the log does not show the command).

## Run 3 (final)

```
RESULT: 216 passed, 0 failed, 0 skipped
RESULT (after reboot): 12 passed, 0 failed, 0 skipped
```

Source: `../logs/vm-test-2026-11-18_150037.log`. The log has 228 `PASS:` lines (216 + 12), no `FAIL:` and no `SKIP:` lines.

Sections of note (PASS lines per section, all passed):

| Section | PASS | What it covers |
|---|---|---|
| T12 | 6 | tunnel: DNS through `utun3` reaches the tunnel (capture), the same query without the route never reaches `utun3` |
| T17 | 13 | DNS modes; `plain mode: Quad9 on 53 allowed` passed (line 240) |
| T28 | 27 | real Mullvad: F9 in all three modes, F10 interactive and unattended, disconnect |
| T29 | 10 | lock returns after another program's `pfctl -d` (N1, D5) |
| T30 | 8 | unattended legacy migration keeps a foreign anchor (F10, D7) |

T28 info lines:
- `main ruleset with Mullvad: anchor "com.apple/*" all anchor "mullvad" all`
- `after Mullvad disconnect: Status: Disabled, references: 0`
- `lock active 60 s after Mullvad disconnected (-1 = not within 90 s), references: 1`

T29 info lines:
- `right after pfctl -d: PF off, references: 0`
- `daemon: runs = 1; run interval = 60 seconds;`
- `lock back after about 60 s (-1 = not within 90 s)`
- Idle re-runs over 65 s did not grow `/var/log/foxhole-pf.log`; nothing returned after disable.

The 60 s values are measured by polling every 5 s (`tests/vm/vmtest.sh:552-556` and `:612-619`), so each is accurate to about 5 s. Only one run is in the log.

T30 info lines: `Unattended run (FOXHOLE_ASSUME_YES=1) and the main PF ruleset holds other anchors: fakevpn`, then `Reload skipped`.

## Run 1 (NAT, no internet)

```
RESULT: 149 passed, 1 failed, 12 skipped
RESULT (after reboot): 11 passed, 0 failed, 1 skipped
```

The one FAIL (line 135):

```
FAIL: DNS through the tunnel does not hit the udp/53 block rules (blocks are scoped to en*, no pass rule needed)
```

- The info lines show 33 udp/53 block-rule packets after the dig through `utun3` (line 133) and 34 for the same dig without the route (line 137).
- The maintainer's diagnosis: the old check counted every udp/53 block system-wide, and the VM's own resolver traffic hit the blocks. The counts fit that explanation but do not prove it.
- The check was rewritten to capture on `utun3` with tcpdump. A packet that PF blocks never reaches the interface's BPF tap. Run 3 passed the new check.

Skipped checks (12, all "no direct internet in VM" or Homebrew-only): lines 50, 51, 53 (T3), 95 (T6), 130 (T11), 162 (T15), 180 and 200 (T17), 210 and 212 (T18, T19), 244 (T22), 275 (T28, so the Mullvad section did not run). After reboot: line 314 (HTTPS by IP).

T17 `plain mode: Quad9 on 53 allowed` was skipped in run 1 (line 200) and passed in run 3 (line 240).

## Offline checks

`tests/ci/offline.sh`: 62 passed / 0 failed (run by the main session on 2026-11-18). No log file; unverified here.

## Notes

- T5 (`verify_dns_stack`) prints `Results: 4/10 passed, 6 failed` in both logs (lines 81). The test passes because the health check reaches its summary. The cause is unproven; the checks that fail are Quad9 profile, DNS and DoH, which are expected with no profile installed and plain DNS blocked in `doh` mode.
- Runs 1 and 3 are the first VM runs of v0.17.6 (the changelog said the suite had not been run for this release). Run 1 still had the old T12 check.

## Open (after this run)

- `CLAUDE.md:51` and `AGENTS.md:51` still state the `utun0`–`utun15` pass rules as a design rule. The rule is obsolete with v0.17.6 (changelog). `CLAUDE.md:16` and `AGENTS.md:16` still say netlib v0.17.4. The maintainer edits these files.
- `private-all` is 4 commits behind `debug` (`git rev-list --count private-all..debug` = 4; `debug..private-all` = 0).
- The worktree `claude/multi-agent-doc-parsing-f0f8cc` has uncommitted changes (`CLAUDE.md`, `docs/README.md`, `docs/dev/*`, untracked `.claude/`). The 2026-11-11 doc sync was not checked further.

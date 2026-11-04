# netlib v0.17.2 — fixes on branch `debug`

Findings from the code review of v0.17.1 plus uncommitted edits.

| Area | Change |
|---|---|
| `disable_pf_dns_lock` | Removes the marker and the `anchor` / `load anchor` lines; installs `/etc/pf.conf` as `root:wheel 0644` (was a user-owned `0600` temp file); flushes the anchor rules. |
| PF anchor | Block rules scoped to physical `en*` interfaces again (detected via `networksetup`); quoted heredoc; Quad9 IPs come from the `QUAD9_*` constants; English comments. |
| `enable_pf_dns_lock` | `pfctl -f` and `pfctl -e` run separately; "already enabled" is not an error; verification reads the anchor with `pfctl -a com.hardening.dnsleak -sr`. |
| `verify_dns_stack` | `(( PASS++ ))` replaced (aborted under `set -e`); `eval` removed from `_chk`; duplicate check removed; `timeout` (absent on macOS) replaced by `dig +time=3 +tries=1`; hosts counter no longer yields `0\n0`. |
| `vpn_daily.sh` | Rewritten around DoH + PF lock; no dnscrypt calls; netlib path resolved from the script location. |
| Docs | README, CLAUDE.md and AGENTS.md updated to match. |

Not changed: `update_hosts` / `disable_hosts_blocklist` use `sudo tee` + `sudo mv`, so the result is already root-owned.

## Second pass — 2026-11-03 (offline review, no VM)

| Area | Change |
|---|---|
| `proxy-toggle.sh` `vpn_active` | `grep -i "Connected"` also matched `(Disconnected)`, so any configured but idle VPN counted as active and the proxy never came on. Now matches `(Connected)` exactly, and also detects tunnels `scutil --nc` does not list (Mullvad, ClearVPN, OpenVPN) as a `utun` with an IPv4 address; Tailscale's `100.64.0.0/10` is ignored. |
| `proxy-toggle.sh` `set_proxy` | Writes only when the setting differs. Each write touched `/Library/Preferences/SystemConfiguration`, the daemon's own WatchPath. |
| `proxy-toggle.sh` | Never turns the proxy on while nothing listens on `127.0.0.1:8118` (that would cut all web traffic). |
| `install_privoxy` | Starts Privoxy with `brew services start privoxy`; nothing started it before. |
| `enable_privoxy_vpn_autoswitch` | Exposure check grepped `0.0.0.0.8118`; macOS netstat prints `*.8118`, so it never fired. Now reports not listening / loopback only / exposed. |
| `disable_privoxy_autoswitch` | Also turns system web proxies off (was only done by `reset_net_hardening`). |
| `configure_privoxy_vpn_bypass` | `forward` takes URL patterns, not CIDR; rules rewritten as `10.*.*.*/`, `172.1[6-9].*.*/` … Existing installs keep the old lines (marker check). |
| `update_hosts` | Downloads and validates (≥ 1000 `0.0.0.0` entries) **before** editing `/etc/hosts`; a failed or truncated download no longer leaves the system without a blocklist. |
| Installer | `dnscrypt-proxy` dropped from `SECURITY_FORMULAS`; `ask` uses `printf -v` instead of `eval`; script names in messages fixed. |
| Lint | shellcheck `-S warning` clean for install, netlib, vpn_daily. |

Tested offline with stubbed `scutil` / `ifconfig` / `nc` / `networksetup` (toggle) and stubbed `sudo` / `curl` on a scratch hosts file (`update_hosts`). Not yet run in the VM.

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

# PR #1 (`debug` → `main`): suggested title and body

The session's GitHub connection could read PR #1 but not edit it (403), so paste these by hand.

**Title**

```
v0.17.3: PF DNS lock in com.apple/* child anchor, DNS modes, installer fixes, VM test suite
```

**Body**

```markdown
## What changed (netlib v0.17.3)

- **PF DNS lock** lives in the child anchor `com.apple/foxhole.dnsleak`. `/etc/pf.conf` is no longer edited and the main ruleset is no longer reloaded, so VPN kill switches keep their rules. PF is enabled by reference (`pfctl -E` token, released with `pfctl -X`). One helper (`/usr/local/libexec/foxhole-pf-dnslock`) serves enable, disable and boot; launchd uses `bootstrap`/`bootout`. Installs from v0.17.2 or older are migrated automatically.
- **DNS modes** (`FOXHOLE_DNS_MODE`, or a prompt): `doh` (default, Quad9 on tcp 443 only), `vpn` (no Quad9 exception, DNS only through the tunnel), `plain` (Quad9 on any port, the old behaviour).
- **Interface re-render:** the boot helper re-reads the physical interfaces, so a NIC added later is covered (falls back to the rules as written).
- **Fixes found by running the scripts in a VM:** no `utun+` wildcard in PF (now `utun0-15`), `proxy-toggle.sh` never written on clean Apple Silicon, Privoxy VPN detection matched "(Disconnected)", hosts update removed the old list before downloading, installer fixes (OverSight/Mergen downloads, brew-vulns, Gatekeeper `spctl`, SSH-aware firewall step), `create_net_backup` now writes a working `restore.sh`.
- **Tests and CI:** `tests/ci/offline.sh` (17 checks, nothing touches the system), `tests/vm/run.sh` (Tart VM suite), GitHub `lint` workflow (shellcheck + bash 3.2 syntax + offline checks).
- `debug_netlib/` moved to `docs/archive/`; installer option [2] (Tor profile) marked "planned".

Details: `docs/changelog/v0.17.3.md`.

## Testing

- VM suite (`FOXHOLE_VM_NET=bridged bash tests/vm/run.sh --reset`): **125 passed / 0 failed / 0 skipped** on the Homebrew image (`FOXHOLE_VM_BASE=foxhole-brew`, includes real Privoxy and a real WireGuard tunnel); 112 / 0 / 1 skipped on the clean image. Logs and report in `docs/testing/`.
- Offline: 17/17. `shellcheck -S warning` and `bash -n` clean. `lint` is green on this branch.

## Not covered / open

- Real Mullvad running side by side with the lock (only simulated with a second PF reference holder).
- Real DoH profile (the VM uses a plain-DNS Quad9 stand-in; needs a GUI click).
- `profile-paranoid-tor.sh` is still a stub.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

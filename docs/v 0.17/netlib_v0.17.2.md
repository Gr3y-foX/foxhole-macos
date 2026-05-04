# Foxhole macOS — Handoff: v0.17 Fix List
**File:** `mac-hardening-netlib.sh`  
**Branch:** `debug`  
**Reviewed:** 2026-05-04  
**Status:** Pre-release — fixes required before merge to main

***

## How to Use This Document

Each entry follows the format:
- **Where** — exact function / line context
- **What** — what is broken and why
- **Fix** — concrete code change
- **Devnote tag** — short label for CHANGELOG / commit message

Priority legend: 🔴 Critical · 🟠 High · 🟡 Medium · 🟢 Low

***

## 🔴 CRITICAL

***

### [CR-1] `eval` with user-controlled argument — shell injection

**Where:** `ask()` function

```bash
# CURRENT — VULNERABLE
eval "$VAR=N"
```

**What:**  
`eval` expands `$VAR` before assignment. If the caller passes a crafted
string (e.g. `$(malicious_cmd)` or `; rm -rf /`), it executes in the
current shell context — which may be a sudo session.

**Fix:**
```bash
# SAFE — printf -v does not evaluate content
printf -v "$VAR" '%s' 'N'
```

**Devnote tag:** `[SEC] replace eval with printf -v in ask() — shell injection`

***

### [CR-2] TOCTOU race condition on `/etc/pf.anchors/` write

**Where:** `prepare_pf_dns_lock_anchor()`

```bash
# CURRENT — race window between mkdir and tee
sudo mkdir -p /etc/pf.anchors
sudo tee "$PF_ANCHOR" > /dev/null <<'EOF'
```

**What:**  
Between `mkdir` and `tee`, an attacker with local access can create a
symlink at `$PF_ANCHOR` pointing to `/etc/pf.conf`. `tee` will then
overwrite the main PF config instead of the anchor file.

**Fix:**
```bash
# Atomic write via tmpfile + install
local TMP
TMP=$(mktemp /tmp/pf.anchor.XXXXXX)
cat > "$TMP" <<'EOF'
...anchor content...
EOF
sudo install -m 644 -o root -g wheel "$TMP" "$PF_ANCHOR"
rm -f "$TMP"
```

**Devnote tag:** `[SEC] atomic anchor write via install — TOCTOU fix`

***

### [CR-3] Unquoted variables in heredoc — XML/config injection

**Where:** `enable_privoxy_vpn_autoswitch()`, `_install_pf_launchdaemon()`

```bash
# CURRENT — $TOGGLE_SCRIPT expands inside heredoc
sudo tee "$DAEMON_PLIST" > /dev/null << EOF
    <string>${TOGGLE_SCRIPT}</string>
EOF
```

**What:**  
If `TOGGLE_SCRIPT` or `BREW_PREFIX` contains XML special characters
(`<`, `>`, `&`), the plist becomes malformed or injects arbitrary XML
nodes. Test vector: `BREW_PREFIX='/usr/local/<evil>&cmd'`.

**Fix:**  
Use `'EOF'` (single-quoted heredoc) wherever variable expansion is not
needed. Where a variable must appear, validate it first:

```bash
[[ "$TOGGLE_SCRIPT" =~ ^[a-zA-Z0-9/_.-]+$ ]] \
    || die "Invalid path in TOGGLE_SCRIPT: ${TOGGLE_SCRIPT}"
```

**Devnote tag:** `[SEC] quote heredoc delimiters, validate path vars — XML injection`

***

### [CR-4] `proxy-toggle.sh` overwritten without content verification

**Where:** `enable_privoxy_vpn_autoswitch()`

```bash
# CURRENT — silent overwrite, no integrity check
sudo tee "$TOGGLE_SCRIPT" > /dev/null << 'SCRIPT'
...
SCRIPT
sudo chmod 755 "$TOGGLE_SCRIPT"
```

**What:**  
On re-run, an existing `proxy-toggle.sh` (potentially tampered) is
silently replaced with no record of what was there before.

**Fix:**
```bash
if [[ -f "$TOGGLE_SCRIPT" ]]; then
    local EXISTING_HASH
    EXISTING_HASH=$(shasum -a 256 "$TOGGLE_SCRIPT" | awk '{print $1}')
    warn "Overwriting existing proxy-toggle.sh (SHA-256: ${EXISTING_HASH})"
fi
# after write:
local NEW_HASH
NEW_HASH=$(shasum -a 256 "$TOGGLE_SCRIPT" | awk '{print $1}')
log "  [✓] proxy-toggle.sh written (SHA-256: ${NEW_HASH})"
```

**Devnote tag:** `[SEC] log SHA-256 before/after proxy-toggle.sh write`

***

## 🟠 HIGH

***

### [H-1] dnscrypt-proxy as user LaunchAgent, not root LaunchDaemon

**Where:** `enable_dnscrypt()` — `brew services start dnscrypt-proxy`

**What:**  
`brew services` installs a LaunchAgent under `~/Library/LaunchAgents/`.
A DNS resolver running as user UID can be stopped, reconfigured, or
replaced by any user-space process without privilege escalation.
Security tools acting as DNS resolvers must run as root (LaunchDaemon).

> Note: if dnscrypt-proxy is removed from the project (v0.17 decision),
> this issue is resolved by removal.

**Devnote tag:** `[ARCH] dnscrypt-proxy removed — LaunchAgent issue moot`

***

### [H-2] DNS lock does not block DoH on port 443 — incomplete protection

**Where:** `prepare_pf_dns_lock_anchor()`

```bash
block out quick proto { udp tcp } to any port 53
block out quick proto { udp tcp } to any port 853
# port 443 (DoH) is not blocked
```

**What:**  
DNS-over-HTTPS operates on port 443 as plain HTTPS — any app can bypass
the DNS lock by sending DoH directly to `8.8.8.8:443`. The anchor blocks
plain DNS and DoT but leaves DoH completely open.

**Fix (recommended — document the limitation):**  
Add to the anchor header:
```pf
# KNOWN LIMITATION: DoH on port 443 is not blocked at the PF level.
# Protection relies on the macOS DoH Configuration Profile (Quad9)
# being the only active DoH endpoint. Apps bypassing via custom
# DoH servers (e.g. 8.8.8.8:443) are not covered by this anchor.
```

**Devnote tag:** `[KNOWN-LIMIT] DoH :443 not blocked — document in anchor header`

***

### [H-3] `vpn_active()` — false positives on iCloud Private Relay / Tailscale

**Where:** `vpn_active()` inside `proxy-toggle.sh`

```bash
ifconfig 2>/dev/null \
    | awk '/^utun[0-9]/{iface=...; found=1}
           found && /inet /{print iface; exit}' \
    | grep -q "utun" && return 0
```

**What:**  
Detects any `utun` interface with an inet address. iCloud Private Relay,
Tailscale, and AirDrop all create `utun` interfaces on macOS, causing
Privoxy to be disabled when no tunnel VPN is actually active.

**Fix:**
```bash
vpn_active() {
    scutil --nc list 2>/dev/null \
        | grep -i "Connected" \
        | grep -viE "tailscale|icloud|relay" \
        | grep -q "." && return 0
    return 1
}
```

**Devnote tag:** `[FIX] vpn_active() — use scutil --nc list, exclude iCloud/Tailscale`

***

### [H-4] PF LaunchDaemon discards pfctl stdout — diagnostics lost

**Where:** `_install_pf_launchdaemon()` plist

```xml
<!-- CURRENT — only stderr -->
<key>StandardErrorPath</key>
<string>/var/log/foxhole-pf.log</string>
```

**What:**  
`pfctl` writes rule confirmations and warnings to stdout. Without
`StandardOutPath`, boot-time PF failures are invisible.

**Fix:**
```xml
<key>StandardOutPath</key>
<string>/var/log/foxhole-pf.log</string>
<key>StandardErrorPath</key>
<string>/var/log/foxhole-pf.log</string>
```

**Devnote tag:** `[FIX] pf LaunchDaemon add StandardOutPath`

***

### [H-5] StevenBlack hosts SHA-256 computed but never verified

**Where:** `update_hosts()`

```bash
SHA256=$(shasum -a 256 "$TMP_HOSTS" | awk '{print $1}')
info "SHA-256: ${SHA256}"  # shown only — never checked against anything
```

**What:**  
Hash is displayed but not verified. A MITM or compromised CDN could
serve a malicious hosts file; the script would apply it without warning.

**Fix:**  
Cross-check against GitHub API commit hash:
```bash
local REMOTE_COMMIT
REMOTE_COMMIT=$(curl -fsSL \
    "https://api.github.com/repos/StevenBlack/hosts/commits?path=hosts&per_page=1" \
    2>/dev/null | grep '"sha"' | head -1 | awk -F'"' '{print $4}' | cut -c1-7)
info "Remote commit: ${REMOTE_COMMIT:-unknown}"
warn "Manual verification recommended: https://github.com/StevenBlack/hosts"
```

**Devnote tag:** `[SEC] hosts: add GitHub commit cross-check, document verification gap`

***

## 🟡 MEDIUM

***

### [M-1] No `set -euo pipefail` — partial state on failure

**Where:** Top of script (missing entirely)

**What:**  
Without `set -euo pipefail`, a failed command mid-function does not abort
execution. An unset variable silently expands to an empty string
(`sudo cp "" /etc/pf.conf`). The system can be left in a partial,
inconsistent hardening state with no error reported.

**Fix:**
```bash
#!/bin/bash
set -euo pipefail
```
Add at top. Mark intentionally non-fatal commands with explicit `|| true`.

**Devnote tag:** `[RELIABILITY] add set -euo pipefail`

***

### [M-2] `awk` regex unescaped `/` in `disable_pf_dns_lock()` — crash risk

**Where:** `disable_pf_dns_lock()`

```bash
awk "/$(echo "$PF_MARKER" | sed 's/[^^]/[&]/g; s/\^/\\^/g')/ {exit} {print}" \
    "$PF_CONF" > "$TMP_CONF"
```

**What:**  
The `sed` escaping pattern does not handle `/` (awk regex delimiter).
If `PF_MARKER` ever contains a slash, awk throws a syntax error and
`pf.conf` processing fails mid-operation — potentially corrupting the file.

**Fix:**
```bash
grep -vF "$PF_MARKER" "$PF_CONF" > "$TMP_CONF"
```

**Devnote tag:** `[FIX] disable_pf_dns_lock: replace awk regex with grep -vF`

***

### [M-3] Backup failure does not abort execution

**Where:** `create_net_backup()`

```bash
sudo cp /etc/pf.conf "${NET_BACKUP_DIR}/pf.conf" \
    && log "  [✓] /etc/pf.conf" \
    || warn "  [–] skipped"
# script continues regardless
```

**What:**  
A failed backup (disk full, permission error) prints a warning and
execution continues into destructive system modifications. A backup that
doesn't block on failure provides no actual safety guarantee.

**Fix:**  
For critical files, abort if backup fails:
```bash
sudo cp /etc/pf.conf "${NET_BACKUP_DIR}/pf.conf" \
    || die "Failed to backup /etc/pf.conf — aborting."
log "  [✓] /etc/pf.conf"
```

**Devnote tag:** `[RELIABILITY] backup: die on pf.conf/hosts backup failure`

***

### [M-4] `networksetup` errors silenced via `2>/dev/null`

**Where:** `set_proxy()` in `proxy-toggle.sh`, `reset_net_hardening()`

```bash
networksetup -setwebproxy "$SERVICE" "127.0.0.1" "8118" 2>/dev/null
```

**What:**  
If a network service is renamed or deleted, `networksetup` returns an
error that is silently discarded. The proxy appears set but is not.

**Fix:**
```bash
local ERR
ERR=$(networksetup -setwebproxy "$SERVICE" "127.0.0.1" "8118" 2>&1) \
    || warn "  [!] networksetup failed for '${SERVICE}': ${ERR}"
```

**Devnote tag:** `[RELIABILITY] networksetup: capture stderr, log on failure`

***

## 🟢 LOW

***

### [L-1] Magic strings — no named constants

**Where:** Throughout the script

**What:**  
`"127.0.0.1"`, `"8118"`, `"9.9.9.9"`, `"149.112.112.112"` appear
hardcoded in multiple functions. Any IP/port change risks partial updates.

**Fix:**  
Add after color definitions:
```bash
readonly PRIVOXY_ADDR="127.0.0.1"
readonly PRIVOXY_PORT="8118"
readonly QUAD9_PRIMARY="9.9.9.9"
readonly QUAD9_SECONDARY="149.112.112.112"
readonly QUAD9_ECS_PRIMARY="9.9.9.11"
readonly QUAD9_ECS_SECONDARY="149.112.112.11"
```

**Devnote tag:** `[STYLE] extract magic strings to named constants`

***

### [L-2] `sudo` prompt appears mid-interactive-menu

**Where:** `main()` — no upfront privilege check

**What:**  
Functions call `sudo` internally. The user receives an unexpected sudo
prompt mid-menu with no context about what is being authorized.

**Fix:**
```bash
# At the start of main(), before the menu loop:
info "This script requires sudo for system modifications."
sudo -v || die "sudo authentication failed."
while true; do sudo -n true; sleep 55; done &
SUDO_KEEPALIVE_PID=$!
trap 'kill $SUDO_KEEPALIVE_PID 2>/dev/null' EXIT
```

**Devnote tag:** `[UX] sudo -v keepalive in main() before menu`

***

### [L-3] Health check test  — error message text is inverted

**Where:** `verify_dns_stack()` — test 

```bash
if echo "$DNS_OUT" | grep -q "NOERROR"; then
    err "  [7] Plain DNS blocked (@8.8.8.8)"  # ← wrong: NOERROR means NOT blocked
```

**What:**  
`NOERROR` means the query succeeded — DNS is **not** blocked, this is a
failure. The error message incorrectly says "Plain DNS blocked."

**Fix:**
```bash
err "  [7] Plain DNS NOT blocked — leak possible (@8.8.8.8 responded)"
```

**Devnote tag:** `[FIX] health check [7]: fix inverted error message text`

***

### [L-4] `reset_net_hardening()` naming misleads — no rollback performed

**Where:** `reset_net_hardening()`, menu item `[5]`

**What:**  
The name implies rollback to pre-hardening state. In reality it only
disables components — the backup snapshot is never used.

**Fix (option A):** Rename to `disable_net_hardening()`, update menu label:
```
[5] Disable network hardening (does not restore backup)
```

**Fix (option B):** Implement actual rollback from `NET_BACKUP_DIR`.

**Devnote tag:** `[UX] rename reset → disable_net_hardening or implement real rollback`

***

## Fix Priority Order

```
Phase 1 — Security (required before any public use)
  [CR-1]  eval → printf -v
  [CR-2]  TOCTOU atomic write
  [CR-3]  heredoc quoting + path validation
  [CR-4]  proxy-toggle.sh SHA-256 logging

Phase 2 — Reliability
  [M-1]   set -euo pipefail
  [H-3]   vpn_active() → scutil --nc list
  [H-4]   LaunchDaemon StandardOutPath
  [M-2]   awk → grep -vF in disable_pf_dns_lock
  [M-3]   backup: die on critical file failure

Phase 3 — Completeness (before v0.17 tag)
  [H-1]   dnscrypt-proxy removal (decided)
  [H-2]   Document DoH :443 limitation in anchor header
  [H-5]   hosts: GitHub commit cross-check
  [M-4]   networksetup stderr capture
  [L-3]   health check [7] message fix

Phase 4 — Polish
  [L-1]   Named constants
  [L-2]   sudo keepalive
  [L-4]   reset → disable or real rollback
```

***

## Devnote Summary (for CHANGELOG)

```
[SEC]          replace eval with printf -v in ask()
[SEC]          atomic anchor write via install — TOCTOU fix
[SEC]          quote heredoc delimiters, validate path vars
[SEC]          log SHA-256 before/after proxy-toggle.sh write
[SEC]          hosts: add GitHub commit cross-check
[ARCH]         dnscrypt-proxy removed from stack
[FIX]          pf LaunchDaemon add StandardOutPath
[FIX]          vpn_active() — scutil --nc list, exclude iCloud/Tailscale
[FIX]          disable_pf_dns_lock: replace awk regex with grep -vF
[FIX]          health check [7]: fix inverted error message text
[RELIABILITY]  add set -euo pipefail
[RELIABILITY]  backup: die on pf.conf/hosts backup failure
[RELIABILITY]  networksetup: capture stderr, log on failure
[KNOWN-LIMIT]  DoH on :443 not blocked — documented in anchor header
[UX]           sudo -v keepalive in main() before menu
[UX]           rename reset → disable_net_hardening or implement rollback
[STYLE]        extract magic strings to named constants
```

***

*Generated from security review of `mac-hardening-netlib.sh` v0.16 — foxhole-macos / debug branch*
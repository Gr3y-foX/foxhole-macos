#!/bin/bash
set -euo pipefail
#
# Foxhole-macos — macOS Network Hardening Library
#
# File:    mac-hardening-netlib.sh
# Version: 0.17.1 (2026-05-04)
# Author:  Gr3y-foX
# Based on: drduh/macOS-Security-and-Privacy-Guide (MIT)
# License: GNU GPL v3 — see LICENSE for details
#
# Overview:
#   Network hardening primitives for macOS:
#     - PF DNS leak prevention (utun+ VPN compatible)
#     - /etc/hosts blocklist (StevenBlack)
#     - Privoxy with VPN-aware auto-proxy switching
#
# Usage:
#   Source from profile scripts or run directly for interactive menu.
#
# v0.17.1 Highlights:
#   • Security fixes: shell injection, TOCTOU, XML injection
#   • Reliability: strict mode, better error handling
#   • Fixed VPN packet drops (utun0-9) with explicit pass rules
#   • Removed dnscrypt-proxy (conflicts with macOS DoH profile)
#   • DNS stack: macOS DoH Profile (Quad9) → PF anchor (leak lock)
#   • PF anchor now scopes block rules to physical interfaces only

# Constants
readonly PRIVOXY_ADDR="127.0.0.1"
readonly PRIVOXY_PORT="8118"
readonly QUAD9_PRIMARY="9.9.9.9"
readonly QUAD9_SECONDARY="149.112.112.112"
readonly QUAD9_ECS_PRIMARY="9.9.9.11"
readonly QUAD9_ECS_SECONDARY="149.112.112.11"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m';   CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }
die()  { err "$1"; exit 1; }

ask() {
    local PROMPT="$1" VAR="$2"
    if [[ -t 0 ]]; then
        read -rp "    ${PROMPT} (y/N): " "$VAR"
    else
        warn "Non-interactive — skipping: $PROMPT"
       # Safe: use `printf -v` instead of `eval`
        printf -v "$VAR" '%s' 'N'
    fi
}

# ──────────────────────────────────────────
# BACKUP — snapshot before hardening
# ──────────────────────────────────────────
NET_BACKUP_DIR="${HOME}/.foxhole/backups/$(date +%Y%m%d_%H%M%S)"

create_net_backup() {
    log "Creating pre-hardening backup snapshot..."
    mkdir -p "$NET_BACKUP_DIR" \
        || { warn "Cannot create backup dir: ${NET_BACKUP_DIR}"; return 1; }

    # 1. /etc/pf.conf
    if [[ -f /etc/pf.conf ]]; then
        sudo cp /etc/pf.conf "${NET_BACKUP_DIR}/pf.conf" \
            || die "Failed to backup /etc/pf.conf — aborting."
        log "  [✓] /etc/pf.conf"
    else
        warn "  [–] /etc/pf.conf not found — skipped"
    fi

    # 2. pf anchor (already exist)
    [[ -f /etc/pf.anchors/com.hardening.dnsleak ]] \
        && sudo cp /etc/pf.anchors/com.hardening.dnsleak "${NET_BACKUP_DIR}/pf.anchor.dnsleak" \
        && log "  [✓] pf anchor"

    # 3. /etc/hosts
    if [[ -f /etc/hosts ]]; then
        sudo cp /etc/hosts "${NET_BACKUP_DIR}/hosts" \
            || die "Failed to backup /etc/hosts — aborting."
        log "  [✓] /etc/hosts"
    else
        warn "  [–] /etc/hosts not found — skipped"
    fi

    # 4. /etc/resolv.conf
    [[ -f /etc/resolv.conf ]] \
        && sudo cp /etc/resolv.conf "${NET_BACKUP_DIR}/resolv.conf" \
        && log "  [✓] /etc/resolv.conf"

    # 5. System DNS resolver snapshot
    scutil --dns > "${NET_BACKUP_DIR}/system-dns.txt" 2>/dev/null \
        && log "  [✓] scutil --dns"

    # 6. /etc/resolver/ directory (split DNS configurations)
    if [[ -d /etc/resolver ]]; then
        sudo cp -r /etc/resolver "${NET_BACKUP_DIR}/resolver" \
            && log "  [✓] /etc/resolver/"
    fi

    
    # 9. Network proxies
    local PROXY_DUMP="${NET_BACKUP_DIR}/network_proxies.txt"
    {
        echo "# Network proxy snapshot — $(date)"
        networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | grep -v '^\*' \
        | while IFS= read -r SVC; do
            echo "=== $SVC ==="
            networksetup -getwebproxy        "$SVC" 2>/dev/null
            networksetup -getsecurewebproxy  "$SVC" 2>/dev/null
            networksetup -getproxybypassdomains "$SVC" 2>/dev/null
            echo ""
          done
    } > "$PROXY_DUMP"
    log "  [✓] Network proxy settings → ${PROXY_DUMP}"

    # 10. Privoxy LaunchDaemon
    local PRIV_PLIST="/Library/LaunchDaemons/com.hardening.proxytoggle.plist"
    [[ -f "$PRIV_PLIST" ]] \
        && sudo cp "$PRIV_PLIST" "${NET_BACKUP_DIR}/proxytoggle.plist" \
        && log "  [✓] Privoxy LaunchDaemon plist"

    echo ""
    log "Backup saved to: ${NET_BACKUP_DIR}"
    info "To restore: sudo bash ${NET_BACKUP_DIR}/../rollback.sh"
    echo ""
}

# ──────────────────────────────────────────
# INSTALL FORMULA
# ──────────────────────────────────────────
install_formula() {
    local pkg="$1"
    if brew list --formula --versions "$pkg" &>/dev/null; then
        local VER
        VER=$(brew list --formula --versions "$pkg")
        warn "${pkg} already installed: ${VER}"
        ask "Reinstall ${pkg}?" CONFIRM
        [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]] \
            && brew reinstall "$pkg" \
            || { log "Skipping ${pkg}."; return 0; }
    else
        log "Installing ${pkg}..."
        brew install "$pkg" || { err "Failed to install ${pkg}!"; return 1; }
    fi
}

resolve_brew_prefix() {
    if [[ -z "${BREW_PREFIX:-}" ]]; then
        BREW_PREFIX=$(brew --prefix 2>/dev/null) || die "Homebrew not found!"
        export BREW_PREFIX
    fi
}





# ──────────────────────────────────────────
# PF — DNS LEAK PREVENTION
# ──────────────────────────────────────────
prepare_pf_dns_lock_anchor() {
    local PF_ANCHOR="/etc/pf.anchors/com.hardening.dnsleak"

    log "Writing PF anchor for DNS leak prevention: ${PF_ANCHOR}"
    sudo mkdir -p /etc/pf.anchors

    # Atomic write via tmpfile + install (CR-2 TOCTOU fix)
    local TMP
    TMP=$(mktemp /tmp/pf.anchor.XXXXXX)
    cat > "$TMP" <<'EOF'
# ============================================================
# foxhole-macos — DNS Leak Prevention Anchor
# Generated by mac-hardening-netlib.sh v0.17.1
# References: RFC 4890 (ICMPv6), OpenBSD pf docs
# DNS: macOS native DoH profile (Quad9)
# KNOWN LIMITATION: DoH on port 443 is not blocked at the PF level.
# Protection relies on the macOS DoH Configuration Profile (Quad9)
# being the only active DoH endpoint. Apps bypassing via custom
# DoH servers (e.g. 8.8.8.8:443) are not covered by this anchor.
# ============================================================

# --- [1] Loopback: без ограничений ---
pass quick on lo0 all

# --- [2] VPN tunnels: pass ALL traffic on any utun interface ---
# Covers: ClearVPN, ProtonVPN, Mullvad, WireGuard, OpenVPN, etc.
# utun+ = utun0, utun1, ... utun9 (PF wildcard syntax)
pass out quick on utun+ all
pass in  quick on utun+ all

# --- [3] RFC 4890 §4.3.1: ICMPv6 obligatory ---
# Without this: NDP (neighbor discovery) and PMTUD break
pass quick inet6 proto icmp6 all

# --- [4] Quad9 DoH — whitelist по IP (на физических интерфейсах) ---
# Разрешаем исходящий трафик к Quad9 (DoH port 443 + DNS port 53)
# macOS DoH profile использует HTTPS (443), не plain DNS
pass out quick proto { udp tcp } to ${QUAD9_PRIMARY}
pass out quick proto { udp tcp } to ${QUAD9_SECONDARY}
# Quad9 ECS (Extended Client Subnet) endpoints
pass out quick proto { udp tcp } to ${QUAD9_ECS_PRIMARY}
pass out quick proto { udp tcp } to ${QUAD9_ECS_SECONDARY}

# --- [5] Block plain DNS на физических интерфейсах (IPv4) ---
# Не блокируем utun+ — там уже pass выше (правило [2])
block out quick on { en0 en1 en2 bridge0 } proto { udp tcp } to any port 53
block out quick on { en0 en1 en2 bridge0 } proto { udp tcp } to any port 853

# --- [6] Block plain DNS на физических интерфейсах (IPv6) ---
block out quick on { en0 en1 en2 bridge0 } inet6 proto { udp tcp } to any port 53
block out quick on { en0 en1 en2 bridge0 } inet6 proto { udp tcp } to any port 853
EOF
    sudo install -m 644 -o root -g wheel "$TMP" "$PF_ANCHOR" \
        || die "Failed to install PF anchor: ${PF_ANCHOR}"
    rm -f "$TMP"
    log "  [✓] PF anchor written: ${PF_ANCHOR}"
}

enable_pf_dns_lock() {
    local PF_CONF="/etc/pf.conf"
    local PF_MARKER="# ===== hardening dns lock ====="

    log "Enabling PF DNS leak lock..."
    warn "WARNING: Blocks direct DNS (53/853 v4/v6)."
    warn "Ensure Quad9 DoH profile is already installed."
    ask "Continue enabling PF DNS lock?" CONFIRM
    if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
        log "PF DNS lock aborted by user."
        return 0
    fi

    if ! grep -qF "$PF_MARKER" "$PF_CONF" 2>/dev/null; then
        sudo tee -a "$PF_CONF" > /dev/null << EOF

${PF_MARKER}
anchor "com.hardening.dnsleak"
load anchor "com.hardening.dnsleak" from "/etc/pf.anchors/com.hardening.dnsleak"
EOF
        log "PF marker added to ${PF_CONF}"
    else
        warn "PF DNS lock marker already present in ${PF_CONF}"
    fi

    if sudo pfctl -f "$PF_CONF" 2>/dev/null && sudo pfctl -e 2>/dev/null; then
        log "PF rules loaded — DNS leak prevention active."
    else
        warn "PF reload failed — reboot may be required."
    fi

    if sudo pfctl -sr 2>/dev/null | grep -q "port 53"; then
        log "PF DNS lock: ACTIVE ✓"
    else
        warn "PF DNS lock: verify manually: sudo pfctl -sr"
    fi

    # [H-5] NEW: LaunchDaemon for auto-starting pf on boot
    _install_pf_launchdaemon
}

# [H-5] NEW: auto-start pf anchor on system boot
_install_pf_launchdaemon() {
    local PLIST="/Library/LaunchDaemons/com.hardening.pf.dnsleak.plist"

    sudo tee "$PLIST" > /dev/null << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.hardening.pf.dnsleak</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>/sbin/pfctl -e -f /etc/pf.conf 2>/dev/null; /sbin/pfctl -a com.hardening.dnsleak -f /etc/pf.anchors/com.hardening.dnsleak</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/foxhole-pf.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/foxhole-pf.log</string>
</dict>
</plist>
EOF
    sudo chown root:wheel "$PLIST"
    sudo chmod 644 "$PLIST"
    sudo launchctl load "$PLIST" 2>/dev/null || true
    log "  [✓] pf LaunchDaemon installed (auto-loads on boot)"
}

disable_pf_dns_lock() {
    local PF_CONF="/etc/pf.conf"
    local PF_MARKER="# ===== hardening dns lock ====="

    log "Disabling PF DNS leak lock..."

    if [[ -f "$PF_CONF" ]] && grep -qF "$PF_MARKER" "$PF_CONF"; then
        local TMP_CONF
        TMP_CONF=$(mktemp)
        grep -vF "$PF_MARKER" "$PF_CONF" > "$TMP_CONF" \
            || die "Failed to process PF configuration file"
        sudo cp "$PF_CONF" "${PF_CONF}.bak.hardening_$(date +%Y%m%d_%H%M%S)"
        sudo mv "$TMP_CONF" "$PF_CONF"
        log "PF marker removed, backup saved."
    else
        log "No PF DNS lock marker found — nothing to remove."
    fi

    sudo rm -f /etc/pf.anchors/com.hardening.dnsleak || true

    # Unload LaunchDaemon
    local PLIST="/Library/LaunchDaemons/com.hardening.pf.dnsleak.plist"
    sudo launchctl unload "$PLIST" 2>/dev/null || true
    sudo rm -f "$PLIST"

    sudo pfctl -f "$PF_CONF" 2>/dev/null && log "PF reloaded without DNS lock."
}

# ──────────────────────────────────────────
# HOSTS — IDEMPOTENT UPDATE
# ──────────────────────────────────────────
update_hosts() {
    local MARKER="# ===== StevenBlack Blocklist ====="
    local HOSTS_URL="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    local HOSTS_FILE="/etc/hosts"
    local BACKUP="/etc/hosts.bak.$(date +%Y%m%d_%H%M%S)"
    local MIN_LINES=50
    local TMP_HOSTS
    TMP_HOSTS=$(mktemp)

    log "Checking /etc/hosts..."

    if grep -qF "$MARKER" "$HOSTS_FILE"; then
        local BLOCK_LINES
        BLOCK_LINES=$(grep -c "^0\.0\.0\.0" "$HOSTS_FILE" 2>/dev/null || echo 0)
        warn "StevenBlack blocklist found. Blocked domains: ${BLOCK_LINES}"
        if [[ "$BLOCK_LINES" -ge "$MIN_LINES" ]]; then
            info "Blocklist has ${BLOCK_LINES} entries — looks healthy."
            ask "Update to latest version anyway?" CONFIRM
        else
            warn "Only ${BLOCK_LINES} entries — looks incomplete!"
            ask "Re-download blocklist?" CONFIRM
        fi
        if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
            log "Skipping hosts update."; rm -f "$TMP_HOSTS"; return 0
        fi
        local LINE_NUM
        LINE_NUM=$(grep -nF "$MARKER" "$HOSTS_FILE" | cut -d: -f1 | head -1)
        sudo cp "$HOSTS_FILE" "$BACKUP"
        sudo head -n "$((LINE_NUM - 1))" "$HOSTS_FILE" \
            | sudo tee "${HOSTS_FILE}.new" > /dev/null
        sudo mv "${HOSTS_FILE}.new" "$HOSTS_FILE"
        log "Old blocklist removed. Backup: $BACKUP"
    else
        local TOTAL_LINES
        TOTAL_LINES=$(wc -l < "$HOSTS_FILE" | tr -d ' ')
        if [[ "$TOTAL_LINES" -ge "$MIN_LINES" ]]; then
            warn "/etc/hosts has ${TOTAL_LINES} lines — custom config detected."
            info "Custom entries (preserved above marker):"
            grep -v "^#\|^[[:space:]]*$" "$HOSTS_FILE" | head -30 || true
            ask "Add StevenBlack below existing content?" CONFIRM
            if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
                log "Skipping hosts update."; rm -f "$TMP_HOSTS"; return 0
            fi
        fi
        sudo cp "$HOSTS_FILE" "$BACKUP"
        log "Backup: $BACKUP"
    fi

    log "Downloading StevenBlack blocklist..."
    if ! curl -fsSL "$HOSTS_URL" -o "$TMP_HOSTS"; then
        rm -f "$TMP_HOSTS"; die "Failed to download StevenBlack hosts!"
    fi

    # SHA-256 + [M-4]: inform user about last commit
    local SHA256
    SHA256=$(shasum -a 256 "$TMP_HOSTS" | awk '{print $1}')
    info "SHA-256: ${SHA256}"
    local LATEST_COMMIT
    LATEST_COMMIT=$(curl -fsSL \
        "https://api.github.com/repos/StevenBlack/hosts/commits?path=hosts&per_page=1" \
        2>/dev/null | grep '"sha"' | head -1 | awk -F'"' '{print $4}' | cut -c1-7)
    info "Latest GitHub commit: ${LATEST_COMMIT:-unknown}"
    info "Verify at: https://github.com/StevenBlack/hosts/commits/master/hosts"

    {
        printf "\n%s\n" "$MARKER"
        printf "# Added:   %s\n" "$(date)"
        printf "# Source:  %s\n" "$HOSTS_URL"
        printf "# SHA-256: %s\n" "$SHA256"
        printf "# Commit:  %s\n" "${LATEST_COMMIT:-unknown}"
        cat "$TMP_HOSTS"
    } | sudo tee -a "$HOSTS_FILE" > /dev/null

    rm -f "$TMP_HOSTS"
    sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder 2>/dev/null || true

    local TOTAL
    TOTAL=$(grep -c "^0\.0\.0\.0" "$HOSTS_FILE" 2>/dev/null || echo "?")
    log "/etc/hosts updated. Blocked domains: ${TOTAL}"
}

disable_hosts_blocklist() {
    local MARKER="# ===== StevenBlack Blocklist ====="
    local HOSTS_FILE="/etc/hosts"
    local BACKUP="/etc/hosts.bak.remove_$(date +%Y%m%d_%H%M%S)"

    if ! grep -qF "$MARKER" "$HOSTS_FILE" 2>/dev/null; then
        log "No StevenBlack marker in ${HOSTS_FILE} — nothing to remove."
        return 0
    fi

    log "Removing StevenBlack blocklist from ${HOSTS_FILE}..."
    sudo cp "$HOSTS_FILE" "$BACKUP"
    local LINE_NUM
    LINE_NUM=$(grep -nF "$MARKER" "$HOSTS_FILE" | cut -d: -f1 | head -1)
    sudo head -n "$((LINE_NUM - 1))" "$HOSTS_FILE" | sudo tee "${HOSTS_FILE}.new" > /dev/null
    sudo mv "${HOSTS_FILE}.new" "$HOSTS_FILE"
    log "Blocklist removed. Backup: $BACKUP"
}

# ──────────────────────────────────────────
# PRIVOXY
# ──────────────────────────────────────────
install_privoxy() {
    install_formula "privoxy" || die "privoxy install failed!"
    resolve_brew_prefix
    local PRIVOXY_CONF="${BREW_PREFIX}/etc/privoxy/config"
    if [[ ! -f "$PRIVOXY_CONF" ]]; then
        die "Privoxy config not found: ${PRIVOXY_CONF}. Check brew --prefix."
    fi
}

configure_privoxy_vpn_bypass() {
    resolve_brew_prefix
    local PRIVOXY_CONF="${BREW_PREFIX}/etc/privoxy/config"
    local BYPASS_MARKER="# ===== VPN bypass ====="

    if grep -qF "$BYPASS_MARKER" "$PRIVOXY_CONF" 2>/dev/null; then
        warn "Privoxy VPN bypass already configured."
        return 0
    fi

    log "Adding VPN bypass rules to Privoxy config..."
    sudo tee -a "$PRIVOXY_CONF" > /dev/null << 'EOF'
# ===== VPN bypass =====
forward 10.0.0.0/8     .
forward 172.16.0.0/12  .
forward 192.168.0.0/16 .
forward 100.64.0.0/10  .
forward 127.0.0.0/8    .
EOF
    log "  [✓] VPN bypass rules added"
}

enable_privoxy_vpn_autoswitch() {
    local TOGGLE_SCRIPT="/usr/local/bin/proxy-toggle.sh"
    local DAEMON_PLIST="/Library/LaunchDaemons/com.hardening.proxytoggle.plist"
    local TOGGLE_LOG="/var/log/proxy-toggle.log"

    log "Configuring Privoxy VPN auto-switch LaunchDaemon..."

    # CR-4: Log SHA-256 before overwriting
    if [[ -f "$TOGGLE_SCRIPT" ]]; then
        local EXISTING_HASH
        EXISTING_HASH=$(shasum -a 256 "$TOGGLE_SCRIPT" | awk '{print $1}')
        warn "Overwriting existing proxy-toggle.sh (SHA-256: ${EXISTING_HASH})"
    fi

    sudo tee "$TOGGLE_SCRIPT" > /dev/null << 'SCRIPT'
#!/bin/bash
LOG="/var/log/proxy-toggle.log"
MAX_LOG_SIZE=5242880

log_msg() {
    if [[ -f "$LOG" ]] && [[ $(stat -f%z "$LOG" 2>/dev/null || echo 0) -gt $MAX_LOG_SIZE ]]; then
        tail -n 500 "$LOG" > "${LOG}.tmp" && mv "${LOG}.tmp" "$LOG"
    fi
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG"
}

vpn_active() {
    # H-3: Use scutil --nc list, exclude iCloud/Tailscale
    scutil --nc list 2>/dev/null \
        | grep -i "Connected" \
        | grep -viE "tailscale|icloud|relay" \
        | grep -q "." && return 0
    return 1
}

get_services() {
    networksetup -listallnetworkservices 2>/dev/null \
        | tail -n +2 \
        | grep -v "^\*" \
        | grep -vEi "vpn|cisco|anyconnect|wireguard"
}

set_proxy() {
    local STATE="$1"
    while IFS= read -r SERVICE; do
        [[ -z "$SERVICE" ]] && continue
        local ERR
        ERR=$(networksetup -setwebproxystate "$SERVICE" "$STATE" 2>&1) \
            || log_msg "[!] networksetup failed for '${SERVICE}': ${ERR}"
        ERR=$(networksetup -setsecurewebproxystate "$SERVICE" "$STATE" 2>&1) \
            || log_msg "[!] networksetup failed for '${SERVICE}': ${ERR}"
        if [[ "$STATE" == "on" ]]; then
            ERR=$(networksetup -setwebproxy "$SERVICE" "127.0.0.1" "8118" 2>&1) \
                || log_msg "[!] networksetup failed for '${SERVICE}': ${ERR}"
            ERR=$(networksetup -setsecurewebproxy "$SERVICE" "127.0.0.1" "8118" 2>&1) \
                || log_msg "[!] networksetup failed for '${SERVICE}': ${ERR}"
        fi
    done <<< "$(get_services)"
}

if vpn_active; then
    log_msg "VPN detected (scutil) → proxy OFF"
    set_proxy off
else
    log_msg "No tunnel VPN → proxy ON"
    set_proxy on
fi
SCRIPT

    sudo chown root:wheel "$TOGGLE_SCRIPT"
    sudo chmod 755 "$TOGGLE_SCRIPT"
    
    # CR-4: Log SHA-256 after write
    local NEW_HASH
    NEW_HASH=$(shasum -a 256 "$TOGGLE_SCRIPT" | awk '{print $1}')
    log "  [✓] proxy-toggle.sh written (SHA-256: ${NEW_HASH})"

    # CR-3: Validate path variables and use single-quoted heredoc
    [[ "$TOGGLE_SCRIPT" =~ ^[a-zA-Z0-9/_.-]+$ ]] \
        || die "Invalid path in TOGGLE_SCRIPT: ${TOGGLE_SCRIPT}"
    [[ "$TOGGLE_LOG" =~ ^[a-zA-Z0-9/_.-]+$ ]] \
        || die "Invalid path in TOGGLE_LOG: ${TOGGLE_LOG}"

    sudo tee "$DAEMON_PLIST" > /dev/null << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.hardening.proxytoggle</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/usr/local/bin/proxy-toggle.sh</string>
    </array>
    <key>WatchPaths</key>
    <array>
        <string>/Library/Preferences/SystemConfiguration</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>StandardOutPath</key>
    <string>/var/log/proxy-toggle.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/proxy-toggle.log</string>
</dict>
</plist>
EOF

    sudo chown root:wheel "$DAEMON_PLIST"
    sudo chmod 644 "$DAEMON_PLIST"

    sudo launchctl unload "$DAEMON_PLIST" 2>/dev/null || true
    sudo launchctl load  "$DAEMON_PLIST" \
        && log "LaunchDaemon loaded — proxy auto-switches on VPN." \
        || die "LaunchDaemon failed to load!"

    sudo bash "$TOGGLE_SCRIPT"

    if netstat -an 2>/dev/null | grep -q "0.0.0.0.8118"; then
        warn "Privoxy exposed on 0.0.0.0:8118 — check config!"
    else
        log "Privoxy: loopback only ✓"
    fi
}

disable_privoxy_autoswitch() {
    local DAEMON_PLIST="/Library/LaunchDaemons/com.hardening.proxytoggle.plist"
    local TOGGLE_SCRIPT="/usr/local/bin/proxy-toggle.sh"
    log "Disabling Privoxy VPN auto-switch..."
    sudo launchctl unload "$DAEMON_PLIST" 2>/dev/null || true
    sudo rm -f "$DAEMON_PLIST" "$TOGGLE_SCRIPT"
    log "  [✓] Privoxy auto-switch disabled"
}

# ──────────────────────────────────────────
# DNS STACK HEALTH CHECK
# ──────────────────────────────────────────
verify_dns_stack() {
    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║         DNS Stack Health Check           ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""

    local PASS=0 FAIL=0

    _chk() {
        local ID="$1" DESC="$2" CMD="$3" EXPECT="$4"
        local OUT
        OUT=$(eval "$CMD" 2>/dev/null || true)
        if echo "$OUT" | grep -q "$EXPECT"; then
            log "  [${ID}] ${DESC}"
            (( PASS++ ))
        else
            err "  [${ID}] ${DESC}"
            info "       Expected pattern: '${EXPECT}'"
            info "       Got: $(echo "$OUT" | head -1)"
            (( FAIL++ ))
        fi
    }

    # [1] Quad9 Profile active
    _chk "1" "Quad9 Profile active" \
        "scutil --dns" \
        "9\.9\.9"

    # New test [2] — check that macOS DoH profile is active:
    _chk "2" "Quad9 DoH profile active (scutil)" \
        "scutil --dns" \
        "9\.9\.9"

    # New test [2b] — passing utun interfaces in pf:
    local PF_UTUN
    PF_UTUN=$(sudo pfctl -sr 2>/dev/null | grep "utun" || true)
    if [[ -n "$PF_UTUN" ]]; then
        log "  [2b] PF utun+ pass rule present ✓"
        (( PASS++ ))
    else
        err "  [2b] PF utun+ pass rule MISSING"
        (( FAIL++ ))
    fi

    # [3] Basic DNS resolution
    _chk "3" "Basic DNS resolution" \
        "dig +short google.com" \
        "[0-9]"

    # [4] DNSSEC ad flag
    _chk "4" "DNSSEC (ad flag)" \
        "dig +dnssec icann.org" \
        " ad"

    # [5] DNSSEC fail test — should return SERVFAIL
    _chk "5" "DNSSEC validation (SERVFAIL on bad domain)" \
        "dig www.dnssec-failed.org" \
        "SERVFAIL"

    # [6] Quad9 reachability
    _chk "6" "Quad9 DoH reachability" \
        "curl -s --max-time 5 https://on.quad9.net" \
        "Yes"

    # [7] Plain DNS locked from the outside
    local DNS_OUT
    DNS_OUT=$(timeout 3 dig google.com @8.8.8.8 2>/dev/null || true)
    if echo "$DNS_OUT" | grep -q "NOERROR"; then
        err "  [7] Plain DNS NOT blocked — leak possible (@8.8.8.8 responded)"
        info "       pf DNS lock may not be active"
        (( FAIL++ ))
    else
        log "  [7] Plain DNS blocked (@8.8.8.8) ✓"
        (( PASS++ ))
    fi

    # [8] Split DNS configuration
    _chk "8" "Split DNS configuration" \
        "scutil --dns" \
        "resolver"

    # [9] pf enabled
    _chk "9" "pf firewall enabled" \
        "sudo pfctl -s info" \
        "Enabled"

    # [10] StevenBlack hosts
    local HOSTS_COUNT
    HOSTS_COUNT=$(grep -c "^0\.0\.0\.0" /etc/hosts 2>/dev/null || echo 0)
    if [[ "$HOSTS_COUNT" -gt 1000 ]]; then
        log "  [10] StevenBlack hosts (${HOSTS_COUNT} entries) ✓"
        (( PASS++ ))
    else
        err "  [10] StevenBlack hosts (${HOSTS_COUNT} entries — too few)"
        (( FAIL++ ))
    fi

    echo ""
    echo "  ──────────────────────────────────────────"
    echo "  Results: ${PASS}/10 passed, ${FAIL} failed"
    echo "  ──────────────────────────────────────────"
    echo ""
    [[ "$FAIL" -eq 0 ]] && log "All checks passed. Stack is healthy. ✓" \
                        || warn "${FAIL} check(s) failed — review above."
    echo ""
}

# ──────────────────────────────────────────
# RESET
# ──────────────────────────────────────────
reset_net_hardening() {
    log "Resetting network hardening (PF DNS lock, Privoxy toggle, hosts blocklist)..."
    disable_pf_dns_lock
    disable_privoxy_autoswitch
    disable_hosts_blocklist
    while IFS= read -r SERVICE; do
        [[ -z "$SERVICE" ]] && continue
        local ERR
        ERR=$(networksetup -setwebproxystate "$SERVICE" off 2>&1) \
            && log "  [✓] Disabled proxy for ${SERVICE}" \
            || warn "  [!] Failed to disable proxy for ${SERVICE}: ${ERR}"
        ERR=$(networksetup -setsecurewebproxystate "$SERVICE" off 2>&1) \
            && log "  [✓] Disabled secure proxy for ${SERVICE}" \
            || warn "  [!] Failed to disable secure proxy for ${SERVICE}: ${ERR}"
    done <<< "$(networksetup -listallnetworkservices | tail -n +2 | grep -v '^\*' || true)"
    log "Network hardening reset complete."
}

# ══════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════
main() {
    clear
    echo ""
    echo "  ░██████████                      ░██                   ░██           "
    echo "  ░██                              ░██                   ░██           "
    echo "  ░██         ░███████  ░██    ░██ ░████████   ░███████  ░██  ░███████ "
    echo "  ░█████████ ░██    ░██  ░██  ░██  ░██    ░██ ░██    ░██ ░██ ░██    ░██"
    echo "  ░██        ░██    ░██  ░██  ░██  ░██    ░██ ░██    ░██ ░██ ░██       "
    echo "  ░██         ░███████  ░██    ░██ ░██    ░██  ░███████  ░██  ░███████ "
    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║       macOS Network Hardening Netlib     ║"
    echo "  ║            v0.17  ·  by Gr3y-foX         ║"
    echo "  ║       ARM/M-chip  |  strict mode         ║"
    echo "  ╠══════════════════════════════════════════╣"
    echo "  ║  module: netlib   |  mode: interactive   ║"
    echo "  ╠══════════════════════════════════════════╣"
    echo "  ║  [!] Unauthorized use is prohibited.     ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""
    warn "This module modifies network settings. Sudo may be required."
    info "Tip: usually sourced from profiles (vpn_daily / paranoid_tor)."
    echo ""
    
    # L-2: Sudo keepalive
    info "This script requires sudo for system modifications."
    sudo -v || die "sudo authentication failed."
    while true; do sudo -n true; sleep 55; done &
    SUDO_KEEPALIVE_PID=$!
    trap 'kill $SUDO_KEEPALIVE_PID 2>/dev/null' EXIT
    
    ask "Continue?" CONFIRM
    [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && { echo "Aborted."; exit 0; }
    echo ""

    ask "Create backup snapshot before proceeding?" CONFIRM_BK
    if [[ "$CONFIRM_BK" == "y" || "$CONFIRM_BK" == "Y" ]]; then
        create_net_backup
    else
        warn "Skipping backup — proceeding without snapshot."
        echo ""
    fi

    while true; do
        echo "  ╔══════════════════════════════════════════╗"
        echo "  ║           Network Hardening Menu         ║"
        echo "  ╠══════════════════════════════════════════╣"
        echo "  ║  [1]  Enable PF DNS leak lock            ║"
        echo "  ║       (ports 53/853 — IPv4/IPv6 BLOCKED) ║"
        echo "  ║  [2]  Update /etc/hosts blocklist        ║"
        echo "  ║       (StevenBlack)                      ║"
        echo "  ║  [3]  Install Privoxy + VPN auto-switch  ║"
        echo "  ║  [4]  Disable network hardening         ║"
        echo "  ║       (PF / Privoxy / proxy)             ║"
        echo "  ║  [5]  DNS Stack Health Check             ║"
        echo "  ╠══════════════════════════════════════════╣"
        echo "  ║  [6]  Quit                               ║"
        echo "  ╚══════════════════════════════════════════╝"
        echo ""
        read -rp "  Choice (1-6): " CHOICE
        echo ""

        case "$CHOICE" in
            1)
                log "[1] PF DNS leak lock"
                prepare_pf_dns_lock_anchor
                enable_pf_dns_lock
                echo ""
                ;;
            2)
                log "[2] StevenBlack /etc/hosts blocklist"
                update_hosts
                echo ""
                ;;
            3)
                log "[3] Privoxy + VPN auto-switch"
                install_privoxy
                configure_privoxy_vpn_bypass
                enable_privoxy_vpn_autoswitch
                echo ""
                ;;
            4)
                warn "[4] DISABLE: disabling PF DNS lock, Privoxy auto-switch, clearing proxies"
                ask "Are you sure? This will disable network hardening (does not restore backup)." CONFIRM_RESET
                if [[ "$CONFIRM_RESET" == "y" || "$CONFIRM_RESET" == "Y" ]]; then
                    reset_net_hardening
                else
                    log "Reset aborted."
                fi
                echo ""
                ;;
            5)
                verify_dns_stack
                ;;
            6)
                echo "Done. Stay paranoid. 🔒"
                exit 0
                ;;
            *)
                warn "Invalid choice. Please select 1-6."
                echo ""
                ;;
        esac
    done
}

if [[ "${0##*/}" == "mac-hardening-netlib.sh" ]]; then
    main
fi

#!/bin/bash
set -euo pipefail
#
# Foxhole-macos — macOS Network Hardening Library
#
# File:    mac-hardening-netlib.sh
# Version: 0.17.3 (2026-11-03)
# Author:  Gr3y-foX
# Based on: drduh/macOS-Security-and-Privacy-Guide (MIT)
# License: GNU GPL v3 — see LICENSE for details
#
# Overview:
#   Network hardening primitives for macOS:
#     - PF DNS leak prevention (VPN tunnels utun0-15 pass)
#     - /etc/hosts blocklist (StevenBlack)
#     - Privoxy with VPN-aware auto-proxy switching
#
# Usage:
#   Source from profile scripts or run directly for interactive menu.
#
# v0.17.3 Highlights:
#   • tunnel pass rule lists utun0-utun15: PF on macOS has no "utun+" wildcard
#     (a block rule on utun+ matched nothing in the VM)
#   • PF DNS lock lives in anchor com.apple/foxhole.dnsleak: /etc/pf.conf is
#     no longer edited and the main ruleset no longer reloaded (VPN-safe)
#   • PF enabled by reference (pfctl -E / -X): disable restores the old state
#   • helper /usr/local/libexec/foxhole-pf-dnslock shared by enable/disable/boot
#   • launchctl bootstrap/bootout instead of load/unload
#   • old pf.conf marker installs are migrated automatically
#
# v0.17.2 Highlights:
#   • disable_pf_dns_lock removes marker + anchor lines, keeps pf.conf root:wheel
#   • PF block rules scoped to physical (en*) interfaces again
#   • enable/verify read the anchor rules, not plain "pfctl -sr"
#   • verify_dns_stack no longer aborts under "set -e"; no eval
#   • proxy-toggle: VPN detection fixed ("(Disconnected)" matched), utun with IPv4
#     tunnels detected, idempotent writes, never proxies to a dead Privoxy
#   • update_hosts validates the download before editing /etc/hosts
#
# v0.17.1 Highlights:
#   • Security fixes: shell injection, TOCTOU, XML injection
#   • Reliability: strict mode, better error handling
#   • Fixed VPN packet drops (utun0-9) with explicit pass rules
#   • Removed dnscrypt-proxy (conflicts with macOS DoH profile)
#   • DNS stack: macOS DoH Profile (Quad9) → PF anchor (leak lock)
#   • PF anchor now scopes block rules to physical interfaces only

# Constants
# PRIVOXY_* are for profiles that source the netlib (proxy-toggle.sh hard-codes them)
# shellcheck disable=SC2034
readonly PRIVOXY_ADDR="127.0.0.1"
# shellcheck disable=SC2034
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
        # shellcheck disable=SC2229  # reads into the variable *named* by $VAR
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
    [[ -f "$PF_LOCK_RULES" ]] \
        && sudo cp "$PF_LOCK_RULES" "${NET_BACKUP_DIR}/pf.anchor.dnsleak" \
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
# Rules live in a child of Apple's "com.apple/*" anchor, which the stock
# /etc/pf.conf already evaluates: /etc/pf.conf is never edited and the main
# ruleset (VPN kill switches live there too) is never reloaded.
readonly PF_LOCK_ANCHOR="com.apple/foxhole.dnsleak"
readonly PF_LOCK_RULES="/etc/pf.anchors/com.hardening.dnsleak"
readonly PF_LOCK_HELPER="/usr/local/libexec/foxhole-pf-dnslock"
readonly PF_LOCK_TOKEN="/var/db/foxhole/pf.token"
readonly PF_LOCK_LABEL="com.hardening.pf.dnsleak"
readonly PF_LOCK_PLIST="/Library/LaunchDaemons/com.hardening.pf.dnsleak.plist"

# Physical (en*) interfaces for PF scoping; falls back to common defaults
_physical_ifaces() {
    local LIST
    LIST=$(networksetup -listallhardwareports 2>/dev/null \
        | awk '/^Device: en[0-9]+$/ {print $2}' | tr '\n' ' ' | sed 's/ $//')
    printf '%s\n' "${LIST:-en0 en1 en2 bridge0}"
}

prepare_pf_dns_lock_anchor() {
    local PF_ANCHOR="$PF_LOCK_RULES"

    log "Writing PF anchor for DNS leak prevention: ${PF_ANCHOR}"
    sudo mkdir -p /etc/pf.anchors

    local IFACES
    IFACES=$(_physical_ifaces)
    local UTUNS=""
    local N
    for N in $(seq 0 15); do UTUNS="${UTUNS}${UTUNS:+ }utun${N}"; done
    info "Physical interfaces scoped for DNS block: ${IFACES}"

    # Atomic write via tmpfile + install (CR-2 TOCTOU fix)
    local TMP
    TMP=$(mktemp /tmp/pf.anchor.XXXXXX)
    {
        cat <<'EOF'
# ============================================================
# foxhole-macos — DNS Leak Prevention Anchor
# Generated by mac-hardening-netlib.sh
# References: RFC 4890 (ICMPv6), OpenBSD pf docs
# DNS: macOS native DoH profile (Quad9)
# KNOWN LIMITATION: DoH on port 443 is not blocked at the PF level.
# Protection relies on the macOS DoH Configuration Profile (Quad9)
# being the only active DoH endpoint. Apps bypassing via custom
# DoH servers (e.g. 8.8.8.8:443) are not covered by this anchor.
# All rules are "quick": the first matching rule wins.
# ============================================================

# [1] Loopback
pass quick on lo0 all

EOF
        # [2] VPN tunnels. PF on macOS does NOT treat "utun+" as a wildcard (verified:
        # a block rule on utun+ matched nothing), so list the interfaces explicitly.
        printf '# [2] VPN tunnels: pass everything on utun0-utun15 (no wildcard in PF)\n'
        printf 'pass out quick on { %s } all\n' "$UTUNS"
        printf 'pass in  quick on { %s } all\n' "$UTUNS"
        cat <<'EOF'

# [3] RFC 4890 ICMPv6 obligatory
pass quick inet6 proto icmp6 all

# [4] Quad9 whitelist (any interface; evaluated before the blocks below)
EOF
        local IP
        for IP in "$QUAD9_PRIMARY" "$QUAD9_SECONDARY" \
                  "$QUAD9_ECS_PRIMARY" "$QUAD9_ECS_SECONDARY"; do
            printf 'pass out quick proto { udp tcp } to %s\n' "$IP"
        done
        printf '\n# [5] Block plain DNS (53) and DNS-over-TLS (853) on physical interfaces only\n'
        printf '# Tunnels are already passed by rule [2], so these never reach them\n'
        printf 'block out quick on { %s } proto { udp tcp } to any port 53\n' "$IFACES"
        printf 'block out quick on { %s } proto { udp tcp } to any port 853\n' "$IFACES"
        printf 'block out quick on { %s } inet6 proto { udp tcp } to any port 53\n' "$IFACES"
        printf 'block out quick on { %s } inet6 proto { udp tcp } to any port 853\n' "$IFACES"
    } > "$TMP"
    sudo install -m 644 -o root -g wheel "$TMP" "$PF_ANCHOR" \
        || die "Failed to install PF anchor: ${PF_ANCHOR}"
    rm -f "$TMP"
    log "  [✓] PF anchor written: ${PF_ANCHOR}"
}

# Helper shared by enable, disable and the boot LaunchDaemon (one code path)
_install_pf_helper() {
    sudo mkdir -p "$(dirname "$PF_LOCK_HELPER")"
    local TMP
    TMP=$(mktemp /tmp/foxhole-pf-helper.XXXXXX)
    cat > "$TMP" <<'HELPER'
#!/bin/bash
# foxhole-macos PF DNS lock helper — installed by mac-hardening-netlib.sh
#   start   load the rules into com.apple/foxhole.dnsleak and hold one PF
#           enable reference (pfctl -E)
#   stop    flush the rules and release that reference (pfctl -X); PF goes
#           back off unless something else (e.g. a VPN kill switch) holds one
#   status  exit 0 if the rules are loaded and the reference is held
# The stock /etc/pf.conf evaluates anchor "com.apple/*", so neither
# /etc/pf.conf nor the main ruleset is ever touched.
ANCHOR="com.apple/foxhole.dnsleak"
RULES="/etc/pf.anchors/com.hardening.dnsleak"
TOKEN_FILE="/var/db/foxhole/pf.token"

# pfctl prints ALTQ and "-f" warnings on every call; keep the rest
pf() {
    local OUT RC
    OUT=$(/sbin/pfctl "$@" 2>&1); RC=$?
    grep -v -e 'ALTQ' -e 'Use of -f option' -e 'present in the main ruleset' \
            -e 'See /etc/pf.conf' -e '^$' <<< "$OUT" || true
    return $RC
}

held_token() {
    local T
    [[ -s "$TOKEN_FILE" ]] || return 1
    T=$(cat "$TOKEN_FILE")
    [[ "$T" =~ ^[0-9]+$ ]] || return 1
    pf -s References | grep -qw -- "$T" || return 1
    echo "$T"
}

rules_loaded() { pf -a "$ANCHOR" -sr | grep -q "port = 53"; }

case "${1:-}" in
    start)
        [[ -f "$RULES" ]] || { echo "rules file missing: $RULES" >&2; exit 1; }
        pf -a "$ANCHOR" -f "$RULES" >&2 || { echo "failed to load $ANCHOR" >&2; exit 1; }
        if ! held_token >/dev/null; then
            OUT=$(pf -E)
            TOKEN=$(sed -n 's/^Token : //p' <<< "$OUT")
            [[ -n "$TOKEN" ]] || { echo "pfctl -E returned no token: $OUT" >&2; exit 1; }
            mkdir -p "$(dirname "$TOKEN_FILE")"
            ( umask 077; echo "$TOKEN" > "$TOKEN_FILE" )
        fi
        echo "$(date '+%F %T') start: rules loaded into $ANCHOR, PF reference held"
        ;;
    stop)
        pf -a "$ANCHOR" -F all >/dev/null || true
        if T=$(held_token); then
            pf -X "$T" || true
        fi
        rm -f "$TOKEN_FILE"
        echo "$(date '+%F %T') stop: rules flushed, PF reference released"
        ;;
    status)
        rules_loaded && held_token >/dev/null
        ;;
    *)
        echo "usage: $0 start|stop|status" >&2; exit 2
        ;;
esac
HELPER
    sudo install -m 755 -o root -g wheel "$TMP" "$PF_LOCK_HELPER" \
        || { rm -f "$TMP"; die "Failed to install ${PF_LOCK_HELPER}"; }
    rm -f "$TMP"
}

_launchd_bootout() {
    sudo launchctl bootout "system/$1" 2>/dev/null || true
}

# bootstrap can fail with "5: Input/output error" right after a bootout
_launchd_bootstrap() {
    local _
    for _ in 1 2 3; do
        sudo launchctl bootstrap system "$1" 2>/dev/null && return 0
        sleep 1
    done
    return 1
}

# Main ruleset evaluates the com.apple/* children (stock /etc/pf.conf)
_pf_main_has_apple_anchor() {
    sudo pfctl -sr 2>/dev/null | grep -qE '^anchor "com\.apple/\*"'
}

# Pre-0.17.3 installs edited /etc/pf.conf and loaded anchor "com.hardening.dnsleak"
_pf_legacy_cleanup() {
    local PF_CONF="/etc/pf.conf"
    local PF_MARKER="# ===== hardening dns lock ====="

    if [[ -f "$PF_CONF" ]] && grep -qF "$PF_MARKER" "$PF_CONF"; then
        info "Removing the DNS lock lines an older version added to ${PF_CONF}..."
        local TMP_CONF
        TMP_CONF=$(mktemp)
        grep -vF -e "$PF_MARKER" \
                 -e 'anchor "com.hardening.dnsleak"' "$PF_CONF" > "$TMP_CONF" \
            || { rm -f "$TMP_CONF"; die "Failed to process PF configuration file"; }
        sudo cp "$PF_CONF" "${PF_CONF}.bak.hardening_$(date +%Y%m%d_%H%M%S)"
        # install (not mv): mktemp file is user-owned 0600, pf.conf must stay root:wheel
        sudo install -m 644 -o root -g wheel "$TMP_CONF" "$PF_CONF" \
            || { rm -f "$TMP_CONF"; die "Failed to install ${PF_CONF}"; }
        rm -f "$TMP_CONF"
        # One reload is unavoidable here: it drops the old anchor from the main ruleset
        sudo pfctl -f "$PF_CONF" 2>/dev/null \
            || warn "PF reload failed — check: sudo pfctl -nf ${PF_CONF}"
        log "  [✓] ${PF_CONF} restored (backup saved next to it)"
        info "Older versions enabled PF with 'pfctl -e'; it stays on. If nothing else uses PF: sudo pfctl -d"
    fi
    sudo pfctl -a com.hardening.dnsleak -F all >/dev/null 2>&1 || true
}

enable_pf_dns_lock() {
    log "Enabling PF DNS leak lock..."
    warn "WARNING: Blocks direct DNS (53/853 v4/v6)."
    warn "Ensure Quad9 DoH profile is already installed."
    ask "Continue enabling PF DNS lock?" CONFIRM
    if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
        log "PF DNS lock aborted by user."
        return 0
    fi

    [[ -f "$PF_LOCK_RULES" ]] \
        || die "PF rules missing: ${PF_LOCK_RULES} (run prepare_pf_dns_lock_anchor first)"

    _pf_legacy_cleanup

    # Rules in com.apple/foxhole.dnsleak only apply if the main ruleset evaluates com.apple/*
    if ! _pf_main_has_apple_anchor; then
        if [[ -z "$(sudo pfctl -sr 2>/dev/null)" ]] \
           && grep -qE '^anchor "com\.apple/\*"' /etc/pf.conf 2>/dev/null; then
            # Nothing loaded yet, so there is nothing to clobber
            info "PF main ruleset is empty — loading the stock /etc/pf.conf once."
            sudo pfctl -f /etc/pf.conf 2>/dev/null || die "Failed to load /etc/pf.conf"
        else
            err "PF main ruleset does not evaluate anchor \"com.apple/*\" — the lock would never apply."
            info "A custom /etc/pf.conf or another tool replaced it. Inspect: sudo pfctl -sr"
            return 1
        fi
    fi

    _install_pf_helper
    _install_pf_launchdaemon    # RunAtLoad: runs "helper start" now and at every boot

    local _
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        sudo /bin/bash "$PF_LOCK_HELPER" status && break
        sleep 0.5
    done
    if sudo /bin/bash "$PF_LOCK_HELPER" status; then
        log "PF DNS lock: ACTIVE ✓ (anchor ${PF_LOCK_ANCHOR})"
    else
        err "PF DNS lock did not come up. Log: /var/log/foxhole-pf.log"
        sudo tail -n 5 /var/log/foxhole-pf.log 2>/dev/null || true
        return 1
    fi
}

_install_pf_launchdaemon() {
    local TMP
    TMP=$(mktemp /tmp/foxhole-pf-plist.XXXXXX)
    cat > "$TMP" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.hardening.pf.dnsleak</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/usr/local/libexec/foxhole-pf-dnslock</string>
        <string>start</string>
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
    _launchd_bootout "$PF_LOCK_LABEL"
    sudo install -m 644 -o root -g wheel "$TMP" "$PF_LOCK_PLIST" \
        || { rm -f "$TMP"; die "Failed to install ${PF_LOCK_PLIST}"; }
    rm -f "$TMP"
    _launchd_bootstrap "$PF_LOCK_PLIST" \
        && log "  [✓] PF LaunchDaemon installed (re-applies the lock at boot)" \
        || warn "launchctl bootstrap failed for ${PF_LOCK_PLIST}"
}

disable_pf_dns_lock() {
    log "Disabling PF DNS leak lock..."

    _launchd_bootout "$PF_LOCK_LABEL"
    sudo rm -f "$PF_LOCK_PLIST"

    # Re-install first so the current stop logic runs even if the helper is missing
    _install_pf_helper
    sudo /bin/bash "$PF_LOCK_HELPER" stop >/dev/null \
        || warn "PF lock helper stop failed"
    sudo rm -f "$PF_LOCK_HELPER" "$PF_LOCK_RULES" "$PF_LOCK_TOKEN"

    _pf_legacy_cleanup

    if sudo pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
        info "PF stays enabled: another program holds a reference (sudo pfctl -s References)."
    else
        log "PF is off again (as before the lock)."
    fi
    log "PF DNS lock removed."
}

# ──────────────────────────────────────────
# HOSTS — IDEMPOTENT UPDATE
# ──────────────────────────────────────────
update_hosts() {
    local MARKER="# ===== StevenBlack Blocklist ====="
    local HOSTS_URL="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    local HOSTS_FILE="/etc/hosts"
    local BACKUP
    BACKUP="/etc/hosts.bak.$(date +%Y%m%d_%H%M%S)"
    local MIN_LINES=50
    local HAS_BLOCKLIST=false
    local TMP_HOSTS

    log "Checking /etc/hosts..."

    # 1. Decide (no changes yet)
    if grep -qF "$MARKER" "$HOSTS_FILE"; then
        HAS_BLOCKLIST=true
        local BLOCK_LINES
        BLOCK_LINES=$(grep -c "^0\.0\.0\.0" "$HOSTS_FILE" 2>/dev/null || true)
        BLOCK_LINES=${BLOCK_LINES:-0}
        warn "StevenBlack blocklist found. Blocked domains: ${BLOCK_LINES}"
        if [[ "$BLOCK_LINES" -ge "$MIN_LINES" ]]; then
            info "Blocklist has ${BLOCK_LINES} entries — looks healthy."
            ask "Update to latest version anyway?" CONFIRM
        else
            warn "Only ${BLOCK_LINES} entries — looks incomplete!"
            ask "Re-download blocklist?" CONFIRM
        fi
        if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
            log "Skipping hosts update."; return 0
        fi
    else
        local TOTAL_LINES
        TOTAL_LINES=$(wc -l < "$HOSTS_FILE" | tr -d ' ')
        if [[ "$TOTAL_LINES" -ge "$MIN_LINES" ]]; then
            warn "/etc/hosts has ${TOTAL_LINES} lines — custom config detected."
            info "Custom entries (preserved above marker):"
            grep -v "^#\|^[[:space:]]*$" "$HOSTS_FILE" | head -30 || true
            ask "Add StevenBlack below existing content?" CONFIRM
            if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
                log "Skipping hosts update."; return 0
            fi
        fi
    fi

    # 2. Download and validate before touching /etc/hosts, so a failed or
    #    truncated download never leaves the system without a blocklist
    TMP_HOSTS=$(mktemp)
    log "Downloading StevenBlack blocklist..."
    if ! curl -fsSL "$HOSTS_URL" -o "$TMP_HOSTS"; then
        rm -f "$TMP_HOSTS"; die "Failed to download StevenBlack hosts! /etc/hosts unchanged."
    fi
    local NEW_LINES
    NEW_LINES=$(grep -c "^0\.0\.0\.0 " "$TMP_HOSTS" || true)
    if [[ "${NEW_LINES:-0}" -lt 1000 ]]; then
        rm -f "$TMP_HOSTS"
        die "Downloaded file has only ${NEW_LINES:-0} block entries — not a hosts blocklist? /etc/hosts unchanged."
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

    # 3. Apply
    sudo cp "$HOSTS_FILE" "$BACKUP"
    log "Backup: $BACKUP"
    if [[ "$HAS_BLOCKLIST" == true ]]; then
        local LINE_NUM
        LINE_NUM=$(grep -nF "$MARKER" "$HOSTS_FILE" | cut -d: -f1 | head -1)
        sudo head -n "$((LINE_NUM - 1))" "$HOSTS_FILE" \
            | sudo tee "${HOSTS_FILE}.new" > /dev/null
        sudo mv "${HOSTS_FILE}.new" "$HOSTS_FILE"
        log "Old blocklist removed."
    fi

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
    local BACKUP
    BACKUP="/etc/hosts.bak.remove_$(date +%Y%m%d_%H%M%S)"

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
    # Nothing else starts it; without it the proxy toggle would point at a dead port
    if brew services start privoxy >/dev/null 2>&1; then
        log "  [✓] Privoxy service started (brew services, runs at login)"
    else
        warn "Could not start Privoxy — try: brew services start privoxy"
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
    # forward takes URL patterns, not CIDR ("10.0.0.0/8" would match host
    # 10.0.0.0 with path /8). Host patterns accept * and [] classes.
    sudo tee -a "$PRIVOXY_CONF" > /dev/null << 'EOF'
# ===== VPN bypass =====
# 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 127.0.0.0/8
forward 10.*.*.*/                .
forward 172.1[6-9].*.*/          .
forward 172.2[0-9].*.*/          .
forward 172.3[01].*.*/           .
forward 192.168.*.*/             .
forward 100.6[4-9].*.*/          .
forward 100.[7-9][0-9].*.*/      .
forward 100.1[01][0-9].*.*/      .
forward 100.12[0-7].*.*/         .
forward 127.*.*.*/               .
forward localhost/               .
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
    # H-3: Network Extension VPNs via scutil, excluding iCloud/Tailscale.
    # Match "(Connected)" exactly: "(Disconnected)" also contains "Connected".
    scutil --nc list 2>/dev/null \
        | grep -F "(Connected)" \
        | grep -viE "tailscale|icloud|relay" \
        | grep -q "." && return 0
    # Tunnels that scutil does not list (Mullvad, ClearVPN, OpenVPN):
    # a utun with an IPv4 address. System utuns (iCloud, Continuity) only
    # carry IPv6 link-local; Tailscale's 100.64.0.0/10 is skipped.
    local IF
    for IF in $(ifconfig -l 2>/dev/null); do
        [[ "$IF" == utun* ]] || continue
        ifconfig "$IF" 2>/dev/null | awk '$1 == "inet" {print $2}' \
            | grep -vqE '^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.' \
            && return 0
    done
    return 1
}

privoxy_listening() {
    /usr/bin/nc -z -G 2 127.0.0.1 8118 >/dev/null 2>&1
}

get_services() {
    networksetup -listallnetworkservices 2>/dev/null \
        | tail -n +2 \
        | grep -v "^\*" \
        | grep -vEi "vpn|cisco|anyconnect|wireguard"
}

# "Yes 127.0.0.1 8118" style summary of one -getwebproxy/-getsecurewebproxy
proxy_state() {
    networksetup "$1" "$2" 2>/dev/null \
        | awk -F': ' '$1=="Enabled"{e=$2} $1=="Server"{s=$2} $1=="Port"{p=$2} END{print e, s, p}'
}

set_proxy() {
    local STATE="$1" WANT
    # Only write when something changes: every write touches
    # /Library/Preferences/SystemConfiguration, which is our own WatchPath
    if [[ "$STATE" == "on" ]]; then WANT="Yes 127.0.0.1 8118"; else WANT="No"; fi
    while IFS= read -r SERVICE; do
        [[ -z "$SERVICE" ]] && continue
        local ERR KIND CUR
        for KIND in web secureweb; do
            CUR=$(proxy_state "-get${KIND}proxy" "$SERVICE")
            if [[ "$STATE" == "on" && "$CUR" == "$WANT" ]] \
               || [[ "$STATE" == "off" && "$CUR" == No* ]]; then
                continue
            fi
            if [[ "$STATE" == "on" ]]; then
                ERR=$(networksetup "-set${KIND}proxy" "$SERVICE" "127.0.0.1" "8118" 2>&1) \
                    || log_msg "[!] networksetup failed for '${SERVICE}': ${ERR}"
            fi
            ERR=$(networksetup "-set${KIND}proxystate" "$SERVICE" "$STATE" 2>&1) \
                || log_msg "[!] networksetup failed for '${SERVICE}': ${ERR}"
            log_msg "${SERVICE}: ${KIND} proxy ${STATE}"
        done
    done <<< "$(get_services)"
}

if vpn_active; then
    set_proxy off
elif ! privoxy_listening; then
    # Pointing the system at a dead proxy would cut all web traffic
    log_msg "[!] No VPN, but Privoxy is not listening on 127.0.0.1:8118 → proxy OFF"
    set_proxy off
else
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

    _launchd_bootout com.hardening.proxytoggle
    _launchd_bootstrap "$DAEMON_PLIST" \
        && log "LaunchDaemon loaded — proxy auto-switches on VPN." \
        || die "LaunchDaemon failed to load!"

    sudo bash "$TOGGLE_SCRIPT"

    # macOS netstat prints a wildcard listener as "*.8118", not "0.0.0.0.8118"
    local LISTEN
    LISTEN=$(netstat -an -p tcp 2>/dev/null | awk '$NF == "LISTEN" && $4 ~ /\.8118$/ {print $4}')
    if [[ -z "$LISTEN" ]]; then
        warn "Privoxy is not listening on :8118 — proxy stays OFF until it runs."
    elif grep -qvE '^(127\.0\.0\.1|::1)\.8118$' <<< "$LISTEN"; then
        warn "Privoxy exposed beyond loopback (${LISTEN//$'\n'/, }) — check listen-address!"
    else
        log "Privoxy: loopback only ✓"
    fi
}

disable_privoxy_autoswitch() {
    local DAEMON_PLIST="/Library/LaunchDaemons/com.hardening.proxytoggle.plist"
    local TOGGLE_SCRIPT="/usr/local/bin/proxy-toggle.sh"
    log "Disabling Privoxy VPN auto-switch..."
    _launchd_bootout com.hardening.proxytoggle
    sudo rm -f "$DAEMON_PLIST" "$TOGGLE_SCRIPT"
    log "  [✓] Privoxy auto-switch disabled"

    # The toggle may have left services pointing at 127.0.0.1:8118
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
        local ID="$1" DESC="$2" EXPECT="$3"
        shift 3
        local OUT
        OUT=$("$@" 2>/dev/null || true)
        if echo "$OUT" | grep -q "$EXPECT"; then
            log "  [${ID}] ${DESC}"
            PASS=$((PASS + 1))
        else
            err "  [${ID}] ${DESC}"
            info "       Expected pattern: '${EXPECT}'"
            info "       Got: $(echo "$OUT" | head -1)"
            FAIL=$((FAIL + 1))
        fi
    }

    # [1] Quad9 Profile active
    _chk "1" "Quad9 Profile active" "9\.9\.9" scutil --dns

    # [2] utun interfaces pass in the PF anchor:
    local PF_UTUN
    PF_UTUN=$(sudo pfctl -a "$PF_LOCK_ANCHOR" -sr 2>/dev/null | grep "utun" || true)
    if [[ -n "$PF_UTUN" ]]; then
        log "  [2] PF utun pass rule present ✓"
        PASS=$((PASS + 1))
    else
        err "  [2] PF utun pass rule MISSING"
        FAIL=$((FAIL + 1))
    fi

    # [3] Basic DNS resolution
    _chk "3" "Basic DNS resolution" "[0-9]" dig +short google.com

    # [4] DNSSEC ad flag
    _chk "4" "DNSSEC (ad flag)" " ad" dig +dnssec icann.org

    # [5] DNSSEC fail test — should return SERVFAIL
    _chk "5" "DNSSEC validation (SERVFAIL on bad domain)" "SERVFAIL" dig www.dnssec-failed.org

    # [6] Quad9 reachability
    _chk "6" "Quad9 DoH reachability" "Yes" curl -s --max-time 5 https://on.quad9.net

    # [7] Plain DNS locked from the outside
    local DNS_OUT
    # macOS has no `timeout`; use dig's own limits
    DNS_OUT=$(dig +time=3 +tries=1 google.com @8.8.8.8 2>/dev/null || true)
    if echo "$DNS_OUT" | grep -q "NOERROR"; then
        err "  [7] Plain DNS NOT blocked — leak possible (@8.8.8.8 responded)"
        info "       pf DNS lock may not be active"
        FAIL=$((FAIL + 1))
    else
        log "  [7] Plain DNS blocked (@8.8.8.8) ✓"
        PASS=$((PASS + 1))
    fi

    # [8] Split DNS configuration
    _chk "8" "Split DNS configuration" "resolver" scutil --dns

    # [9] pf enabled
    _chk "9" "pf firewall enabled" "Enabled" sudo pfctl -s info

    # [10] StevenBlack hosts
    local HOSTS_COUNT
    HOSTS_COUNT=$(grep -c "^0\.0\.0\.0" /etc/hosts 2>/dev/null || true)
    HOSTS_COUNT=${HOSTS_COUNT:-0}
    if [[ "$HOSTS_COUNT" -gt 1000 ]]; then
        log "  [10] StevenBlack hosts (${HOSTS_COUNT} entries) ✓"
        PASS=$((PASS + 1))
    else
        err "  [10] StevenBlack hosts (${HOSTS_COUNT} entries — too few)"
        FAIL=$((FAIL + 1))
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
    disable_privoxy_autoswitch   # also turns system web proxies off
    disable_hosts_blocklist
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
    echo "  ║            v0.17.3 ·  by Gr3y-foX         ║"
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
    # Re-exec natively if run from a Rosetta (x86_64) shell
    if [[ "$(sysctl -n sysctl.proc_translated 2>/dev/null)" == "1" ]]; then
        exec arch -arm64 /bin/bash "$0" "$@"
    fi
    main
fi

#!/bin/bash

# Debug script for network selection block
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "Select network scenario:"
echo "  [1] VPN Daily profile (ClearVPN / OpenVPN, without complex rules)"
echo "  [2] Paranoid Tor profile (maximum anonymity, complex scheme)"
echo "  [3] Open mac-hardening-netlib menu (manual blocks dnscrypt/PF/Privoxy)"
echo "  [4] Do nothing now"
echo ""
read -rp "Choice (1-4): " NET_CHOICE
echo ""

case "$NET_CHOICE" in
  1)
    log "Running VPN Daily profile..."
    bash "$SCRIPT_DIR/vpn_daily.sh"
    ;;
  2)
    log "Running Paranoid Tor profile..."
    bash "$SCRIPT_DIR/profile-paranoid-tor.sh"
    ;;
  3)
    log "Running mac-hardening-netlib menu..."
    bash "$SCRIPT_DIR/mac-hardening-netlib.sh"
    ;;
  4|"")
    log "Network profiles can be run manually later."
    ;;
  *)
    warn "Invalid choice. Network profiles not run."
    ;;
esac

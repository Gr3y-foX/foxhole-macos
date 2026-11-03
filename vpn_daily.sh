#!/bin/bash

# foxhole-macos — VPN Daily Profile
#
# File:    vpn_daily.sh
# Version: 0.17.2 (2026)
# Author:  Gr3y-foX
# Based on: drduh/macOS-Security-and-Privacy-Guide (MIT)
# License: GNU GPL v3 — see LICENSE for details
#
# Overview:
#   Profile for everyday use with a commercial VPN client
#   (e.g. ClearVPN, OpenVPN). DNS design (same as the netlib):
#     macOS DoH profile (Quad9) + PF anchor that blocks plain DNS (53/853)
#     on physical interfaces while letting VPN tunnels (utun+) pass.
#
# Assumptions:
#   - mac-hardening-install.sh was already executed.
#   - The Quad9 DoH configuration profile is installed in System Settings.
#   - mac-hardening-netlib.sh sits next to this script and provides:
#       * prepare_pf_dns_lock_anchor / enable_pf_dns_lock / disable_pf_dns_lock
#       * verify_dns_stack
#       * reset_net_hardening
#
# Behavior:
#   - Does not edit /etc/hosts and does not start Privoxy.
#   - Every PF change is reversible from this menu ([2] or [5]).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Provides log/warn/err/info/ask helpers and the network functions.
# shellcheck source=mac-hardening-netlib.sh
source "${SCRIPT_DIR}/mac-hardening-netlib.sh"

main() {
  clear
  echo ""
  echo "  ╔══════════════════════════════════════╗"
  echo "  ║          VPN Daily Profile          ║"
  echo "  ║      ClearVPN / OpenVPN friendly    ║"
  echo "  ╚══════════════════════════════════════╝"
  echo ""
  warn "Requires the Quad9 DoH profile. Without it, enabling the PF lock breaks DNS."
  info "Idea: set up once, turn on ClearVPN/OpenVPN, enjoy."
  ask "Continue?" CONFIRM
  [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && { echo "Aborted."; exit 0; }
  echo ""

  info "This script requires sudo for PF changes."
  sudo -v || die "sudo authentication failed."
  echo ""

  while true; do
    echo "Choose an action:"
    echo "  [1] Enable PF DNS lock (blocks plain DNS 53/853 outside the VPN tunnel)"
    echo "  [2] Disable PF DNS lock"
    echo "  [3] DNS stack health check"
    echo "  [4] Tips for ClearVPN/OpenVPN and DNS leak tests"
    echo "  [5] RESET: roll back PF lock, proxies and hosts blocklist (netlib)"
    echo "  [6] Exit"
    echo ""
    read -rp "Choice (1-6): " CHOICE
    echo ""

    case "$CHOICE" in
      1)
        log "[1] Enable PF DNS lock"
        prepare_pf_dns_lock_anchor
        enable_pf_dns_lock
        echo ""
        ;;

      2)
        log "[2] Disable PF DNS lock"
        disable_pf_dns_lock
        echo ""
        ;;

      3)
        verify_dns_stack
        ;;

      4)
        echo "=== How to use this profile with ClearVPN + OpenVPN ==="
        echo ""
        echo "1) Install the Quad9 DoH profile (System Settings > Privacy & Security > Profiles)."
        echo "2) Install and configure ClearVPN, or an OpenVPN client"
        echo "   (Tunnelblick / OpenVPN Connect) and import the .ovpn file."
        echo "3) Run [1] to enable the PF DNS lock."
        echo "   VPN traffic on utun interfaces is not affected by the lock."
        echo "4) If DNS stops working: run [2] to disable the lock, then [3] to diagnose."
        echo ""
        echo "=== How to check that the VPN is working and there are no DNS leaks ==="
        echo "   1) Connect to the VPN."
        echo "   2) Open a DNS leak test in your browser, for example:"
        echo "      - https://ipleak.net/"
        echo "      - https://www.dnsleaktest.com/"
        echo "   3) Make sure that:"
        echo "      - IP and geolocation match the VPN, not your ISP."
        echo "      - DNS servers belong to the VPN (or Quad9), not your local ISP."
        echo ""
        ;;

      5)
        warn "[5] RESET: disables PF lock, Privoxy auto-switch, hosts blocklist and system proxies"
        ask "Execute reset_net_hardening()?" CONFIRM_RESET
        if [[ "$CONFIRM_RESET" == "y" || "$CONFIRM_RESET" == "Y" ]]; then
          reset_net_hardening
        else
          log "Reset cancelled."
        fi
        echo ""
        ;;

      6)
        echo "Done. For daily use: turn on your VPN and forget about it."
        exit 0
        ;;

      *)
        warn "Invalid choice. Specify 1-6."
        echo ""
        ;;
    esac
  done
}

if [[ "${0##*/}" == "vpn_daily.sh" ]]; then
  main
fi

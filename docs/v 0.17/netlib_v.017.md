## [v0.17] — PF Anchor Rewrite + dnscrypt-proxy Removal
**Date:** 2026-05-04
**Branch:** debug → main (pending)

---

### Summary
Removed dnscrypt-proxy entirely from the stack due to architectural
conflicts with the macOS native DoH profile. Rewrote the PF anchor
to fix packet drops on VPN tunnel interfaces (utun0–utun9).

---

### Bug → Cause → Fix

#### [B-1] 🔴 Packets dropped on active VPN (utun0–utun9)
**Bug:**
All outbound traffic dropped when any VPN client (ClearVPN, ProtonVPN,
WireGuard, etc.) was active. Affected: DNS resolution, general traffic
inside the tunnel.

**Cause:**
PF `block` rules in the DNS leak anchor used no interface qualifier:
  block out quick proto { udp tcp } to any port 53
This applied to ALL interfaces — including utun+ — not just physical
adapters (en0/en1). VPN clients route traffic through utun, which was
caught by the blanket block before any pass rule could match.

**Fix:**
Added explicit `pass out/in quick on utun+ all` as the first rule after
loopback. Changed `block` rules to target physical interfaces only:
  block out quick on { en0 en1 en2 bridge0 } proto { udp tcp } to any port 53
utun+ is now fully unmanaged by the anchor — the VPN client handles
its own tunnel policy.

---

#### [B-2] 🟠 dnscrypt-proxy conflicts with macOS DoH profile
**Bug:**
When both dnscrypt-proxy (port 5355) and the macOS native Quad9 DoH
Configuration Profile were active, DNS resolution became non-deterministic.
Some queries resolved via DoH, others via dnscrypt relay — health check
tests [3]–[5] produced inconsistent results across reboots.

**Cause:**
macOS mDNSResponder + a DoH Configuration Profile already provides
encrypted, DNSSEC-validated resolution via Quad9. Running dnscrypt-proxy
in parallel created a split-stack with no clear priority. The two
resolvers competed for the same query path.

**Fix:**
Removed dnscrypt-proxy from the stack entirely:
- Deleted: install_dnscrypt(), configure_dnscrypt(),
           enable_dnscrypt(), disable_dnscrypt()
- Removed: menu item [1] (dnscrypt setup)
- Removed: health check test [2] (UDP:5355 listener check)
- Replaced test [2] with: scutil --dns Quad9 DoH profile verification
  and pfctl utun+ pass rule presence check.

DNS stack is now: macOS DoH Profile (Quad9) → PF anchor (leak lock)

---

### Anchor diff (key changes)
- ADDED:   pass out quick on utun+ all
- ADDED:   pass in  quick on utun+ all
- ADDED:   pass out to 9.9.9.11, 149.112.112.11  (Quad9 ECS endpoints)
- CHANGED: block rules scoped to { en0 en1 en2 bridge0 } only
- REMOVED: any reference to port 5355 (dnscrypt-proxy)

---

### DNS Stack (v0.17)
  [App] → mDNSResponder → DoH Profile (Quad9 9.9.9.9:443)
                        → PF anchor blocks plain DNS on en0/en1
                        → utun+ fully passed (VPN-managed)
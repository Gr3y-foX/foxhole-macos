# 🦊 Foxhole-macos — macOS Security Hardening 2026

Advanced hardening toolkit for macOS (Intel + Apple Silicon), focused on **practical security baselines** and **network‑safe profiles**, inspired by [drduh/macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide).

<div align="left">

![Platform](https://img.shields.io/badge/platform-macOS_13%2B-lightgrey?logo=apple)
![Shell](https://img.shields.io/badge/shell-bash%20%7C%20zsh-blue)
![License](https://img.shields.io/badge/license-GPLv3-green)
![Status](https://img.shields.io/badge/status-experimental-orange)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
  - [Base hardening](#base-hardening)
  - [Network hardening architecture](#network-hardening-architecture)
  - [Profiles](#profiles)
- [Requirements](#requirements)
- [Usage](#usage)
  - [1. Base install](#1-base-install)
  - [2. Network hardening & profiles](#2-network-hardening--profiles)
- [Documentation](#documentation)
- [Warnings & Disclaimer](#warnings--disclaimer)
- [Attribution](#attribution)
- [License](#license)
- [Roadmap](#roadmap)

---

## Overview

**foxhole-macos** is a modular hardening toolkit for macOS.  
The goal is a **safe, composable setup** that:

- Improves local system security without breaking basic network connectivity.
- Provides reusable network hardening primitives (DNS, PF, proxies).
- Offers separate profiles for different threat models (daily VPN user vs. paranoid Tor routing).

This project is developed by a cybersecurity student and is intended for **power users and security practitioners**, not for fully managed enterprise deployments.

---

## Features

### Base hardening

The base installer (`mac-hardening-install.sh`) focuses on **local system security** and deliberately avoids risky network changes:

- Homebrew bootstrap and sanity checks.
- macOS Application Firewall configuration (`socketfilterfw`):
  - Enables the firewall.
  - Enables stealth mode.
  - Disables auto‑allowing signed apps.
- Security tooling (via Homebrew / casks), for example:
  - Objective‑See tools (LuLu, BlockBlock, KnockKnock, Do Not Disturb).
  - `lynis` for system audits.
  - `pipx` + `pip-audit` (Python dependency CVE scanning).
  - `brew-vulns` (Homebrew package CVE scanning).
  - Optional: Mergen (CIS benchmark GUI).
- Optional compiler hardening:
  - Adjusts permissions or adds Lynis exceptions for HRDN‑7222.
- Privacy‑oriented defaults:
  - Password on screensaver resume.
  - No GUI crash reporter dialogs.
  - Show hidden files and all extensions.
  - Disable “save new documents to iCloud” by default.

The base installer **does not**:

- Touch `/etc/pf.conf`.
- Change system proxies.
- Start custom DNS or HTTP proxies by default.

This keeps the **first run** as safe and reversible as possible.

---

### Network hardening architecture

Network functionality is split into two layers:

1. **Network library** — `mac-hardening-netlib.sh`  
   Low‑level, reusable functions for the PF DNS leak lock, Privoxy, and `/etc/hosts` blocklists.
2. **Profiles** — e.g. `vpn_daily.sh`  
   High‑level scripts that call the netlib with a specific threat model.

This design lets you reuse the same primitives across multiple profiles without duplicating logic.

#### mac-hardening-netlib.sh

Key building blocks include:

- **DNS stack** (v0.17.1+)
  DNS is handled by the **macOS DoH configuration profile (Quad9)**. `dnscrypt-proxy` was removed because it conflicts with the profile.

- **PF DNS leak lock**
  - `prepare_pf_dns_lock_anchor`
    Writes the anchor `/etc/pf.anchors/com.hardening.dnsleak`:
    - Passes loopback, all VPN tunnels (`utun0`–`utun15`, listed explicitly: PF on macOS has no `utun+` wildcard) and ICMPv6 (RFC 4890).
    - Applies the DNS policy (`FOXHOLE_DNS_MODE`, or a prompt in the menu; unattended runs and `FOXHOLE_ASSUME_YES=1` use `doh`):
      - `doh` (default): Quad9 is reachable on **tcp 443 only** (the DoH profile); plain DNS to 9.9.9.9 is blocked.
      - `vpn`: no Quad9 exception; DNS leaves only through the VPN tunnel. Set your resolver inside the VPN (for example Mullvad with Quad9).
      - `plain`: Quad9 on any port (plain DNS to 9.9.9.9), for setups without a DoH profile.
    - Blocks plain DNS and DNS‑over‑TLS (ports 53/853, IPv4 and IPv6) on **physical interfaces only** (`en*`, detected with `networksetup`).
  - `enable_pf_dns_lock` (v0.17.3+)
    Loads the rules into `com.apple/foxhole.dnsleak`, a child of the `com.apple/*` anchor that the stock `/etc/pf.conf` already evaluates. `/etc/pf.conf` is **not edited** and the main ruleset is **not reloaded**, so other PF users (e.g. a VPN kill switch) keep their rules. PF is enabled with a reference token (`pfctl -E`). A helper (`/usr/local/libexec/foxhole-pf-dnslock start|stop|status`) does the work. A LaunchDaemon runs it again at every boot. At each start it re-reads the physical interfaces, so a network card added later is covered too (falls back to the rules as written). Enable refuses to run if the main ruleset does not evaluate `com.apple/*`.
  - `disable_pf_dns_lock`
    Flushes the rules and releases the token (`pfctl -X`), so PF goes back to off unless another program still holds a reference. Removes the helper, the rules file and the LaunchDaemon. Installs from v0.17.2 or older, which edited `/etc/pf.conf`, are cleaned up automatically on enable or disable.
  - Inspect: `sudo pfctl -a com.apple/foxhole.dnsleak -sr` (rules), `sudo pfctl -s References` (who keeps PF on), `/var/log/foxhole-pf.log`.

- **/etc/hosts blocklist**
  - `update_hosts_blocklist`  
    Integrates the StevenBlack hosts file under a clear marker, preserves existing entries above it, and logs SHA‑256 of the downloaded list for manual verification.
  - `disable_hosts_blocklist`  
    Removes the blocklist section by marker while keeping original hosts entries.

- **Privoxy**
  - `install_privoxy`  
    Installs Privoxy and validates its config path using `brew --prefix`.
  - `configure_privoxy_vpn_bypass`  
    Adds forwarding rules so private/VPN ranges bypass the proxy.
  - `enable_privoxy_vpn_autoswitch`  
    Creates a `proxy-toggle.sh` script and LaunchDaemon that:
    - Detects a VPN via `scutil --nc` ("(Connected)") or a `utun` interface with an IPv4 address (Mullvad, ClearVPN, OpenVPN; Tailscale ignored).
    - Turns system HTTP/HTTPS proxy **ON** (`127.0.0.1:8118`) when no VPN is active and Privoxy is listening.
    - Turns proxy **OFF** when a VPN is active.
    - Implements simple log rotation for `/var/log/proxy-toggle.log`.
  - `disable_privoxy_autoswitch`  
    Unloads and removes the LaunchDaemon and toggle script, and turns system web proxies off.

- **Global reset**
  - `reset_net_hardening`  
    Convenience helper that attempts to:
    - Remove the hosts blocklist.
    - Disable PF DNS lock.
    - Disable Privoxy auto‑switch.
    - Clear system HTTP/HTTPS proxy settings across all network services.

You can run `mac-hardening-netlib.sh` directly (it has its own menu), but the common pattern is to `source` it from profile scripts.

---

### Profiles

Profiles define **how** to use the netlib for a specific threat model.

#### VPN Daily — `vpn_daily.sh`

Threat model: everyday user with a commercial VPN (e.g. ClearVPN, OpenVPN) who wants “**turn on VPN and forget**”.

Design goals:

- No PF kill‑switches.
- PF changes are limited to the DNS leak lock anchor and are reversible from the menu.
- No Privoxy auto‑proxy for non‑technical users.
- DNS changes are minimal and easily reversible (Quad9 DoH profile + PF anchor).

Menu actions:

- **[1] Enable PF DNS lock** — blocks plain DNS (53/853) on physical interfaces; VPN tunnels are not affected.
- **[2] Disable PF DNS lock**
- **[3] DNS stack health check** (`verify_dns_stack`)
- **[4] Usage & DNS‑leak guidance** (ClearVPN / OpenVPN, ipleak.net, dnsleaktest.com)
- **[5] Reset** — calls `reset_net_hardening` from the netlib
- **[6] Exit**

In the default `doh` and in `plain` mode the Quad9 DoH profile (or a Quad9 plain-DNS resolver) must be set up first; otherwise the PF lock breaks DNS. In `vpn` mode set the DNS resolver inside your VPN. The lock asks for the mode when you enable it.

This profile is intentionally **non‑destructive** and aims to be safe for non‑experts.

> Planned: a separate `profile-paranoid-tor.sh` that uses PF DNS lock, Privoxy→Tor, and stronger traffic constraints. This profile is **not** meant for casual users.

---

## Requirements

- macOS (tested on recent versions with zsh/bash).
- Non‑root user with `sudo` privileges.
- Stable internet connection.
- [Homebrew](https://brew.sh/) (the installer will offer to install it if missing).

---

## Usage

### 1. Base install

```bash
git clone https://github.com/Gr3y-foX/foxhole-macos.git
cd foxhole-macos

### Run base installer (not as root)
bash mac-hardening-install.sh
```
The installer will:

- Check for Homebrew and `curl`.
- Install/update security tools.
- Configure firewall and privacy defaults.
- Offer to continue into network hardening.

---

### 2. Network hardening & profiles

After the base install, you can either:

- Let the installer launch a profile immediately, or
- Run profiles manually later:
```
### Netlib menu (advanced, manual building blocks)
bash mac-hardening-netlib.sh

### Everyday VPN profile (ClearVPN/OpenVPN)
bash vpn_daily.sh

### (Future) Paranoid Tor profile
bash profile-paranoid-tor.sh

```

### Unattended runs and tests
- `FOXHOLE_ASSUME_YES=1` answers every prompt "y" (the DNS mode defaults to `doh`; set `FOXHOLE_DNS_MODE=doh|vpn|plain` to choose).
- `bash tests/ci/offline.sh` checks the scripts without touching the system.
- `FOXHOLE_VM_NET=bridged bash tests/vm/run.sh --reset` runs the full suite in a Tart VM (never on your Mac). Logs go to `docs/testing/logs/`; see `docs/testing/README.md`. `FOXHOLE_VM_BASE=foxhole-brew` starts from an image with Homebrew, which also runs the real-Privoxy (T18) and real-WireGuard (T19) tests.

---

## Documentation

See [`docs/`](docs/README.md): release notes in `docs/changelog/`, how the scripts are tested in `docs/testing/` (offline checks and the Tart VM suite), maintainer working notes in `docs/dev/`, old material in `docs/archive/`.

---

## Warnings & Disclaimer

- This project is developed as part of ongoing **cybersecurity studies** and personal research.  
  It is **not** an officially audited, enterprise‑grade hardening framework.
- PF, DNS, and proxy changes can break connectivity if misconfigured.  
  Use the **VPN Daily** profile for non‑experts and only experiment with PF‑based DNS lock or kill‑switches if you understand the implications.
- This toolkit is **not** a magic “secure my Mac” button. It provides opinionated building blocks for security baselines.
- Always keep backups and test on a non‑critical machine first.
- The author assumes **no responsibility** for any damage, data loss, or outages caused by using these scripts in production or unsafe environments.

---

## Attribution

Based on the excellent  
[macOS Security and Privacy Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide)  
by [@drduh](https://github.com/drduh) — [MIT License](https://opensource.org/licenses/MIT).

---

## License

This project is licensed under **GNU GPL v3**.  
See [LICENSE](./LICENSE) for full details.

---

## Roadmap

- Finalize `profile-paranoid-tor.sh` (Tor routing, Privoxy integration, PF‑based DNS lock).
- Add automated checks:
  - DNS leak tests.
  - Basic connectivity tests after applying profiles.
- Improve logging and dry‑run options for all scripts.
- Add versioning and changelog per macOS release.
- Document example threat models and recommended combinations of profiles.


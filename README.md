# new readme
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
   Low‑level, reusable functions for DNSCrypt, PF, Privoxy, and `/etc/hosts` blocklists.
2. **Profiles** — e.g. `profile-vpn-daily.sh`  
   High‑level scripts that call the netlib with a specific threat model.

This design lets you reuse the same primitives across multiple profiles without duplicating logic.

#### mac-hardening-netlib.sh

Key building blocks include:

- **DNSCrypt**
  - `install_dnscrypt`, `enable_dnscrypt`, `disable_dnscrypt`  
    Installs and controls `dnscrypt-proxy` as a **user‑level** service (no `sudo brew services`).  
    Provides encrypted DNS on localhost (e.g. `127.0.0.1:5355`).

- **PF DNS leak lock**
  - `prepare_pf_dns_lock_anchor`  
    Writes PF anchor (`/etc/pf.anchors/com.hardening.dnsleak`) with rules that:
    - Allow DNS over HTTPS from `127.0.0.1` / `::1` to ports 443/8443.
    - Block direct DNS (ports 53/853) for IPv4 and IPv6.
  - `enable_pf_dns_lock`  
    Appends a marker + anchor load block into `/etc/pf.conf` and reloads PF.
  - `disable_pf_dns_lock`  
    Removes the marker and anchor from PF and reloads a clean configuration.

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
    - Detects VPN presence via `utun` interfaces.
    - Turns system HTTP/HTTPS proxy **ON** (`127.0.0.1:8118`) when no VPN is active.
    - Turns proxy **OFF** when a VPN is active.
    - Implements simple log rotation for `/var/log/proxy-toggle.log`.
  - `disable_privoxy_autoswitch`  
    Unloads and removes the LaunchDaemon and toggle script.

- **Global reset**
  - `reset_net_hardening`  
    Convenience helper that attempts to:
    - Stop `dnscrypt-proxy`.
    - Disable PF DNS lock.
    - Disable Privoxy auto‑switch.
    - Clear system HTTP/HTTPS proxy settings across all network services.

You can run `mac-hardening-netlib.sh` directly (it has its own menu), but the common pattern is to `source` it from profile scripts.

---

### Profiles

Profiles define **how** to use the netlib for a specific threat model.

#### VPN Daily — `profile-vpn-daily.sh`

Threat model: everyday user with a commercial VPN (e.g. ClearVPN, OpenVPN) who wants “**turn on VPN and forget**”.

Design goals:

- No PF kill‑switches by default.
- No direct editing of `/etc/pf.conf` from this profile.
- No Privoxy auto‑proxy for non‑technical users.
- DNS changes are minimal and easily reversible.

Menu actions:

- **[1] Without VPN — enable `dnscrypt-proxy`**
  - Installs + enables `dnscrypt-proxy` as a user service.
  - Provides local encrypted DNS when browsing on regular Wi‑Fi.

- **[2] With VPN — disable `dnscrypt-proxy`**
  - Lets the VPN client fully control DNS (recommended for simpler setups).
  - Avoids conflicts between system DNS and VPN‑pushed resolvers.

- **[3] Usage & DNS‑leak guidance**
  - Explains how to:
    - Combine ClearVPN / OpenVPN with this profile.
    - Test VPN and DNS leaks via online tools (ipleak.net, dnsleaktest.com, etc.).

- **[4] Reset**
  - Calls `reset_net_hardening` from the netlib to undo DNS/proxy changes.

- **[5] Exit**

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
bash profile-vpn-daily.sh

### (Future) Paranoid Tor profile
bash profile-paranoid-tor.sh

```

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


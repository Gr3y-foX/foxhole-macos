# CLAUDE.md

Guidance for Claude Code when working in this repo.

## What this is

**foxhole-macos** — a bash toolkit that hardens macOS (Intel + Apple Silicon): base system hardening plus reusable network-hardening primitives (PF DNS-leak lock, `/etc/hosts` blocklist, Privoxy with VPN-aware auto-switching). GPLv3, experimental, written by a cybersecurity student for power users. Based on drduh/macOS-Security-and-Privacy-Guide.

These scripts change **live system state** (firewall, `/etc/pf.conf`, `/etc/hosts`, system proxies, LaunchDaemons). A bug can cut the user's network. Treat every edit with that in mind.

## Layout

| Path | Role |
|---|---|
| `mac-hardening-install.sh` | Base installer: Homebrew, app firewall, security tools (Objective-See, lynis, pip-audit…), privacy defaults. Deliberately does **not** touch PF, proxies or DNS. |
| `mac-hardening-netlib.sh` | Network library (current v0.17.2). Source it from profiles, or run directly for its own menu. Holds PF anchor, hosts blocklist, Privoxy autoswitch, `verify_dns_stack`, `reset_net_hardening`, backups. |
| `vpn_daily.sh` | "VPN Daily" profile: sources the netlib (path resolved from the script), menu for the PF DNS lock, health check and reset. |
| `profile-paranoid-tor.sh` | Stub (header only). Planned Tor/PF/Privoxy profile. |
| `docs/archive/debug_netlib/`, `debug/` | Work-in-progress copies, audit reports, handoff notes, draw.io diagrams. **Not shipped**; `docs/archive/debug_netlib/handoff.md` and `docs/v 0.17/` are the fix lists/changelog notes for the current release. |
| `free-claude-code/` | Unrelated, separately-cloned Python project (own CLAUDE.md, untracked). Ignore it for foxhole work. |

Branches: `main` (release), `debug` (current work). Remote `origin` is `Gr3y-foX/macos-sec-harder-26` (the GitHub repo is also known as `foxhole-macos`).

## Commands

There is no build system or test suite.

```bash
bash -n mac-hardening-netlib.sh          # syntax check (do this after every edit)
shellcheck mac-hardening-*.sh vpn_daily.sh   # lint (shellcheck is NOT installed yet: brew install shellcheck)
bash mac-hardening-install.sh            # run as normal user, never root; uses sudo internally
bash mac-hardening-netlib.sh             # interactive netlib menu
```

Do **not** run the installer, netlib menu or any `pfctl`/`networksetup`/`launchctl` command to "test" a change unless the user asks — they modify the real machine. Prefer `bash -n`, shellcheck, and reading the code. Netlib backups go to `~/.foxhole/backups/<timestamp>/`.

## Conventions

- Shell is `bash` (`#!/bin/bash`), `set -euo pipefail`. Keep scripts compatible with macOS's stock bash 3.2 (no associative arrays, no `${var,,}`, no `mapfile`).
- Shared helpers (duplicated at the top of each script): `log` `[+]`, `warn` `[!]`, `err` `[✗]`, `info` `[i]`, `die`, `ask`. Reuse them; don't invent new output styles.
- `ask` must never use `eval` (v0.17.1 fixed a shell-injection there) — use `printf -v`. Quote all variables; never interpolate untrusted input into `sudo`/`sh -c`/XML/plist strings.
- Resolve Homebrew via `resolve_brew_prefix` (Intel `/usr/local` vs Apple Silicon `/opt/homebrew`) — never hard-code.
- Anything that edits system config must be **idempotent**, wrapped in a clear marker (see PF anchor / hosts blocklist), have a matching `disable_*`/rollback, and be covered by `reset_net_hardening`. Snapshot first with `create_net_backup`.
- PF rules must keep VPN tunnels (`utun0-9`) passing and scope blocks to physical interfaces; DNS design is macOS DoH profile (Quad9) + PF leak-lock anchor. `dnscrypt-proxy` was **removed** in v0.17.1 — don't reintroduce it.
- Each script has a version/date header; bump it and note the change when behaviour changes. Commit style so far: `v0.17.1 - short summary` or `fix(netlib): …` / `docs: …`.

## Testing without touching the system

- Generate the PF anchor with `sudo` stubbed, then check it offline: `pfctl -nvf <anchor file>`.
- Test `disable_pf_dns_lock` against a copy of `/etc/pf.conf` by rewriting the path in a sourced copy of the function.
- `verify_dns_stack` is read-only apart from `sudo pfctl -s info`.

## Working notes

- Docs and handoff notes mix English and Russian; reply to the user in the language they write in, write code comments and commit messages in English.
- Don't commit `.DS_Store`, `.gitnexus/` index files or `free-claude-code/`.
- The user's home directory is itself a git repo; stay inside this repo's root for all git operations.

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **macos-sec-harder-26** (7373 symbols, 18514 relationships, 400 execution flows).

> Index stale? Run `node .gitnexus/run.cjs analyze --index-only` from the project root — it auto-selects an available runner. No `.gitnexus/run.cjs` yet? Bootstrap with `npx`, `bunx`, or `pnpm dlx` — e.g. `bunx gitnexus@latest analyze` (npm 11 npx crash; #1939).

## Always Do

- **MUST run impact before editing.** Use `impact({target: "symbolName", direction: "upstream"})` or `node .gitnexus/run.cjs impact "symbolName" --direction upstream --repo .`; report callers, processes, and risk. Never substitute grep for graph analysis.
- **MUST analyze graph changes before committing.** Use `detect_changes({scope: "all"})` (MCP) or `node .gitnexus/run.cjs detect-changes --scope all --repo .` (CLI fallback). `partial: true` or `truncated: true` is not a clean check — a zero means unseen, not unaffected; re-run it. For regression review: `detect_changes({scope: "compare", base_ref: "main"})` or `node .gitnexus/run.cjs detect-changes --scope compare --base-ref "main" --repo .`.
- **MUST warn the user before editing** if impact returns HIGH or CRITICAL `risk`; report the direct callers, affected processes and risk level to the user. Never use `riskSharedAxes` to waive a HIGH/CRITICAL `risk` warning. Compare File/symbol: MCP File omits axes; Graph-RAG expands File.
- **Bash in this repo: expect `UNKNOWN`.** GitNexus does not resolve calls between shell functions and `source`d files, so `impact` on netlib/installer functions usually returns `UNKNOWN`. Confirm callers with `grep -rn` over the repo's `*.sh` files (the repo's own rule: `bash -n`, shellcheck, and reading the code), then state that you did so.
- **MUST treat `risk: UNKNOWN` as unresolved, not as low.** An empty caller set is not evidence the symbol is unused — it can also mean the callers are not resolvable by the index (plain-object property access, dynamic dispatch, cross-language calls). `impact` pairs `UNKNOWN` with a `riskNote` saying so. Confirm with a text search before treating the symbol as safe to change or delete; do not proceed on the strength of a zero.
- **MUST use `query({search_query: "concept"})` for concepts/flows, `context({name: "symbolName"})` for a named symbol, or `impact` for blast radius, on read-only callers, dependencies, imports, or execution flow.** Graph first; text search only for empty/`UNKNOWN`/literals.
- For security review, `explain({target: "fileOrSymbol"})` lists taint findings (source→sink flows; needs `analyze --pdg`).

## Never Do

- NEVER edit a function, class, or method before MCP/CLI impact analysis.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis, and never read `UNKNOWN` as an all-clear — it means the walk could not answer, which is the one verdict that requires confirming by other means.
- NEVER rename symbols with find-and-replace — use `rename` which understands the call graph.
- NEVER commit before MCP/CLI graph change analysis.

## Resources

| Resource | Use for |
| --- | --- |
| `gitnexus://repo/macos-sec-harder-26/context` | Codebase overview, check index freshness |
| `gitnexus://repo/macos-sec-harder-26/clusters` | All functional areas |
| `gitnexus://repo/macos-sec-harder-26/processes` | All execution flows |
| `gitnexus://repo/macos-sec-harder-26/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
| --- | --- |
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->

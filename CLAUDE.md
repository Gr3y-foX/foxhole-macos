# CLAUDE.md

Guidance for Claude Code when working in this repo.

## What this is

**foxhole-macos** — a bash toolkit that hardens macOS (Intel + Apple Silicon): base system hardening plus reusable network-hardening primitives (PF DNS-leak lock, `/etc/hosts` blocklist, Privoxy with VPN-aware auto-switching). GPLv3, experimental, written by a cybersecurity student for power users. Based on drduh/macOS-Security-and-Privacy-Guide.

These scripts change **live system state** (firewall, `/etc/pf.conf`, `/etc/hosts`, system proxies, LaunchDaemons). A bug can cut the user's network. Treat every edit with that in mind.

## Layout

| Path | Role |
|---|---|
| `mac-hardening-install.sh` | Base installer: Homebrew, app firewall, security tools (Objective-See, lynis, pip-audit…), privacy defaults. Deliberately does **not** touch PF, proxies or DNS. Option [2] of its network menu (Tor profile) is a "planned" message only. |
| `mac-hardening-netlib.sh` | Network library (current **v0.17.3**). Source it from profiles, or run directly for its own menu. Holds the PF DNS lock (anchor + boot helper + LaunchDaemon), hosts blocklist, Privoxy autoswitch, `verify_dns_stack`, `reset_net_hardening`, backups (`create_net_backup` also writes `restore.sh`). |
| `vpn_daily.sh` | "VPN Daily" profile: sources the netlib (path resolved from the script), menu for the PF DNS lock, health check and reset. |
| `profile-paranoid-tor.sh` | Stub (header only). Planned Tor/PF/Privoxy profile. |
| `tests/ci/offline.sh` | Offline checks (sudo shimmed, nothing touches the system). Run by CI. |
| `tests/vm/` | Tart VM suite: `run.sh` (full run, log to `docs/testing/logs/`), `vm.sh` (ad-hoc VM work), `vmtest.sh` (runs inside the VM, sections T0–T19). |
| `.github/workflows/lint.yml` | CI: shellcheck (Linux), bash 3.2 syntax + `tests/ci/offline.sh` (macOS). |
| `docs/` | `changelog/` (release notes), `testing/` (README, `reports/`, `logs/`), `dev/` (maintainer working notes: start at `dev/CHECKPOINT.md`), `archive/` (old copies, audits). Index: `docs/README.md`. |
| `debug/` | Local scratch (git-ignored): drawings, notes. Not shipped. |
| `free-claude-code/` | Unrelated, separately-cloned Python project (own CLAUDE.md, untracked, in `.gitnexusignore`). Ignore it for foxhole work. |

Branches: `main` (release), `debug` (current work; **PR #1 `debug` → `main` is open**, every push to `debug` updates it). Remote `origin` is `git@github-foxhole:Gr3y-foX/foxhole-macos.git` (SSH alias from `~/.ssh/config`; the repo used to be `macos-sec-harder-26`).

## Commands

The checks are scripts, not a build system.

```bash
bash -n mac-hardening-netlib.sh                    # syntax check (after every edit)
shellcheck -S warning mac-hardening-*.sh vpn_daily.sh tests/ci/offline.sh tests/vm/*.sh
bash tests/ci/offline.sh                           # offline checks, nothing touches the system
FOXHOLE_VM_NET=bridged bash tests/vm/run.sh --reset   # full suite in the Tart VM (SSD mounted)
FOXHOLE_VM_BASE=foxhole-brew FOXHOLE_VM_NET=bridged bash tests/vm/run.sh --reset   # + real Privoxy (T18) and WireGuard (T19)
```

Do **not** run the installer, the netlib menu or any `pfctl`/`networksetup`/`launchctl` command on the host to test a change. They modify the real machine: use the VM. Netlib backups go to `~/.foxhole/backups/<timestamp>/` (`restore.sh` inside restores them).

## Conventions

- Shell is `bash` (`#!/bin/bash`), `set -euo pipefail`. Keep scripts compatible with macOS's stock bash 3.2 (no associative arrays, no `${var,,}`, no `mapfile`).
- Shared helpers (duplicated at the top of each script): `log` `[+]`, `warn` `[!]`, `err` `[✗]`, `info` `[i]`, `die`, `ask`. Reuse them; don't invent new output styles. `FOXHOLE_ASSUME_YES=1` answers every `ask` with "y" (unattended runs and tests).
- `ask` must never use `eval` (v0.17.1 fixed a shell-injection there) — use `printf -v`. Quote all variables; never interpolate untrusted input into `sudo`/`sh -c`/XML/plist strings.
- Resolve Homebrew via `resolve_brew_prefix` (Intel `/usr/local` vs Apple Silicon `/opt/homebrew`) — never hard-code.
- Anything that edits system config must be **idempotent**, wrapped in a clear marker (see PF anchor / hosts blocklist), have a matching `disable_*`/rollback, and be covered by `reset_net_hardening`. Snapshot first with `create_net_backup`.
- **PF lock design (v0.17.3):** rules live in the child anchor `com.apple/foxhole.dnsleak` (rules file `/etc/pf.anchors/com.hardening.dnsleak`). `/etc/pf.conf` is **never edited** and the main ruleset is never reloaded (VPN kill switches keep working). PF is enabled by reference token (`pfctl -E` / `-X`). One helper `/usr/local/libexec/foxhole-pf-dnslock start|stop|status` serves enable, disable and the boot LaunchDaemon; launchd uses `bootstrap`/`bootout`, never `load`/`unload`. Keep it that way.
- PF rules must keep VPN tunnels passing (`utun0`–`utun15`, listed explicitly: PF on macOS has **no `utun+` wildcard**) and scope blocks to physical interfaces. PF prints rules differently than written (`inet proto tcp … port = 443`): test against `pfctl -sr` output, not the source text.
- **DNS modes** (`FOXHOLE_DNS_MODE`): `doh` (default, Quad9 on tcp 443 only), `vpn` (no Quad9 exception, DNS only through the tunnel), `plain` (Quad9 any port). The design is macOS DoH profile (Quad9) + PF leak-lock anchor. `dnscrypt-proxy` was **removed** in v0.17.1 — don't reintroduce it.
- No temp files in root-run helpers (a `/var/run` temp file once leaked from the boot daemon): pass data to `pfctl -f -` on stdin.
- Each script has a version/date header; bump it and note the change in `docs/changelog/` when behaviour changes. Commit style so far: `v0.17.1 - short summary` or `fix(netlib): …` / `feat(netlib): …` / `docs: …` / `test(vm): …`.

## Testing

- `tests/ci/offline.sh` renders the PF anchor with `sudo` stubbed (all three DNS modes) and checks it; it runs in CI.
- `tests/vm/run.sh` runs `tests/vm/vmtest.sh` in the Tart VM `foxhole-test` (images on the SSD `Disc Samsung T7`; `foxhole-clean` is the base, `foxhole-brew` adds Homebrew). Covers enable/disable, helper start, migration from ≤0.17.2, Privoxy toggle, installer fixes, backups, DNS modes, real Privoxy, real WireGuard. Add a section there for every behaviour change, then run the whole suite; the result goes into `docs/testing/reports/`.
- When a test fails, check whether the test or the product is wrong (twice it was the test: PF rule text, a new prompt). Don't weaken a check to get green.
- `verify_dns_stack` is read-only apart from `sudo pfctl -s info`.
- Details: `docs/testing/README.md`.

## Working notes

- **Resume a session:** read `docs/dev/CHECKPOINT.md`, then `docs/dev/SESSION_PLAN.md` and `docs/dev/NEXT_SESSION.md`. Keep CHECKPOINT current before ending a session.
- Work on `debug` only. No push to `main`, no PR actions unless the user asks. The session's GitHub connection can read PRs but may not edit them (403): put suggested PR text in `docs/dev/` for the user to paste.
- Push: `git push -u origin debug` over SSH. In a sandboxed session `ssh`/`git push`/`tests/ci/offline.sh` need the sandbox off (DNS and `mktemp` are blocked).
- Commit footer: the Co-Authored-By line from the session's attribution reminder. Never commit `.DS_Store`, `.claude/`, `.gitnexus/` or `free-claude-code/`.
- A Mullvad account number (or any credential) the user mentions for a VM test is never written to files, git, logs or memory.
- Docs and handoff notes mix English and Russian; reply to the user in the language they write in, write code comments and commit messages in English.
- The user's home directory is itself a git repo; stay inside this repo's root for all git operations.

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **macos-sec-harder-26** (348 symbols, 338 relationships, 0 execution flows; re-run `analyze` to refresh).

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

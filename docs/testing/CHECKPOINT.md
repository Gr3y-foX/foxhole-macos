# Checkpoint — 2026-11-03 (resume here)

## State
- Branch `debug` pushed at `27fc974`. `main` still v0.16.1. PR debug→main: GitHub form was opened, **unknown if submitted** — check `github.com/Gr3y-foX/foxhole-macos/pulls`.
- Uncommitted on purpose: `CLAUDE.md`, `AGENTS.md` (the user's own edits — don't touch without asking).
- Last VM run: 31 pass / 0 fail / 4 skip, see `vm-test-report-2026-11-03.md`. The Rosetta guard (commit `77c92e6`) was tested on the host only (re-exec from `/usr/local/bin/bash` → arm64), **not yet re-run in the VM**.

## Test VM (Tart 2.41.1, installed manually in `~/.local/tart`, symlink `~/.local/bin/tart`)
- Storage: `TART_HOME="/Volumes/Disc Samsung T7/vm - backups/macos_vm"` (SSD must be plugged in).
- VMs: `foxhole-test` (work copy), `foxhole-clean` (untouched backup). Login `admin`/`admin`, passwordless `sudo -n`, but `sudo -v` asks for the password.
- Run: `bash tests/vm/run.sh --reset` (re-execs natively; host `bash` is Intel-only `/usr/local/bin/bash`).
- VM has **no direct internet** (host Mullvad Lockdown Mode likely blocks NAT); DNS via the host gateway works.

## Next (from the report's plan)
1. Re-run `tests/vm/run.sh --reset` to cover the Rosetta guard commit.
2. P1.2 — load rules into `com.apple/foxhole.dnsleak` instead of editing `/etc/pf.conf` + `pfctl -f` (Mullvad-safe). Prototype + verify in the VM.
3. P1.3 — `pfctl -E` token / `pfctl -X` so disable restores PF's previous on/off state.
4. P1.4 — `launchctl bootstrap/bootout system` instead of `load/unload`.
5. P2 — VM egress (pause Mullvad Lockdown or `--net-softnet`), Quad9 DoH profile image (`foxhole-doh`), WireGuard tunnel test.
6. Before merge: decide on `debug_netlib/`, update CLAUDE.md testing section → `tests/vm/run.sh`, refresh GitNexus index (`node .gitnexus/run.cjs analyze`).

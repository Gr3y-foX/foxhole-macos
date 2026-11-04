# Draft: CLAUDE.md "Commands" and "Testing" text (not applied, for your review)

CLAUDE.md is your file, so this is only a proposal. Replace the two sections below if you agree.

## Commands

The tests are scripts, not a build system.

```bash
bash -n mac-hardening-netlib.sh                    # syntax check (after every edit)
shellcheck -S warning mac-hardening-*.sh vpn_daily.sh tests/ci/offline.sh tests/vm/*.sh
bash tests/ci/offline.sh                           # offline checks, nothing touches the system (sudo is shimmed)
FOXHOLE_VM_NET=bridged bash tests/vm/run.sh --reset   # full suite in a Tart VM (SSD mounted), log in docs/testing/
bash mac-hardening-install.sh                      # real installer: normal user, never root, VM only for tests
```

Do **not** run the installer, the netlib menu or any `pfctl`/`networksetup`/`launchctl` command on the host to test a change. They modify the real machine: use the VM. Netlib backups go to `~/.foxhole/backups/<timestamp>/` (`restore.sh` inside restores them).

## Testing without touching the system

- `tests/ci/offline.sh` renders the PF anchor with `sudo` stubbed (all three `FOXHOLE_DNS_MODE` values) and checks it.
- `tests/vm/run.sh` runs `tests/vm/vmtest.sh` inside the Tart VM `foxhole-test`: enable/disable, reboot-style helper start, migration from <=0.17.2, Privoxy toggle, installer fixes, backups. `tests/vm/vm.sh` is for ad-hoc work in the VM.
- `FOXHOLE_ASSUME_YES=1` answers every prompt "y" (unattended runs); `FOXHOLE_DNS_MODE=doh|vpn|plain` picks the DNS policy.
- `verify_dns_stack` is read-only apart from `sudo pfctl -s info`.

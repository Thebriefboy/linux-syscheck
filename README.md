# syscheck

A complete, **read-only** system health checkup in a single Python file. It checks your machine, scores it from 0 to 100, and tells you exactly what to fix.

- No dependencies (standard library only), Python 3.8+
- One file, easy to read and audit
- Works without root; `sudo` unlocks a few extra checks
- Colour terminal output, plain ASCII fallback, JSON output, exit codes for automation

## What it checks

| Area | Checks |
|---|---|
| System | OS, kernel, hardware/virtualisation, uptime, pending reboot, NTP clock sync |
| CPU | usage, load average, I/O wait, hypervisor steal, temperature |
| Memory | RAM and swap pressure, missing swap on low-memory machines |
| Processes | top CPU and memory users, zombies, blocked (D-state) processes, kernel pressure (PSI), file handles |
| Storage | disk space, inodes, read-only system mounts, SMART drive health |
| Network | interfaces, packet errors, internet reachability and latency, DNS, exposed listening ports |
| Services | failed systemd units, boot time |
| Security | pending updates (apt / dnf / pacman), firewall, SSH root login and password auth, empty passwords |
| Logs & kernel | error volume (24h), journal size, out-of-memory kills, disk and hardware errors |
| Cleanliness | user cache, trash, package caches, logs, core dumps, temp dirs, Docker |
| Power | battery health and cycle count |

Every warning or critical finding comes with a concrete suggestion, collected into a prioritised **WHAT TO FIX** list at the end.

## Install and run

```bash
git clone https://github.com/Thebriefboy/syscheck.git
cd syscheck
python3 syscheck.py
```

Or just download `syscheck.py` and run it. For the most complete result:

```bash
sudo python3 syscheck.py
```

## Options

| Option | Description |
|---|---|
| `--fast` | shorter sampling, skips the slowest checks |
| `--offline` | skip network connectivity tests |
| `--json` | machine-readable JSON output |
| `--no-color` | disable colours (also respects `NO_COLOR`) |
| `--report FILE` | also save a plain-text report to `FILE` |
| `--version` | print the version |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | healthy |
| `1` | warnings found |
| `2` | critical problems found |

This makes it easy to use in cron or monitoring:

```bash
0 8 * * * /usr/bin/python3 /opt/syscheck/syscheck.py --fast --no-color --report /var/log/syscheck.txt
```

## Health score

The score starts at 100 and drops by 5 for each warning and 15 for each critical finding: 90+ excellent, 75+ good, 55+ needs attention, below that poor.

## Platform support

- **Linux**: full checkup
- **macOS / BSD**: reduced checkup (basic system, load, disk, network)
- **Windows**: not supported

## Safety

syscheck only reads system state (`/proc`, `/sys`, config files and read-only commands such as `systemctl`, `journalctl`, `apt list`, `smartctl -H`). It never changes your settings or deletes anything; cleanup commands are only suggested, never run. Note that some package managers (for example `dnf check-update`) may refresh their own metadata cache.

## Contributing

Issues and pull requests are welcome. Each check is a small function (`check_*`) that adds findings with a status (`OK`, `WARN`, `CRIT`, `INFO`) and an optional suggestion, so adding a new check is easy.

## License

Choose a licence for your repository (MIT is a common choice) and add a `LICENSE` file.

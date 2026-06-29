# Sentinel Agent

![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)
![Python](https://img.shields.io/badge/python-3.13%2B-blue)
![Mode](https://img.shields.io/badge/mode-outbound--only-green)

**Lightweight push agent for monitored Linux nodes.**

Sentinel Agent runs as a background daemon on each monitored node. It collects system telemetry via 21 collection routines and pushes alerts to the central [Sentinel Commander](https://github.com/foxik0070/Sentinel) server over outbound-only TCP — no inbound ports required.

---

## Features

- **21 collection routines** — CPU/RAM/disk, temperature, SMART, systemd services, fail2ban, dmesg, kernel OOM, RAID/mdstat, NFS, ZFS, login sessions, network, processes, and more
- **Stateful delta filter** — only sends data that changed since the last cycle, minimizing traffic
- **Outbound-only** — no listening ports, zero attack surface on monitored nodes
- **Re-affirmation** — periodically re-sends critical state even without changes
- **Self-configuring** — single config file, runs as a systemd service

---

## Quick Start

### Requirements

- Python 3.13+
- Root access (required for `smartctl`, `dmesg`, privilege syscalls)
- Network access to Sentinel Commander (port 5050)

### Install

```bash
git clone https://github.com/foxik0070/sentinel-agent /opt/sentinel-agent
cd /opt/sentinel-agent
pip install -r requirements.txt   # psutil, requests
python sentinel_agent_init.py     # configure + install systemd service
```

### Configure

Edit the generated config (default: `/etc/sentinel-agent/config.yaml`):

```yaml
sentinel:
  url: http://192.168.1.100:5050
  token: <your-agent-token>        # generated in Sentinel web UI → Agents
  interval: 60                     # seconds between collection cycles
```

### Run

```bash
systemctl enable --now sentinel-agent
```

---

## Collection Routines

| # | Routine | Data source |
|---|---|---|
| 1 | CPU load | `/proc/loadavg` |
| 2 | RAM usage | `/proc/meminfo` |
| 3 | Disk usage | `statvfs` per mount |
| 4 | Temperature | `/sys/class/thermal` |
| 5 | SMART | `smartctl -A` |
| 6 | Systemd services | `systemctl --failed` |
| 7 | Fail2ban | `fail2ban-client status` |
| 8 | dmesg errors | `/dev/kmsg` |
| 9 | Kernel OOM | dmesg filter |
| 10 | RAID / mdstat | `/proc/mdstat` |
| 11 | ZFS pool | `zpool status` |
| 12 | NFS mounts | `/proc/mounts` |
| 13 | Login sessions | `who` / `utmp` |
| 14 | Network interfaces | `/proc/net/dev` |
| 15 | Open ports | `ss -tuln` |
| 16 | Process count | `/proc` |
| 17 | Swap | `/proc/meminfo` |
| 18 | Uptime | `/proc/uptime` |
| 19 | Last logins | `lastlog` |
| 20 | Entropy | `/proc/sys/kernel/random/entropy_avail` |
| 21 | Block device errors | `/sys/block/*/stat` |

---

## Documentation

Full documentation: **https://sentinel-docs.example.com**

---

## Related

- [Sentinel Commander](https://github.com/foxik0070/Sentinel) — central server
- [sentinel-overhealth](https://github.com/foxik0070/sentinel-overhealth) — pull-based orchestrator (alternative)

---

## License

MIT — see [LICENSE](LICENSE). Copyright © 2026 foxik0070.

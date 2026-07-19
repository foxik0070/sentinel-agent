# Sentinel Agent Infrastructure Specification
## Enterprise Stateful Delta Monitoring & Communication Protocol

This document serves as the definitive technical reference for the Sentinel Agent subsystem. It describes the runtime architecture, stateful data filter pipeline, network wire-protocol mechanics, and exhaustive sub-module metrics criteria.

> **Bezpečnostní vrstva:** podrobný popis ochrany před CVE a detekce podezřelého chování (model hrozby, jednotlivé detekce, omezení falešných poplachů) najdete v [`SECURITY.md`](SECURITY.md).

---

## 1. System Architecture Deep Dive

The Sentinel Agent operates as a persistent, high-privilege background daemon within the host operating system user space. It handles telemetry strictly via an asymmetric **Push-Only (Outbound)** model. This eliminates the security risks associated with exposing listening ports on monitored production nodes and minimizes network attack surfaces.

```text
+---------------------------------------------------------------------------------------+
|                                     MONITORED NODE                                    |
|                                                                                       |
|   +-------------------------------------------------------------------------------+   |
|   |                           Kernel Space & Subsystems                           |   |
|   |   (/sys/class/thermal, /proc/mdstat, /dev/kmsg, netfilter, statvfs syscall)   |   |
|   +---------------------------------------+---------------------------------------+   |
|                                           |                                           |
|                                           v Raw Metric Ingestion                      |
|   +-------------------------------------------------------------------------------+   |
|   |                        Sentinel Agent Monolithic Daemon                       |   |
|   |   * Runs as Root User (Required for smartctl, dmesg, and privilege syscalls)  |   |
|   |   * Executes 25 localized collection routines sequentially every X seconds    |   |
|   +---------------------------------------+---------------------------------------+   |
|                                           |                                           |
|                                           v Discrete Status + Formatted String        |
|   +-------------------------------------------------------------------------------+   |
|   |                         Stateful Delta Filter Engine                          |   |
|   |   * In-memory key-value lookups (`self.last_reported_states`)                 |   |
|   |   * Suppresses redundant data streams directly at the source                  |   |
|   +---------------------------------------+---------------------------------------+   |
|                                           |                                           |
+-------------------------------------------|-------------------------------------------+
                                            |
                                            | On Message Mutation (State Transition)
                                            v Outbound HTTPS POST (JSON Payload)
    +-----------------------------------------------------------------------------------+
    |                               Central Sentinel API                                |
    |   * Processes incoming delta vectors                                              |
    |   * Mutates central cluster UI state and triggers incident notification matrices  |
    +-----------------------------------------------------------------------------------+
```

### Root Privilege Justification
The agent must execute under the `root` user context. This is required due to restricted operating system boundaries:
*   Reading the kernel ring buffer (`dmesg`) is restricted via `kernel.dmesg_restrict`.
*   Querying low-level hardware registers and disk sector health maps via `smartctl` requires direct block-device access (`/dev/sdX`, `/dev/nvmeX`).
*   Inspecting connected user terminals (`who`) and monitoring cross-namespace listening sockets (`ss -tulpn`) require administrative networking privileges.

---

## 2. The Stateful Delta Pipeline & Initialization Guards

The foundational design principle of the Sentinel Agent is **Network Quietness**. Instead of flooding the network with repetitive status packets, the agent determines state changes locally before transmitting anything.

### Detailed State Transition Flowchart

```text
       [ Start Metrics Engine Iteration ]
                       |
                       v
       [ Execute Local Gathering Function ] ----> Reads raw data from OS subsystem
                       |
                       v
       [ Map Raw Values to Logical States ] ----> Maps values to OK, WARNING, or CRITICAL
                       |
                       v
       [ Compile Precise Message String ] ------> Creates message with dynamic system values
                       |
                       v
          /---------------------------\
         /    Is compiled message      \
        <  identical to the string stored >
         \   in the local cache?       /
          \---------------------------/
                       |
                       +---> YES ---> [ Terminate Routine Execution ]
                       |              (Network packet is dropped locally)
                       |
                       +---> NO  ---> [ Mutate Local Cache Buffer ]
                                              |
                                              v
                                     [ Append Event to Batch ]
                                              |
                                              v
                                     [ Dispatch JSON Payload to API ]
```

### The Post-Boot Stabilization Window (`boot_delay_sec`)
To eliminate race conditions and prevent post-reboot false positives, the agent implements a mandatory startup guard window. 

When a server reboots, services initialize asynchronously. For example, a heavy database engine might take 45 seconds to bind to its TCP port, network interfaces might delay setting up target routes, or secondary storage units might wait on slow automount parameters. 

If the agent compiled its baseline matrix immediately upon startup, it would capture a transient, uninitialized system state. This would trigger a flood of critical alerts. The `boot_delay_sec` parameter forces the agent to sleep (default: `90` seconds) during initialization. This allows all system layers to settle down into a trusted, stable operational baseline before monitoring begins.

---

## 3. Wire Protocol & Communication Specification

The agent communicates with the Central Sentinel API using a stateless, asynchronous transaction model over standard HTTP/HTTPS.

### Protocol Rules:
1.  **Authentication:** Every transmission must include the HTTP header: `Authorization: Bearer <secure_token>`.
2.  **Content Negotiation:** Payloads are transmitted inside the HTTP request body using `Content-Type: application/json`.
3.  **Timestamp Enforcements:** Timestamps use the ISO 8601 format with explicit UTC time zone offsets (`YYYY-MM-DDTHH:MM:SS.ffffff+00:00`).
4.  **Outage Resilience (Retry Buffer):** Events from failed pushes are buffered in memory, persisted into the state file (surviving agent restarts mid-outage), and replayed on the next successful push. Exact duplicates (identical re-affirmations) are deduplicated; the buffer is capped at `agent_core.max_pending_events` (default `500`, oldest dropped first).

### Message Exchange Sequence Matrix

```text
Sentinel Monitored Node                                                       Central Sentinel API
          |                                                                             |
          | 1. POST /api/v1/agent/ingest (Boot Registration Event)                     |
          |---------------------------------------------------------------------------->|
          | 2. HTTP 200 OK (Node is registered as ONLINE in UI)                        |
          |<----------------------------------------------------------------------------|
          |                                                                             |
          | <-- Executing Loop Every 60s: Local metrics remain in trusted matrix.  --> |
          | <-- Delta Filter drops all matching payloads. No network traffic.      --> |
          |                                                                             |
          | 3. POST /api/v1/agent/ingest (Delta Event: OOM Intercepted)                |
          |---------------------------------------------------------------------------->|
          | 4. HTTP 200 OK (UI Dashboard transitions to CRITICAL red alert state)       |
          |<----------------------------------------------------------------------------|
          |                                                                             |
          | <-- Next Loop: OOM state persists but message is identical.           --> |
          | <-- Network packet is dropped locally. No duplicate spam sent to API.   --> |
          |                                                                             |
          | 5. POST /api/v1/agent/ingest (Resolution Event: OOM counter cleared)       |
          |---------------------------------------------------------------------------->|
          | 6. HTTP 200 OK (UI Dashboard falls back into healthy green status)          |
          |<----------------------------------------------------------------------------|
```

### Wire-Format Payload Examples

#### Payload A: Initial Post-Boot Registration Block
Sent exactly once after the initialization stabilization delay expires. Every payload carries `agent_version` (the agent's short git SHA) so the server can flag nodes running stale code.

```json
{
  "timestamp": "2026-05-18T16:20:00.001234+00:00",
  "hostname": "hpc-node-04.hpc.cz",
  "agent_version": "77b680e",
  "events": [
    {
      "plugin": "agent_core_updater",
      "target": "auto_update",
      "status": "OK",
      "message": "Agent service successfully started and running clean."
    }
  ]
}
```

#### Payload B: Multi-Incident Delta Trigger Block
Sent immediately if one or more sub-modules detect a state mutation during the same collection pass.

```json
{
  "timestamp": "2026-05-18T17:04:15.118942+00:00",
  "hostname": "hpc-node-04.hpc.cz",
  "agent_version": "77b680e",
  "events": [
    {
      "plugin": "agent_services_monitor",
      "target": "fail2ban",
      "status": "WARNING",
      "message": "Systemd service 'fail2ban' shifted to unexpected state: inactive."
    },
    {
      "plugin": "agent_storage_capacity_monitor",
      "target": "/",
      "status": "CRITICAL",
      "message": "Storage target '/' has exceeded critical capacity threshold. Space Used: 96.2%, Inodes Used: 14.8%."
    }
  ]
}
```

---

## 4. Comprehensive Module Specification

The monolithic agent execution block contains 25 built-in sub-modules. Each module operates on precise low-level parsing logic.

### 1. `agent_services_monitor`
*   **Mechanism:** Executes `systemctl is-active <service_name>`.
*   **Logic:** If the output is `active` or `inactive`, it evaluates to `OK`. Any other state (`failed`, `activating`, etc.) triggers the configured severity. To prevent false positives from transient restarts, a service must fail **N consecutive checks** before an alert is dispatched. N is controlled by `checks.service_confirm_count` (default: `2`).

### 2. `agent_mounts_monitor`
*   **Mechanism:** Calls the native Python `os.path.ismount(path)` system abstraction wrapper.
*   **Logic:** Checks if the target directory path points to a valid, active mount point. If the system call returns `False`, it alerts that the storage mount has detached.

### 3. `agent_network_port_security`
*   **Mechanism:** Parses outputs from the network socket inspection utility: `ss -tulpn`.
*   **Logic:** Filters out standard infrastructure fallback ports (e.g., 22, 53, 123, 443). When the boot delay expires, it compiles an initial baseline set of open sockets. If any unassigned socket bindings appear in later runs, it triggers a `WARNING`.

### 4. `agent_security_root_monitor`
*   **Mechanism:** Reads the logged-in users file subsystem using the `who` command binary.
*   **Logic:** Iterates line-by-line over terminal attachments. Only SSH sessions are captured (lines with 5+ fields where the source field is a valid IP or IPv6 address). Local console and tmux sessions are filtered out. IPs listed in `security.root_login_ignore_ips` are silently skipped. Each active session generates a `WARNING` with TTY, IP, and login timestamp.

### 5. `agent_security_vulnerability_scan`
*   **Mechanism:** Evaluates target OS package trees. On Debian/Ubuntu systems, it runs `apt-get -s upgrade`. On RedHat-based systems, it runs `dnf check-update --security`.
*   **Logic:** On Debian systems, it parses lines starting with `Inst `. If the string contains the tokens `security` or `cve`, it increments the critical counter. If any unpatched security updates are found, it sets the system status to `CRITICAL`.

### 6. `agent_security_firewall_fail2ban`
*   **Mechanism:** Communicates with the local brute-force engine via `fail2ban-client status`.
*   **Logic:** Uses regular expressions to extract active jails from the output. It then queries each jail individually to parse the `Currently banned:` integer metric. If the sum of all active bans exceeds `50`, it returns a `WARNING`.

### 7. `agent_temperature_monitor`
*   **Mechanism:** Natively reads sysfs files from `/sys/class/thermal/thermal_zone*/temp` and `/sys/class/hwmon/hwmon*/temp1_input`.
*   **Logic:** Divides the raw integer string by `1000.0` to calculate the current temperature in Celsius. It then compares this float value directly against your configured `warning` and `critical` thresholds.

### 8. `agent_storage_capacity_monitor`
*   **Mechanism:** Issues an `os.statvfs(path)` system call to interact with the underlying filesystem.
*   **Logic:** Calculates the current disk space and inode use percentages using these equations:
    $$\text{Space Used \%} = \frac{\text{f\_blocks} - \text{f\_bavail}}{\text{f\_blocks}} \times 100$$
    $$\text{Inodes Used \%} = \frac{\text{f\_files} - \text{f\_favail}}{\text{f\_files}} \times 100$$
    It uses the higher of these two percentages to evaluate the configured disk warning or critical limits.

### 9. `agent_raid_monitor`
*   **Mechanism:** Natively streams and parses lines from the kernel software RAID pseudo-file: `/proc/mdstat`.
*   **Logic:** Scans for the down-array recovery flag character (`_`) or the explicit literal sub-string `degraded`. If found, it triggers a `CRITICAL` alert. If it finds the tokens `resync` or `recovery`, it returns a `WARNING`.

### 10. `agent_ssd_wearout_monitor`
*   **Mechanism:** Scans for physical device nodes in `/sys/block/` and queries them via `smartctl -A /dev/XX`.
*   **Logic:** For NVMe drives, it extracts the `Percentage Used` metric and subtracts it from 100. For SATA drives, it parses attributes like `Media_Wearout_Indicator` or `Remaining_Lifetime_Perc`. If remaining life falls $\le 10\%$, it triggers a `CRITICAL` alert (target `/dev/XX`).
*   **Sector health (target `/dev/XX:sectors`):** From the same SMART output it parses `Reallocated_Sector_Ct`, `Current_Pending_Sector`, `Offline_Uncorrectable` (SATA) and `Media and Data Integrity Errors` (NVMe). Any non-zero count triggers a `CRITICAL` alert — failing sectors predict drive death earlier than the overall SMART health verdict.

### 11. `agent_kernel_oom_monitor`
*   **Mechanism:** Primary: reads the kernel journal incrementally via `journalctl -k --cursor-file`. The persistent cursor (stored next to the state file) guarantees each log line is examined exactly once — counting survives ring buffer rotation and agent restarts. Fallback for non-systemd hosts: `dmesg` occurrence count delta.
*   **Logic:** Uses regular expressions to match `Out of memory: Kill process` (old kernels) and `Killed process ... total-vm` (new kernels). Any new kill event triggers an immediate `CRITICAL` alert with the exact count.

### 12. `agent_process_zombie_monitor`
*   **Mechanism:** Scans the active process execution tree using `ps -eo state`.
*   **Logic:** Counts all process lines matching the execution state character `Z` (Defunct/Zombie). If the count exceeds your configured `max_zombies` threshold, it returns a `WARNING` to prevent process ID starvation.

### 13. `agent_system_time_sync`
*   **Mechanism:** Parses outputs from the system clock daemon controller: `timedatectl`.
*   **Logic:** Checks for the presence of the exact synchronization confirmation sub-strings: `System clock synchronized: yes` or `NTP service: active`. If both strings are missing, it triggers a `WARNING`.

### 14. `agent_network_dns_monitor`
*   **Mechanism:** Triggers a standard network name resolution lookup using `socket.gethostbyname("one.one.one.one")`.
*   **Logic:** If the system environment fails to resolve the host and throws a `socket.gaierror` exception, it flags a `WARNING` to indicate a local DNS resolver failure.

### 15. `agent_systemd_global_monitor`
*   **Mechanism:** Queries systemd globally for failed units using: `systemctl list-units --state=failed --no-legend`.
*   **Logic:** Collects all failed units into an active list. If the list contains any entries, it bypasses individual service configs and triggers a `CRITICAL` alert containing the names of all crashed units.

### 16. `agent_kernel_io_monitor`
*   **Mechanism:** Evaluates process schedulers via `ps -eo state,pid,comm`.
*   **Logic:** Counts processes stuck in state `D` (Uninterruptible Sleep). This state usually indicates unresolvable hardware I/O hangs or frozen NFS shares. If $\ge 2$ processes get stuck in this state simultaneously, it triggers a `CRITICAL` alert.

### 17. `agent_netfilter_monitor`
*   **Mechanism:** Reads the netfilter connection state metrics from `/proc/sys/net/netfilter/nf_conntrack_count` and `nf_conntrack_max`.
*   **Logic:** Tracks connection limit saturation using this equation:
    $$\text{Conntrack Saturation \%} = \frac{\text{nf\_conntrack\_count}}{\text{nf\_conntrack\_max}} \times 100$$
    If usage reaches $\ge 90\%$, it triggers a `CRITICAL` alert, because the kernel will soon begin dropping new incoming network packets.

### 18. `agent_disk_health_monitor`
*   **Mechanism:** Enumerates physical drives (`/sys/block/sd*`, `nvme*N*`) and runs `smartctl -H /dev/XX` on each.
*   **Logic:** If SMART reports `FAILED`, it triggers a `CRITICAL` alert. If SMART reports `PASSED` or `OK`, it clears the state. Skipped automatically on virtual machines (LXC, QEMU, KVM). Controlled by `storage.monitor_disk_health`.

### 19. `agent_kernel_taint_monitor`
*   **Mechanism:** Reads the integer taint flag from `/proc/sys/kernel/tainted`.
*   **Logic:** A non-zero value indicates the kernel has been tainted (e.g., proprietary/unsigned module loaded, MCE hardware error, kernel crash). Any non-zero value triggers a `WARNING` with the raw taint bitmask. Controlled by `kernel.monitor_taint`.

### 20. `agent_ssl_cert_monitor`
*   **Mechanism:** Runs `openssl x509 -enddate -noout -in <cert_path>` for each configured certificate file.
*   **Logic:** Calculates days remaining until expiry. Triggers `WARNING` if $\le 14$ days remain, and `CRITICAL` if $\le 3$ days remain. Certificate paths are listed under `security.ssl_certs`.

### 21. `agent_memory_monitor`
*   **Mechanism:** Reads `/proc/meminfo` directly — no external tools required.
*   **Logic:** Reports two independent targets: `ram` and `swap`. For RAM, it uses `MemAvailable` (not just `MemFree`) to account for page cache that the kernel can reclaim, giving a realistic picture of actual memory pressure. Swap monitoring is optional via `memory.monitor_swap`. Each target reports independently against the configured `warn_percent` / `crit_percent` thresholds.

### 22. `agent_security_suspicious_activity`
*   **Mechanism:** Six independent sub-detections targeting post-exploit footprints. Controlled by `security.monitor_suspicious`.
*   **Logic:**
    *   **critical_files:** SHA-256 baseline of `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`. Any change triggers `CRITICAL` — Dirty COW / Dirty Pipe class exploits rewrite these files to escalate privileges. Baseline re-compiles after the alert (event-style, like OOM).
    *   **persistence_files:** SHA-256 baseline of SSH `authorized_keys` (root + every `/home` user) and cron entries (`/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/*`). Added, removed, or modified files trigger `CRITICAL` — these are the classic persistence mechanisms planted after CVE exploitation.
    *   **ld_preload:** A non-empty `/etc/ld.so.preload` triggers `CRITICAL` — system-wide LD_PRELOAD hooks are the signature of userland rootkits.
    *   **uid0_accounts:** Parses `/etc/passwd` for non-root accounts with UID 0 (privilege escalation backdoor). Persistent `CRITICAL` while present.
    *   **processes:** Walks `/proc` and flags processes executing from `/tmp`, `/var/tmp`, `/dev/shm`, fileless (memfd) executables, processes running from deleted binaries outside system paths (self-deleting payloads; `/usr`, `/opt`, `/lib`, ... are excluded to avoid package-upgrade false positives), known cryptominer names (xmrig, kinsing, kdevtmpfsi, ...), and reverse-shell patterns in command lines (`/dev/tcp/` & `/dev/udp/`, `nc -e`, `socat exec`, `pty.spawn`, perl/php/ruby/python one-liners, `exec N<>/dev/tcp`, msfvenom/meterpreter).
    *   **suid_binaries:** Runs `find` over temp directories for SUID-root files (exploit staging artifacts).
    *   **suid_baseline:** Full-filesystem SUID/SGID inventory (single device, rescanned every 10 cycles). A newly appeared SUID/SGID binary triggers `CRITICAL` — LPE exploits and backdoored packages plant SUID shells for persistence. Removals are absorbed silently. The baseline persists across restarts.
    *   **auth_failures:** Reads `sudo`/`su` journal entries incrementally (persistent cursor). If authentication failures since the last cycle reach `security.sudo_fail_threshold` (default `3`), it triggers a `WARNING` with sample lines — a burst signals a privilege-escalation attempt.
    *   **promisc_interfaces:** Reads the `IFF_PROMISC` flag (bit `0x100`) from `/sys/class/net/*/flags`. An interface in promiscuous mode (`WARNING`) usually means a packet sniffer is running.
    *   **kernel_modules:** Baselines the loaded module set from `/proc/modules`. A newly loaded module triggers a `WARNING` — loadable kernel module (LKM) rootkits install themselves this way. Unloads are absorbed silently. The baseline persists across restarts.

### 23. `agent_security_kernel_cve`
*   **Mechanism:** Parses `os.uname().release` into a `(major, minor, patch)` tuple and compares it against a static table of well-known, actively-abused local privilege escalation CVE ranges. Controlled by `security.scan_cves`.
*   **Logic:** Covers Dirty COW (CVE-2016-5195), OverlayFS capability abuse (CVE-2021-3493), Dirty Pipe (CVE-2022-0847), and nf_tables UAF (CVE-2024-1086). A kernel inside a vulnerable range triggers a `WARNING` with a note to verify the distribution backported the fix — distro kernels patch without bumping the upstream version, so this is a heads-up, not a confirmed vulnerability.

### 24. `agent_security_reboot_required`
*   **Mechanism:** Checks for the `/var/run/reboot-required` flag file (Debian/Ubuntu). Controlled by `security.check_system_updates`.
*   **Logic:** An installed kernel or core library security patch is not effective until the machine restarts. If the flag exists, it triggers a `WARNING` listing the packages that requested the reboot (from `reboot-required.pkgs`).

### 25. `agent_rpi_power_monitor`
*   **Mechanism:** Queries the Raspberry Pi firmware via `vcgencmd get_throttled` and decodes the bitmask. Automatically skipped on non-RPi hardware (binary absent). Controlled by `hardware.monitor_rpi_throttling`.
*   **Logic:** Bits 0–3 are active conditions, bits 16–19 are since-boot history. Active under-voltage (bit 0) triggers `CRITICAL` — it is the most common cause of mysterious RPi instability (bad PSU or cable). Frequency capping, active throttling, soft temperature limits, and all historical flags trigger `WARNING`. Historical flags persist until reboot, keeping an unstable power supply visible.

---

## 5. Configuration Schema Blueprint

The entire configuration for the agent is managed within a single structured file located at `/etc/sentinel/agent_config.yaml`. Use `sentinel_agent_init.py` to generate or update it interactively.

```yaml
# ==========================================================================
# Agent Core
# ==========================================================================
agent_core:
  git_auto_update: false          # Pull latest code from git and restart via systemd suicide.
                                  # Pulled code is sanity-compiled first; a broken commit is
                                  # rolled back and reported CRITICAL instead of restarting.
  state_file: /var/lib/sentinel/state.json  # Active issue registry (read by agent_issues).
                                  # Also persists reported states, file-integrity baselines and
                                  # the retry buffer across agent restarts (port baseline
                                  # intentionally resets).
  max_pending_events: 500         # Retry buffer cap for events from failed pushes
  max_self_rss_mb: 0              # Self-restart if agent RSS exceeds this many MB (0 = disabled)

# ==========================================================================
# Central Sentinel API Authorization Credentials
# ==========================================================================
sentinel_api:
  url: http://192.168.1.100:5050
  token: secure_agent_token_abc123
  hostname: myserver                # Logical name shown in dashboard — must be unique per host
  source_ip: ""                     # Bind outgoing requests to this IP (leave empty = automatic).
                                    # Set to eth0 IP when device has multiple interfaces to
                                    # prevent duplicate reports on the Sentinel server.

# ==========================================================================
# Daemon Core Timing
# ==========================================================================
intervals:
  metrics_push_sec: 60    # How often to run all checks and push results (seconds)
  boot_delay_sec: 90      # Post-boot grace period before monitoring starts (seconds)

# ==========================================================================
# Sub-Module Flags & Thresholds
# ==========================================================================
checks:
  service_confirm_count: 2  # How many consecutive failures before a service alert is sent

  services:
    - name: nginx
      severity: CRITICAL
    - name: fail2ban
      severity: WARNING
      confirm_count: 3    # Per-service override of service_confirm_count

  mounts:
    - path: /mnt/data
      severity: CRITICAL

  temperature:
    enabled: true
    warning: 75.0
    critical: 85.0

  hardware:
    monitor_rpi_throttling: true  # RPi undervoltage/throttling via vcgencmd (skipped elsewhere)

  storage:
    enabled: true
    paths:
      - /
      - /var
    warn_percent: 85
    crit_percent: 95
    monitor_wearout: true       # SSD/NVMe wear via SMART attributes
    monitor_raid: true          # mdadm software RAID health (/proc/mdstat)
    monitor_disk_health: false  # SMART overall health (smartctl -H); skipped on VMs

  memory:
    enabled: true
    warn_percent: 85            # RAM and swap warning threshold
    crit_percent: 95
    monitor_swap: true          # Also report swap utilization independently

  kernel:
    monitor_oom: true           # OOM killer events from dmesg
    monitor_zombies: true
    max_zombies: 5
    monitor_io_hangs: true      # Processes stuck in D state (uninterruptible sleep)
    monitor_taint: true         # Kernel taint flag (/proc/sys/kernel/tainted)

  system:
    monitor_time_sync: true     # NTP synchronization via timedatectl
    monitor_global_systemd: true # systemctl list-units --state=failed

  network:
    monitor_dns: true           # DNS resolution test (one.one.one.one)
    monitor_conntrack: true     # Netfilter conntrack table utilization

  security:
    monitor_root_logins: true   # SSH root logins only (tmux/console filtered out)
    root_login_ignore_ips:      # Root logins from these IPs are silently ignored
      - 192.168.1.1
    monitor_ports: true         # Alert on new TCP ports vs. startup baseline
    check_system_updates: true  # Pending apt/dnf packages + reboot-required flag
    scan_cves: true             # Security-tagged packages in pending updates + kernel LPE CVE ranges
    fail2ban_stats: true        # Alert when active ban count exceeds 50
    monitor_suspicious: true    # Exploit footprints: critical file & authorized_keys/cron integrity,
                                # LD_PRELOAD rootkits, UID 0 backdoors, processes from /tmp,
                                # cryptominers, reverse shells, SUID in temp dirs, system-wide
                                # SUID/SGID baseline, sudo/su auth-failure bursts
    sudo_fail_threshold: 3      # sudo/su auth failures per cycle before a WARNING is raised
    ssl_certs:
      - /etc/letsencrypt/live/example.com/fullchain.pem
```

---

## 6. Systemd Supervision & Production Deployment

The daemon runs inside an isolated systemd execution wrapper. This setup enforces clean directory parameters and automatically restarts the process if it encounters a runtime exception.

```text
+-------------------------------------------------------------+
|               Systemd Service Lifecycle Matrix              |
|                                                             |
|   1. OS boot triggers multi-user.target dependency tracking |
|   2. Network layer validates network-online.target is active|
|   3. Systemd spawns the simple script process wrapper       |
|   4. If process drops out, systemd cools down for 5s        |
|   5. Force invocation loop executes indefinitely            |
+-------------------------------------------------------------+
```

### Production Unit Configuration File
The unit profile is deployed to `/etc/systemd/system/sentinel-agent.service`:

```ini
[Unit]
Description=Sentinel Agent Daemon Stateful Framework
After=network-online.target multi-user.target
Wants=network-online.target

[Service]
Type=notify
NotifyAccess=main
WatchdogSec=1200
WorkingDirectory=/etc/sentinel
ExecStart=/usr/bin/env python3 /usr/local/bin/sentinel_agent.py
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

### Essential Administration Command Matrix
Use these commands on the terminal to manage production systems:

```bash
# Generate or update configuration and (re)deploy the systemd service
sudo python3 sentinel_agent_init.py

# View all currently active issues on this host
agent_issues

# Send a test alert to verify connectivity with the Sentinel server
python3 sentinel_agent.py --test

# Print active issues from state file (same as agent_issues, useful outside venv)
python3 sentinel_agent.py --issues

# Run every check once, print events as JSON, push nothing (safe preview)
python3 sentinel_agent.py --dry-run

# Run with 5s intervals for manual testing
python3 sentinel_agent.py --fast

# Reload check thresholds without restarting (connection settings need a restart)
sudo systemctl kill -s HUP sentinel-agent

# Force reload of unit configuration after manual edits
sudo systemctl daemon-reload

# Restart the daemon (also resets port security baseline)
sudo systemctl restart sentinel-agent

# Stream live daemon logs
sudo journalctl -u sentinel-agent.service -f --output cat
```

### Testing

The parsing/decoding logic (reverse-shell patterns, kernel CVE ranges, SMART
sector attributes, RPi throttle bitmask, OOM regex, retry buffer) is covered by
a pytest suite that runs without a config file or root privileges:

```bash
pip install -r requirements-dev.txt
python3 -m pytest        # 53 tests
```

These tests guard the git auto-update mechanism: a logic regression that would
otherwise be pulled and self-restarted into a broken agent is caught here first.

### Continuous Integration (Gitea Actions)

`.gitea/workflows/ci.yaml` runs the compile check (`compileall` over the agent
and the `checks/` package) and the pytest suite on every push to `main` and on
pull requests. This closes the loop on the auto-update mechanism — a broken
commit is caught by CI before agents can pull it.

The pipeline runs on the same registered `act_runner` (label `ubuntu-latest`)
already serving the central Sentinel server repository, and uses
`actions/setup-python@v5` so it does not depend on the runner base image
shipping a specific Python version.

## Project layout

```text
sentinel_agent.py        # core: config, state, HTTP push, git auto-update, run_loop
sentinel_agent_init.py   # interactive installer / systemd deployment
checks/
  __init__.py            # @register_check registry (ordered run_loop discovery)
  services.py            # ServicesChecks  — systemd services, mountpoints
  security.py            # SecurityChecks  — ports, root logins, CVE, suspicious activity, SSL
  storage.py             # StorageChecks   — capacity, RAID, SSD wearout, SMART
  kernel.py              # KernelChecks    — OOM, zombies, I/O hangs, taint
  system.py              # SystemChecks    — temperature, RPi throttling, time, DNS, memory
tests/                   # pytest suite (runs without config or root)
```

The check mixins are composed onto `SentinelAgent` by inheritance, so every
check shares `self.config`, `self.should_report`, and the persisted baselines
unchanged. Adding a check is a decorated method in the relevant mixin — no edit
to `run_loop`.

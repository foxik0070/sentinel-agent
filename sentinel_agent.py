#!/usr/bin/env python3
"""
Sentinel Agent Daemon - Stateful Delta Edition & Autonomous Git Auto-Update
==========================================================================
This daemon monitors critical system metrics (services, mounts, ports, root logins,
vulnerabilities, fail2ban pressure, hardware temperature, storage, RAID arrays,
SSD wearout, OOM events, zombie processes, time sync, DNS health, global systemd 
failures, uninterruptible sleep states, conntrack pressure, kernel taint, and SSL certs).
It strictly reports changes (deltas) based on exact message content to ensure 
the central UI always matches reality without spamming the network.

To eliminate post-reboot false positives (race conditions), it features a built-in
startup warm-up delay (boot grace period) ensuring all system daemons have fully 
bound their network interfaces before compiling the baseline matrices.
"""

import os
import sys
import time
import socket
import subprocess
import argparse
import re
import json
import hashlib
import datetime
from datetime import datetime, timezone

# --- Dynamic Dependency Checks ---
try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:
    print("[!] Missing critical dependency 'requests'. Execution aborted.", flush=True)
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("[!] Missing critical dependency 'pyyaml'. Execution aborted.", flush=True)
    sys.exit(1)

# Central configuration path
CONFIG_FILE = "/etc/sentinel/agent_config.yaml"


class SourceAddressAdapter(HTTPAdapter):
    """Binds outgoing HTTP requests to a specific local IP address."""
    def __init__(self, source_address, **kwargs):
        self.source_address = source_address
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['source_address'] = (self.source_address, 0)
        super().init_poolmanager(*args, **kwargs)

class SentinelAgent:
    def __init__(self, fast_mode=False):
        """Initializes the agent, loads configuration, and prepares state trackers."""
        self.fast_mode = fast_mode
        
        if not os.path.exists(CONFIG_FILE):
            print(f"[!] Configuration file target missing: {CONFIG_FILE}", flush=True)
            sys.exit(1)
            
        with open(CONFIG_FILE, 'r') as stream:
            self.config = yaml.safe_load(stream)
            
        # API Connection Setup
        self.api_url = self.config['sentinel_api']['url'].rstrip('/')
        self.token = self.config['sentinel_api']['token']
        self.hostname = self.config['sentinel_api'].get('hostname', socket.gethostname())
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        self.os_family = self._detect_os_family()
        self.is_virtual = self._is_virtual_environment()

        # --- Stateful Tracking Memory ---
        self.last_reported_states = {}
        self.last_oom_count = 0
        self.oom_initialized = False
        
        # --- Network Baseline Matrices ---
        self.baseline_ports = set()
        self.ports_initialized = False

        # --- Active Issue Registry & Service Flap Tracking ---
        self.active_issues = {}
        self.flap_counts = {}

        # --- Retry Buffer (events from failed pushes, replayed on next success) ---
        self.pending_events = []
        self.max_pending_events = self.config.get('agent_core', {}).get('max_pending_events', 500)

        # --- Suspicious Activity Baselines (critical file integrity) ---
        self.critical_file_hashes = {}
        self.critical_files_initialized = False

        # --- Persistence Files Baseline (authorized_keys, cron) ---
        self.persistence_file_hashes = {}
        self.persistence_files_initialized = False

        # --- System-wide SUID/SGID Baseline (scanned every N cycles) ---
        self.suid_baseline = set()
        self.suid_baseline_initialized = False
        self.suid_cycle_counter = 0
        self.state_file = self.config.get('agent_core', {}).get('state_file', '/var/lib/sentinel/state.json')

        # --- HTTP Session (optional source IP binding to prevent multi-IP duplicates) ---
        self.session = requests.Session()
        source_ip = self.config.get('sentinel_api', {}).get('source_ip', '').strip()
        if source_ip:
            adapter = SourceAddressAdapter(source_ip)
            self.session.mount('http://', adapter)
            self.session.mount('https://', adapter)

        # Restore persisted state so a restart neither re-spams OK transitions nor
        # opens a re-baseline window an attacker could use to launder file changes.
        self._load_state()

    def _load_state(self):
        try:
            if not os.path.exists(self.state_file):
                return
            with open(self.state_file, 'r') as f:
                state = json.load(f)
            if state.get('hostname') != self.hostname:
                return
            self.active_issues = state.get('issues', {})
            self.last_reported_states = state.get('reported_states', {})
            self.pending_events = state.get('pending_events', [])
            baselines = state.get('baselines', {})
            if baselines.get('critical_files'):
                self.critical_file_hashes = baselines['critical_files']
                self.critical_files_initialized = True
            if baselines.get('persistence_files'):
                self.persistence_file_hashes = baselines['persistence_files']
                self.persistence_files_initialized = True
            if baselines.get('suid_files'):
                self.suid_baseline = set(baselines['suid_files'])
                self.suid_baseline_initialized = True
            print(f"[*] Restored persisted state: {len(self.active_issues)} active issues, "
                  f"{len(self.last_reported_states)} reported states, integrity baselines "
                  f"{'restored' if self.critical_files_initialized else 'fresh'}.", flush=True)
        except Exception as e:
            print(f"[-] State restore failure (starting fresh): {e}", flush=True)

    def _detect_os_family(self):
        """Heuristically detects the underlying Linux distribution family."""
        if os.path.exists("/etc/debian_version"): return "debian"
        elif os.path.exists("/etc/redhat-release") or os.path.exists("/etc/centos-release"): return "rhel"
        return "generic"

    def _is_virtual_environment(self):
        """Returns True if running inside a VM or container (LXC, QEMU, KVM, etc.)."""
        try:
            result = subprocess.run(
                ["systemd-detect-virt"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10
            )
            return result.stdout.strip() != "none"
        except Exception:
            return False

    def _get_cpu_temperature(self):
        """Reads the CPU temperature from system thermal zones (compatible with Pi and Ubuntu)."""
        thermal_paths = [
            "/sys/class/thermal/thermal_zone0/temp",
            "/sys/class/thermal/thermal_zone1/temp",
            "/sys/class/hwmon/hwmon0/temp1_input",
            "/sys/class/hwmon/hwmon1/temp1_input"
        ]
        for path in thermal_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as stream:
                        raw_temp = stream.read().strip()
                        return float(raw_temp) / 1000.0
                except Exception:
                    continue
        return None

    def check_for_git_updates(self):
        """
        Autonomous Git Auto-Update (Systemd Suicide Mechanism).
        Checks the remote Git repository for new commits. If a drift is detected,
        it pulls the new code, sends a WARNING telemetry to the central server,
        and terminates the process (sys.exit). Systemd will immediately restart it.
        """
        # Validace proti konfiguraci - preskoc pokud je funkce vypnuta
        if not self.config.get('agent_core', {}).get('git_auto_update', False):
            return

        if not hasattr(self, 'update_counter'):
            self.update_counter = 0
            
        self.update_counter += 1
        # Check only once every 10 execution loops to optimize resource utilization
        if self.update_counter < 10:  
            return
            
        self.update_counter = 0
        repo_dir = os.path.dirname(os.path.abspath(__file__))
        
        if not os.path.exists(os.path.join(repo_dir, ".git")):
            return
            
        try:
            local_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_dir, text=True, timeout=60).strip()
            subprocess.run(["git", "fetch"], cwd=repo_dir, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
            remote_sha = subprocess.check_output(["git", "rev-parse", "@{u}"], cwd=repo_dir, text=True, timeout=60).strip()
            
            if local_sha != remote_sha:
                print(f"[{datetime.now().isoformat()}] 🔄 Drift detected in Git repository! Initiating git pull...", flush=True)
                subprocess.run(["git", "pull"], cwd=repo_dir, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)

                # Sanity-compile the pulled code BEFORE the suicide restart — a broken
                # remote commit would otherwise leave the agent dead until manual fix.
                compile_proc = subprocess.run(
                    [sys.executable, "-m", "py_compile", os.path.abspath(__file__)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=60
                )
                if compile_proc.returncode != 0:
                    subprocess.run(["git", "reset", "--hard", local_sha], cwd=repo_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
                    msg = f"Auto-update ABORTED: commit {remote_sha[:7]} fails to compile, rolled back to {local_sha[:7]}. Fix the remote repository. Error: {compile_proc.stderr.strip()[:200]}"
                    print(f"[{datetime.now().isoformat()}] ❌ {msg}", flush=True)
                    self.push_to_sentinel([{
                        "plugin": "agent_core_updater",
                        "target": "auto_update",
                        "status": "CRITICAL",
                        "message": msg
                    }])
                    return

                msg = f"Agent source code auto-updated via Git (from {local_sha[:7]} to {remote_sha[:7]}). Executing Systemd Suicide restart."
                print(f"[{datetime.now().isoformat()}] ✅ {msg}", flush=True)
                
                update_event = [{
                    "plugin": "agent_core_updater",
                    "target": "auto_update",
                    "status": "WARNING", 
                    "message": msg
                }]
                self.push_to_sentinel(update_event)
                sys.exit(0)
                
        except subprocess.CalledProcessError:
            pass
        except Exception as e:
            print(f"[-] Git auto-update check failed (verify root SSH keys): {e}", flush=True)

    def should_report(self, unique_check_key, current_message):
        """
        Stateful validation engine (Delta Filter).
        Returns True ONLY if the exact message payload has changed since the last execution.
        """
        last_message = self.last_reported_states.get(unique_check_key)
        if last_message != current_message:
            self.last_reported_states[unique_check_key] = current_message
            return True
        return False

    def check_services(self):
        events = []
        services = self.config.get('checks', {}).get('services', [])
        if not services:
            return events
        
        confirm_threshold = self.config.get('checks', {}).get('service_confirm_count', 2)
        for svc in services:
            name = svc['name']
            severity = svc.get('severity', 'CRITICAL').upper()
            state_key = f"service:{name}"

            result = subprocess.run(
                ["systemctl", "is-active", name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10
            )
            state = result.stdout.strip()
            current_status = severity if state not in ["active", "inactive"] else "OK"

            svc_threshold = svc.get('confirm_count', confirm_threshold)
            if current_status != "OK":
                self.flap_counts[state_key] = self.flap_counts.get(state_key, 0) + 1
                if self.flap_counts[state_key] < svc_threshold:
                    continue
            else:
                self.flap_counts[state_key] = 0

            msg = f"Systemd service '{name}' shifted to unexpected state: {state}." if current_status != "OK" else f"Service '{name}' is back to normal configuration matrix."

            if self.should_report(state_key, msg):
                events.append({
                    "plugin": "agent_services_monitor",
                    "target": name,
                    "status": current_status,
                    "message": msg
                })
        return events

    def check_mounts(self):
        events = []
        mounts = self.config.get('checks', {}).get('mounts', [])
        if not mounts:
            return events

        for mnt in mounts:
            path = mnt['path']
            severity = mnt.get('severity', 'CRITICAL').upper()
            state_key = f"mount:{path}"
            
            is_mounted = os.path.ismount(path)
            current_status = severity if not is_mounted else "OK"
            
            msg = f"Storage path '{path}' is missing or detached from file system matrix." if current_status != "OK" else f"Storage path '{path}' re-attached successfully."
            
            if self.should_report(state_key, msg):
                events.append({
                    "plugin": "agent_mounts_monitor",
                    "target": path,
                    "status": current_status,
                    "message": msg
                })
        return events

    def _get_listening_ports(self):
        active_ports = set()
        ignored_ports = {"123", "53", "68", "111", "22", "80", "443"}
        try:
            proc = subprocess.run(["ss", "-tulpn"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
            lines = proc.stdout.splitlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    protocol = "tcp" if "tcp" in parts[0].lower() else "udp"
                    local_addr = parts[4]
                    if ":" in local_addr:
                        port = local_addr.split(":")[-1]
                        if port not in ignored_ports:
                            active_ports.add(f"{protocol}:{port}")
        except Exception as e:
            print(f"[-] Listening sockets scanning failure: {e}", flush=True)
        return active_ports

    def check_network_ports(self):
        events = []
        if not self.config.get('checks', {}).get('security', {}).get('monitor_ports', False):
            return events
            
        current_ports = self._get_listening_ports()
        state_key = "network:ports_drift"
        
        if not self.ports_initialized:
            self.baseline_ports = current_ports
            self.ports_initialized = True
            print(f"[*] Sockets Baseline compiled. Tracked ports list: {list(self.baseline_ports)}", flush=True)
            return events

        unassigned_ports = current_ports - self.baseline_ports
        # UDP ports are expected (DNS, NTP, mDNS, etc.) — only flag new TCP ports
        suspicious = sorted(p for p in unassigned_ports if p.startswith('tcp:'))
        current_status = "WARNING" if suspicious else "OK"

        if current_status == "WARNING":
            msg = f"Security Alert! Unregistered listening ports identified after initialization: {suspicious}"
        else:
            msg = "Network architecture returned back to trusted baseline configurations matrix."
            
        if self.should_report(state_key, msg):
            events.append({
                "plugin": "agent_network_port_security",
                "target": "sockets",
                "status": current_status,
                "message": msg
            })
        return events

    def check_security_metrics(self):
        events = []
        sec_config = self.config.get('checks', {}).get('security', {})

        # --- 1. Real-time Root Logins Tracking ---
        if sec_config.get('monitor_root_logins', False):
            state_key = "security:root_logins"
            ignore_ips = sec_config.get('root_login_ignore_ips', [])
            try:
                who_proc = subprocess.run(["who"], stdout=subprocess.PIPE, text=True, timeout=10)
                root_sessions = []
                for line in who_proc.stdout.splitlines():
                    if line.startswith("root"):
                        parts = line.split()
                        if len(parts) < 4:
                            continue
                        tty = parts[1]
                        # IP is always in parentheses — extract by regex regardless of column count
                        ip_match = re.search(r'\(([^)]+)\)', line)
                        if not ip_match:
                            continue
                        ip = ip_match.group(1)
                        # Skip non-SSH sessions (no valid IP/hostname in parentheses)
                        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip) and ':' not in ip:
                            continue
                        # time_str: everything between tty and the parenthesised IP
                        time_str = line[line.index(tty) + len(tty):line.index('(')].strip()
                        # Skip whitelisted IPs
                        if ip in ignore_ips:
                            continue
                        root_sessions.append(f"🟢 [ACTIVE] {tty} from {ip} (since {time_str})")

                current_status = "WARNING" if root_sessions else "OK"
                msg = " | ".join(root_sessions) if current_status == "WARNING" else "Root access session cleared. Normal state restored."

                if self.should_report(state_key, msg):
                    events.append({
                        "plugin": "agent_security_root_monitor",
                        "target": "root_users",
                        "status": current_status,
                        "message": msg
                    })
            except Exception as e:
                print(f"[-] Root monitor error: {e}")

        # --- 2. System Architecture Upgrades & CVE Profiling ---
        if sec_config.get('check_system_updates', False) or sec_config.get('scan_cves', False):
            state_key = "security:vulnerabilities"
            update_count, sec_update_count = 0, 0
            sec_packages = []
            try:
                if self.os_family == "debian":
                    apt_proc = subprocess.run(["apt-get", "-s", "upgrade"], stdout=subprocess.PIPE, text=True, timeout=120)
                    upgrade_lines = [l for l in apt_proc.stdout.splitlines() if l.startswith("Inst ")]
                    update_count = len(upgrade_lines)
                    sec_lines = [l for l in upgrade_lines if "security" in l.lower() or "cve" in l.lower()]
                    sec_update_count = len(sec_lines)
                    sec_packages = [l.split()[1] for l in sec_lines if len(l.split()) > 1]
                elif self.os_family == "rhel":
                    dnf_proc = subprocess.run(["dnf", "check-update", "--security"], stdout=subprocess.PIPE, text=True, timeout=120)
                    if dnf_proc.returncode == 100:
                        sec_lines = [l for l in dnf_proc.stdout.splitlines() if l.strip() and not l.startswith(('Last metadata', 'Obsoleting'))]
                        sec_update_count = len(sec_lines)
                        sec_packages = [l.split()[0] for l in sec_lines if l.split()]
                    dnf_all = subprocess.run(["dnf", "check-update"], stdout=subprocess.PIPE, text=True, timeout=120)
                    if dnf_all.returncode == 100:
                        update_count = len([l for l in dnf_all.stdout.splitlines() if l.strip()])

                current_status = "CRITICAL" if sec_update_count > 0 else ("WARNING" if update_count > 20 else "OK")
                if current_status == "CRITICAL":
                    pkg_list = ", ".join(sec_packages[:10]) + ("..." if len(sec_packages) > 10 else "")
                    msg = f"System is vulnerable! Found {sec_update_count} unpatched security updates/CVE vectors. Affected: {pkg_list}"
                elif current_status == "WARNING":
                    msg = f"System software array is drifting out of date. Found {update_count} pending updates."
                else:
                    msg = "All core software distribution binaries up to date."
                    
                if self.should_report(state_key, msg):
                    events.append({
                        "plugin": "agent_security_vulnerability_scan",
                        "target": "packages",
                        "status": current_status,
                        "message": msg
                    })
            except Exception: pass

        # --- 2b. Pending Reboot (installed kernel/libc patch not effective yet) ---
        if sec_config.get('check_system_updates', False):
            state_key = "security:reboot_required"
            reboot_flag = "/var/run/reboot-required"
            pending = os.path.exists(reboot_flag)
            if pending:
                pkgs = ""
                try:
                    with open("/var/run/reboot-required.pkgs", 'r') as f:
                        pkg_names = sorted(set(l.strip() for l in f if l.strip()))
                        pkgs = f" Triggered by: {', '.join(pkg_names[:10])}."
                except Exception:
                    pass
                current_status = "WARNING"
                msg = f"Reboot required! Installed security patches (kernel/libraries) are not effective until restart.{pkgs}"
            else:
                current_status = "OK"
                msg = "No pending reboot. All installed patches are active."

            if self.should_report(state_key, msg):
                events.append({
                    "plugin": "agent_security_reboot_required",
                    "target": "reboot",
                    "status": current_status,
                    "message": msg
                })

        # --- 3. Fail2ban Brute-Force Pressure Statistics ---
        if sec_config.get('fail2ban_stats', False):
            state_key = "security:fail2ban"
            try:
                f2b_proc = subprocess.run(["fail2ban-client", "status"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=15)
                if f2b_proc.returncode == 0:
                    jails = re.findall(r"Jail list:\s+(.*)", f2b_proc.stdout)
                    if jails:
                        jail_list = [j.strip() for j in jails[0].split(",")]
                        total_banned = 0
                        for jail in jail_list:
                            j_stat = subprocess.run(["fail2ban-client", "status", jail], stdout=subprocess.PIPE, text=True, timeout=15)
                            banned_match = re.search(r"Currently banned:\s+(\d+)", j_stat.stdout)
                            if banned_match: total_banned += int(banned_match.group(1))
                                
                        current_status = "WARNING" if total_banned > 50 else "OK"
                        msg = f"High brute-force pressure detected. Fail2ban actively blocking {total_banned} attackers." if current_status == "WARNING" else "Firewall traffic profile inside baseline levels."
                        
                        if self.should_report(state_key, msg):
                            events.append({
                                "plugin": "agent_security_firewall_fail2ban",
                                "target": "bans",
                                "status": current_status,
                                "message": msg
                            })
            except Exception: pass

        return events

    # Critical files whose unexpected change signals privilege-escalation abuse
    # (Dirty COW / Dirty Pipe exploits typically rewrite /etc/passwd or sudoers).
    CRITICAL_FILES = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
    TMP_EXEC_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
    # Deleted binaries under these prefixes are normal after package upgrades;
    # anywhere else (typically /home, /root, /var) it signals a self-deleting payload.
    SYSTEM_EXEC_PREFIXES = ("/usr/", "/opt/", "/lib", "/bin/", "/sbin/", "/snap/", "/nix/")
    MINER_NAMES = {"xmrig", "xmr-stak", "minerd", "cpuminer", "kinsing", "kdevtmpfsi"}
    REVSHELL_PATTERNS = [
        r"/dev/tcp/\d",
        r"\bnc(at)?\b.*\s-e\s",
        r"\bsocat\b.*\bexec\b",
        r"pty\.spawn",
        r"\bsh -i\b.*\d+\.\d+\.\d+\.\d+",
    ]

    # Well-known local privilege escalation kernel CVEs actively abused in the wild.
    # Format: (cve_id, nickname, [(first_affected_incl, fixed_in_excl), ...]).
    # Distro kernels backport fixes without bumping upstream version, hence WARNING
    # severity with a "verify backport" note instead of CRITICAL.
    KERNEL_LPE_CVES = [
        ("CVE-2016-5195", "Dirty COW", [((2, 6, 22), (4, 4, 26)), ((4, 5, 0), (4, 7, 9)), ((4, 8, 0), (4, 8, 3))]),
        ("CVE-2021-3493", "OverlayFS cap abuse (Ubuntu)", [((3, 13, 0), (5, 11, 0))]),
        ("CVE-2022-0847", "Dirty Pipe", [((5, 8, 0), (5, 10, 102)), ((5, 11, 0), (5, 15, 25)), ((5, 16, 0), (5, 16, 11))]),
        ("CVE-2024-1086", "nf_tables UAF", [((3, 15, 0), (6, 1, 76)), ((6, 2, 0), (6, 6, 15)), ((6, 7, 0), (6, 7, 3))]),
    ]

    def _kernel_version(self):
        """Returns the running kernel version as a (major, minor, patch) tuple, or None."""
        match = re.match(r'^(\d+)\.(\d+)\.(\d+)', os.uname().release)
        if not match:
            return None
        return tuple(int(g) for g in match.groups())

    def check_kernel_cves(self):
        """Compares the running kernel version against known local privilege
        escalation CVE ranges (Dirty COW, Dirty Pipe, ...)."""
        events = []
        if not self.config.get('checks', {}).get('security', {}).get('scan_cves', False):
            return events

        kver = self._kernel_version()
        if kver is None:
            return events

        hits = []
        for cve_id, nickname, ranges in self.KERNEL_LPE_CVES:
            if any(lo <= kver < hi for lo, hi in ranges):
                hits.append(f"{cve_id} ({nickname})")

        state_key = "security:kernel_lpe_cves"
        release = os.uname().release
        if hits:
            current_status = "WARNING"
            msg = (f"Kernel {release} version falls into known privilege-escalation CVE ranges: "
                   f"{', '.join(hits)}. Verify your distribution backported the fixes, or update/reboot the kernel.")
        else:
            current_status = "OK"
            msg = f"Kernel {release} is outside known local privilege-escalation CVE ranges."

        if self.should_report(state_key, msg):
            events.append({
                "plugin": "agent_security_kernel_cve",
                "target": "kernel",
                "status": current_status,
                "message": msg
            })
        return events

    def _hash_file(self, path):
        try:
            with open(path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return None

    def _journal_delta(self, cursor_filename, journal_args):
        """Returns journal lines new since the last call (persistent cursor next to
        the state file), [] when nothing new, or None if the journal is unavailable."""
        cursor_file = os.path.join(os.path.dirname(self.state_file) or "/var/lib/sentinel", cursor_filename)
        try:
            if not os.path.exists(cursor_file):
                os.makedirs(os.path.dirname(cursor_file), exist_ok=True)
                init_proc = subprocess.run(
                    ["journalctl"] + journal_args + ["-n", "1", "-o", "cat", f"--cursor-file={cursor_file}"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30
                )
                if init_proc.returncode == 0 and os.path.exists(cursor_file):
                    return []
                return None
            proc = subprocess.run(
                ["journalctl"] + journal_args + ["-o", "cat", f"--cursor-file={cursor_file}", "--no-pager"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=30
            )
            if proc.returncode != 0:
                return None
            return proc.stdout.splitlines()
        except Exception:
            return None

    def _scan_suid_files(self):
        """Full-filesystem SUID/SGID inventory (single device, /proc etc. excluded)."""
        proc = subprocess.run(
            ["find", "/", "-xdev", "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=120
        )
        return set(l for l in proc.stdout.splitlines() if l.strip())

    def _collect_persistence_files(self):
        """Returns paths of files attackers modify for post-exploit persistence:
        SSH authorized_keys (root + users) and cron entries."""
        paths = ["/root/.ssh/authorized_keys", "/etc/crontab"]
        try:
            for home in os.listdir('/home'):
                paths.append(f"/home/{home}/.ssh/authorized_keys")
        except Exception:
            pass
        for cron_dir in ("/etc/cron.d", "/var/spool/cron/crontabs", "/var/spool/cron"):
            try:
                for entry in os.listdir(cron_dir):
                    full = os.path.join(cron_dir, entry)
                    if os.path.isfile(full):
                        paths.append(full)
            except Exception:
                continue
        return [p for p in paths if os.path.exists(p)]

    def _scan_suspicious_processes(self):
        """Walks /proc for processes executing from tmp dirs, known miners and reverse-shell patterns."""
        findings = []
        for pid in os.listdir('/proc'):
            if not pid.isdigit() or int(pid) == os.getpid():
                continue
            base = f"/proc/{pid}"
            try:
                with open(f"{base}/comm", 'r') as f:
                    comm = f.read().strip()
                with open(f"{base}/cmdline", 'rb') as f:
                    cmdline = f.read().replace(b'\x00', b' ').decode(errors='replace').strip()
            except Exception:
                continue  # process vanished mid-scan
            try:
                exe = os.readlink(f"{base}/exe")
            except Exception:
                exe = ""

            deleted = exe.endswith(" (deleted)")
            exe_path = exe[:-len(" (deleted)")] if deleted else exe

            if exe_path.startswith(self.TMP_EXEC_DIRS):
                findings.append(f"'{comm}' (PID {pid}) executing from temp dir: {exe}")
            elif exe_path.startswith("/memfd:") or exe_path.startswith("memfd:"):
                findings.append(f"fileless (memfd) executable '{comm}' (PID {pid}): {exe}")
            elif deleted and exe_path and not exe_path.startswith(self.SYSTEM_EXEC_PREFIXES):
                findings.append(f"'{comm}' (PID {pid}) running from deleted binary: {exe} (self-deleting payload?)")
            elif comm in self.MINER_NAMES:
                findings.append(f"known cryptominer process '{comm}' (PID {pid})")
            elif cmdline and any(re.search(p, cmdline) for p in self.REVSHELL_PATTERNS):
                findings.append(f"reverse-shell pattern in '{comm}' (PID {pid}): {cmdline[:100]}")
        return findings

    def check_suspicious_activity(self):
        """Detects suspicious user behavior and processes: critical file tampering
        (Dirty COW/Dirty Pipe footprint), rogue UID 0 accounts, processes running
        from temp dirs / miners / reverse shells, and SUID binaries in temp dirs."""
        events = []
        if not self.config.get('checks', {}).get('security', {}).get('monitor_suspicious', False):
            return events

        # --- 1. Critical file integrity (event-style, like OOM) ---
        current_hashes = {p: self._hash_file(p) for p in self.CRITICAL_FILES}
        if not self.critical_files_initialized:
            self.critical_file_hashes = current_hashes
            self.critical_files_initialized = True
        else:
            changed = [p for p in self.CRITICAL_FILES
                       if current_hashes.get(p) != self.critical_file_hashes.get(p)]
            state_key = "security:critical_files"
            if changed:
                msg = f"Integrity Alert! Critical auth files modified since baseline: {', '.join(changed)}. Verify this was a legitimate admin change (Dirty COW/Dirty Pipe exploits rewrite these files)."
                self.critical_file_hashes = current_hashes
                self.last_reported_states[state_key] = msg
                events.append({
                    "plugin": "agent_security_suspicious_activity",
                    "target": "critical_files",
                    "status": "CRITICAL",
                    "message": msg
                })
            else:
                msg = "Critical auth file integrity matches trusted baseline."
                if self.should_report(state_key, msg):
                    events.append({
                        "plugin": "agent_security_suspicious_activity",
                        "target": "critical_files",
                        "status": "OK",
                        "message": msg
                    })

        # --- 1b. Persistence file integrity: authorized_keys + cron (event-style) ---
        persist_hashes = {p: self._hash_file(p) for p in self._collect_persistence_files()}
        if not self.persistence_files_initialized:
            self.persistence_file_hashes = persist_hashes
            self.persistence_files_initialized = True
        else:
            changed = [p for p in set(persist_hashes) | set(self.persistence_file_hashes)
                       if persist_hashes.get(p) != self.persistence_file_hashes.get(p)]
            state_key = "security:persistence_files"
            if changed:
                msg = f"Persistence Alert! SSH keys / cron entries changed since baseline: {', '.join(sorted(changed))}. Attackers plant these after CVE exploitation - verify this was a legitimate admin change."
                self.persistence_file_hashes = persist_hashes
                self.last_reported_states[state_key] = msg
                events.append({
                    "plugin": "agent_security_suspicious_activity",
                    "target": "persistence_files",
                    "status": "CRITICAL",
                    "message": msg
                })
            else:
                msg = "SSH authorized_keys and cron entries match trusted baseline."
                if self.should_report(state_key, msg):
                    events.append({
                        "plugin": "agent_security_suspicious_activity",
                        "target": "persistence_files",
                        "status": "OK",
                        "message": msg
                    })

        # --- 1c. LD_PRELOAD rootkit hook (persistent condition) ---
        try:
            preload_content = ""
            if os.path.exists('/etc/ld.so.preload'):
                with open('/etc/ld.so.preload', 'r') as f:
                    preload_content = f.read().strip()
            state_key = "security:ld_preload"
            current_status = "CRITICAL" if preload_content else "OK"
            msg = f"Userland rootkit suspected! /etc/ld.so.preload is active with: {preload_content[:200]}" if preload_content else "No system-wide LD_PRELOAD hooks present."
            if self.should_report(state_key, msg):
                events.append({
                    "plugin": "agent_security_suspicious_activity",
                    "target": "ld_preload",
                    "status": current_status,
                    "message": msg
                })
        except Exception as e:
            print(f"[-] ld.so.preload check failure: {e}", flush=True)

        # --- 2. Rogue UID 0 accounts (persistent condition) ---
        try:
            rogue_uid0 = []
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    parts = line.split(':')
                    if len(parts) >= 3 and parts[2] == '0' and parts[0] != 'root':
                        rogue_uid0.append(parts[0])
            state_key = "security:uid0_accounts"
            current_status = "CRITICAL" if rogue_uid0 else "OK"
            msg = f"Privilege escalation backdoor suspected! Non-root accounts with UID 0: {', '.join(rogue_uid0)}" if rogue_uid0 else "No unauthorized UID 0 accounts present."
            if self.should_report(state_key, msg):
                events.append({
                    "plugin": "agent_security_suspicious_activity",
                    "target": "uid0_accounts",
                    "status": current_status,
                    "message": msg
                })
        except Exception as e:
            print(f"[-] UID 0 account scan failure: {e}", flush=True)

        # --- 3. Suspicious processes (persistent condition) ---
        try:
            findings = self._scan_suspicious_processes()
            state_key = "security:susp_processes"
            current_status = "CRITICAL" if findings else "OK"
            msg = f"Suspicious process activity detected: {' | '.join(findings)}" if findings else "Process behavioral scan clean."
            if self.should_report(state_key, msg):
                events.append({
                    "plugin": "agent_security_suspicious_activity",
                    "target": "processes",
                    "status": current_status,
                    "message": msg
                })
        except Exception as e:
            print(f"[-] Suspicious process scan failure: {e}", flush=True)

        # --- 4. SUID binaries in temp dirs (persistent condition) ---
        try:
            proc = subprocess.run(
                ["find", "/tmp", "/var/tmp", "/dev/shm", "-xdev", "-type", "f", "-perm", "-4000"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=30
            )
            suid_files = [l for l in proc.stdout.splitlines() if l.strip()]
            state_key = "security:suid_tmp"
            current_status = "CRITICAL" if suid_files else "OK"
            msg = f"SUID binaries planted in temp dirs (exploit staging): {', '.join(suid_files)}" if suid_files else "No SUID binaries in temp dirs."
            if self.should_report(state_key, msg):
                events.append({
                    "plugin": "agent_security_suspicious_activity",
                    "target": "suid_binaries",
                    "status": current_status,
                    "message": msg
                })
        except Exception as e:
            print(f"[-] SUID temp dir scan failure: {e}", flush=True)

        # --- 5. System-wide SUID/SGID baseline (event-style, scanned every 10 cycles) ---
        # Kernel LPE exploits and package backdoors typically plant a SUID shell.
        # Full-filesystem find is too heavy for every cycle, hence the reduced cadence.
        try:
            if self.suid_cycle_counter % 10 == 0:
                current_suid = self._scan_suid_files()
                if not self.suid_baseline_initialized:
                    self.suid_baseline = current_suid
                    self.suid_baseline_initialized = True
                    print(f"[*] SUID/SGID baseline compiled: {len(current_suid)} files tracked.", flush=True)
                else:
                    new_files = sorted(current_suid - self.suid_baseline)
                    state_key = "security:suid_baseline"
                    if new_files:
                        msg = f"New SUID/SGID binaries appeared since baseline: {', '.join(new_files[:10])}{'...' if len(new_files) > 10 else ''}. Verify this was a legitimate package install (exploits plant SUID shells for persistence)."
                        self.suid_baseline = current_suid
                        self.last_reported_states[state_key] = msg
                        events.append({
                            "plugin": "agent_security_suspicious_activity",
                            "target": "suid_baseline",
                            "status": "CRITICAL",
                            "message": msg
                        })
                    else:
                        self.suid_baseline = current_suid  # absorb removals silently
                        msg = "System-wide SUID/SGID inventory matches trusted baseline."
                        if self.should_report(state_key, msg):
                            events.append({
                                "plugin": "agent_security_suspicious_activity",
                                "target": "suid_baseline",
                                "status": "OK",
                                "message": msg
                            })
            self.suid_cycle_counter += 1
        except Exception as e:
            print(f"[-] SUID baseline scan failure: {e}", flush=True)

        # --- 6. sudo/su authentication failure burst (event-style, journal cursor) ---
        try:
            lines = self._journal_delta("auth_journal.cursor", ["-t", "sudo", "-t", "su"])
            if lines is not None:
                fails = [l for l in lines if re.search(
                    r"authentication failure|FAILED SU|NOT in sudoers|incorrect password attempt", l, re.IGNORECASE)]
                threshold = self.config.get('checks', {}).get('security', {}).get('sudo_fail_threshold', 3)
                state_key = "security:auth_failures"
                if len(fails) >= threshold:
                    sample = " | ".join(f.strip()[:90] for f in fails[:3])
                    msg = f"Privilege escalation attempts! {len(fails)} sudo/su authentication failures since last cycle. Samples: {sample}"
                    self.last_reported_states[state_key] = msg
                    events.append({
                        "plugin": "agent_security_suspicious_activity",
                        "target": "auth_failures",
                        "status": "WARNING",
                        "message": msg
                    })
                else:
                    msg = "Local sudo/su authentication activity within normal limits."
                    if self.should_report(state_key, msg):
                        events.append({
                            "plugin": "agent_security_suspicious_activity",
                            "target": "auth_failures",
                            "status": "OK",
                            "message": msg
                        })
        except Exception as e:
            print(f"[-] Auth failure journal scan error: {e}", flush=True)

        return events

    def check_temperature(self):
        events = []
        temp_config = self.config.get('checks', {}).get('temperature', {})
        if not temp_config.get('enabled', False):
            return events
            
        temp = self._get_cpu_temperature()
        if temp is None:
            return events
            
        warning_thresh = temp_config.get('warning', 75.0)
        critical_thresh = temp_config.get('critical', 85.0)
        
        if temp >= critical_thresh:
            current_status = "CRITICAL"
            msg = "CPU thermal crisis! Architecture operating above critical threshold."
        elif temp >= warning_thresh:
            current_status = "WARNING"
            msg = "CPU thermal pressure! Architecture operating above warning threshold."
        else:
            current_status = "OK"
            msg = "CPU thermal profile returned back to trusted operational baseline matrix."
            
        state_key = "hardware:temperature"
        if self.should_report(state_key, msg):
            full_msg = f"{msg} Current temperature: {temp:.1f}C."
            events.append({
                "plugin": "agent_temperature_monitor",
                "target": "cpu_thermal",
                "status": current_status,
                "message": full_msg
            })
        return events

    # vcgencmd get_throttled bitmask (Raspberry Pi firmware).
    # Bits 0-3 = active conditions, bits 16-19 = occurred since boot.
    RPI_THROTTLE_BITS = [
        (0,  "CRITICAL", "under-voltage detected NOW"),
        (1,  "WARNING",  "ARM frequency capped NOW"),
        (2,  "WARNING",  "currently throttled NOW"),
        (3,  "WARNING",  "soft temperature limit active NOW"),
        (16, "WARNING",  "under-voltage occurred since boot"),
        (17, "WARNING",  "ARM frequency capping occurred since boot"),
        (18, "WARNING",  "throttling occurred since boot"),
        (19, "WARNING",  "soft temperature limit occurred since boot"),
    ]

    def check_rpi_throttling(self):
        """Raspberry Pi undervoltage/throttling via vcgencmd get_throttled.
        Undervoltage is the most common cause of mysterious RPi instability
        (bad PSU/cable) - often more important than the temperature itself."""
        events = []
        if not self.config.get('checks', {}).get('hardware', {}).get('monitor_rpi_throttling', False):
            return events

        try:
            proc = subprocess.run(["vcgencmd", "get_throttled"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
        except FileNotFoundError:
            return events  # not a Raspberry Pi
        except Exception as e:
            print(f"[-] vcgencmd execution failure: {e}", flush=True)
            return events

        match = re.search(r'throttled=(0x[0-9a-fA-F]+)', proc.stdout)
        if not match:
            return events
        value = int(match.group(1), 16)

        flags = [(sev, desc) for bit, sev, desc in self.RPI_THROTTLE_BITS if value & (1 << bit)]
        state_key = "hardware:rpi_throttling"

        if flags:
            current_status = "CRITICAL" if any(sev == "CRITICAL" for sev, _ in flags) else "WARNING"
            msg = f"Power/thermal firmware flags active ({hex(value)}): {'; '.join(d for _, d in flags)}. Check PSU/cable and cooling."
        else:
            current_status = "OK"
            msg = "Firmware power and thermal profile clean (no undervoltage or throttling flags)."

        if self.should_report(state_key, msg):
            events.append({
                "plugin": "agent_rpi_power_monitor",
                "target": "firmware_throttling",
                "status": current_status,
                "message": msg
            })
        return events

    def check_storage_capacity(self):
        events = []
        storage_config = self.config.get('checks', {}).get('storage', {})
        if not storage_config.get('enabled', False):
            return events

        paths = storage_config.get('paths', [])
        warn_pct = storage_config.get('warn_percent', 85)
        crit_pct = storage_config.get('crit_percent', 95)

        for path in paths:
            if not os.path.exists(path):
                continue
            try:
                st = os.statvfs(path)
                total_bytes = st.f_blocks * st.f_frsize
                free_bytes = st.f_bavail * st.f_frsize
                used_pct = ((total_bytes - free_bytes) / total_bytes) * 100 if total_bytes > 0 else 0

                total_inodes = st.f_files
                free_inodes = st.f_favail
                used_inode_pct = ((total_inodes - free_inodes) / total_inodes) * 100 if total_inodes > 0 else 0

                max_pct = max(used_pct, used_inode_pct)
                if max_pct >= crit_pct:
                    current_status = "CRITICAL"
                    msg = f"Storage target '{path}' has exceeded critical capacity threshold."
                elif max_pct >= warn_pct:
                    current_status = "WARNING"
                    msg = f"Storage target '{path}' has exceeded warning capacity threshold."
                else:
                    current_status = "OK"
                    msg = f"Storage target '{path}' capacity matrix safely inside baseline boundaries."

                state_key = f"storage:space:{path}"
                if self.should_report(state_key, msg):
                    full_msg = f"{msg} Space Used: {used_pct:.1f}%, Inodes Used: {used_inode_pct:.1f}%."
                    events.append({
                        "plugin": "agent_storage_capacity_monitor",
                        "target": path,
                        "status": current_status,
                        "message": full_msg
                    })
            except Exception as e:
                print(f"[-] Storage capacity collection failure for {path}: {e}")
        return events

    def check_raid_arrays(self):
        events = []
        storage_config = self.config.get('checks', {}).get('storage', {})
        if not storage_config.get('monitor_raid', False):
            return events

        if self.is_virtual:
            return events

        if not os.path.exists("/proc/mdstat"):
            return events

        try:
            with open("/proc/mdstat", "r") as stream:
                content = stream.read()

            state_key = "storage:mdadm_raid"
            if "_" in content or "degraded" in content.lower():
                current_status = "CRITICAL"
                msg = "RAID Matrix Alert! Degraded disk arrays detected in infrastructure layers."
            elif "resync" in content.lower() or "recovery" in content.lower():
                current_status = "WARNING"
                msg = "RAID Matrix Warning. Active reconstruction/resync operations identified."
            else:
                current_status = "OK"
                msg = "All detected software RAID arrays running in healthy synchronized configuration matrix."

            if self.should_report(state_key, msg):
                events.append({
                    "plugin": "agent_raid_monitor",
                    "target": "mdadm_arrays",
                    "status": current_status,
                    "message": msg
                })
        except Exception as e:
            print(f"[-] RAID health parser exception: {e}")
        return events

    def check_ssd_wearout(self):
        events = []
        storage_config = self.config.get('checks', {}).get('storage', {})
        if not storage_config.get('monitor_wearout', False):
            return events

        if self.is_virtual:
            return events

        drives = []
        try:
            for d in os.listdir("/sys/block/"):
                if re.match(r'^(sd[a-z]+|nvme\d+n\d+)$', d):
                    drives.append(f"/dev/{d}")
        except Exception:
            return events

        for drive in drives:
            try:
                proc = subprocess.run(["smartctl", "-A", drive], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=30)
                if proc.returncode != 0:
                    continue
                
                wearout_pct = None
                if "nvme" in drive:
                    match = re.search(r"Percentage Used:\s+(\d+)%", proc.stdout)
                    if match:
                        wearout_pct = 100 - int(match.group(1))
                else:
                    match = re.search(r"(Media_Wearout_Indicator|Remaining_Lifetime_Perc|Wearout_Linear).*?\s+(\d+)(?=\s|$)", proc.stdout)
                    if match:
                        wearout_pct = int(match.group(2))

                if wearout_pct is None:
                    continue

                state_key = f"storage:wearout:{drive}"
                if wearout_pct <= 10:
                    current_status = "CRITICAL"
                    msg = f"Hardware wearout emergency! Drive lifespan approaching critical depletion state."
                elif wearout_pct <= 20:
                    current_status = "WARNING"
                    msg = f"Hardware wearout alert. Drive lifespan falling below safety parameters."
                else:
                    current_status = "OK"
                    msg = f"Drive silicon cells endurance profile structurally sound."

                if self.should_report(state_key, msg):
                    full_msg = f"{msg} Remaining Life Estimate: {wearout_pct}%."
                    events.append({
                        "plugin": "agent_ssd_wearout_monitor",
                        "target": drive,
                        "status": current_status,
                        "message": full_msg
                    })
            except Exception as e:
                print(f"[-] SMART query abstraction error for {drive}: {e}")
        return events

    def check_disk_health(self):
        """SMART overall health check for physical drives. Skipped on virtual machines."""
        events = []
        if not self.config.get('checks', {}).get('storage', {}).get('monitor_disk_health', False):
            return events
        if self.is_virtual:
            return events

        drives = []
        try:
            for d in os.listdir("/sys/block/"):
                if re.match(r'^sd[a-z]$', d) or re.match(r'^nvme\d+n\d+$', d) or re.match(r'^hd[a-z]$', d):
                    drives.append(f"/dev/{d}")
        except Exception:
            return events

        for drive in drives:
            try:
                proc = subprocess.run(
                    ["smartctl", "-H", drive],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=30
                )
                output = proc.stdout
                state_key = f"storage:health:{drive}"

                if "FAILED" in output:
                    current_status = "CRITICAL"
                    msg = f"SMART health FAILED for drive '{drive}'! Possible imminent hardware failure."
                elif "PASSED" in output or "OK" in output:
                    current_status = "OK"
                    msg = f"Drive '{drive}' SMART health check passed."
                else:
                    continue  # SMART not supported or inconclusive

                if self.should_report(state_key, msg):
                    events.append({
                        "plugin": "agent_disk_health_monitor",
                        "target": drive,
                        "status": current_status,
                        "message": msg
                    })
            except Exception as e:
                print(f"[-] SMART health check error for {drive}: {e}", flush=True)
        return events

    OOM_REGEX = r"(Out of memory: Kill process|Killed process \d+ \(.+?\) total-vm)"

    def _oom_event(self, kill_count):
        state_key = "kernel:oom_events"
        if kill_count > 0:
            msg = f"Kernel Architecture Error! Out-Of-Memory (OOM) killer context triggered. {kill_count} processes terminated."
            self.last_reported_states[state_key] = msg
            return [{
                "plugin": "agent_kernel_oom_monitor",
                "target": "oom_killer",
                "status": "CRITICAL",
                "message": msg
            }]
        msg = "Kernel memory allocation subsystems operating within safe structural limits."
        if self.should_report(state_key, msg):
            return [{
                "plugin": "agent_kernel_oom_monitor",
                "target": "oom_killer",
                "status": "OK",
                "message": msg
            }]
        return []

    def check_oom_killer_events(self):
        """OOM kill detection. Primary: journal cursor (exact, survives ring buffer
        rotation and agent restarts). Fallback: dmesg count delta (non-systemd hosts)."""
        events = []
        if not self.config.get('checks', {}).get('kernel', {}).get('monitor_oom', False):
            return events

        # --- Primary: kernel journal with persistent cursor ---
        cursor_file = os.path.join(os.path.dirname(self.state_file) or "/var/lib/sentinel", "oom_journal.cursor")
        try:
            if not os.path.exists(cursor_file):
                os.makedirs(os.path.dirname(cursor_file), exist_ok=True)
                init_proc = subprocess.run(
                    ["journalctl", "-k", "-n", "1", "-o", "cat", f"--cursor-file={cursor_file}"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30
                )
                if init_proc.returncode == 0 and os.path.exists(cursor_file):
                    return events  # cursor initialized; deltas count from next cycle
                raise RuntimeError("journal cursor initialization failed")

            proc = subprocess.run(
                ["journalctl", "-k", "-o", "cat", f"--cursor-file={cursor_file}", "--no-pager"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=30
            )
            if proc.returncode != 0:
                raise RuntimeError(f"journalctl exited {proc.returncode}")

            new_kills = len(re.findall(self.OOM_REGEX, proc.stdout, re.IGNORECASE))
            return self._oom_event(new_kills)
        except Exception:
            pass  # journal unavailable - fall through to dmesg counting

        # --- Fallback: dmesg occurrence count delta ---
        try:
            proc = subprocess.run(["dmesg"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
            current_count = len(re.findall(self.OOM_REGEX, proc.stdout, re.IGNORECASE))

            if not self.oom_initialized:
                self.last_oom_count = current_count
                self.oom_initialized = True
                return events

            new_kills = max(0, current_count - self.last_oom_count)
            self.last_oom_count = current_count
            return self._oom_event(new_kills)
        except Exception as e:
            print(f"[-] OOM ring buffer tracking failure: {e}")
        return events

    def check_zombie_processes(self):
        events = []
        kernel_config = self.config.get('checks', {}).get('kernel', {})
        if not kernel_config.get('monitor_zombies', False):
            return events

        max_zombies = kernel_config.get('max_zombies', 5)
        try:
            proc = subprocess.run(["ps", "-eo", "state"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
            zombie_count = proc.stdout.splitlines().count("Z")

            state_key = "kernel:zombies"
            if zombie_count >= max_zombies:
                current_status = "WARNING"
                msg = f"Defunct process accumulation detected. System contains multiple uncleaned zombie tasks."
            else:
                current_status = "OK"
                msg = "Process lifecycle management execution context is clear."

            if self.should_report(state_key, msg):
                full_msg = f"{msg} Active Defunct Count: {zombie_count} (Limit: {max_zombies})."
                events.append({
                    "plugin": "agent_process_zombie_monitor",
                    "target": "process_table",
                    "status": current_status,
                    "message": full_msg
                })
        except Exception as e:
            print(f"[-] Zombie tracking utility execution exception: {e}")
        return events

    def check_time_synchronization(self):
        events = []
        if not self.config.get('checks', {}).get('system', {}).get('monitor_time_sync', False):
            return events

        try:
            proc = subprocess.run(["timedatectl"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
            state_key = "system:time_sync"
            if "System clock synchronized: yes" in proc.stdout or "NTP service: active" in proc.stdout:
                current_status = "OK"
                msg = "System reference clock synchronized with upstream network time clusters."
            else:
                current_status = "WARNING"
                msg = "System reference clock drift warning! Local timestamp is unsynchronized."

            if self.should_report(state_key, msg):
                events.append({
                    "plugin": "agent_system_time_sync",
                    "target": "ntp_clock",
                    "status": current_status,
                    "message": msg
                })
        except Exception as e:
            print(f"[-] Time synchronization status validation failure: {e}")
        return events

    def check_dns_resolution_health(self):
        events = []
        if not self.config.get('checks', {}).get('network', {}).get('monitor_dns', False):
            return events

        state_key = "network:dns_resolution"
        test_domain = "one.one.one.one"
        try:
            socket.gethostbyname(test_domain)
            current_status = "OK"
            msg = "Network resolver loops functioning normally. DNS resolution online."
        except socket.gaierror:
            current_status = "WARNING"
            msg = f"Network socket resolution exception. Unable to resolve test target domain '{test_domain}'."

        if self.should_report(state_key, msg):
            events.append({
                "plugin": "agent_network_dns_monitor",
                "target": "resolver",
                "status": current_status,
                "message": msg
            })
        return events

    def check_global_systemd_failures(self):
        events = []
        if not self.config.get('checks', {}).get('system', {}).get('monitor_global_systemd', False):
            return events

        try:
            proc = subprocess.run(["systemctl", "list-units", "--state=failed", "--no-legend"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
            failed_units = [line.split()[0] for line in proc.stdout.splitlines() if line.strip()]

            state_key = "systemd:global_failures"
            if failed_units:
                current_status = "CRITICAL"
                msg = f"Systemd subsystem alert! Failed units detected: {', '.join(failed_units)}"
            else:
                current_status = "OK"
                msg = "All systemd units operating within expected runtime parameters."

            if self.should_report(state_key, msg):
                events.append({
                    "plugin": "agent_systemd_global_monitor",
                    "target": "unit_matrix",
                    "status": current_status,
                    "message": msg
                })
        except Exception as e:
            print(f"[-] Global systemd failure check exception: {e}")
        return events

    def check_uninterruptible_processes(self):
        events = []
        if not self.config.get('checks', {}).get('kernel', {}).get('monitor_io_hangs', False):
            return events

        try:
            proc = subprocess.run(["ps", "-eo", "state,pid,comm"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
            d_processes = []
            for line in proc.stdout.splitlines():
                if line.strip().startswith("D"):
                    parts = line.split(None, 2)
                    if len(parts) >= 3:
                        d_processes.append(f"{parts[2]} (PID: {parts[1]})")

            state_key = "kernel:io_hang"
            if len(d_processes) >= 2:
                current_status = "CRITICAL"
                msg = f"I/O Hang Detected! Processes stuck in uninterruptible sleep: {', '.join(d_processes)}"
            else:
                current_status = "OK"
                msg = "Storage Subsystem and kernel I/O pipelines executing cleanly."

            if self.should_report(state_key, msg):
                events.append({
                    "plugin": "agent_kernel_io_monitor",
                    "target": "process_scheduler",
                    "status": current_status,
                    "message": msg
                })
        except Exception as e:
            print(f"[-] D-state tracking exception: {e}")
        return events

    def check_conntrack_pressure(self):
        events = []
        if not self.config.get('checks', {}).get('network', {}).get('monitor_conntrack', False):
            return events

        count_path = "/proc/sys/net/netfilter/nf_conntrack_count"
        max_path = "/proc/sys/net/netfilter/nf_conntrack_max"

        if os.path.exists(count_path) and os.path.exists(max_path):
            try:
                with open(count_path, 'r') as c_file, open(max_path, 'r') as m_file:
                    count = int(c_file.read().strip())
                    maximum = int(m_file.read().strip())
                
                pct_used = (count / maximum) * 100 if maximum > 0 else 0
                state_key = "network:conntrack_table"

                if pct_used >= 90:
                    current_status = "CRITICAL"
                    msg = "Network Firewall Emergency! Netfilter conntrack table is near exhaustion."
                elif pct_used >= 75:
                    current_status = "WARNING"
                    msg = "Network Firewall Pressure. High connection tracking table utilization detected."
                else:
                    current_status = "OK"
                    msg = "Netfilter connection tracking table metrics inside safe structural baselines."

                if self.should_report(state_key, msg):
                    full_msg = f"{msg} Current usage: {pct_used:.1f}% ({count}/{maximum})."
                    events.append({
                        "plugin": "agent_netfilter_monitor",
                        "target": "conntrack_subsystem",
                        "status": current_status,
                        "message": full_msg
                    })
            except Exception as e:
                print(f"[-] Conntrack reading metrics exception: {e}")
        return events

    def check_kernel_taint(self):
        events = []
        if not self.config.get('checks', {}).get('kernel', {}).get('monitor_taint', False):
            return events

        taint_path = "/proc/sys/kernel/tainted"
        if os.path.exists(taint_path):
            try:
                with open(taint_path, 'r') as stream:
                    taint_value = int(stream.read().strip())

                state_key = "kernel:taint_status"
                if taint_value != 0:
                    current_status = "WARNING"
                    msg = f"Kernel status flag is TAINTED (Value: {taint_value}). Subsystems might be unstable or non-free modules/MCE hardware errors occurred."
                else:
                    current_status = "OK"
                    msg = "Kernel execution context is pristine and untainted."

                if self.should_report(state_key, msg):
                    events.append({
                        "plugin": "agent_kernel_taint_monitor",
                        "target": "core_kernel",
                        "status": current_status,
                        "message": msg
                    })
            except Exception as e:
                print(f"[-] Kernel taint abstraction check failure: {e}")
        return events

    def check_ssl_cert_expiration(self):
        events = []
        cert_config = self.config.get('checks', {}).get('security', {}).get('ssl_certs', [])
        if not cert_config:
            return events

        for cert_path in cert_config:
            if not os.path.exists(cert_path):
                continue
            try:
                proc = subprocess.run(["openssl", "x509", "-enddate", "-noout", "-in", cert_path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
                if proc.returncode != 0:
                    continue
                
                date_str = proc.stdout.replace("notAfter=", "").strip()
                exp_date = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (exp_date - datetime.now(timezone.utc)).days

                state_key = f"security:ssl_expire:{cert_path}"
                if days_left <= 3:
                    current_status = "CRITICAL"
                    msg = f"SSL Certificate target '{cert_path}' is about to expire immediately!"
                elif days_left <= 14:
                    current_status = "WARNING"
                    msg = f"SSL Certificate target '{cert_path}' approaching expiration parameters."
                else:
                    current_status = "OK"
                    msg = f"SSL Certificate target '{cert_path}' cryptographic validity window is safe."

                if self.should_report(state_key, msg):
                    full_msg = f"{msg} Days remaining: {days_left} days (Expires: {date_str})."
                    events.append({
                        "plugin": "agent_ssl_cert_monitor",
                        "target": cert_path,
                        "status": current_status,
                        "message": full_msg
                    })
            except Exception as e:
                print(f"[-] SSL certificate parsing exception for {cert_path}: {e}")
        return events

    def check_memory_usage(self):
        events = []
        mem_config = self.config.get('checks', {}).get('memory', {})
        if not mem_config.get('enabled', False):
            return events

        warn_pct = mem_config.get('warn_percent', 85)
        crit_pct = mem_config.get('crit_percent', 95)
        monitor_swap = mem_config.get('monitor_swap', True)

        try:
            meminfo = {}
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    parts = line.split(':')
                    if len(parts) == 2:
                        meminfo[parts[0].strip()] = int(parts[1].strip().split()[0])

            mem_total = meminfo.get('MemTotal', 0)
            mem_available = meminfo.get('MemAvailable', 0)
            if mem_total > 0:
                used_pct = ((mem_total - mem_available) / mem_total) * 100
                state_key = "memory:ram"
                if used_pct >= crit_pct:
                    current_status = "CRITICAL"
                    msg = "RAM utilization has exceeded critical threshold."
                elif used_pct >= warn_pct:
                    current_status = "WARNING"
                    msg = "RAM utilization has exceeded warning threshold."
                else:
                    current_status = "OK"
                    msg = "RAM utilization within safe limits."
                if self.should_report(state_key, msg):
                    events.append({
                        "plugin": "agent_memory_monitor",
                        "target": "ram",
                        "status": current_status,
                        "message": f"{msg} Used: {used_pct:.1f}% ({(mem_total - mem_available) // 1024} MB / {mem_total // 1024} MB)."
                    })

            if monitor_swap:
                swap_total = meminfo.get('SwapTotal', 0)
                swap_free = meminfo.get('SwapFree', 0)
                if swap_total > 0:
                    swap_used_pct = ((swap_total - swap_free) / swap_total) * 100
                    state_key = "memory:swap"
                    if swap_used_pct >= crit_pct:
                        current_status = "CRITICAL"
                        msg = "Swap space utilization has exceeded critical threshold."
                    elif swap_used_pct >= warn_pct:
                        current_status = "WARNING"
                        msg = "Swap space utilization has exceeded warning threshold."
                    else:
                        current_status = "OK"
                        msg = "Swap space utilization within safe limits."
                    if self.should_report(state_key, msg):
                        events.append({
                            "plugin": "agent_memory_monitor",
                            "target": "swap",
                            "status": current_status,
                            "message": f"{msg} Used: {swap_used_pct:.1f}% ({(swap_total - swap_free) // 1024} MB / {swap_total // 1024} MB)."
                        })

        except Exception as e:
            print(f"[-] Memory utilization read failure: {e}", flush=True)
        return events

    def _save_state(self):
        state_dir = os.path.dirname(self.state_file)
        try:
            if state_dir:
                os.makedirs(state_dir, exist_ok=True)
            with open(self.state_file, 'w') as f:
                json.dump({
                    "updated": datetime.now(timezone.utc).isoformat(),
                    "hostname": self.hostname,
                    "issues": self.active_issues,
                    "reported_states": self.last_reported_states,
                    "pending_events": self.pending_events,
                    "baselines": {
                        "critical_files": self.critical_file_hashes,
                        "persistence_files": self.persistence_file_hashes,
                        "suid_files": sorted(self.suid_baseline)
                    }
                }, f, indent=2)
        except Exception as e:
            print(f"[-] State file write failure: {e}", flush=True)

    def print_issues(self):
        if not os.path.exists(self.state_file):
            print(f"No state file found at {self.state_file}. Is sentinel-agent running?")
            return
        with open(self.state_file, 'r') as f:
            state = json.load(f)
        issues = state.get('issues', {})
        hostname = state.get('hostname', 'unknown')
        updated = state.get('updated', 'unknown')
        print(f"Active issues on {hostname}  (last update: {updated})")
        print("-" * 60)
        if not issues:
            print("  No active issues.")
            return
        for _, issue in sorted(issues.items()):
            print(f"  [{issue['status']}] {issue['target']} ({issue['plugin']})")
            print(f"    {issue['message']}")
            print()

    def push_to_sentinel(self, events):
        """
        Odesila datovy ramec na centralni server.
        Odstranena blokovaci podminka udrzuje heartbeat aktivni.
        Eventy z neuspesnych pushu se bufferuji a preposlou pri obnoveni spojeni.
        """
        # Replay buffered events from previous failed pushes. Exact duplicates are
        # dropped (re-affirmations repeat identically every cycle) while distinct
        # state transitions are preserved in original order. A stale intermediate
        # state surviving dedup is corrected by the next re-affirmation cycle.
        if self.pending_events:
            print(f"[{datetime.now().isoformat()}] Replaying {len(self.pending_events)} buffered events from failed pushes.", flush=True)
            merged, seen = [], set()
            for evt in self.pending_events + list(events):
                key = (evt['plugin'], evt['target'], evt['status'], evt['message'])
                if key in seen:
                    continue
                seen.add(key)
                merged.append(evt)
            events = merged

        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": self.hostname,
            "events": events
        }

        try:
            resp = self.session.post(
                f"{self.api_url}/api/v1/agent/ingest",
                headers=self.headers,
                json=payload,
                timeout=5
            )
            resp.raise_for_status()
            self.pending_events = []

            if events:
                print(f"[{datetime.now().isoformat()}] Pushed {len(events)} state updates.", flush=True)
            else:
                print(f"[{datetime.now().isoformat()}] Pushed heartbeat matrix (0 state updates).", flush=True)

        except requests.exceptions.RequestException as e:
            if events:
                dropped = len(events) - self.max_pending_events
                self.pending_events = events[-self.max_pending_events:]
                buffer_note = f" Buffered {len(self.pending_events)} events for retry"
                buffer_note += f" ({dropped} oldest dropped, buffer full)." if dropped > 0 else "."
            else:
                buffer_note = ""
            print(f"[{datetime.now().isoformat()}] Failed to push package streams: {e}.{buffer_note}", flush=True)
            if self.pending_events:
                self._save_state()  # persist the buffer now - a restart mid-outage must not lose it

    def send_test_issue(self):
        print(f"Connecting to Sentinel central API at {self.api_url} as identity '{self.hostname}'...", flush=True)
        events = [{
            "plugin": "agent_test",
            "target": "connectivity",
            "status": "CRITICAL",
            "message": "This is an automated stateful delta TUI validation run testing structural alert pipelines."
        }]
        self.push_to_sentinel(events)
        print("\n" + "="*65)
        print("🚨 SIMULATED TELEMETRY DISPATCHED.")
        print("Check the UI dashboard. You must observe the active error.")
        print("="*65 + "\n", flush=True)
        input("Press [ENTER] to dispatch an OK clear packet and close the issue context...")
        events_resolved = [{
            "plugin": "agent_test",
            "target": "connectivity",
            "status": "OK",
            "message": "Simulated structural test completed clean."
        }]
        self.push_to_sentinel(events_resolved)

    def run_loop(self):
        if self.fast_mode:
            boot_delay = 5
            interval = 5
            print(f"[*] FAST MODE ACTIVE: Enforcing short stabilization grace period ({boot_delay}s)...", flush=True)
        else:
            boot_delay = self.config.get('intervals', {}).get('boot_delay_sec', 90)
            interval = self.config.get('intervals', {}).get('metrics_push_sec', 60)
            print(f"[*] Enforcing system stabilization grace period ({boot_delay}s). Waiting for OS layers to settle...", flush=True)
            
        time.sleep(boot_delay)

        print(f"Starting Stateful Sentinel Agent on {self.hostname}. Cadence: {interval}s.", flush=True)

        boot_event = [{
            "plugin": "agent_core_updater",
            "target": "auto_update",
            "status": "OK",
            "message": "Agent service successfully started and running clean."
        }]
        self.push_to_sentinel(boot_event)
        
        while True:
            try:
                self.check_for_git_updates()
                
                events = []
                events.extend(self.check_services())
                events.extend(self.check_mounts())
                events.extend(self.check_network_ports())
                events.extend(self.check_security_metrics())
                events.extend(self.check_suspicious_activity())
                events.extend(self.check_kernel_cves())
                events.extend(self.check_temperature())
                events.extend(self.check_rpi_throttling())
                events.extend(self.check_storage_capacity())
                events.extend(self.check_raid_arrays())
                events.extend(self.check_ssd_wearout())
                events.extend(self.check_disk_health())
                events.extend(self.check_oom_killer_events())
                events.extend(self.check_zombie_processes())
                events.extend(self.check_time_synchronization())
                events.extend(self.check_dns_resolution_health())
                events.extend(self.check_global_systemd_failures())
                events.extend(self.check_uninterruptible_processes())
                events.extend(self.check_conntrack_pressure())
                events.extend(self.check_kernel_taint())
                events.extend(self.check_ssl_cert_expiration())
                events.extend(self.check_memory_usage())
                
                # Update active issue registry from this cycle's deltas FIRST.
                for evt in events:
                    issue_key = f"{evt['plugin']}:{evt['target']}"
                    if evt['status'] == 'OK':
                        self.active_issues.pop(issue_key, None)
                    else:
                        self.active_issues[issue_key] = {
                            'status': evt['status'],
                            'message': evt['message'],
                            'target': evt['target'],
                            'plugin': evt['plugin'],
                            'updated': datetime.now(timezone.utc).isoformat()
                        }
                self._save_state()

                # Re-affirm ALL currently-active issues every cycle. The central server
                # auto-resolves AGENT issues absent from a report after a few cycles
                # (missing_count threshold), so a delta-only push made still-active
                # issues vanish — and a server restart "forgot" them entirely. OK
                # transitions stay in `events` so resolutions still propagate.
                push_events = list(events)
                _delta_keys = {f"{e['plugin']}:{e['target']}" for e in events}
                for _k, _info in self.active_issues.items():
                    if _k not in _delta_keys:
                        push_events.append({
                            "plugin": _info['plugin'],
                            "target": _info['target'],
                            "status": _info['status'],
                            "message": _info['message'],
                        })
                self.push_to_sentinel(push_events)

            except Exception as loop_err:
                print(f"[{datetime.now().isoformat()}] Internal runtime processing loop error: {loop_err}", flush=True)
                
            time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel Agent Configuration Suite")
    parser.add_argument("--test", action="store_true", help="Send a test delta execution and exit")
    parser.add_argument("--fast", action="store_true", help="Run loop with 5s boot delay and 5s interval for quick manual testing")
    parser.add_argument("--issues", action="store_true", help="Print active issues from state file and exit")
    args = parser.parse_args()

    agent = SentinelAgent(fast_mode=args.fast)
    if args.issues:
        agent.print_issues()
    elif args.test:
        agent.send_test_issue()
    else:
        agent.run_loop()

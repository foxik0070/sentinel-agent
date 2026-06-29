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
import datetime
from datetime import datetime, timezone

# --- Dynamic Dependency Checks ---
try:
    import requests
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
        
        # --- Stateful Tracking Memory ---
        self.last_reported_states = {}
        self.last_oom_count = 0
        self.oom_initialized = False
        
        # --- Network Baseline Matrices ---
        self.baseline_ports = set()
        self.ports_initialized = False

    def _detect_os_family(self):
        """Heuristically detects the underlying Linux distribution family."""
        if os.path.exists("/etc/debian_version"): return "debian"
        elif os.path.exists("/etc/redhat-release") or os.path.exists("/etc/centos-release"): return "rhel"
        return "generic"

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
            local_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_dir, text=True).strip()
            subprocess.run(["git", "fetch"], cwd=repo_dir, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            remote_sha = subprocess.check_output(["git", "rev-parse", "@{u}"], cwd=repo_dir, text=True).strip()
            
            if local_sha != remote_sha:
                print(f"[{datetime.now().isoformat()}] 🔄 Drift detected in Git repository! Initiating git pull...", flush=True)
                subprocess.run(["git", "pull"], cwd=repo_dir, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
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
        
        for svc in services:
            name = svc['name']
            severity = svc.get('severity', 'CRITICAL').upper()
            state_key = f"service:{name}"
            
            result = subprocess.run(
                ["systemctl", "is-active", name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            state = result.stdout.strip()
            current_status = severity if state not in ["active", "inactive"] else "OK"
            
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
            proc = subprocess.run(["ss", "-tulpn"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
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
        current_status = "WARNING" if unassigned_ports else "OK"
        
        if current_status == "WARNING":
            msg = f"Security Alert! Unregistered listening ports identified after initialization: {sorted(list(unassigned_ports))}"
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
            try:
                who_proc = subprocess.run(["who"], stdout=subprocess.PIPE, text=True)
                root_sessions = []
                for line in who_proc.stdout.splitlines():
                    if line.startswith("root"):
                        parts = line.split()
                        if len(parts) >= 4:
                            tty = parts[1]
                            time_str = f"{parts[2]} {parts[3]}"
                            ip = parts[4].strip("()") if len(parts) >= 5 else "localhost"
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
            try:
                if self.os_family == "debian":
                    apt_proc = subprocess.run(["apt-get", "-s", "upgrade"], stdout=subprocess.PIPE, text=True)
                    upgrade_lines = [l for l in apt_proc.stdout.splitlines() if l.startswith("Inst ")]
                    update_count = len(upgrade_lines)
                    sec_update_count = len([l for l in upgrade_lines if "security" in l.lower() or "cve" in l.lower()])
                elif self.os_family == "rhel":
                    dnf_proc = subprocess.run(["dnf", "check-update", "--security"], stdout=subprocess.PIPE, text=True)
                    if dnf_proc.returncode == 100:
                        sec_update_count = len([l for l in dnf_proc.stdout.splitlines() if l.strip()])
                    dnf_all = subprocess.run(["dnf", "check-update"], stdout=subprocess.PIPE, text=True)
                    if dnf_all.returncode == 100:
                        update_count = len([l for l in dnf_all.stdout.splitlines() if l.strip()])

                current_status = "CRITICAL" if sec_update_count > 0 else ("WARNING" if update_count > 20 else "OK")
                if current_status == "CRITICAL":
                    msg = f"System is vulnerable! Found {sec_update_count} unpatched security updates/CVE vectors."
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

        # --- 3. Fail2ban Brute-Force Pressure Statistics ---
        if sec_config.get('fail2ban_stats', False):
            state_key = "security:fail2ban"
            try:
                f2b_proc = subprocess.run(["fail2ban-client", "status"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                if f2b_proc.returncode == 0:
                    jails = re.findall(r"Jail list:\s+(.*)", f2b_proc.stdout)
                    if jails:
                        jail_list = [j.strip() for j in jails[0].split(",")]
                        total_banned = 0
                        for jail in jail_list:
                            j_stat = subprocess.run(["fail2ban-client", "status", jail], stdout=subprocess.PIPE, text=True)
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

        drives = []
        try:
            for d in os.listdir("/sys/block/"):
                if d.startswith(("sd", "nvme")):
                    if not re.search(r"p\d+$|\d+$", d):
                        drives.append(f"/dev/{d}")
        except Exception:
            return events

        for drive in drives:
            try:
                proc = subprocess.run(["smartctl", "-A", drive], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
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

    def check_oom_killer_events(self):
        events = []
        if not self.config.get('checks', {}).get('kernel', {}).get('monitor_oom', False):
            return events

        try:
            proc = subprocess.run(["dmesg"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            oom_hits = re.findall(r"(Out of memory: Kill process|Killed process \d+ \(.+?\) total-vm)", proc.stdout, re.IGNORECASE)
            current_count = len(oom_hits)

            if not self.oom_initialized:
                self.last_oom_count = current_count
                self.oom_initialized = True
                return events

            state_key = "kernel:oom_events"
            if current_count > self.last_oom_count:
                current_status = "CRITICAL"
                msg = f"Kernel Architecture Error! Out-Of-Memory (OOM) killer context triggered. {current_count - self.last_oom_count} processes terminated."
                self.last_reported_states[state_key] = msg
                self.last_oom_count = current_count
                
                events.append({
                    "plugin": "agent_kernel_oom_monitor",
                    "target": "oom_killer",
                    "status": current_status,
                    "message": msg
                })
            else:
                msg = "Kernel memory allocation subsystems operating within safe structural limits."
                if self.should_report(state_key, msg):
                    events.append({
                        "plugin": "agent_kernel_oom_monitor",
                        "target": "oom_killer",
                        "status": "OK",
                        "message": msg
                    })
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
            proc = subprocess.run(["ps", "-eo", "state"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
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
            proc = subprocess.run(["timedatectl"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
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
            proc = subprocess.run(["systemctl", "list-units", "--state=failed", "--no-legend"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
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
            proc = subprocess.run(["ps", "-eo", "state,pid,comm"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
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
                proc = subprocess.run(["openssl", "x509", "-enddate", "-noout", "-in", cert_path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
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

    def push_to_sentinel(self, events):
        """
        Odesila datovy ramec na centralni server. 
        Odstranena blokovaci podminka udrzuje heartbeat aktivni.
        """
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": self.hostname,
            "events": events
        }
        
        try:
            resp = requests.post(
                f"{self.api_url}/api/v1/agent/ingest", 
                headers=self.headers, 
                json=payload, 
                timeout=5
            )
            resp.raise_for_status()
            
            if events:
                print(f"[{datetime.now().isoformat()}] Pushed {len(events)} state updates.", flush=True)
            else:
                print(f"[{datetime.now().isoformat()}] Pushed heartbeat matrix (0 state updates).", flush=True)
                
        except requests.exceptions.RequestException as e:
            print(f"[{datetime.now().isoformat()}] Failed to push package streams: {e}", flush=True)

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
                events.extend(self.check_temperature())
                events.extend(self.check_storage_capacity())
                events.extend(self.check_raid_arrays())
                events.extend(self.check_ssd_wearout())
                events.extend(self.check_oom_killer_events())
                events.extend(self.check_zombie_processes())
                events.extend(self.check_time_synchronization())
                events.extend(self.check_dns_resolution_health())
                events.extend(self.check_global_systemd_failures())
                events.extend(self.check_uninterruptible_processes())
                events.extend(self.check_conntrack_pressure())
                events.extend(self.check_kernel_taint())
                events.extend(self.check_ssl_cert_expiration())
                
                self.push_to_sentinel(events)
            except Exception as loop_err:
                print(f"[{datetime.now().isoformat()}] Internal runtime processing loop error: {loop_err}", flush=True)
                
            time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel Agent Configuration Suite")
    parser.add_argument("--test", action="store_true", help="Send a test delta execution and exit")
    parser.add_argument("--fast", action="store_true", help="Run loop with 5s boot delay and 5s interval for quick manual testing")
    args = parser.parse_args()
    
    agent = SentinelAgent(fast_mode=args.fast)
    if args.test:
        agent.send_test_issue()
    else:
        agent.run_loop()

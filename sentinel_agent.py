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
import gzip
import signal
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

from checks import registered_check_names
from checks.services import ServicesChecks
from checks.security import SecurityChecks
from checks.storage import StorageChecks
from checks.kernel import KernelChecks
from checks.system import SystemChecks


class SourceAddressAdapter(HTTPAdapter):
    """Binds outgoing HTTP requests to a specific local IP address."""
    def __init__(self, source_address, **kwargs):
        self.source_address = source_address
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['source_address'] = (self.source_address, 0)
        super().init_poolmanager(*args, **kwargs)

class SentinelAgent(ServicesChecks, SecurityChecks, StorageChecks,
                    KernelChecks, SystemChecks):
    def __init__(self, fast_mode=False):
        """Initializes the agent, loads configuration, and prepares state trackers."""
        self.fast_mode = fast_mode
        
        if not os.path.exists(CONFIG_FILE):
            print(f"[!] Configuration file target missing: {CONFIG_FILE}", flush=True)
            sys.exit(1)
            
        with open(CONFIG_FILE, 'r') as stream:
            self.config = yaml.safe_load(stream)

        self._validate_config()

        # API Connection Setup
        self.api_url = self.config['sentinel_api']['url'].rstrip('/')
        if self.api_url.startswith('http://'):
            print("[!] WARNING: Sentinel API URL is plaintext HTTP — the bearer token "
                  "is sent unencrypted. Use https:// (see sentinel_api.verify_tls/ca_bundle).", flush=True)
        self.token = self.config['sentinel_api']['token']
        self.hostname = self.config['sentinel_api'].get('hostname', socket.gethostname())
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        self.os_family = self._detect_os_family()
        self.is_virtual = self._is_virtual_environment()
        self.agent_version = self._detect_agent_version()

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

        # --- Kernel Module Baseline (rootkit detection) ---
        self.module_baseline = set()
        self.module_baseline_initialized = False

        # --- Privileged Group Membership Baseline ---
        self.priv_groups_baseline = {}
        self.priv_groups_initialized = False
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
            if baselines.get('kernel_modules'):
                self.module_baseline = set(baselines['kernel_modules'])
                self.module_baseline_initialized = True
            if baselines.get('priv_groups'):
                self.priv_groups_baseline = {g: set(m) for g, m in baselines['priv_groups'].items()}
                self.priv_groups_initialized = True
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

    def _detect_agent_version(self):
        """Returns the agent's git commit SHA (short) so the server can spot nodes
        running stale code. Falls back to 'unknown' outside a git checkout."""
        repo_dir = os.path.dirname(os.path.abspath(__file__))
        try:
            return subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=repo_dir, stderr=subprocess.DEVNULL, text=True, timeout=10
            ).strip() or "unknown"
        except Exception:
            return "unknown"

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
                # compileall covers the whole checks/ package, not just this file.
                compile_targets = [os.path.abspath(__file__), os.path.join(repo_dir, "checks")]
                compile_proc = subprocess.run(
                    [sys.executable, "-m", "compileall", "-q"] + compile_targets,
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
                        "suid_files": sorted(self.suid_baseline),
                        "kernel_modules": sorted(self.module_baseline),
                        "priv_groups": {g: sorted(m) for g, m in self.priv_groups_baseline.items()}
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
            proc = subprocess.run(["systemctl", "list-units", "--state=failed", "--no-legend", "--plain"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            failed_units = []
            for line in proc.stdout.splitlines():
                parts = line.split()
                if not parts:
                    continue
                # systemctl prepends ● bullet — skip it to get the unit name
                unit = parts[1] if parts[0] == '●' else parts[0]
                if unit and '.' in unit:
                    failed_units.append(unit)

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

        api = self.config.get('sentinel_api', {})
        if api.get('plain_messages', False):
            events = [{**e, "message": self._plainify(e["message"])} for e in events]

        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": self.hostname,
            "agent_version": self.agent_version,
            "events": events
        }

        # TLS verification (#43): default on; optional custom CA bundle.
        verify = api.get('ca_bundle') or api.get('verify_tls', True)

        try:
            post_kwargs = {"timeout": 5, "verify": verify}
            headers = dict(self.headers)
            if api.get('gzip', False):
                # Optional gzip of the JSON body (#44); server must accept
                # Content-Encoding: gzip. Off by default for compatibility.
                body = gzip.compress(json.dumps(payload).encode('utf-8'))
                headers["Content-Encoding"] = "gzip"
                post_kwargs["data"] = body
            else:
                post_kwargs["json"] = payload

            resp = self.session.post(
                f"{self.api_url}/api/v1/agent/ingest",
                headers=headers,
                **post_kwargs
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

    def _validate_config(self):
        """Fails fast with a clear message on a malformed config instead of a
        cryptic KeyError deep in a check (todo #29)."""
        if not isinstance(self.config, dict):
            print(f"[!] Config root of {CONFIG_FILE} is not a mapping. Aborting.", flush=True)
            sys.exit(1)
        missing = []
        api = self.config.get('sentinel_api')
        if not isinstance(api, dict) or not api.get('url'):
            missing.append('sentinel_api.url')
        if not isinstance(api, dict) or not api.get('token'):
            missing.append('sentinel_api.token')
        if missing:
            print(f"[!] Config {CONFIG_FILE} missing required key(s): {', '.join(missing)}. "
                  f"Run sentinel_agent_init.py to regenerate it.", flush=True)
            sys.exit(1)

    # Flowery filler -> plain wording for the optional plain_messages mode (#48).
    _PLAIN_SUBS = [
        (r"\s*configuration matrix", ""),
        (r"\s*baseline matrix", " baseline"),
        (r"\s*structural ", " "),
        (r"\s*architecture ", " system "),
        (r"\s*matrix\b", ""),
        (r"\s{2,}", " "),
    ]

    def _plainify(self, msg):
        out = msg
        for pat, repl in self._PLAIN_SUBS:
            out = re.sub(pat, repl, out)
        return out.strip()

    def _sd_notify(self, state):
        """Best-effort sd_notify to systemd (READY/WATCHDOG/STOPPING). No-op when
        not run under a systemd notify unit (todo #25)."""
        addr = os.environ.get('NOTIFY_SOCKET')
        if not addr:
            return
        try:
            if addr.startswith('@'):
                addr = '\0' + addr[1:]
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.connect(addr)
            sock.sendall(state.encode())
            sock.close()
        except Exception:
            pass

    def _reload_config(self, signum, frame):
        """SIGHUP handler: reload check thresholds without a restart. Connection
        settings (url/token) still require a restart (todo #28)."""
        try:
            with open(CONFIG_FILE, 'r') as stream:
                self.config = yaml.safe_load(stream)
            self._validate_config()
            print(f"[{datetime.now().isoformat()}] Config reloaded via SIGHUP.", flush=True)
        except Exception as e:
            print(f"[-] SIGHUP config reload failed (keeping old config): {e}", flush=True)

    def _check_self_resources(self):
        """Self-restart if the agent's own RSS exceeds a configured limit, letting
        systemd restart it clean (guards against slow leaks) (todo #26)."""
        limit_mb = self.config.get('agent_core', {}).get('max_self_rss_mb', 0)
        if not limit_mb:
            return
        try:
            with open('/proc/self/status', 'r') as f:
                for line in f:
                    if line.startswith('VmRSS:'):
                        rss_mb = int(line.split()[1]) / 1024
                        if rss_mb > limit_mb:
                            print(f"[!] Agent RSS {rss_mb:.0f}MB exceeds limit {limit_mb}MB — "
                                  f"exiting for a clean systemd restart.", flush=True)
                            self._sd_notify("STOPPING=1")
                            sys.exit(0)
                        break
        except Exception:
            pass

    def run_cycle(self):
        """Runs every registered check once and returns the collected events."""
        events = []
        for check_name in registered_check_names():
            events.extend(getattr(self, check_name)())
        return events

    def _apply_and_push(self, events):
        """Updates the active-issue registry, persists state, and pushes deltas
        plus re-affirmations of still-active issues."""
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

    def run_dry(self):
        """Runs all checks once and prints the resulting events as JSON without
        touching the server or the state file (todo #30)."""
        events = self.run_cycle()
        print(json.dumps(events, indent=2))
        print(f"\n[dry-run] {len(events)} event(s) from {len(registered_check_names())} checks. "
              f"Nothing pushed, state file untouched.", flush=True)

    def run_loop(self):
        if self.fast_mode:
            boot_delay = 5
            interval = 5
            print(f"[*] FAST MODE ACTIVE: Enforcing short stabilization grace period ({boot_delay}s)...", flush=True)
        else:
            boot_delay = self.config.get('intervals', {}).get('boot_delay_sec', 90)
            interval = self.config.get('intervals', {}).get('metrics_push_sec', 60)
            print(f"[*] Enforcing system stabilization grace period ({boot_delay}s). Waiting for OS layers to settle...", flush=True)
            
        # Notify systemd we are up (Type=notify units) and install SIGHUP reload.
        self._sd_notify("READY=1")
        try:
            signal.signal(signal.SIGHUP, self._reload_config)
        except (ValueError, OSError):
            pass  # not in main thread / unsupported platform

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
                # Re-affirmation of still-active issues happens inside _apply_and_push;
                # the central server auto-resolves AGENT issues absent from a report.
                self._apply_and_push(self.run_cycle())
                self._check_self_resources()
                self._sd_notify("WATCHDOG=1")
            except Exception as loop_err:
                print(f"[{datetime.now().isoformat()}] Internal runtime processing loop error: {loop_err}", flush=True)

            time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel Agent Configuration Suite")
    parser.add_argument("--test", action="store_true", help="Send a test delta execution and exit")
    parser.add_argument("--fast", action="store_true", help="Run loop with 5s boot delay and 5s interval for quick manual testing")
    parser.add_argument("--issues", action="store_true", help="Print active issues from state file and exit")
    parser.add_argument("--dry-run", action="store_true", help="Run all checks once, print events as JSON, push nothing")
    args = parser.parse_args()

    agent = SentinelAgent(fast_mode=args.fast)
    if args.issues:
        agent.print_issues()
    elif args.dry_run:
        agent.run_dry()
    elif args.test:
        agent.send_test_issue()
    else:
        agent.run_loop()

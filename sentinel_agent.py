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
            "agent_version": self.agent_version,
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
                # Checks run in the order registered via @register_check across the
                # checks/* mixin modules (see checks/__init__.py).
                for check_name in registered_check_names():
                    events.extend(getattr(self, check_name)())

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

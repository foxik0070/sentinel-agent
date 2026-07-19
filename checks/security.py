"""Security & intrusion-detection checks: ports, root logins,
vulnerabilities/CVE, suspicious activity, SSL certificates."""
import hashlib, os, re, socket, subprocess
from datetime import datetime, timezone

from checks import register_check


class SecurityChecks:
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

    @register_check(30)
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

    @register_check(40)
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
        r"/dev/udp/\d",
        r"\bnc(at)?\b.*\s-e\s",
        r"\bsocat\b.*\bexec\b",
        r"pty\.spawn",
        r"\bsh -i\b.*\d+\.\d+\.\d+\.\d+",
        # perl reverse shell: perl -e '...socket...exec...'
        r"perl\b.*-e.*socket.*(exec|/bin/sh)",
        # php reverse shell: php -r 'fsockopen ... exec'
        r"php\b.*-r.*fsockopen",
        # ruby reverse shell: ruby -rsocket ... TCPSocket ... exec
        r"ruby\b.*(-rsocket|TCPSocket).*exec",
        # python socket-based shell without pty.spawn
        r"python[0-9.]*\b.*-c.*socket.*(subprocess|/bin/sh|/bin/bash)",
        # bash /dev/tcp redirect via exec
        r"exec\s+\d+<>/dev/tcp/",
        # msfvenom / meterpreter staging artifacts
        r"\b(msfvenom|meterpreter)\b",
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

    @register_check(60)
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
        # User-defined allowlist of substrings; a process whose cmdline or exe
        # matches is skipped (e.g. a legitimate CI runner script under /tmp).
        ignore = self.config.get('checks', {}).get('security', {}).get('suspicious_ignore', [])
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
            if any(pat and pat in cmdline for pat in ignore):
                continue
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

    @register_check(50)
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

        # --- 7. Promiscuous network interfaces (packet sniffing) ---
        try:
            promisc_ifaces = []
            for iface in os.listdir('/sys/class/net'):
                flags_path = f"/sys/class/net/{iface}/flags"
                if not os.path.exists(flags_path):
                    continue
                with open(flags_path, 'r') as f:
                    flags = int(f.read().strip(), 16)
                if flags & 0x100:  # IFF_PROMISC
                    promisc_ifaces.append(iface)
            state_key = "security:promisc"
            current_status = "WARNING" if promisc_ifaces else "OK"
            msg = f"Network interface(s) in promiscuous mode (possible packet sniffing): {', '.join(promisc_ifaces)}" if promisc_ifaces else "No network interfaces in promiscuous mode."
            if self.should_report(state_key, msg):
                events.append({
                    "plugin": "agent_security_suspicious_activity",
                    "target": "promisc_interfaces",
                    "status": current_status,
                    "message": msg
                })
        except Exception as e:
            print(f"[-] Promiscuous mode check failure: {e}", flush=True)

        # --- 8. Kernel module baseline (rootkit / unexpected module load) ---
        try:
            current_modules = set()
            with open('/proc/modules', 'r') as f:
                for line in f:
                    name = line.split()
                    if name:
                        current_modules.add(name[0])
            state_key = "security:kernel_modules"
            if not self.module_baseline_initialized:
                self.module_baseline = current_modules
                self.module_baseline_initialized = True
            else:
                new_modules = sorted(current_modules - self.module_baseline)
                if new_modules:
                    msg = f"New kernel module(s) loaded since baseline: {', '.join(new_modules)}. Verify this was legitimate (LKM rootkits load as kernel modules)."
                    self.module_baseline = current_modules
                    self.last_reported_states[state_key] = msg
                    events.append({
                        "plugin": "agent_security_suspicious_activity",
                        "target": "kernel_modules",
                        "status": "WARNING",
                        "message": msg
                    })
                else:
                    self.module_baseline = current_modules  # absorb unloads silently
                    msg = "Loaded kernel module set matches trusted baseline."
                    if self.should_report(state_key, msg):
                        events.append({
                            "plugin": "agent_security_suspicious_activity",
                            "target": "kernel_modules",
                            "status": "OK",
                            "message": msg
                        })
        except Exception as e:
            print(f"[-] Kernel module baseline check failure: {e}", flush=True)

        return events

    @register_check(41)
    def check_package_integrity(self):
        """Verifies installed system packages against their manifest checksums
        (debsums / rpm -V). Heavy, so it runs on a configurable cadence (todo #15)."""
        events = []
        sec = self.config.get('checks', {}).get('security', {})
        if not sec.get('pkg_integrity', False):
            return events
        cadence = sec.get('pkg_integrity_cadence_cycles', 10080)  # ~weekly at 60s
        if not hasattr(self, 'pkg_integrity_counter'):
            self.pkg_integrity_counter = 0
        run_now = self.pkg_integrity_counter % cadence == 0
        self.pkg_integrity_counter += 1
        if not run_now:
            return events

        modified = []
        try:
            if self.os_family == "debian":
                proc = subprocess.run(["debsums", "-c"], stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, text=True, timeout=600)
                modified = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
            elif self.os_family == "rhel":
                proc = subprocess.run(["rpm", "-Va", "--nomtime", "--nordev"], stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, text=True, timeout=600)
                # only flag checksum (5) mismatches on binaries, not config files (c)
                modified = [l for l in proc.stdout.splitlines()
                            if l and l[0:9].find('5') != -1 and ' c ' not in l]
        except FileNotFoundError:
            return events  # debsums/rpm not installed
        except Exception as e:
            print(f"[-] Package integrity check failure: {e}", flush=True)
            return events

        state_key = "security:pkg_integrity"
        current_status = "WARNING" if modified else "OK"
        msg = (f"System package files modified vs. distribution manifest ({len(modified)}): {', '.join(modified[:10])}{'...' if len(modified) > 10 else ''}"
               if modified else "Installed system package files match distribution manifest.")
        if self.should_report(state_key, msg):
            events.append({
                "plugin": "agent_security_package_integrity",
                "target": "packages",
                "status": current_status,
                "message": msg,
            })
        return events

    @register_check(42)
    def check_needrestart(self):
        """Detects services running with old (already-patched) libraries still
        mapped in memory - the patch is installed but not effective (todo #19)."""
        events = []
        if not self.config.get('checks', {}).get('security', {}).get('check_needrestart', False):
            return events
        try:
            proc = subprocess.run(["needrestart", "-b"], stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True, timeout=60)
        except FileNotFoundError:
            return events
        except Exception as e:
            print(f"[-] needrestart check failure: {e}", flush=True)
            return events

        svcs = re.findall(r"NEEDRESTART-SVC:\s*(\S+)", proc.stdout)
        svc_count = len(svcs)
        state_key = "security:needrestart"
        current_status = "WARNING" if svc_count > 0 else "OK"
        msg = (f"{svc_count} service(s) still running old libraries after an update - restart them so the patch takes effect: {', '.join(svcs[:10])}"
               if svc_count else "No services running outdated libraries.")
        if self.should_report(state_key, msg):
            events.append({
                "plugin": "agent_security_needrestart",
                "target": "services",
                "status": current_status,
                "message": msg,
            })
        return events

    @register_check(43)
    def check_unattended_upgrades(self):
        """Alerts when automatic security updates (unattended-upgrades) are failing
        or stale, so a node does not silently stop patching itself (todo #20)."""
        events = []
        if not self.config.get('checks', {}).get('security', {}).get('check_unattended_upgrades', False):
            return events
        if self.os_family != "debian":
            return events
        log = "/var/log/unattended-upgrades/unattended-upgrades.log"
        if not os.path.exists(log):
            return events
        state_key = "security:unattended_upgrades"
        try:
            import time as _time
            age_days = (_time.time() - os.path.getmtime(log)) / 86400
            tail = subprocess.run(["tail", "-n", "50", log], stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True, timeout=10).stdout
            failed = re.search(r"(ERROR|Traceback|failed to|Exception)", tail, re.IGNORECASE)
            if failed:
                current_status = "WARNING"
                msg = "Automatic security updates (unattended-upgrades) are reporting errors - node may not be patching itself."
            elif age_days > 14:
                current_status = "WARNING"
                msg = f"unattended-upgrades has not run for {age_days:.0f} days - automatic patching may be stalled."
            else:
                current_status = "OK"
                msg = "Automatic security updates running normally."
            if self.should_report(state_key, msg):
                events.append({
                    "plugin": "agent_security_unattended_upgrades",
                    "target": "auto_updates",
                    "status": current_status,
                    "message": msg,
                })
        except Exception as e:
            print(f"[-] unattended-upgrades check failure: {e}", flush=True)
        return events

    # Remote ports strongly associated with reverse shells and mining pools.
    SUSPICIOUS_REMOTE_PORTS = {
        "1337", "3333", "4028", "4040", "4444", "4445", "5555", "6666",
        "6667", "7777", "9999", "14444", "14433", "45560",
    }

    @register_check(46)
    def check_outbound_connections(self):
        """Flags established outbound TCP connections to ports associated with
        reverse shells / mining pools (todo #7)."""
        events = []
        sec = self.config.get('checks', {}).get('security', {})
        if not sec.get('monitor_outbound', False):
            return events
        ports = set(self.SUSPICIOUS_REMOTE_PORTS) | {str(p) for p in sec.get('suspicious_remote_ports', [])}
        try:
            proc = subprocess.run(["ss", "-tnp", "state", "established"],
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
        except Exception as e:
            print(f"[-] Outbound connection scan failure: {e}", flush=True)
            return events

        hits = []
        for line in proc.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            peer = parts[4]
            rport = peer.rsplit(":", 1)[-1]
            if rport in ports:
                pinfo = re.search(r'\("([^"]+)",pid=(\d+)', line)
                who = f" [{pinfo.group(1)} PID {pinfo.group(2)}]" if pinfo else ""
                hits.append(f"{peer}{who}")

        state_key = "security:outbound"
        current_status = "WARNING" if hits else "OK"
        msg = (f"Outbound connection(s) to suspicious ports (reverse shell / mining pool): {', '.join(sorted(set(hits)))}"
               if hits else "No outbound connections to suspicious ports.")
        if self.should_report(state_key, msg):
            events.append({
                "plugin": "agent_security_outbound_monitor",
                "target": "connections",
                "status": current_status,
                "message": msg,
            })
        return events

    PRIVILEGED_GROUPS = ("sudo", "wheel", "docker", "adm", "lxd", "root")

    @register_check(55)
    def check_privileged_groups(self):
        """Baselines membership of privilege-granting groups; a new member is a
        WARNING (docker/lxd membership is effectively root) (todo #9)."""
        events = []
        if not self.config.get('checks', {}).get('security', {}).get('monitor_priv_groups', False):
            return events
        current = {}
        try:
            with open('/etc/group', 'r') as f:
                for line in f:
                    parts = line.split(':')
                    if len(parts) >= 4 and parts[0] in self.PRIVILEGED_GROUPS:
                        members = set(m for m in parts[3].strip().split(',') if m)
                        current[parts[0]] = members
        except Exception as e:
            print(f"[-] Privileged group scan failure: {e}", flush=True)
            return events

        state_key = "security:priv_groups"
        if not self.priv_groups_initialized:
            self.priv_groups_baseline = current
            self.priv_groups_initialized = True
            return events

        added = []
        for grp, members in current.items():
            new_members = members - self.priv_groups_baseline.get(grp, set())
            for m in sorted(new_members):
                added.append(f"{m} -> {grp}")
        if added:
            self.priv_groups_baseline = current
            msg = f"New member(s) added to privilege-granting groups: {', '.join(added)}. docker/lxd/sudo membership grants root-equivalent access - verify this was intentional."
            self.last_reported_states[state_key] = msg
            events.append({
                "plugin": "agent_security_priv_groups",
                "target": "group_members",
                "status": "WARNING",
                "message": msg,
            })
        else:
            self.priv_groups_baseline = current
            msg = "Privileged group membership matches trusted baseline."
            if self.should_report(state_key, msg):
                events.append({
                    "plugin": "agent_security_priv_groups",
                    "target": "group_members",
                    "status": "OK",
                    "message": msg,
                })
        return events

    @register_check(52)
    def check_immutable_flags(self):
        """Detects the immutable attribute (chattr +i) on files in temp dirs or on
        tracked persistence files - attackers set it to protect a backdoor (todo #12)."""
        events = []
        if not self.config.get('checks', {}).get('security', {}).get('monitor_suspicious', False):
            return events
        targets = []
        for d in ("/tmp", "/var/tmp", "/dev/shm"):
            try:
                for entry in os.listdir(d):
                    full = os.path.join(d, entry)
                    if os.path.isfile(full):
                        targets.append(full)
            except Exception:
                continue
        targets += self._collect_persistence_files()

        immutable = []
        for path in targets[:500]:  # cap to bound runtime
            try:
                proc = subprocess.run(["lsattr", "-d", path], stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, text=True, timeout=10)
                if proc.returncode == 0 and proc.stdout and 'i' in proc.stdout.split()[0]:
                    immutable.append(path)
            except Exception:
                continue

        state_key = "security:immutable"
        current_status = "WARNING" if immutable else "OK"
        msg = (f"Immutable (chattr +i) files in temp/persistence paths (backdoor protection?): {', '.join(immutable)}"
               if immutable else "No unexpected immutable files in temp/persistence paths.")
        if self.should_report(state_key, msg):
            events.append({
                "plugin": "agent_security_suspicious_activity",
                "target": "immutable_files",
                "status": current_status,
                "message": msg,
            })
        return events

    @register_check(53)
    def check_raw_sockets(self):
        """Flags processes holding raw IP sockets outside an expected daemon
        allowlist - possible scanner or backdoor (todo #13, opt-in)."""
        events = []
        if not self.config.get('checks', {}).get('security', {}).get('monitor_raw_sockets', False):
            return events
        allow = set(self.config.get('checks', {}).get('security', {}).get(
            'raw_socket_allow', ['dhclient', 'dhcpcd', 'NetworkManager', 'ping', 'ping6', 'systemd-network']))
        try:
            with open('/proc/net/raw', 'r') as f:
                raw_lines = f.readlines()[1:]
            with open('/proc/net/raw6', 'r') as f:
                raw_lines += f.readlines()[1:]
        except Exception:
            return events
        raw_inodes = set()
        for line in raw_lines:
            parts = line.split()
            if len(parts) >= 10:
                raw_inodes.add(parts[9])
        if not raw_inodes:
            state_key = "security:raw_sockets"
            if self.should_report(state_key, "No raw sockets open."):
                events.append({"plugin": "agent_security_suspicious_activity", "target": "raw_sockets",
                               "status": "OK", "message": "No raw sockets open."})
            return events

        offenders = []
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue
            try:
                comm = open(f"/proc/{pid}/comm").read().strip()
                if comm in allow:
                    continue
                for fd in os.listdir(f"/proc/{pid}/fd"):
                    link = os.readlink(f"/proc/{pid}/fd/{fd}")
                    m = re.search(r'socket:\[(\d+)\]', link)
                    if m and m.group(1) in raw_inodes:
                        offenders.append(f"{comm} (PID {pid})")
                        break
            except Exception:
                continue

        state_key = "security:raw_sockets"
        current_status = "WARNING" if offenders else "OK"
        msg = (f"Process(es) holding raw sockets outside allowlist (scanner/backdoor?): {', '.join(sorted(set(offenders)))}"
               if offenders else "Raw socket holders all within expected daemon allowlist.")
        if self.should_report(state_key, msg):
            events.append({
                "plugin": "agent_security_suspicious_activity",
                "target": "raw_sockets",
                "status": current_status,
                "message": msg,
            })
        return events

    @register_check(210)
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

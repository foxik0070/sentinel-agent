"""System & network health: temperature, RPi throttling, time sync,
DNS, systemd failures, conntrack, memory, plus network reachability,
HTTP health, IP change, bandwidth, UPS and mDNS conflict checks."""
import os, re, socket, subprocess, time, urllib.request

from checks import register_check


class SystemChecks:
    def _default_gateway(self):
        """Returns the IPv4 default gateway address from /proc/net/route, or None."""
        try:
            with open('/proc/net/route', 'r') as f:
                for line in f.readlines()[1:]:
                    fields = line.split()
                    if len(fields) >= 3 and fields[1] == '00000000':
                        gw = int(fields[2], 16)
                        return ".".join(str((gw >> (8 * i)) & 0xff) for i in range(4))
        except Exception:
            return None
        return None

    @register_check(155)
    def check_network_reachability(self):
        """Pings configured targets plus the default gateway; reports unreachable
        hosts and high latency (todo #31, #36)."""
        events = []
        net = self.config.get('checks', {}).get('network', {})
        if not net.get('monitor_reachability', False):
            return events
        targets = list(net.get('ping_targets', []))
        if net.get('ping_gateway', True):
            gw = self._default_gateway()
            if gw and gw not in targets:
                targets.append(gw)
        max_latency = net.get('ping_max_latency_ms', 200)

        for target in targets:
            state_key = f"network:ping:{target}"
            try:
                proc = subprocess.run(["ping", "-c", "3", "-W", "2", target],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=15)
                if proc.returncode != 0:
                    current_status, msg = "WARNING", f"Ping target '{target}' unreachable (100% packet loss)."
                else:
                    m = re.search(r"= [\d.]+/([\d.]+)/", proc.stdout)
                    avg = float(m.group(1)) if m else 0.0
                    if avg > max_latency:
                        current_status = "WARNING"
                        msg = f"Ping target '{target}' high latency: {avg:.0f}ms (limit {max_latency}ms)."
                    else:
                        current_status = "OK"
                        msg = f"Ping target '{target}' reachable ({avg:.0f}ms)."
            except Exception as e:
                current_status, msg = "WARNING", f"Ping target '{target}' check error: {e}"
            if self.should_report(state_key, msg):
                events.append({"plugin": "agent_network_reachability", "target": target,
                               "status": current_status, "message": msg})
        return events

    @register_check(156)
    def check_http_health(self):
        """HTTP(S) health check of configured URLs: status code + latency (todo #33)."""
        events = []
        checks = self.config.get('checks', {}).get('network', {}).get('http_checks', [])
        for entry in checks:
            url = entry.get('url')
            if not url:
                continue
            expect = entry.get('expect_status', 200)
            max_ms = entry.get('max_latency_ms', 5000)
            state_key = f"network:http:{url}"
            try:
                start = time.monotonic()
                req = urllib.request.Request(url, method="GET", headers={"User-Agent": "sentinel-agent"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    code = resp.status
                elapsed = (time.monotonic() - start) * 1000
                if code != expect:
                    current_status, msg = "WARNING", f"HTTP check '{url}' returned {code} (expected {expect})."
                elif elapsed > max_ms:
                    current_status, msg = "WARNING", f"HTTP check '{url}' slow: {elapsed:.0f}ms (limit {max_ms}ms)."
                else:
                    current_status, msg = "OK", f"HTTP check '{url}' healthy ({code}, {elapsed:.0f}ms)."
            except Exception as e:
                current_status, msg = "WARNING", f"HTTP check '{url}' failed: {type(e).__name__}: {e}"
            if self.should_report(state_key, msg):
                events.append({"plugin": "agent_network_http_monitor", "target": url,
                               "status": current_status, "message": msg})
        return events

    @register_check(157)
    def check_ip_change(self):
        """Alerts when the node's primary outbound IP changes (todo #34)."""
        events = []
        if not self.config.get('checks', {}).get('network', {}).get('monitor_ip_change', False):
            return events
        current_ip = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("192.0.2.1", 9))  # TEST-NET-1, no packets sent
            current_ip = s.getsockname()[0]
            s.close()
        except Exception:
            return events

        if not hasattr(self, '_ip_baseline') or self._ip_baseline is None:
            self._ip_baseline = current_ip
            return events
        state_key = "network:primary_ip"
        if current_ip != self._ip_baseline:
            msg = f"Primary IP address changed from {self._ip_baseline} to {current_ip}."
            self._ip_baseline = current_ip
            self.last_reported_states[state_key] = msg
            events.append({"plugin": "agent_network_ip_monitor", "target": "primary_ip",
                           "status": "WARNING", "message": msg})
        else:
            msg = f"Primary IP address stable at {current_ip}."
            if self.should_report(state_key, msg):
                events.append({"plugin": "agent_network_ip_monitor", "target": "primary_ip",
                               "status": "OK", "message": msg})
        return events

    @register_check(158)
    def check_bandwidth(self):
        """Interface throughput; WARNING above a configured rate (exfiltration /
        saturation) (todo #32)."""
        events = []
        net = self.config.get('checks', {}).get('network', {})
        warn_mbps = net.get('bandwidth_warn_mbps', 0)
        if not warn_mbps:
            return events
        ifaces = net.get('bandwidth_ifaces', []) or [
            d for d in os.listdir('/sys/class/net') if d != 'lo']
        if not hasattr(self, '_bw_last'):
            self._bw_last = {}
        now = time.monotonic()
        for iface in ifaces:
            try:
                with open(f"/sys/class/net/{iface}/statistics/rx_bytes") as f:
                    rx = int(f.read())
                with open(f"/sys/class/net/{iface}/statistics/tx_bytes") as f:
                    tx = int(f.read())
            except Exception:
                continue
            prev = self._bw_last.get(iface)
            self._bw_last[iface] = (rx, tx, now)
            if not prev:
                continue
            dt = now - prev[2]
            if dt <= 0:
                continue
            rx_mbps = (rx - prev[0]) * 8 / dt / 1e6
            tx_mbps = (tx - prev[1]) * 8 / dt / 1e6
            peak = max(rx_mbps, tx_mbps)
            state_key = f"network:bandwidth:{iface}"
            if peak > warn_mbps:
                current_status = "WARNING"
                msg = f"Interface '{iface}' throughput {peak:.0f} Mbps exceeds threshold {warn_mbps} Mbps (rx {rx_mbps:.0f}/tx {tx_mbps:.0f})."
            else:
                current_status = "OK"
                msg = f"Interface '{iface}' throughput within limits ({peak:.0f} Mbps)."
            if self.should_report(state_key, msg):
                events.append({"plugin": "agent_network_bandwidth_monitor", "target": iface,
                               "status": current_status, "message": msg})
        return events

    @register_check(85)
    def check_ups_nut(self):
        """UPS status via NUT (upsc): on-battery / low-battery / charge (todo #35)."""
        events = []
        ups = self.config.get('checks', {}).get('hardware', {}).get('nut_ups', '')
        if not ups:
            return events
        try:
            proc = subprocess.run(["upsc", ups], stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True, timeout=10)
        except FileNotFoundError:
            return events
        except Exception as e:
            print(f"[-] UPS (NUT) check failure: {e}", flush=True)
            return events
        if proc.returncode != 0:
            return events
        status = re.search(r"ups\.status:\s*(.+)", proc.stdout)
        charge = re.search(r"battery\.charge:\s*(\d+)", proc.stdout)
        st = status.group(1).strip() if status else ""
        chg = f", charge {charge.group(1)}%" if charge else ""
        state_key = "hardware:ups"
        if "OB" in st or "LB" in st:
            current_status = "CRITICAL" if "LB" in st else "WARNING"
            msg = f"UPS '{ups}' on battery / low (status: {st}{chg}). Mains power lost."
        elif st:
            current_status = "OK"
            msg = f"UPS '{ups}' on mains power (status: {st}{chg})."
        else:
            return events
        if self.should_report(state_key, msg):
            events.append({"plugin": "agent_ups_monitor", "target": ups,
                           "status": current_status, "message": msg})
        return events

    @register_check(159)
    def check_mdns_conflict(self):
        """Detects Avahi/mDNS hostname conflicts (duplicate hostname on the LAN)
        from the journal (todo #37)."""
        events = []
        if not self.config.get('checks', {}).get('network', {}).get('monitor_mdns_conflict', False):
            return events
        lines = self._journal_delta("avahi_journal.cursor", ["-t", "avahi-daemon"])
        if lines is None:
            return events
        conflicts = [l for l in lines if re.search(r"conflict|withdrawing|Host name.*already", l, re.IGNORECASE)]
        state_key = "network:mdns_conflict"
        if conflicts:
            msg = f"mDNS/Avahi hostname conflict detected (duplicate hostname on network): {conflicts[-1].strip()[:120]}"
            self.last_reported_states[state_key] = msg
            events.append({"plugin": "agent_network_mdns_monitor", "target": "hostname",
                           "status": "WARNING", "message": msg})
        else:
            msg = "No mDNS/Avahi hostname conflicts."
            if self.should_report(state_key, msg):
                events.append({"plugin": "agent_network_mdns_monitor", "target": "hostname",
                               "status": "OK", "message": msg})
        return events


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

    @register_check(70)
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

    @register_check(80)
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

    @register_check(150)
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

    @register_check(160)
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

    @register_check(170)
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

    @register_check(190)
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

    @register_check(220)
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

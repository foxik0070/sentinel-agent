"""System & network health: temperature, RPi throttling, time sync,
DNS, systemd failures, conntrack, memory."""
import os, re, socket, subprocess

from checks import register_check


class SystemChecks:
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

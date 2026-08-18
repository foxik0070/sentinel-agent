"""Storage checks: capacity/inodes, RAID, SSD wearout, SMART health."""
import os, re, subprocess

from checks import register_check


class StorageChecks:
    @register_check(90)
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

    @register_check(100)
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

    @register_check(110)
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
            except FileNotFoundError:
                return events
            try:
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

                # Pending/reallocated sectors predict failure earlier than overall SMART health.
                events.extend(self._check_drive_sectors(drive, proc.stdout))

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

    def _check_drive_sectors(self, drive, smart_output):
        """Parses reallocated / pending / uncorrectable sector counts from smartctl -A.
        A non-zero raw value is an early hardware-failure signal (SATA and NVMe)."""
        events = []
        # SATA SMART attribute lines: raw value is the last whitespace-separated field.
        sata_attrs = {
            "Reallocated_Sector_Ct": "reallocated sectors",
            "Current_Pending_Sector": "pending sectors",
            "Offline_Uncorrectable": "uncorrectable sectors",
        }
        findings = []
        for attr, label in sata_attrs.items():
            m = re.search(rf"^\s*\d+\s+{attr}\b.*?(\d+)\s*$", smart_output, re.MULTILINE)
            if m and int(m.group(1)) > 0:
                findings.append(f"{int(m.group(1))} {label}")
        # NVMe SMART/Health section uses named fields.
        for field, label in (("Media and Data Integrity Errors", "media/data integrity errors"),):
            m = re.search(rf"{re.escape(field)}:\s*([\d,]+)", smart_output)
            if m:
                val = int(m.group(1).replace(",", ""))
                if val > 0:
                    findings.append(f"{val} {label}")

        state_key = f"storage:sectors:{drive}"
        if findings:
            current_status = "CRITICAL"
            msg = f"Drive '{drive}' reports failing sectors: {', '.join(findings)}. Back up and replace the drive - failure is imminent."
        else:
            current_status = "OK"
            msg = f"Drive '{drive}' sector health clean (no reallocated/pending/uncorrectable sectors)."

        if self.should_report(state_key, msg):
            events.append({
                "plugin": "agent_ssd_wearout_monitor",
                "target": f"{drive}:sectors",
                "status": current_status,
                "message": msg
            })
        return events

    @register_check(120)
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
            except FileNotFoundError:
                return events
            try:
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

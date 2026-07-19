"""Kernel-level checks: OOM killer, zombies, I/O hangs, taint."""
import os, re, subprocess

from checks import register_check


class KernelChecks:
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

    @register_check(130)
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

    @register_check(140)
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

    @register_check(180)
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

    @register_check(200)
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

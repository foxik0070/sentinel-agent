"""Systemd service and mountpoint checks."""
import os, subprocess

from checks import register_check


class ServicesChecks:
    @register_check(10)
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

    @register_check(20)
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

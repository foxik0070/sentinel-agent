#!/usr/bin/env python3
"""
Sentinel Agent Initialization and Configuration Script.
Generates or alters /etc/sentinel/agent_config.yaml with a clean interactive TUI.
Automates systemd service deployment and management with precise boot guards.
Automatically provisions a Python Virtual Environment to prevent PEP 668 conflicts.
Includes built-in localization (CS/EN) and explanation prompts.
All inline comments and logs are maintained in English.
"""

import os
import sys
import socket
import shutil
import subprocess
import argparse

try:
    import yaml
except ImportError:
    print("\033[91m[!] PyYAML dependency is missing. Installing via pip...\033[0m")
    try:
        # Fallback for the init script itself if running outside venv
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyyaml", "--break-system-packages"])
        import yaml
    except Exception as e:
        print(f"\033[91m[!] Failed to install PyYAML automatically: {e}\033[0m")
        print("\033[93m[i] Please install it manually: apt install python3-yaml (Debian) or dnf install python3-pyyaml (RHEL)\033[0m")
        sys.exit(1)

C_HEADER = '\033[95m'
C_BLUE = '\033[94m'
C_CYAN = '\033[96m'
C_GREEN = '\033[92m'
C_WARN = '\033[93m'
C_FAIL = '\033[91m'
C_END = '\033[0m'
C_BOLD = '\033[1m'

CONFIG_DIR = "/etc/sentinel"
CONFIG_FILE = os.path.join(CONFIG_DIR, "agent_config.yaml")

# --- Localization Dictionary ---
LANG_DICT = {
    'cs': {
        'api_url': "Zakladni URL adresa centralniho Sentinel serveru (vcetne portu).",
        'api_token': "Autentizacni token vygenerovany na serveru pro zabezpecenou komunikaci.",
        'api_host': "Unikatni jmeno tohoto serveru/uzlu pro identifikaci v dashboardu.",
        'source_ip': "Zdrojova IP pro odchozi HTTP pozadavky (prazdne = automaticky). Pouzijte pri vice sítovych rozhranich (eth+wifi) pro zabraneni duplicitnich hlaseni.",
        'update_q': "Ma se agent sam automaticky aktualizovat z Gitu, kdyz detekuje zmenu (auto-refresh)?",
        'int_push': "Jak casto (v sekundach) se maji posilat data na server.",
        'int_boot': "Cas (v sekundach), po ktery agent po startu ceka na nabehnuti ostatnich sluzeb (zabranuje falesnym poplachum).",
        'temp': "Sleduje teplotu procesoru a upozorni na pripadne prehrati hardware.",
        'rpi_throttle': "Raspberry Pi: cte firmware flagy (vcgencmd get_throttled) - undervoltage (vadny zdroj/kabel), CPU throttling, teplotni limity. Na jinem hardware se automaticky preskoci.",
        'storage': "Sleduje volne misto a inody na disku, cimz predchazi chybam typu 'disk is full'.",
        'wearout': "Vyuziva SMART data pro detekci bliziciho se konce zivotnosti SSD/NVMe disku.",
        'raid': "Sleduje stav softwarovych diskovych poli (mdadm) a varuje pri jejich degradaci.",
        'oom': "Detekuje zasahy jadra (OOM Killer), ktere ukoncuji procesy kvuli nedostatku RAM.",
        'zombie': "Sleduje hromadeni mrtvych (defunct) procesu, ktere mohou zahltit tabulku pids.",
        'io': "Hleda procesy zaseknute v uninterruptible sleep (D state), coz casto znaci problem s diskem.",
        'taint': "Varuje, pokud je jadro OS 'tainted' (napr. pad ovladace, hardwarova chyba MCE).",
        'time': "Overuje, zda je systemovy cas spravne synchronizovan pres NTP.",
        'systemd': "Globalne kontroluje, zda neselhala nejaka sluzba na pozadi (failed units).",
        'dns': "Testuje funkcnost prekladu domenovych jmen (zda funguje sitovy resolver).",
        'conn': "Sleduje vytizeni tabulky conntrack na firewallu, cimz predchazi zahazovani paketu.",
        'root': "Spusti poplach pokazde, kdyz se nekdo prihlasi na server pod uctem root (pouze SSH prihlaseni, tmux sessiony jsou ignorovany).",
        'root_ignore_ips': "Zadejte IP adresy, ze kterych se root prihlaseni ignoruji (napr. 192.168.1.1).",
        'ports': "Vytvori snimek aktualne otevrenych portu a varuje, pokud se otevre novy (necekany) port.",
        'updates': "Dotazuje se balickovaciho systemu (apt/dnf) na cekajici systemove aktualizace.",
        'cve': "Hleda kriticke bezpecnostni zaplaty (CVE) v cekajicich aktualizacich a porovnava verzi kernelu se znamymi privilege-escalation exploity (Dirty COW, Dirty Pipe, nf_tables...).",
        'f2b': "Analyzuje Fail2ban a upozorni, pokud probiha masivni brute-force utok (vysoky pocet banu).",
        'suspicious': "Detekuje podezrele chovani: zmeny /etc/passwd|shadow|sudoers (stopa exploitu Dirty COW/Dirty Pipe), nove ucty s UID 0, procesy spustene z /tmp, known cryptominery, reverse-shell vzory a SUID binarky v docasnych adresarich.",
        'mem': "Sleduje vyuziti RAM a swap pameti. Cte data z /proc/meminfo bez zavislosti na externích nastrojich.",
        'svc_q': "Chcete specifikovat konkretni systemd sluzby (treba nginx, docker), ktere maji byt hlidany?",
        'mnt_q': "Chcete specifikovat konkretni pripojne body (napr. /mnt/data), ktere musi byt pripojeny?",
        'ssl_q': "Chcete nastavit hlidani exspirace pro konkretni SSL/TLS certifikaty?",
        'disk_health': "Spusti smartctl -H na kazdem fyzickem disku pro detekci bliziciho se selhani hardware. Automaticky preskoceno na virtualnim stroji (LXC, QEMU, KVM)."
    },
    'en': {
        'api_url': "Base URL address of the central Sentinel server (including port).",
        'api_token': "Authentication token generated on the server for secure communication.",
        'api_host': "Unique name of this server/node for dashboard identification.",
        'source_ip': "Source IP for outgoing HTTP requests (empty = automatic). Use when device has multiple interfaces (eth+wifi) to prevent duplicate reports.",
        'update_q': "Should the agent automatically pull from Git when a change is detected (auto-refresh)?",
        'int_push': "How often (in seconds) to send telemetry data to the server.",
        'int_boot': "Time (in seconds) the agent waits after boot for other services to start (prevents false alerts).",
        'temp': "Monitors CPU temperature and alerts on hardware overheating.",
        'rpi_throttle': "Raspberry Pi: reads firmware flags (vcgencmd get_throttled) - undervoltage (bad PSU/cable), CPU throttling, thermal limits. Automatically skipped on other hardware.",
        'storage': "Monitors free space and inodes on disks to prevent 'disk is full' errors.",
        'wearout': "Uses SMART data to detect impending SSD/NVMe drive failure/lifespan end.",
        'raid': "Monitors the state of software disk arrays (mdadm) and warns on degradation.",
        'oom': "Detects kernel interventions (OOM Killer) terminating processes due to RAM exhaustion.",
        'zombie': "Monitors accumulation of dead (defunct) processes that can exhaust the PIDs table.",
        'io': "Looks for processes stuck in uninterruptible sleep (D state), indicating disk I/O issues.",
        'taint': "Warns if the OS kernel is 'tainted' (e.g., driver crash, MCE hardware error).",
        'time': "Verifies if the system time is correctly synchronized via NTP.",
        'systemd': "Globally checks if any background service has failed (failed units).",
        'dns': "Tests the functionality of domain name resolution (network resolver health).",
        'conn': "Monitors firewall conntrack table utilization to prevent packet drops.",
        'root': "Triggers an alert whenever someone logs into the server as the root user (SSH logins only, tmux sessions are ignored).",
        'root_ignore_ips': "Enter IP addresses from which root logins are ignored (e.g., 192.168.1.1).",
        'ports': "Creates a snapshot of currently open ports and warns if a new (unexpected) port opens.",
        'updates': "Queries the package manager (apt/dnf) for pending system updates.",
        'cve': "Looks for critical security patches (CVE) in pending updates and compares the kernel version against known privilege-escalation exploits (Dirty COW, Dirty Pipe, nf_tables...).",
        'f2b': "Analyzes Fail2ban and alerts if a massive brute-force attack is ongoing (high ban count).",
        'suspicious': "Detects suspicious behavior: changes to /etc/passwd|shadow|sudoers (Dirty COW/Dirty Pipe exploit footprint), new UID 0 accounts, processes running from /tmp, known cryptominers, reverse-shell patterns and SUID binaries in temp dirs.",
        'mem': "Monitors RAM and swap utilization. Reads /proc/meminfo with no external tool dependencies.",
        'svc_q': "Do you want to specify exact systemd services (e.g., nginx, docker) to be monitored?",
        'mnt_q': "Do you want to specify exact mountpoints (e.g., /mnt/data) that must remain attached?",
        'ssl_q': "Do you want to set up expiration monitoring for specific SSL/TLS certificates?",
        'disk_health': "Runs smartctl -H on each physical drive to detect imminent hardware failure. Automatically skipped on virtual machines (LXC, QEMU, KVM)."
    }
}

def print_banner():
    print(f"{C_HEADER}{C_BOLD}" + "="*60)
    print("      ____  _____ _   _ _____ ___ _   _ _____ _     ")
    print("     / ___|| ____| \\ | |_   _|_ _| \\ | | ____| |    ")
    print("     \\___ \\|  _| |  \\| | | |  | ||  \\| |  _| | |    ")
    print("      ___) | |___| |\\  | | |  | || |\\  | |___| |___ ")
    print("     |____/|_____|_| \\_| |_| |___|_| \\_|_____|_____|")
    print("                                                    ")
    print("               AGENT DAEMON INITIALIZATION SUITE       ")
    print("="*60 + f"{C_END}\n")

def check_privileges():
    if os.geteuid() != 0:
        print(f"{C_FAIL}{C_BOLD}[!] Error: This deployment tool requires root administrative privileges.{C_END}")
        sys.exit(1)

def print_explanation(text):
    if text:
        print(f"  {C_BLUE}ℹ️  {text}{C_END}")

def prompt_input(message, default_value, explanation=None):
    if explanation: print_explanation(explanation)
    display_default = str(default_value)
    user_val = input(f"{C_BOLD}{message}{C_END} [{C_GREEN}{display_default}{C_END}]: ").strip()
    return user_val if user_val else default_value

def prompt_bool(message, default_bool, explanation=None):
    if explanation: print_explanation(explanation)
    display_str = "Y/n" if default_bool else "y/N"
    user_val = input(f"{C_BOLD}{message}{C_END} ({C_GREEN}{display_str}{C_END}): ").strip().lower()
    if not user_val: return default_bool
    return user_val in ['y', 'yes', 'true', '1']

def load_existing_config():
    default_config = {
        "agent_core": {
            "git_auto_update": False,
            "state_file": "/var/lib/sentinel/state.json",
            "max_pending_events": 500,
            "max_self_rss_mb": 0
        },
        "sentinel_api": {
            "url": "http://192.168.1.100:5050",
            "token": "",
            "hostname": socket.gethostname(),
            "source_ip": "",
            "verify_tls": True,
            "ca_bundle": "",
            "gzip": False,
            "plain_messages": False
        },
        "intervals": {
            "metrics_push_sec": 60,
            "heartbeat_sec": 30,
            "boot_delay_sec": 90
        },
        "checks": {
            "services": [],
            "mounts": [],
            "temperature": {"enabled": True, "warning": 75.0, "critical": 85.0},
            "hardware": {"monitor_rpi_throttling": True, "nut_ups": "", "monitor_fans": False, "monitor_readonly_remount": True, "readonly_mounts": ["/"]},
            "storage": {"enabled": True, "paths": ["/"], "warn_percent": 85, "crit_percent": 95, "monitor_wearout": True, "monitor_raid": True, "monitor_disk_health": False},
            "memory": {"enabled": True, "warn_percent": 85, "crit_percent": 95, "monitor_swap": True},
            "kernel": {"monitor_oom": True, "monitor_zombies": True, "max_zombies": 5, "monitor_io_hangs": True, "monitor_taint": True},
            "system": {"monitor_time_sync": True, "monitor_global_systemd": True},
            "network": {"monitor_dns": True, "monitor_conntrack": True, "monitor_reachability": False, "ping_targets": [], "ping_gateway": True, "ping_max_latency_ms": 200, "http_checks": [], "monitor_ip_change": False, "bandwidth_warn_mbps": 0, "bandwidth_ifaces": [], "monitor_mdns_conflict": False},
            "security": {"monitor_root_logins": True, "root_login_ignore_ips": [], "monitor_ports": True, "check_system_updates": True, "scan_cves": True, "fail2ban_stats": True, "monitor_suspicious": True, "sudo_fail_threshold": 3, "suspicious_ignore": [], "monitor_outbound": True, "suspicious_remote_ports": [], "monitor_priv_groups": True, "monitor_raw_sockets": False, "raw_socket_allow": ["dhclient", "dhcpcd", "NetworkManager", "ping", "ping6", "systemd-network"], "pkg_integrity": False, "pkg_integrity_cadence_cycles": 10080, "check_needrestart": False, "check_unattended_upgrades": False, "ssl_certs": []}
        }
    }

    if os.path.exists(CONFIG_FILE):
        print(f"{C_CYAN}[*] Located existing configuration framework at {CONFIG_FILE}{C_END}\n")
        try:
            with open(CONFIG_FILE, 'r') as stream:
                existing_data = yaml.safe_load(stream)
                if existing_data and isinstance(existing_data, dict):
                    for section in ["agent_core", "sentinel_api", "intervals", "checks"]:
                        if section in existing_data and isinstance(existing_data[section], dict):
                            if section != "checks":
                                default_config[section].update(existing_data[section])
                            else:
                                for check_key in default_config["checks"].keys():
                                    if check_key in existing_data["checks"]:
                                        if isinstance(default_config["checks"][check_key], dict):
                                            default_config["checks"][check_key].update(existing_data["checks"][check_key])
                                        else:
                                            default_config["checks"][check_key] = existing_data["checks"][check_key]
        except Exception as err:
            print(f"{C_WARN}[!] Warning: Failed parsing file structures ({err}).{C_END}\n")
            
    return default_config

def configure_services(current_services):
    print(f"\n{C_CYAN}--- Systemd Services Inspection Target Mapping ---{C_END}")
    modified_services = list(current_services)
    while True:
        print(f"\nCurrent configured services:")
        if not modified_services: print("  (None)")
        for idx, svc in enumerate(modified_services):
            print(f"  [{C_GREEN}{idx}{C_END}] Name: {C_BOLD}{svc['name']}{C_END} | Severity: {C_WARN}{svc['severity']}{C_END}")
        choice = input(f"\nOptions: [{C_GREEN}a{C_END}]dd service, [{C_GREEN}d{C_END}]elete service, [{C_GREEN}n{C_END}]ext step: ").strip().lower()
        if choice == 'n' or not choice: break
        elif choice == 'a':
            name = input("Enter systemd service name: ").strip()
            if not name: continue
            severity = input("Allocation priority severity (CRITICAL / WARNING) [CRITICAL]: ").strip().upper()
            if severity not in ['CRITICAL', 'WARNING']: severity = 'CRITICAL'
            modified_services.append({"name": name, "severity": severity})
        elif choice == 'd':
            try:
                idx_del = int(input("Enter service index ID to wipe out: ").strip())
                if 0 <= idx_del < len(modified_services): modified_services.pop(idx_del)
            except ValueError: print(f"{C_FAIL}[!] Invalid index.{C_END}")
    return modified_services

def configure_mounts(current_mounts):
    print(f"\n{C_CYAN}--- Block Storage Mountpoint Validation Engine ---{C_END}")
    modified_mounts = list(current_mounts)
    while True:
        print(f"\nCurrent tracked mountpaths:")
        if not modified_mounts: print("  (None)")
        for idx, mnt in enumerate(modified_mounts):
            print(f"  [{C_GREEN}{idx}{C_END}] Path: {C_BOLD}{mnt['path']}{C_END} | Alert: {C_WARN}{mnt['severity']}{C_END}")
        choice = input(f"\nOptions: [{C_GREEN}a{C_END}]dd mountpath, [{C_GREEN}d{C_END}]elete path, [{C_GREEN}n{C_END}]ext step: ").strip().lower()
        if choice == 'n' or not choice: break
        elif choice == 'a':
            path = input("Enter fully absolute target mountpath: ").strip()
            if not path: continue
            severity = input("Allocation priority severity (CRITICAL / WARNING) [CRITICAL]: ").strip().upper()
            if severity not in ['CRITICAL', 'WARNING']: severity = 'CRITICAL'
            modified_mounts.append({"path": path, "severity": severity})
        elif choice == 'd':
            try:
                idx_del = int(input("Enter target path index ID to discard: ").strip())
                if 0 <= idx_del < len(modified_mounts): modified_mounts.pop(idx_del)
            except ValueError: print(f"{C_FAIL}[!] Invalid index.{C_END}")
    return modified_mounts

def configure_storage_paths(current_paths):
    print(f"\n{C_CYAN}--- Storage Capacity Path Targets ---{C_END}")
    modified_paths = list(current_paths)
    while True:
        print(f"\nCurrent tracked disk paths: {modified_paths}")
        choice = input(f"Options: [{C_GREEN}a{C_END}]dd path, [{C_GREEN}d{C_END}]elete path, [{C_GREEN}n{C_END}]ext step: ").strip().lower()
        if choice == 'n' or not choice: break
        elif choice == 'a':
            path = input("Enter path (e.g. / or /var): ").strip()
            if path and path not in modified_paths: modified_paths.append(path)
        elif choice == 'd':
            path = input("Enter exact path to delete: ").strip()
            if path in modified_paths: modified_paths.remove(path)
    return modified_paths

def configure_ssl_certs(current_certs):
    print(f"\n{C_CYAN}--- Cryptographic SSL/TLS Certificate Expiration Watcher ---{C_END}")
    modified_certs = list(current_certs)
    while True:
        print(f"\nCurrent target cert paths: {modified_certs}")
        choice = input(f"Options: [{C_GREEN}a{C_END}]dd cert path, [{C_GREEN}d{C_END}]elete cert path, [{C_GREEN}n{C_END}]ext step: ").strip().lower()
        if choice == 'n' or not choice: break
        elif choice == 'a':
            path = input("Enter absolute path to certificate file (.pem/.crt): ").strip()
            if path and path not in modified_certs: modified_certs.append(path)
        elif choice == 'd':
            path = input("Enter exact cert path to remove: ").strip()
            if path in modified_certs: modified_certs.remove(path)
    return modified_certs

def configure_root_ignore_ips(current_ips):
    print(f"\n{C_CYAN}--- Root Login IP Whitelist ---{C_END}")
    modified_ips = list(current_ips)
    while True:
        print(f"\nCurrent whitelisted IPs: {modified_ips if modified_ips else '(None)'}")
        choice = input(f"Options: [{C_GREEN}a{C_END}]dd IP, [{C_GREEN}d{C_END}]elete IP, [{C_GREEN}n{C_END}]ext step: ").strip().lower()
        if choice == 'n' or not choice: break
        elif choice == 'a':
            ip = input("Enter IP address to whitelist: ").strip()
            if ip and ip not in modified_ips: modified_ips.append(ip)
        elif choice == 'd':
            ip = input("Enter exact IP to remove: ").strip()
            if ip in modified_ips: modified_ips.remove(ip)
    return modified_ips


def setup_agent_venv(working_dir):
    """
    Creates an isolated Python virtual environment for the Sentinel Agent
    to prevent PEP 668 OS-level conflicts and installs required packages.
    """
    venv_dir = os.path.join(working_dir, "venv")
    python_bin = os.path.join(venv_dir, "bin", "python3")
    pip_bin = os.path.join(venv_dir, "bin", "pip3")

    print(f"\n{C_CYAN}--- Dependency Management (Virtual Environment) ---{C_END}")
    
    if not os.path.exists(venv_dir):
        print(f"{C_BLUE}[*] Creating isolated virtual environment in {venv_dir}...{C_END}")
        import venv
        venv.create(venv_dir, with_pip=True)
    else:
        print(f"{C_GREEN}[+] Virtual environment already exists at {venv_dir}.{C_END}")

    print(f"{C_BLUE}[*] Installing required modules...{C_END}")
    try:
        req_file = os.path.join(working_dir, "requirements.txt")
        if os.path.exists(req_file):
            subprocess.run([pip_bin, "install", "-r", req_file], check=True, stdout=subprocess.DEVNULL)
        else:
            subprocess.run([pip_bin, "install", "requests>=2.31,<3", "PyYAML>=6.0,<7"], check=True, stdout=subprocess.DEVNULL)
        print(f"{C_GREEN}[+] Modules installed successfully.{C_END}")
    except subprocess.CalledProcessError as e:
        print(f"{C_FAIL}[!] Failed to install dependencies into venv: {e}{C_END}")
        sys.exit(1)

    return python_bin

AGENT_ISSUES_SCRIPT = """\
#!/usr/bin/env python3
import os, sys, json

CONFIG_FILE = "/etc/sentinel/agent_config.yaml"

try:
    import yaml
except ImportError:
    print("[!] PyYAML missing. Run: apt install python3-yaml")
    sys.exit(1)

if not os.path.exists(CONFIG_FILE):
    print(f"[!] Config not found: {CONFIG_FILE}")
    sys.exit(1)

with open(CONFIG_FILE, 'r') as f:
    config = yaml.safe_load(f)

state_file = config.get('agent_core', {}).get('state_file', '/var/lib/sentinel/state.json')

if not os.path.exists(state_file):
    print(f"No state file at {state_file}. Is sentinel-agent running?")
    sys.exit(0)

with open(state_file, 'r') as f:
    state = json.load(f)

issues = state.get('issues', {})
hostname = state.get('hostname', 'unknown')
updated = state.get('updated', 'unknown')

print(f"Active issues on {hostname}  (last update: {updated})")
print("-" * 60)
if not issues:
    print("  No active issues.")
else:
    for _, issue in sorted(issues.items()):
        print(f"  [{issue['status']}] {issue['target']} ({issue['plugin']})")
        print(f"    {issue['message']}")
        print()
"""

def _install_agent_issues_binary():
    binary_path = "/usr/local/bin/agent_issues"
    try:
        with open(binary_path, 'w') as f:
            f.write(AGENT_ISSUES_SCRIPT)
        os.chmod(binary_path, 0o755)
        print(f"{C_GREEN}[+] Installed system binary: {binary_path}{C_END}")
    except Exception as e:
        print(f"{C_WARN}[!] Could not install {binary_path}: {e}{C_END}")


def manage_systemd_service():
    print(f"\n{C_GREEN}[Step 6] Systemd Service Deployment & Management{C_END}")
    service_path = "/etc/systemd/system/sentinel-agent.service"
    current_dir = os.path.dirname(os.path.abspath(__file__))
    default_agent_path = os.path.join(current_dir, "sentinel_agent.py")

    if not os.path.exists(service_path):
        if prompt_bool("Do you want to deploy the systemd service now?", True):
            bin_path = prompt_input("Absolute path to sentinel_agent.py", default_agent_path)
            working_dir = os.path.dirname(os.path.abspath(bin_path))
            
            # Setup Virtual Environment before deploying
            python_exec = setup_agent_venv(working_dir)
            
            service_content = f"""[Unit]
Description=Sentinel Agent Daemon Stateful Framework
After=network-online.target multi-user.target
Wants=network-online.target

[Service]
Type=notify
NotifyAccess=main
WatchdogSec=1200
WorkingDirectory={working_dir}
ExecStart={python_exec} {bin_path}
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""
            try:
                with open(service_path, "w") as f: f.write(service_content)
                subprocess.run(["systemctl", "daemon-reload"], check=True)
                print(f"{C_GREEN}[+] Service successfully deployed using isolated venv python binary.{C_END}")
            except Exception as e:
                print(f"{C_FAIL}[!] Failed to create service: {e}{C_END}")
                return

    _install_agent_issues_binary()

    while True:
        print(f"\n{C_CYAN}--- Sentinel Agent Service Control ---{C_END}")
        choice = input(f"Options: [{C_GREEN}s{C_END}]tart, [{C_GREEN}r{C_END}]estart, [{C_GREEN}e{C_END}]nable, [{C_GREEN}q{C_END}]uit: ").strip().lower()
        if choice == 'q' or not choice: break
        elif choice == 's':
            subprocess.run(["systemctl", "start", "sentinel-agent"])
            subprocess.run(["systemctl", "status", "sentinel-agent", "--no-pager", "-n", "3"])
        elif choice == 'r':
            subprocess.run(["systemctl", "restart", "sentinel-agent"])
            subprocess.run(["systemctl", "status", "sentinel-agent", "--no-pager", "-n", "3"])
        elif choice == 'e':
            subprocess.run(["systemctl", "enable", "sentinel-agent"])

def main(lang):
    print_banner()
    check_privileges()
    cfg = load_existing_config()
    txt = LANG_DICT[lang]
    
    print(f"{C_GREEN}[Step 1] Core Ingest Interface Credentials{C_END}")
    cfg["sentinel_api"]["url"] = prompt_input("Sentinel Server API Central URL Base", cfg["sentinel_api"]["url"], txt['api_url'])
    cfg["sentinel_api"]["token"] = prompt_input("Secure Agent API Token Authentication Key", cfg["sentinel_api"]["token"], txt['api_token'])
    cfg["sentinel_api"]["hostname"] = prompt_input("Report Identity (Cluster Node Hostname)", cfg["sentinel_api"]["hostname"], txt['api_host'])
    cfg["sentinel_api"]["source_ip"] = prompt_input("Source IP for outgoing requests (leave empty for automatic)", cfg["sentinel_api"].get("source_ip", ""), txt['source_ip'])

    print(f"\n{C_GREEN}[Step 2] Agent Core Features{C_END}")
    cfg["agent_core"]["git_auto_update"] = prompt_bool("Enable Autonomous Git Auto-Update (auto-refresh)", cfg["agent_core"].get("git_auto_update", False), txt['update_q'])
    
    print(f"\n{C_GREEN}[Step 3] Polling Cadence and Control Loops Timing{C_END}")
    cfg["intervals"]["metrics_push_sec"] = int(prompt_input("Metrics Sync Cadence (Seconds)", cfg["intervals"]["metrics_push_sec"], txt['int_push']))
    cfg["intervals"]["boot_delay_sec"] = int(prompt_input("Post-Reboot OS Stabilization Delay (Seconds)", cfg["intervals"].get("boot_delay_sec", 90), txt['int_boot']))
    
    print(f"\n{C_GREEN}[Step 4] Hardware & OS Environment Thresholds Configuration{C_END}")
    
    cfg["checks"]["temperature"]["enabled"] = prompt_bool("Monitor CPU hardware temperature matrix", cfg["checks"]["temperature"].get("enabled", True), txt['temp'])
    if cfg["checks"]["temperature"]["enabled"]:
        cfg["checks"]["temperature"]["warning"] = float(prompt_input("CPU Temperature WARNING threshold (C)", cfg["checks"]["temperature"].get("warning", 75.0)))
        cfg["checks"]["temperature"]["critical"] = float(prompt_input("CPU Temperature CRITICAL threshold (C)", cfg["checks"]["temperature"].get("critical", 85.0)))

    cfg["checks"].setdefault("hardware", {})
    cfg["checks"]["hardware"]["monitor_rpi_throttling"] = prompt_bool("Monitor Raspberry Pi undervoltage/throttling (vcgencmd)", cfg["checks"]["hardware"].get("monitor_rpi_throttling", True), txt['rpi_throttle'])

    cfg["checks"]["storage"]["enabled"] = prompt_bool("Monitor structural storage metrics (Space/Inodes)", cfg["checks"]["storage"].get("enabled", True), txt['storage'])
    if cfg["checks"]["storage"]["enabled"]:
        cfg["checks"]["storage"]["paths"] = configure_storage_paths(cfg["checks"]["storage"].get("paths", ["/"]))
        cfg["checks"]["storage"]["warn_percent"] = int(prompt_input("Storage capacity WARNING limit (%)", cfg["checks"]["storage"].get("warn_percent", 85)))
        cfg["checks"]["storage"]["crit_percent"] = int(prompt_input("Storage capacity CRITICAL limit (%)", cfg["checks"]["storage"].get("crit_percent", 95)))
    
    cfg["checks"]["storage"]["monitor_wearout"] = prompt_bool("Monitor SSD NVMe/SATA wearout (SMART attributes)", cfg["checks"]["storage"].get("monitor_wearout", True), txt['wearout'])
    cfg["checks"]["storage"]["monitor_raid"] = prompt_bool("Monitor software RAID (mdadm) array health", cfg["checks"]["storage"].get("monitor_raid", True), txt['raid'])
    cfg["checks"]["storage"]["monitor_disk_health"] = prompt_bool("Monitor physical disk SMART overall health (skip on VM/LXC)", cfg["checks"]["storage"].get("monitor_disk_health", False), txt.get('disk_health', 'Runs smartctl -H on each physical drive to detect imminent hardware failure. Skipped automatically on virtual machines.'))

    cfg["checks"]["memory"]["enabled"] = prompt_bool("Monitor RAM and swap memory utilization", cfg["checks"]["memory"].get("enabled", True), txt['mem'])
    if cfg["checks"]["memory"]["enabled"]:
        cfg["checks"]["memory"]["warn_percent"] = int(prompt_input("RAM/Swap WARNING limit (%)", cfg["checks"]["memory"].get("warn_percent", 85)))
        cfg["checks"]["memory"]["crit_percent"] = int(prompt_input("RAM/Swap CRITICAL limit (%)", cfg["checks"]["memory"].get("crit_percent", 95)))
        cfg["checks"]["memory"]["monitor_swap"] = prompt_bool("Also monitor swap utilization", cfg["checks"]["memory"].get("monitor_swap", True))

    cfg["checks"]["kernel"]["monitor_oom"] = prompt_bool("Monitor Kernel Out-Of-Memory (OOM) killer terminations", cfg["checks"]["kernel"].get("monitor_oom", True), txt['oom'])
    cfg["checks"]["kernel"]["monitor_zombies"] = prompt_bool("Monitor defective zombie (defunct) processes", cfg["checks"]["kernel"].get("monitor_zombies", True), txt['zombie'])
    if cfg["checks"]["kernel"]["monitor_zombies"]:
        cfg["checks"]["kernel"]["max_zombies"] = int(prompt_input("Maximum allowed defective zombie processes", cfg["checks"]["kernel"].get("max_zombies", 5)))
    
    cfg["checks"]["kernel"]["monitor_io_hangs"] = prompt_bool("Monitor uninterruptible sleep processes (I/O Hangs)", cfg["checks"]["kernel"].get("monitor_io_hangs", True), txt['io'])
    cfg["checks"]["kernel"]["monitor_taint"] = prompt_bool("Monitor Kernel Taint status (Hardware MCE / Unsafe modules)", cfg["checks"]["kernel"].get("monitor_taint", True), txt['taint'])
    
    cfg["checks"]["system"]["monitor_time_sync"] = prompt_bool("Monitor structural NTP clock reference synchronization", cfg["checks"]["system"].get("monitor_time_sync", True), txt['time'])
    cfg["checks"]["system"]["monitor_global_systemd"] = prompt_bool("Monitor global systemd unit failures", cfg["checks"]["system"].get("monitor_global_systemd", True), txt['systemd'])
    
    cfg["checks"]["network"]["monitor_dns"] = prompt_bool("Monitor upstream name resolution (DNS integrity)", cfg["checks"]["network"].get("monitor_dns", True), txt['dns'])
    cfg["checks"]["network"]["monitor_conntrack"] = prompt_bool("Monitor Netfilter connection tracking (Conntrack) pressure", cfg["checks"]["network"].get("monitor_conntrack", True), txt['conn'])

    print(f"\n{C_GREEN}[Step 5] Execution Routine Target Subsystems Mapping{C_END}")
    if prompt_bool("Do you want to configure targeted systemd services monitoring?", True, txt['svc_q']):
        cfg["checks"]["services"] = configure_services(cfg["checks"].get("services", []))
    else:
        cfg["checks"]["services"] = []

    if prompt_bool("Do you want to configure specific disk mountpoints monitoring?", True, txt['mnt_q']):
        cfg["checks"]["mounts"] = configure_mounts(cfg["checks"].get("mounts", []))
    else:
        cfg["checks"]["mounts"] = []
    
    print(f"\n{C_GREEN}[Step 6] Operating System Security Profiling Framework Controls{C_END}")
    cfg["checks"]["security"]["monitor_root_logins"] = prompt_bool("Monitor active root session terminal access timelines", cfg["checks"]["security"].get("monitor_root_logins", True), txt['root'])
    if cfg["checks"]["security"]["monitor_root_logins"]:
        cfg["checks"]["security"]["root_login_ignore_ips"] = configure_root_ignore_ips(cfg["checks"]["security"].get("root_login_ignore_ips", []))
    cfg["checks"]["security"]["monitor_ports"] = prompt_bool("Monitor network sockets bindings drift against baseline", cfg["checks"]["security"].get("monitor_ports", True), txt['ports'])
    cfg["checks"]["security"]["check_system_updates"] = prompt_bool("Monitor pending OS software upgrades", cfg["checks"]["security"].get("check_system_updates", True), txt['updates'])
    cfg["checks"]["security"]["scan_cves"] = prompt_bool("Monitor package level vulnerability lookup (CVE)", cfg["checks"]["security"].get("scan_cves", True), txt['cve'])
    cfg["checks"]["security"]["fail2ban_stats"] = prompt_bool("Monitor security blocking counts from local Fail2ban", cfg["checks"]["security"].get("fail2ban_stats", True), txt['f2b'])
    cfg["checks"]["security"]["monitor_suspicious"] = prompt_bool("Monitor suspicious processes & exploit footprints (CVE abuse)", cfg["checks"]["security"].get("monitor_suspicious", True), txt['suspicious'])
    
    if prompt_bool("Do you want to configure SSL/TLS Certificate Expiration Watcher?", True, txt['ssl_q']):
        cfg["checks"]["security"]["ssl_certs"] = configure_ssl_certs(cfg["checks"]["security"].get("ssl_certs", []))
    else:
        cfg["checks"]["security"]["ssl_certs"] = []
    
    print(f"\n{C_GREEN}[Step 7] Configuration Export Compilation Strategy{C_END}")
    if not os.path.exists(CONFIG_DIR): os.makedirs(CONFIG_DIR, exist_ok=True)
    try:
        if os.path.exists(CONFIG_FILE): shutil.copyfile(CONFIG_FILE, f"{CONFIG_FILE}.bak")
        with open(CONFIG_FILE, 'w') as out_stream:
            yaml.dump(cfg, out_stream, default_flow_style=False, sort_keys=False)
        print(f"\n{C_GREEN}{C_BOLD}[+] Configuration generated at {CONFIG_FILE} !{C_END}")
    except Exception as io_err:
        print(f"{C_FAIL}[!] File IO allocation error: {io_err}{C_END}")
        sys.exit(1)

    manage_systemd_service()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel Agent Configuration Suite")
    parser.add_argument("-l", "--lang", choices=["cs", "en"], default="cs", help="Select localization language for explanation prompts (cs / en)")
    args = parser.parse_args()

    try: 
        main(args.lang)
    except KeyboardInterrupt: 
        sys.exit(0)

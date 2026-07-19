# Sentinel Agent — TODO / Návrhy na vylepšení

50 návrhů seřazených podle kategorií. Priorita: 🔴 vysoká, 🟡 střední, 🟢 nízká.

## Bezpečnost — detekce (navazuje na nový check_suspicious_activity)

1. ✅ ~~Detekce nových SSH authorized_keys~~ — HOTOVO: baseline hash root + /home/* v `check_suspicious_activity` (persistence_files).
2. ✅ ~~Monitoring nových cronů~~ — HOTOVO: /etc/crontab, /etc/cron.d, /var/spool/cron v persistence_files baseline. Zbývá: systemd timery.
3. ✅ ~~Detekce procesů se smazaným binárním souborem~~ — HOTOVO: deleted exe mimo systémové cesty + fileless memfd exekutably.
4. ✅ ~~Kontrola `LD_PRELOAD` a `/etc/ld.so.preload`~~ — HOTOVO: CRITICAL při neprázdném /etc/ld.so.preload.
5. ✅ ~~Baseline SUID/SGID binárek v celém systému~~ — HOTOVO: celosystémový sken každých 10 cyklů, CRITICAL na nový SUID/SGID, persistence baseline přes restart.
6. ✅ ~~Detekce promiskuitního režimu síťových rozhraní~~ — HOTOVO: IFF_PROMISC z /sys/class/net/*/flags, WARNING při aktivním sniffingu.
7. ✅ ~~Kontrola podezřelých odchozích spojení~~ — HOTOVO: check_outbound_connections, established TCP na podezřelé porty (revshell/miner), config monitor_outbound + suspicious_remote_ports.
8. ✅ ~~Monitoring selhání sudo/su pokusů z journalu~~ — HOTOVO: journal cursor delta, WARNING při burstu ≥ sudo_fail_threshold (default 3) za cyklus.
9. ✅ ~~Detekce nových členů privilegovaných skupin~~ — HOTOVO: check_privileged_groups, baseline sudo/wheel/docker/adm/lxd/root, WARNING na nového člena, persistence.
10. ✅ ~~Kontrola kernel modulů proti baseline~~ — HOTOVO: baseline z /proc/modules, WARNING na nově načtený modul (LKM rootkit), persistence přes restart.
11. ✅ ~~Rozšířit reverse-shell vzory~~ — HOTOVO: perl/php/ruby/python one-linery, /dev/udp, exec N<>/dev/tcp, msfvenom/meterpreter (12 vzorů, otestováno proti false positives).
12. ✅ ~~Kontrola immutable flagu~~ — HOTOVO: check_immutable_flags, lsattr na tmp + persistence soubory, WARNING na chattr +i.
13. ✅ ~~Detekce raw socketů~~ — HOTOVO: check_raw_sockets, /proc/net/raw(6) mapované na PID, allowlist démonů, opt-in (monitor_raw_sockets).
14. ✅ ~~Whitelist pro suspicious-process check~~ — HOTOVO: config suspicious_ignore, přeskočí procesy dle substringu v cmdline.
15. ✅ ~~Integrace debsums/rpm -V~~ — HOTOVO: check_package_integrity, týdenní cadence, WARNING na změněné systémové soubory; opt-in (pkg_integrity).

## Bezpečnost — CVE / aktualizace

16. ✅ ~~Vypsat konkrétní CVE/balíky v hlášení o security updatech~~ — HOTOVO: prvních 10 balíků v CRITICAL hlášce (apt i dnf).
17. ✅ ~~Kontrola verze kernelu proti známým lokálním eskalacím~~ — HOTOVO: `check_kernel_cves` (Dirty COW, OverlayFS, Dirty Pipe, nf_tables UAF). Rozšiřovat tabulku KERNEL_LPE_CVES o nové CVE.
18. ✅ ~~Alert na pending reboot~~ — HOTOVO: /var/run/reboot-required + výpis balíků, které ho vyvolaly.
19. ✅ ~~Podpora needrestart~~ — HOTOVO: check_needrestart, WARNING na služby s neaktuálními knihovnami; opt-in (check_needrestart).
20. ✅ ~~unattended-upgrades status~~ — HOTOVO: check_unattended_upgrades, WARNING při chybách nebo stagnaci (>14 dní); opt-in.

## Spolehlivost agenta

21. ✅ ~~Persistovat `last_reported_states` a baselines~~ — HOTOVO: reported_states + file-integrity baselines ve state.json, restore při startu. Port baseline se záměrně resetuje restartem (dokumentovaný mechanismus přijetí nových portů).
22. ✅ ~~Retry fronta pro push_to_sentinel~~ — HOTOVO: buffer s dedupem, persistence přes restart, cap `max_pending_events` (500), replay při obnovení spojení.
23. ✅ ~~Git auto-update: py_compile před restartem~~ — HOTOVO: rozbité commity se rollbacknou a nahlásí CRITICAL místo suicide restartu.
24. ✅ ~~Timeout u všech subprocess.run volání~~ — HOTOVO: 10–120 s podle nástroje (smartctl 30 s, apt/dnf 120 s).
25. ✅ ~~Watchdog integrace se systemd~~ — HOTOVO: sd_notify READY/WATCHDOG/STOPPING, unit Type=notify + WatchdogSec=1200; no-op mimo systemd.
26. ✅ ~~Self-resource watch + restart~~ — HOTOVO: _check_self_resources, self-exit při RSS > max_self_rss_mb (0=vyp), systemd restartuje čistě.
27. ✅ ~~OOM přes journal kursor~~ — HOTOVO: `journalctl -k --cursor-file` (přesné, přežije rotaci bufferu i restart agenta), dmesg fallback pro non-systemd.
28. ✅ ~~Config reload na SIGHUP~~ — HOTOVO: SIGHUP handler reloaduje thresholdy (url/token vyžadují restart).
29. ✅ ~~Validace configu při startu~~ — HOTOVO: _validate_config, srozumitelná chyba + exit místo KeyError.
30. ✅ ~~--dry-run režim~~ — HOTOVO: proveď všechny checky, vypiš eventy JSON, nic nepushne, state netknutý.

## Síť / infrastruktura — nové checky

31. ✅ ~~Ping/latence check~~ — HOTOVO: check_network_reachability, ping cíle + auto gateway, WARNING na loss/latenci.
32. ✅ ~~Monitoring šířky pásma~~ — HOTOVO: check_bandwidth, rate z /sys statistics, WARNING nad bandwidth_warn_mbps (opt-in).
33. ✅ ~~HTTP(S) health check~~ — HOTOVO: check_http_health, status kód + latence definovaných URL (http_checks).
34. ✅ ~~Detekce změny primární IP~~ — HOTOVO: check_ip_change, WARNING při změně outbound IP (monitor_ip_change).
35. ✅ ~~UPS přes NUT~~ — HOTOVO: check_ups_nut, on-battery=WARNING, low-battery=CRITICAL (hardware.nut_ups).
36. ✅ ~~Dostupnost default gateway~~ — HOTOVO: součást check_network_reachability (auto-detekce gw z /proc/net/route + ping).
37. ✅ ~~mDNS/avahi konflikt~~ — HOTOVO: check_mdns_conflict, journal avahi-daemon, WARNING na hostname konflikt (opt-in).

## Hardware — nové checky

38. ✅ ~~Raspberry Pi vcgencmd get_throttled~~ — HOTOVO: `agent_rpi_power_monitor`, undervoltage NOW = CRITICAL, ostatní + historie od bootu = WARNING; auto-skip mimo RPi.
39. ✅ ~~SMART reallocated/pending sektory~~ — HOTOVO: parsuje Reallocated/Pending/Uncorrectable (SATA) + Media/Data Integrity Errors (NVMe), CRITICAL na nenulový počet.
40. 🟢 Monitoring otáček ventilátorů z hwmon (kde existují).
41. 🟢 SD karta na RPi: detekce read-only remountu filesystému (typická smrt SD karty).

## Server / protokol

42. ✅ ~~Agent → server: verze agenta (git SHA) v payloadu~~ — HOTOVO: `agent_version` v každém payloadu, server vidí uzly na staré verzi.
43. 🟡 HTTPS + ověření certifikátu pro komunikaci se serverem (teď plaintext HTTP token).
44. 🟡 Komprese payloadu / batching při velkém počtu eventů.
45. 🟢 Endpoint `/api/v1/agent/config` — centrální distribuce konfigurace z Ansible/serveru místo ruční editace na každém uzlu.

## Kód / údržba

46. ✅ ~~Rozdělit checky do plugin modulů (checks/*.py)~~ — HOTOVO: mixin moduly (services/security/storage/kernel/system), @register_check registry místo ručního seznamu v run_loop; compile guard rozšířen na compileall celého balíku. Pořadí i funkčnost identické (ověřeno pytest + živý cyklus).
47. ✅ ~~Unit testy pro parsovací logiku~~ — HOTOVO: pytest sada (53 testů) - revshell vzory, CVE rozsahy, SMART sektory, RPi bitmask, OOM regex, retry buffer; běží bez configu a root. Zbývá: who/meminfo (vyžaduje extrakci z check metod).
48. 🟢 Sjednotit stylizované hlášky („matrix", „structural") — volitelně plain-english režim pro čitelnost.
49. 🟢 requirements.txt + pin verzí pro venv (teď se instaluje latest requests/pyyaml).
50. ✅ ~~CI na Gitea (actions)~~ — HOTOVO: `.gitea/workflows/ci.yaml` spouští py_compile + pytest na push do main a PR. Vyžaduje registrovaný act_runner s labelem ubuntu-latest (Python 3 + Node.js).

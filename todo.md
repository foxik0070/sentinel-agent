# Sentinel Agent — TODO / Návrhy na vylepšení

50 návrhů seřazených podle kategorií. Priorita: 🔴 vysoká, 🟡 střední, 🟢 nízká.

## Bezpečnost — detekce (navazuje na nový check_suspicious_activity)

1. ✅ ~~Detekce nových SSH authorized_keys~~ — HOTOVO: baseline hash root + /home/* v `check_suspicious_activity` (persistence_files).
2. ✅ ~~Monitoring nových cronů~~ — HOTOVO: /etc/crontab, /etc/cron.d, /var/spool/cron v persistence_files baseline. Zbývá: systemd timery.
3. ✅ ~~Detekce procesů se smazaným binárním souborem~~ — HOTOVO: deleted exe mimo systémové cesty + fileless memfd exekutably.
4. ✅ ~~Kontrola `LD_PRELOAD` a `/etc/ld.so.preload`~~ — HOTOVO: CRITICAL při neprázdném /etc/ld.so.preload.
5. ✅ ~~Baseline SUID/SGID binárek v celém systému~~ — HOTOVO: celosystémový sken každých 10 cyklů, CRITICAL na nový SUID/SGID, persistence baseline přes restart.
6. ✅ ~~Detekce promiskuitního režimu síťových rozhraní~~ — HOTOVO: IFF_PROMISC z /sys/class/net/*/flags, WARNING při aktivním sniffingu.
7. 🟡 Kontrola podezřelých odchozích spojení — spojení na známé miner pooly / neobvyklé porty (4444, 1337, stratum+tcp).
8. ✅ ~~Monitoring selhání sudo/su pokusů z journalu~~ — HOTOVO: journal cursor delta, WARNING při burstu ≥ sudo_fail_threshold (default 3) za cyklus.
9. 🟡 Detekce nově přidaných uživatelů do skupin sudo/wheel/docker (docker skupina = root ekvivalent).
10. ✅ ~~Kontrola kernel modulů proti baseline~~ — HOTOVO: baseline z /proc/modules, WARNING na nově načtený modul (LKM rootkit), persistence přes restart.
11. ✅ ~~Rozšířit reverse-shell vzory~~ — HOTOVO: perl/php/ruby/python one-linery, /dev/udp, exec N<>/dev/tcp, msfvenom/meterpreter (12 vzorů, otestováno proti false positives).
12. 🟢 Kontrola immutable flagu na kritických souborech — útočník si někdy nastaví `chattr +i` na svůj backdoor.
13. 🟢 Detekce procesů s otevřeným raw socketem (možný backdoor/scanner) přes `/proc/net/raw`.
14. 🟢 Whitelist pro suspicious-process check (config `suspicious_ignore`) — např. legitimní skript v /tmp u CI runneru, omezení false positives.
15. 🟢 Volitelná integrace `debsums`/`rpm -V` pro ověření integrity systémových balíků (týdenní cadence).

## Bezpečnost — CVE / aktualizace

16. ✅ ~~Vypsat konkrétní CVE/balíky v hlášení o security updatech~~ — HOTOVO: prvních 10 balíků v CRITICAL hlášce (apt i dnf).
17. ✅ ~~Kontrola verze kernelu proti známým lokálním eskalacím~~ — HOTOVO: `check_kernel_cves` (Dirty COW, OverlayFS, Dirty Pipe, nf_tables UAF). Rozšiřovat tabulku KERNEL_LPE_CVES o nové CVE.
18. ✅ ~~Alert na pending reboot~~ — HOTOVO: /var/run/reboot-required + výpis balíků, které ho vyvolaly.
19. 🟢 Podpora `needrestart` — detekce služeb běžících se starými (opatchovanými) knihovnami.
20. 🟢 Volitelný `unattended-upgrades` status check — hlásit, když automatické security aktualizace selhávají.

## Spolehlivost agenta

21. ✅ ~~Persistovat `last_reported_states` a baselines~~ — HOTOVO: reported_states + file-integrity baselines ve state.json, restore při startu. Port baseline se záměrně resetuje restartem (dokumentovaný mechanismus přijetí nových portů).
22. ✅ ~~Retry fronta pro push_to_sentinel~~ — HOTOVO: buffer s dedupem, persistence přes restart, cap `max_pending_events` (500), replay při obnovení spojení.
23. ✅ ~~Git auto-update: py_compile před restartem~~ — HOTOVO: rozbité commity se rollbacknou a nahlásí CRITICAL místo suicide restartu.
24. ✅ ~~Timeout u všech subprocess.run volání~~ — HOTOVO: 10–120 s podle nástroje (smartctl 30 s, apt/dnf 120 s).
25. 🟡 Watchdog integrace se systemd (`WatchdogSec` + `sd_notify`) — detekce zamrzlého agenta.
26. 🟡 Hlídat vlastní paměť/CPU agenta a self-restart při překročení limitu.
27. ✅ ~~OOM přes journal kursor~~ — HOTOVO: `journalctl -k --cursor-file` (přesné, přežije rotaci bufferu i restart agenta), dmesg fallback pro non-systemd.
28. 🟢 Config reload na SIGHUP bez restartu služby.
29. 🟢 Validace config schématu při startu (chybějící klíč → srozumitelná chyba místo KeyError).
30. 🟢 `--dry-run` režim: proveď všechny checky, vypiš eventy na stdout, nic neposílej.

## Síť / infrastruktura — nové checky

31. 🟡 Ping/latence check na definované cíle (gateway, internet) — detekce degradace sítě.
32. 🟡 Monitoring šířky pásma rozhraní — alert na saturaci nebo anomální odchozí tok (exfiltrace/miner).
33. 🟡 HTTP(S) health check definovaných URL (interní služby) — status kód + latence.
34. 🟡 Kontrola DHCP vs statické IP — alert když se změní IP adresa uzlu.
35. 🟢 Monitoring UPS přes NUT (`upsc`) — stav baterie, on-battery events.
36. 🟢 Kontrola dostupnosti default gateway (arping) — detekce L2 problémů.
37. 🟢 mDNS/avahi konflikt detekce (duplicitní hostname na síti).

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

46. 🟡 Rozdělit checky do plugin modulů (checks/*.py) — sentinel_agent.py má 1300+ řádků a poroste; registry pattern místo ručního seznamu v run_loop.
47. 🟡 Unit testy pro parsovací logiku (who, smartctl, meminfo, revshell regexy) — pytest, fixture s reálnými výstupy.
48. 🟢 Sjednotit stylizované hlášky („matrix", „structural") — volitelně plain-english režim pro čitelnost.
49. 🟢 requirements.txt + pin verzí pro venv (teď se instaluje latest requests/pyyaml).
50. 🟢 CI na Gitea (actions): py_compile + testy na push — ochrana před rozbitím git auto-update mechanismu (souvisí s #23).

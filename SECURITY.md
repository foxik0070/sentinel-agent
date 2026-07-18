# Sentinel Agent — Ochrana před CVE a detekce podezřelého chování

Tento dokument popisuje bezpečnostní vrstvu agenta: jak detekuje **zneužití
zranitelností (CVE)** a **podezřelé chování** na monitorovaných uzlech, co
každá detekce hlásí, jaké útoky pokrývá a jak omezuje falešné poplachy.

Filozofie je záměrně **detekce, ne prevence**. Agent nezasahuje do systému —
pouze pozoruje a hlásí. Cílem je zachytit *stopy* po úspěšném (nebo probíhajícím)
zneužití zranitelnosti co nejdřív, i když samotný exploit proběhl mimo dohled.

---

## 1. Model hrozby

Typický řetězec útoku na domácí/malou infrastrukturu:

```text
  [1] Vstup            [2] Eskalace práv         [3] Persistence          [4] Zneužití
  ------------------   -----------------------   ----------------------   ------------------
  brute-force SSH      lokální CVE exploit       nový SSH klíč            cryptominer
  zranitelná služba    (Dirty Pipe, nf_tables)   cron job / systemd       reverse shell
  odcizené heslo       SUID binárka              nový UID 0 účet          packet sniffing
                       sudo misconfiguration     LKM rootkit / LD_PRELOAD exfiltrace dat
```

Agent má detekci v **každé** z těchto fází. Útočník, který proklouzne jednou
vrstvou, typicky zakopne o jinou — např. exploit Dirty Pipe (fáze 2) přepíše
`/etc/passwd`, což zachytí kontrola integrity kritických souborů, i kdyby
samotný běh exploitu agent neviděl.

---

## 2. Ochrana před CVE

### 2.1 Kontrola verze kernelu proti známým LPE exploitům
**Modul:** `agent_security_kernel_cve` · **Přepínač:** `security.scan_cves`

Agent porovná verzi běžícího kernelu (`uname -r`) se statickou tabulkou známých,
aktivně zneužívaných **local privilege escalation** zranitelností. Když verze
spadá do zranitelného rozsahu, vyhlásí `WARNING`.

| CVE | Přezdívka | Zranitelné rozsahy (major.minor.patch) |
|-----|-----------|----------------------------------------|
| CVE-2016-5195 | Dirty COW | 2.6.22 – 4.4.25, 4.5 – 4.7.8, 4.8 – 4.8.2 |
| CVE-2021-3493 | OverlayFS cap abuse (Ubuntu) | 3.13 – 5.10.x |
| CVE-2022-0847 | Dirty Pipe | 5.8 – 5.10.101, 5.11 – 5.15.24, 5.16 – 5.16.10 |
| CVE-2024-1086 | nf_tables UAF | 3.15 – 6.1.75, 6.2 – 6.6.14, 6.7 – 6.7.2 |

**Proč jen WARNING a ne CRITICAL:** distribuce (Debian, Ubuntu, RHEL) opravují
tyto CVE *backportem* do svého kernelu, aniž by zvýšily upstream verzi. Uzel
s kernelem `5.15.20` tedy může být *opravený*, přestože verze spadá do rozsahu
Dirty Pipe. Hláška proto obsahuje výzvu **„ověř, zda distribuce backportovala
opravu"** — je to upozornění na riziko, ne potvrzená zranitelnost.

**Rozšíření tabulky:** nové CVE se přidávají do `KERNEL_LPE_CVES` v
`sentinel_agent.py`. Formát: `(id, přezdívka, [(první_zranitelná, první_opravená), ...])`.

### 2.2 Detekce cekajících bezpečnostních záplat
**Modul:** `agent_security_vulnerability_scan` · **Přepínač:** `security.scan_cves`, `security.check_system_updates`

Dotazuje se balíčkovacího systému (`apt-get -s upgrade` / `dnf check-update
--security`) na čekající aktualizace:

- **CRITICAL** — nalezeny bezpečnostní/CVE záplaty. Hláška **vypíše konkrétní
  balíky** (prvních 10), aby bylo možné rozhodnout, zda patchovat okamžitě.
- **WARNING** — více než 20 čekajících běžných aktualizací (systém zaostává).

### 2.3 Pending reboot
**Modul:** `agent_security_reboot_required` · **Přepínač:** `security.check_system_updates`

Nainstalovaná záplata kernelu nebo klíčové knihovny (glibc, openssl) **nechrání,
dokud se systém nerestartuje** — starý zranitelný kód stále běží v paměti. Když
existuje `/var/run/reboot-required`, agent vyhlásí `WARNING` a vypíše balíky,
které restart vyžádaly. Zavírá tak mezeru „opraveno, ale ještě zranitelné".

---

## 3. Detekce podezřelého chování

Všech deset dílčích detekcí níže spadá pod jeden modul
`agent_security_suspicious_activity` a jeden přepínač **`security.monitor_suspicious`**.
Každá dílčí detekce hlásí pod vlastním `target`, takže v Sentinelu jsou vidět
odděleně.

Detekce dělíme na dva typy:
- **Event-style** (jako OOM killer) — porovnává proti *baseline*; při změně
  vyhlásí CRITICAL a baseline posune. Baseline se **persistuje do state souboru**,
  takže restart agenta neotevře okno, ve kterém by útočníkova změna byla tiše
  přijata jako nový normál.
- **Persistentní stav** — hlásí aktuální stav (např. „účet UID 0 existuje"),
  dokud problém trvá.

### 3.1 Integrita kritických autentizačních souborů `[critical_files]`
**Typ:** event-style · **Závažnost:** CRITICAL

SHA-256 baseline souborů `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`. Jakákoli
změna = CRITICAL.

**Co pokrývá:** exploity třídy **Dirty COW (CVE-2016-5195)** a **Dirty Pipe
(CVE-2022-0847)** typicky získávají root přepsáním `/etc/passwd` (přidání účtu
bez hesla) nebo `/etc/sudoers`. I když agent samotný běh exploitu nezachytí,
uvidí jeho *výsledek* — změněný soubor.

### 3.2 Persistence: SSH klíče a cron `[persistence_files]`
**Typ:** event-style · **Závažnost:** CRITICAL

SHA-256 baseline SSH `authorized_keys` (root + všichni uživatelé v `/home`) a
cron záznamů (`/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/*`). Přidání,
změna nebo odebrání = CRITICAL.

**Co pokrývá:** nejběžnější persistence po úspěšném exploitu — útočník si přidá
vlastní SSH klíč (trvalý přístup) nebo cron job (opětovné spuštění payloadu po
rebootu).

### 3.3 LD_PRELOAD rootkit `[ld_preload]`
**Typ:** persistentní stav · **Závažnost:** CRITICAL

Neprázdný `/etc/ld.so.preload` = CRITICAL. Systémový LD_PRELOAD hook je klasická
signatura **userland rootkitu** — knihovna vložená před všechny ostatní dokáže
skrývat procesy, soubory a síťová spojení před běžnými nástroji (`ps`, `ls`, `ss`).

### 3.4 Neoprávněné účty s UID 0 `[uid0_accounts]`
**Typ:** persistentní stav · **Závažnost:** CRITICAL

Parsuje `/etc/passwd`; jakýkoli účet s UID 0 kromě `root` = CRITICAL. Přidání
druhého UID 0 účtu je běžný **backdoor** — útočník získá root práva pod méně
nápadným jménem.

### 3.5 Podezřelé procesy `[processes]`
**Typ:** persistentní stav · **Závažnost:** CRITICAL

Prochází `/proc` a hlásí procesy podle několika kritérií:

- **spuštěné z dočasných adresářů** (`/tmp`, `/var/tmp`, `/dev/shm`) — malware
  se typicky rozbaluje a spouští odtud;
- **fileless (memfd)** — proces běžící z paměti bez souboru na disku (pokročilá
  evazní technika);
- **smazaná binárka** mimo systémové cesty (`/proc/PID/exe → (deleted)`) —
  self-deleting payload, který se po startu smaže, aby zmizel z disku;
  balíčkové upgrady (`/usr`, `/opt`, `/lib`, …) jsou vyloučené, aby se
  negenerovaly falešné poplachy;
- **známé cryptominery** podle názvu procesu: `xmrig`, `xmr-stak`, `minerd`,
  `cpuminer`, `kinsing`, `kdevtmpfsi`;
- **reverse-shell vzory** v příkazové řádce — 12 vzorů: `/dev/tcp/` a `/dev/udp/`,
  `nc -e`, `socat exec`, `pty.spawn`, perl/php/ruby/python one-linery,
  `exec N<>/dev/tcp`, `msfvenom`/`meterpreter`. Vzory cílí na kombinaci
  jazyk + socket/exec, ne jen na název interpretu, takže běžné skripty
  (`python manage.py`, `perl build.pl`) poplach nespouští.

### 3.6 SUID binárky v dočasných adresářích `[suid_binaries]`
**Typ:** persistentní stav · **Závažnost:** CRITICAL

`find` přes `/tmp`, `/var/tmp`, `/dev/shm` hledá SUID-root soubory. SUID binárka
v dočasném adresáři je téměř vždy **exploit staging** — mezikrok při eskalaci práv.

### 3.7 Celosystémový SUID/SGID baseline `[suid_baseline]`
**Typ:** event-style · **Závažnost:** CRITICAL · **Kadence:** každých 10 cyklů

Kompletní inventář SUID/SGID souborů na celém filesystému (`find / -xdev`).
Nově přibyvší binárka = CRITICAL. Odebrání se absorbuje tiše (legitimní
odinstalace). Baseline persistuje přes restart.

**Co pokrývá:** LPE exploity a backdoorované balíky si plantují SUID shell
(např. `/usr/bin/…` s SUID bitem) pro trvalou eskalaci. Plný sken je drahý
(~11 s), proto běží jen každý 10. cyklus, ne každou minutu.

### 3.8 Burst selhání sudo/su `[auth_failures]`
**Typ:** event-style · **Závažnost:** WARNING · **Práh:** `security.sudo_fail_threshold` (default 3)

Čte `sudo`/`su` záznamy z journalu inkrementálně (persistentní kurzor — každý
řádek se zpracuje právě jednou). Když počet selhání autentizace za cyklus dosáhne
prahu, vyhlásí WARNING s ukázkami. Zachytává `authentication failure`,
`NOT in sudoers`, `FAILED SU`, `incorrect password attempt`.

**Co pokrývá:** pokus o **eskalaci práv** hádáním hesla nebo zkoušením sudo
u účtu bez oprávnění.

### 3.9 Promiskuitní režim rozhraní `[promisc_interfaces]`
**Typ:** persistentní stav · **Závažnost:** WARNING

Čte flag `IFF_PROMISC` (bit `0x100`) z `/sys/class/net/*/flags`. Rozhraní
v promisc režimu = WARNING — typicky znamená běžící **packet sniffer**
(odposlech síťového provozu, sběr hesel).

### 3.10 Baseline kernel modulů `[kernel_modules]`
**Typ:** event-style · **Závažnost:** WARNING

Baseline načtených modulů z `/proc/modules`; nově načtený modul = WARNING.
Odebrání se absorbuje tiše. Baseline persistuje přes restart.

**Co pokrývá:** **LKM rootkity** (loadable kernel module) se instalují jako
kernel modul — nejmocnější třída rootkitů, která operuje přímo v jádře.

---

## 4. Konfigurace

Relevantní část `/etc/sentinel/agent_config.yaml`:

```yaml
checks:
  security:
    monitor_suspicious: true    # zapíná celý modul podezřelého chování (3.1–3.10)
    sudo_fail_threshold: 3      # práh selhání sudo/su za cyklus (3.8)
    scan_cves: true             # kernel LPE tabulka (2.1) + CVE balíky (2.2)
    check_system_updates: true  # čekající aktualizace (2.2) + reboot-required (2.3)
    monitor_root_logins: true   # SSH root přihlášení
    root_login_ignore_ips: []   # whitelist IP, ze kterých se root ignoruje
```

> **Pozor při nasazení:** nové bezpečnostní detekce jsou za přepínačem
> `monitor_suspicious`. Agent se sám aktualizuje přes git (kód se šíří), ale
> **konfigurace se nešíří** — na každém hostu je třeba doplnit
> `monitor_suspicious: true` do sekce `checks.security` a restartovat službu,
> nebo znovu projít `sentinel_agent_init.py`.

---

## 5. Omezení falešných poplachů

Bezpečnostní detekce jsou navržené tak, aby nespamovaly:

- **Delta filtr** — každá hláška se odešle jen při *změně*. Trvalý stav
  (např. účet UID 0) se nahlásí jednou, ne každou minutu.
- **Event-style baseline** — legitimní admin změna (přidání SSH klíče, instalace
  balíku) vyvolá *jednu* CRITICAL hlášku a nový stav se stane baseline. Hlášky
  proto obsahují výzvu „ověř, zda šlo o legitimní změnu".
- **Persistence baseline přes restart** — restart agenta neresetuje baseline
  kritických souborů, SUID ani modulů; útočník nemůže „vyprat" změnu tím, že
  počká na restart služby.
- **Vyloučení systémových cest** — smazané binárky pod `/usr`, `/opt`, `/lib`
  (běžné po upgradu balíků) se nehlásí; reverse-shell vzory cílí na
  jazyk + socket, ne na název interpretu.
- **Práh pro burst** — selhání sudo/su se hlásí až od nastaveného počtu za cyklus,
  jednotlivé překlepy v hesle poplach nespustí.

---

## 6. Co agent (zatím) nedělá

Pro transparentnost — hranice současné ochrany:

- **Neprovádí prevenci** — pouze detekuje a hlásí; nezablokuje proces ani spojení.
- **Nedetekuje odchozí spojení** na miner pooly / C2 servery (návrh #7, #32 v `todo.md`).
- **Neověřuje integritu systémových balíků** proti `debsums`/`rpm -V` (návrh #15).
- **Nekontroluje immutable flagy** (`chattr +i`) na backdoorech (návrh #12).
- **Spoléhá na neporušený systém** — pokročilý kernel rootkit může skrýt moduly
  i před `/proc/modules`. Proto je vhodné kombinovat s centrálním logováním mimo
  monitorovaný uzel.

Kompletní seznam plánovaných vylepšení je v [`todo.md`](todo.md).

"""AI agent session monitoring: interactive CLI agents, local LLM runtimes,
MCP servers and outbound connections to AI provider APIs."""
import os, pwd, re, socket, subprocess, time

from checks import register_check


class AIChecks:
    # Interaktivni agenti. Klic je jmeno, pod kterym jde proces poznat -- u
    # vetsiny z nich je comm "node" nebo "python3", takze se matchuje i basename
    # argv[0..3] bez pripony (claude.js -> claude).
    AI_CLI_AGENTS = {
        "claude": "Claude Code",
        "codex": "Codex CLI",
        "cursor-agent": "Cursor Agent",
        "aider": "Aider",
        "gemini": "Gemini CLI",
        "goose": "Goose",
        "opencode": "OpenCode",
        "crush": "Crush",
        "amp": "Amp",
        "copilot": "GitHub Copilot CLI",
    }
    AI_RUNTIMES = {
        "ollama": "Ollama",
        "llama-server": "llama.cpp",
        "llamafile": "llamafile",
        "vllm": "vLLM",
        "localai": "LocalAI",
        "lms": "LM Studio",
        "text-generation-server": "TGI",
        "sglang": "SGLang",
    }
    # MCP server nema ustalene jmeno binarky -- bezi pres npx/uvx, pozna se
    # jen z cele prikazove radky.
    MCP_MARKERS = ("modelcontextprotocol", "mcp-server", "mcp_server", "fastmcp")

    AI_API_HOSTS = (
        "api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com",
        "api.mistral.ai", "api.groq.com", "api.deepseek.com", "openrouter.ai",
        "api.cohere.ai", "api.x.ai",
    )

    # Z /proc/<pid>/environ se cte jen timto whitelistem -- cely environ obsahuje
    # API klice a nesmi opustit stroj.
    MODEL_ENV_KEYS = (
        "ANTHROPIC_MODEL", "ANTHROPIC_SMALL_FAST_MODEL", "CLAUDE_MODEL",
        "OPENAI_MODEL", "OPENAI_BASE_URL", "OLLAMA_HOST", "OLLAMA_MODEL",
        "GEMINI_MODEL", "AIDER_MODEL", "LITELLM_MODEL",
    )

    # Prikazova radka se posila cela (obsahuje prompt), ale hodnota za
    # --api-key/--token a klice tvaru sk-... se zahazuji.
    _SECRET_ARG = re.compile(r'(?i)(--?(?:api[-_]?key|token|password|secret)[=\s])(\S+)')
    _SECRET_VALUE = re.compile(r'\b(?:sk|ghp|gho|xoxb)-[A-Za-z0-9_\-]{8,}')

    CMDLINE_MAX = 300
    MESSAGE_MAX = 4000

    def _boot_time(self):
        if getattr(self, '_btime', None) is None:
            self._btime = 0
            try:
                with open("/proc/stat") as fh:
                    for line in fh:
                        if line.startswith("btime "):
                            self._btime = int(line.split()[1])
                            break
            except Exception:
                pass
        return self._btime

    def _redact(self, text):
        text = self._SECRET_ARG.sub(r'\1<redacted>', text)
        return self._SECRET_VALUE.sub('<redacted>', text)

    def _proc_names(self, comm, tokens):
        """Jmena, pod kterymi muze byt proces znamy: comm + basename prvnich
        argumentu bez pripony (node /usr/lib/claude/cli.js -> cli, claude)."""
        names = {comm}
        for tok in tokens[:4]:
            if not tok or tok.startswith("-"):
                continue
            base = os.path.basename(tok)
            names.add(base)
            names.add(re.sub(r'\.(js|mjs|cjs|py|sh)$', '', base))
        return names

    def _classify(self, comm, tokens):
        """(kategorie, zobrazovany nazev) nebo None."""
        joined = " ".join(tokens).lower()
        if any(m in joined for m in self.MCP_MARKERS):
            return "mcp", "MCP server"
        names = self._proc_names(comm, tokens)
        for name in names:
            if name in self.AI_CLI_AGENTS:
                return "cli", self.AI_CLI_AGENTS[name]
        for name in names:
            if name in self.AI_RUNTIMES:
                return "runtime", self.AI_RUNTIMES[name]
        return None

    def _proc_model(self, pid):
        """Model/endpoint z /proc/<pid>/environ, jen pres MODEL_ENV_KEYS."""
        try:
            with open(f"/proc/{pid}/environ", "rb") as fh:
                raw = fh.read(65536).decode("utf-8", "replace")
        except Exception:
            return None
        for item in raw.split("\0"):
            key, _, val = item.partition("=")
            if key in self.MODEL_ENV_KEYS and val:
                return f"{key}={val}"
        return None

    def _proc_runtime(self, pid):
        """Doba behu procesu v sekundach, nebo None."""
        try:
            with open(f"/proc/{pid}/stat") as fh:
                stat = fh.read()
            # comm muze obsahovat mezery i zavorky -- pole se cte az za posledni ')'
            fields = stat[stat.rindex(")") + 2:].split()
            start_ticks = int(fields[19])
            hz = os.sysconf("SC_CLK_TCK") or 100
            started = self._boot_time() + start_ticks / hz
            return max(0, int(time.time() - started)) if self._boot_time() else None
        except Exception:
            return None

    @staticmethod
    def _human_age(seconds):
        if seconds is None:
            return "?"
        if seconds < 3600:
            return f"{seconds // 60}m"
        if seconds < 86400:
            return f"{seconds // 3600}h"
        return f"{seconds // 86400}d"

    def _scan_proc(self):
        """Vsechny bezici AI procesy na stroji."""
        sessions = []
        try:
            pids = [p for p in os.listdir("/proc") if p.isdigit()]
        except Exception as e:
            print(f"[-] AI session scan failure: {e}", flush=True)
            return sessions

        for pid in pids:
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as fh:
                    tokens = [t for t in fh.read().decode("utf-8", "replace").split("\0") if t]
                if not tokens:
                    continue
                with open(f"/proc/{pid}/comm") as fh:
                    comm = fh.read().strip()
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            except Exception:
                continue

            hit = self._classify(comm, tokens)
            if not hit:
                continue
            category, tool = hit

            try:
                uid = os.stat(f"/proc/{pid}").st_uid
                user = pwd.getpwuid(uid).pw_name
            except Exception:
                user = "?"
            try:
                cwd = os.readlink(f"/proc/{pid}/cwd")
            except Exception:
                cwd = "?"

            sessions.append({
                "pid": int(pid),
                "user": user,
                "category": category,
                "tool": tool,
                "model": self._proc_model(pid),
                "cwd": cwd,
                "age": self._proc_runtime(pid),
                "cmdline": self._redact(" ".join(tokens))[:self.CMDLINE_MAX],
            })
        return sessions

    def _ai_api_ips(self):
        """IP adresy znamych AI API, prelozene jednou za hodinu."""
        now = time.time()
        if now - getattr(self, '_ai_ip_ts', 0) < 3600 and getattr(self, '_ai_ips', None):
            return self._ai_ips
        ips = {}
        for host in self.AI_API_HOSTS:
            try:
                for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP):
                    ips[info[4][0]] = host
            except Exception:
                continue
        self._ai_ips, self._ai_ip_ts = ips, now
        return ips

    def _api_clients(self, known_pids):
        """Procesy se spojenim na AI API, ktere scan /proc nepoznal podle jmena."""
        ips = self._ai_api_ips()
        if not ips:
            return []
        try:
            proc = subprocess.run(["ss", "-tnp", "state", "established"],
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  text=True, timeout=10)
        except Exception as e:
            print(f"[-] AI API connection scan failure: {e}", flush=True)
            return []

        found = {}
        for line in proc.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            peer_ip = parts[4].rsplit(":", 1)[0].strip("[]")
            host = ips.get(peer_ip)
            if not host:
                continue
            pinfo = re.search(r'\("([^"]+)",pid=(\d+)', line)
            if not pinfo:
                continue
            pid = int(pinfo.group(2))
            if pid in known_pids:
                continue
            found[(pid, host)] = pinfo.group(1)

        out = []
        for (pid, host), name in sorted(found.items()):
            try:
                user = pwd.getpwuid(os.stat(f"/proc/{pid}").st_uid).pw_name
            except Exception:
                user = "?"
            out.append({"pid": pid, "user": user, "process": name, "host": host})
        return out

    ICONS = {"cli": "🤖", "runtime": "🧠", "mcp": "🔌"}

    def _describe(self, s):
        bits = [f"{s['user']}/{s['tool']}", f"PID {s['pid']}"]
        if s.get("model"):
            bits.append(s["model"])
        bits.append(self._human_age(s["age"]))
        if s["cwd"] not in ("?", "/"):
            bits.append(s["cwd"])
        return f"{self.ICONS.get(s['category'], '🤖')} " + ", ".join(bits) + f" :: {s['cmdline']}"

    @register_check(56)
    def check_ai_sessions(self):
        """Inventarizuje bezici AI agenty, lokalni LLM runtimy a MCP servery.

        Inventar jde jako OK -- Sentinel vse, co neni ok/resolved, zaklada jako
        aktivni issue, takze informativni stav by tam visel navzdy. WARNING je
        vyhrazeny pro agenta pod rootem nebo pod uzivatelem mimo allowed_users.
        """
        events = []
        cfg = self.config.get('checks', {}).get('ai', {})
        if not cfg.get('monitor_sessions', False):
            return events

        sessions = self._scan_proc()
        if cfg.get('check_api_connections', True):
            extra = self._api_clients({s["pid"] for s in sessions})
        else:
            extra = []

        allowed = set(cfg.get('allowed_users', []))
        ignore_tools = set(cfg.get('ignore_tools', []))
        if ignore_tools:
            sessions = [s for s in sessions if s["tool"] not in ignore_tools]

        # Runtime jako ollama bezi pod systemovym uctem trvale -- to neni
        # "nekdo pusti AI pod rootem", proto se na nej pravidlo nevztahuje.
        offenders = [s for s in sessions
                     if s["category"] != "runtime"
                     and (s["user"] == "root" or (allowed and s["user"] not in allowed))]

        parts = [self._describe(s) for s in sorted(sessions, key=lambda s: (s["user"], s["tool"]))]
        parts += [f"🌐 {c['user']}/{c['process']}, PID {c['pid']} -> {c['host']} (neznamy nastroj)"
                  for c in extra]

        if offenders:
            status = "WARNING"
            who = ", ".join(sorted({f"{s['user']}/{s['tool']}" for s in offenders}))
            msg = f"⚠ AI agent under unapproved account: {who} | " + " | ".join(parts)
        elif parts:
            status = "OK"
            msg = f"{len(parts)} AI session(s): " + " | ".join(parts)
        else:
            status = "OK"
            msg = "No AI agent sessions."

        if len(msg) > self.MESSAGE_MAX:
            msg = msg[:self.MESSAGE_MAX] + " … (truncated)"

        self.pending_metrics["ai_sessions"] = len(sessions) + len(extra)

        if self.should_report("ai:sessions", msg):
            events.append({
                "plugin": "agent_ai_session_monitor",
                "target": "sessions",
                "status": status,
                "message": msg,
            })
        return events

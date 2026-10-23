"""Detektor bezicich AI sezeni: kdo, jaky nastroj, jaky model, co dela."""
import pytest

from checks.ai import AIChecks


@pytest.fixture
def ai(agent):
    agent.config = {"checks": {"ai": {"monitor_sessions": True, "check_api_connections": False}}}
    agent.pending_metrics = {}
    return agent


def _session(**kw):
    base = {"pid": 101, "user": "foxik", "category": "cli", "tool": "Claude Code",
            "model": None, "cwd": "/root/git/Sentinel", "age": 900, "cmdline": "claude"}
    base.update(kw)
    return base


def _wire(agent, monkeypatch, sessions, api=()):
    monkeypatch.setattr(agent, "_scan_proc", lambda: list(sessions))
    monkeypatch.setattr(agent, "_api_clients", lambda known: list(api))


# --- klasifikace ------------------------------------------------------------

@pytest.mark.parametrize("comm,tokens,expected", [
    # Claude Code bezi pod nodem -- comm samo o sobe nic nerekne.
    ("node", ["node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"], None),
    ("claude", ["claude", "-p", "oprav test"], ("cli", "Claude Code")),
    ("node", ["node", "/home/u/.local/bin/claude", "--resume"], ("cli", "Claude Code")),
    ("python3", ["python3", "/usr/bin/aider", "--model", "gpt-4o"], ("cli", "Aider")),
    ("ollama", ["ollama", "serve"], ("runtime", "Ollama")),
    ("node", ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/srv"], ("mcp", "MCP server")),
    ("bash", ["bash", "-lc", "ls"], None),
])
def test_classify(ai, comm, tokens, expected):
    assert ai._classify(comm, tokens) == expected


def test_mcp_wins_over_cli(ai):
    # npx spousteny agentem je MCP server, ne druha instance agenta.
    assert ai._classify("node", ["npx", "mcp-server-claude", "--stdio"])[0] == "mcp"


# --- redakce tajemstvi v cmdline -------------------------------------------

def test_cmdline_keeps_prompt_but_drops_secrets(ai):
    red = ai._redact('claude -p "shrn logy" --api-key sk-ant-abc123def456 --model opus')
    assert "shrn logy" in red          # prompt je zadouci obsah
    assert "sk-ant-abc123def456" not in red
    assert "<redacted>" in red


def test_bare_token_is_redacted(ai):
    assert "ghp_" not in ai._redact("gh auth login --with-token ghp_AbCdEf123456")


# --- hlaseni ----------------------------------------------------------------

def test_inventory_is_ok_not_an_issue(ai, monkeypatch):
    _wire(ai, monkeypatch, [_session(model="ANTHROPIC_MODEL=claude-opus-5")])
    events = ai.check_ai_sessions()
    assert len(events) == 1
    e = events[0]
    # OK proto, ze Sentinel vse mimo ok/resolved zaklada jako aktivni issue.
    assert e["status"] == "OK"
    assert e["plugin"] == "agent_ai_session_monitor"
    for expect in ("foxik/Claude Code", "PID 101", "claude-opus-5", "15m", "/root/git/Sentinel"):
        assert expect in e["message"]


def test_root_session_is_warning(ai, monkeypatch):
    _wire(ai, monkeypatch, [_session(user="root")])
    e = ai.check_ai_sessions()[0]
    assert e["status"] == "WARNING"
    assert "root/Claude Code" in e["message"]


def test_user_outside_allowlist_is_warning(ai, monkeypatch):
    ai.config["checks"]["ai"]["allowed_users"] = ["foxik"]
    _wire(ai, monkeypatch, [_session(user="mallory")])
    assert ai.check_ai_sessions()[0]["status"] == "WARNING"


def test_allowlisted_user_is_ok(ai, monkeypatch):
    ai.config["checks"]["ai"]["allowed_users"] = ["foxik"]
    _wire(ai, monkeypatch, [_session(user="foxik")])
    assert ai.check_ai_sessions()[0]["status"] == "OK"


def test_system_runtime_under_root_is_not_an_offender(ai, monkeypatch):
    # ollama serve bezi trvale pod systemovym uctem -- to neni "nekdo pustil AI pod rootem".
    _wire(ai, monkeypatch, [_session(user="root", category="runtime", tool="Ollama")])
    assert ai.check_ai_sessions()[0]["status"] == "OK"


def test_no_sessions_reports_ok(ai, monkeypatch):
    _wire(ai, monkeypatch, [])
    e = ai.check_ai_sessions()[0]
    assert e["status"] == "OK" and e["message"] == "No AI agent sessions."


def test_unknown_tool_on_ai_api_is_listed(ai, monkeypatch):
    ai.config["checks"]["ai"]["check_api_connections"] = True
    _wire(ai, monkeypatch, [], api=[{"pid": 777, "user": "www-data",
                                     "process": "python3", "host": "api.openai.com"}])
    msg = ai.check_ai_sessions()[0]["message"]
    assert "www-data/python3" in msg and "api.openai.com" in msg
    assert msg.startswith("1 AI session(s)")
    assert ai.pending_metrics["ai_sessions"] == 1


def test_disabled_gate_reports_nothing(ai, monkeypatch):
    ai.config["checks"]["ai"]["monitor_sessions"] = False
    _wire(ai, monkeypatch, [_session()])
    assert ai.check_ai_sessions() == []


def test_delta_filter_suppresses_unchanged_repeat(ai, monkeypatch):
    _wire(ai, monkeypatch, [_session()])
    assert len(ai.check_ai_sessions()) == 1
    assert ai.check_ai_sessions() == []


def test_session_count_goes_out_as_metric(ai, monkeypatch):
    _wire(ai, monkeypatch, [_session(), _session(pid=102, user="jana")])
    ai.check_ai_sessions()
    assert ai.pending_metrics["ai_sessions"] == 2


def test_ignored_tool_is_left_out(ai, monkeypatch):
    ai.config["checks"]["ai"]["ignore_tools"] = ["Ollama"]
    _wire(ai, monkeypatch, [_session(), _session(pid=9, tool="Ollama", category="runtime")])
    assert "Ollama" not in ai.check_ai_sessions()[0]["message"]


def test_long_message_is_truncated(ai, monkeypatch):
    _wire(ai, monkeypatch, [_session(pid=i, cmdline="x" * 300) for i in range(200, 260)])
    msg = ai.check_ai_sessions()[0]["message"]
    assert len(msg) <= AIChecks.MESSAGE_MAX + 20
    assert msg.endswith("(truncated)")


# --- ctení environ: whitelist musí zadržet API klíče -----------------------

def test_environ_yields_model_but_never_the_api_key(ai):
    import os, signal, subprocess, time
    env = dict(os.environ,
               ANTHROPIC_MODEL="claude-opus-5",
               ANTHROPIC_API_KEY="sk-ant-supersecret-should-never-leave",
               OPENAI_API_KEY="sk-proj-also-secret")
    proc = subprocess.Popen(["sleep", "30"], env=env)
    try:
        # /proc/<pid>/environ vznikne uz pri fork(), ale az do exec() nese env
        # rodice -- cekame na skutecnou vymenu, ne na existenci souboru.
        model = None
        for _ in range(200):
            model = ai._proc_model(proc.pid)
            if model:
                break
            time.sleep(0.01)
        assert model == "ANTHROPIC_MODEL=claude-opus-5"
        # Z environ smi projit jen jmeno z whitelistu, nikdy klic.
        assert model.split("=")[0] in AIChecks.MODEL_ENV_KEYS
        assert "supersecret" not in model and "sk-" not in model
    finally:
        proc.send_signal(signal.SIGKILL)
        proc.wait()


def test_runtime_of_live_process_is_measured(ai):
    import os
    age = ai._proc_runtime(os.getpid())
    assert age is None or age >= 0


def test_scan_of_real_proc_does_not_raise(ai):
    # /proc je plny procesu, ke kterym nemusime mit prava a ktere mizi pod rukama.
    for s in ai._scan_proc():
        assert {"pid", "user", "tool", "category", "cmdline"} <= set(s)

"""Hlaseni, ktera se opakovala donekonecna a prebijela skutecne nalezy.

Z provozu: kernel taint 18 439x, systemd failed units 94 029x a nove porty
3 331x na jednom uzlu. Vsechny tri mely jinou pricinu.
"""
import builtins
import io
import subprocess

import pytest

import checks.kernel as kernel_mod
import checks.security as security_mod
import checks.system as system_mod


# ── Kernel taint ────────────────────────────────────────────────────────────
# 77824 = bit12 (modul mimo strom) + bit13 (nepodepsany) + bit16 (pomocny).
# Na HPC uzlu to zpusobuji ovladace InfiniBandu a KNEM — trvaly stav.

def _taint_agent(agent, monkeypatch, value, cfg=None):
    agent.config = {"checks": {"kernel": {"monitor_taint": True, **(cfg or {})}}}
    monkeypatch.setattr(kernel_mod.os.path, "exists", lambda p: p == "/proc/sys/kernel/tainted")
    real = builtins.open

    def fake(path, *a, **k):
        if path == "/proc/sys/kernel/tainted":
            return io.StringIO(str(value))
        return real(path, *a, **k)
    monkeypatch.setattr(builtins, "open", fake)
    return agent


def test_hpc_taint_is_not_reported(agent, monkeypatch):
    """Ovladace vyrobce jadro taintuji trvale — neni to porucha."""
    a = _taint_agent(agent, monkeypatch, 77824)
    events = a.check_kernel_taint()
    assert all(e["status"] == "OK" for e in events), events


def test_hardware_error_still_reported(agent, monkeypatch):
    """MCE (bit 4) znamena hardwarovou chybu — ta se hlasit musi."""
    a = _taint_agent(agent, monkeypatch, 77824 | (1 << 4))
    events = a.check_kernel_taint()
    assert any(e["status"] == "WARNING" for e in events)
    assert "MCE" in events[0]["message"]


def test_soft_lockup_still_reported(agent, monkeypatch):
    a = _taint_agent(agent, monkeypatch, 1 << 14)
    assert any(e["status"] == "WARNING" for e in agent.check_kernel_taint())


def test_ignored_bits_are_configurable(agent, monkeypatch):
    """Kdyz si nekdo preje hlasit vse, staci prazdny seznam."""
    a = _taint_agent(agent, monkeypatch, 77824, {"taint_ignore_bits": []})
    assert any(e["status"] == "WARNING" for e in a.check_kernel_taint())


# ── systemd ─────────────────────────────────────────────────────────────────

SYSTEMD_OUT = """session-124033.scope               loaded failed failed Session 124033 of user xvarsa01
session-124050.scope               loaded failed failed Session 124050 of user xvarsa01
NetworkManager-wait-online.service loaded failed failed Network Manager Wait Online
"""


def _systemd_agent(agent, monkeypatch, cfg=None):
    agent.config = {"checks": {"system": {"monitor_global_systemd": True, **(cfg or {})}}}
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=SYSTEMD_OUT))
    return agent


def test_session_scopes_are_skipped(agent, monkeypatch):
    """Relace uzivatelu padaji bezne a maji pokazde jine cislo."""
    a = _systemd_agent(agent, monkeypatch)
    events = a.check_global_systemd_failures()
    msg = events[0]["message"] if events else ""
    assert "session-124033.scope" not in msg
    assert "NetworkManager-wait-online.service" in msg, "skutecny nalez musi zustat"


def test_only_sessions_failed_means_ok(agent, monkeypatch):
    """Kdyz nezbyde nic jineho, je to v poradku — ne CRITICAL."""
    a = _systemd_agent(agent, monkeypatch)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        a, 0, stdout="session-1.scope loaded failed failed Session 1\n"))
    events = a.check_global_systemd_failures()
    assert all(e["status"] == "OK" for e in events), events


def test_ignore_list_is_configurable(agent, monkeypatch):
    a = _systemd_agent(agent, monkeypatch, {"systemd_ignore_units": []})
    assert "session-124033.scope" in a.check_global_systemd_failures()[0]["message"]


# ── Porty ───────────────────────────────────────────────────────────────────

SS_OUT = """Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      5      0.0.0.0:5902       0.0.0.0:*  users:(("Xvnc",pid=1,fd=8))
tcp   LISTEN 0      100    0.0.0.0:18677      0.0.0.0:*  users:(("websockify",pid=2,fd=4))
tcp   LISTEN 0      128    0.0.0.0:8090       0.0.0.0:*  users:(("app",pid=3,fd=3))
"""


@pytest.fixture
def ports(agent, monkeypatch):
    agent.config = {"checks": {"security": {"monitor_ports": True}}}
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=SS_OUT))
    real = builtins.open

    def fake(path, *a, **k):
        if path == "/proc/sys/net/ipv4/ip_local_port_range":
            return io.StringIO("32768\t60999")
        return real(path, *a, **k)
    monkeypatch.setattr(builtins, "open", fake)
    return agent


def test_range_in_allowed_ports(ports):
    """VNC displeje maji pokazde jine cislo — vyctem se to zapsat neda."""
    ports.config["checks"]["security"]["allowed_ports"] = ["5900-5999", "18000-18999"]
    assert ports._get_listening_ports() == {"tcp:8090"}


def test_single_ports_still_work(ports):
    ports.config["checks"]["security"]["allowed_ports"] = [5902]
    found = ports._get_listening_ports()
    assert "tcp:5902" not in found
    assert "tcp:18677" in found


def test_broken_range_does_not_break_check(ports):
    """Preklep v configu nesmi shodit celou kontrolu."""
    ports.config["checks"]["security"]["allowed_ports"] = ["nesmysl", "9-1", ""]
    assert "tcp:8090" in ports._get_listening_ports()

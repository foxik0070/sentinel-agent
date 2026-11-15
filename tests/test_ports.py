"""Hlidani portu: hlasi se jen porty dosazitelne ze site a baseline se bere
az po ustaleni systemu po startu.

Drive se hlasilo i to, co ze site videt neni (listenery na loopbacku od
uzivatelskych aplikaci, porty z dynamickeho rozsahu), a po rebootu kazda
sluzba, ktera nabehla az po agentovi.
"""
import builtins
import io
import subprocess

import pytest

SS = """Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128    127.0.0.1:43129    0.0.0.0:*  users:(("claude",pid=1,fd=3))
tcp   LISTEN 0      128    [::1]:25           [::]:*     users:(("exim4",pid=2,fd=3))
tcp   LISTEN 0      128    0.0.0.0:4533       0.0.0.0:*  users:(("navidrome",pid=3,fd=3))
tcp   LISTEN 0      128    0.0.0.0:44705      0.0.0.0:*  users:(("nmap",pid=4,fd=3))
tcp   LISTEN 0      128    [::]:8090          [::]:*     users:(("open-webui",pid=5,fd=3))
tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*  users:(("sshd",pid=6,fd=3))
"""


@pytest.fixture
def sec(agent, monkeypatch):
    agent.config = {"checks": {"security": {"monitor_ports": True}}}
    agent.ports_initialized = False
    agent.baseline_ports = set()
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=SS))
    return agent


def _fake_open(monkeypatch, uptime="10000.0 1.0", rng="32768\t60999"):
    """Podstrci /proc/uptime a dynamicky rozsah portu, zbytek cte normalne."""
    real = builtins.open

    def fake(path, *a, **k):
        if path == "/proc/uptime":
            return io.StringIO(uptime)
        if path == "/proc/sys/net/ipv4/ip_local_port_range":
            return io.StringIO(rng)
        return real(path, *a, **k)
    monkeypatch.setattr(builtins, "open", fake)


def test_loopback_and_ephemeral_skipped(sec, monkeypatch):
    """Zustanou jen sluzby otevrene do site mimo dynamicky rozsah."""
    _fake_open(monkeypatch)
    assert sec._get_listening_ports() == {"tcp:4533", "tcp:8090"}


def test_allowed_ports_from_config(sec, monkeypatch):
    """Vlastni vyjimky z agent_config.yaml."""
    _fake_open(monkeypatch)
    sec.config["checks"]["security"]["allowed_ports"] = [4533]
    assert sec._get_listening_ports() == {"tcp:8090"}


def test_baseline_waits_for_settle(sec, monkeypatch):
    """Minutu po startu se baseline jeste nebere — sluzby dobihaji."""
    _fake_open(monkeypatch, uptime="60.0 1.0")
    assert sec.check_network_ports() == []
    assert sec.ports_initialized is False


def test_baseline_after_settle(sec, monkeypatch):
    _fake_open(monkeypatch)
    assert sec.check_network_ports() == []
    assert sec.ports_initialized is True
    assert sec.baseline_ports == {"tcp:4533", "tcp:8090"}


def test_ephemeral_range_falls_back(sec, monkeypatch):
    """Kdyz /proc hodnotu nevrati, plati vychozi rozsah jadra."""
    real = builtins.open

    def fake(path, *a, **k):
        if path == "/proc/sys/net/ipv4/ip_local_port_range":
            raise OSError("no such file")
        return real(path, *a, **k)
    monkeypatch.setattr(builtins, "open", fake)
    assert sec._ephemeral_range() == (32768, 60999)

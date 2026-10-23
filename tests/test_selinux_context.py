"""bin_t label musi prezit relabel -- chcon ho ztrati pri prvnim restoreconu."""
import os
import re

import pytest

pytest.importorskip("yaml")

import sentinel_agent_init as init  # noqa: E402


class _Calls:
    """Zaznamena subprocess.run a vraci navratovy kod podle prvniho argumentu."""

    def __init__(self, missing=(), rc=None, stderr=None):
        self.argv = []
        self.missing = set(missing)
        # Hodnota je navratovy kod, nebo funkce nad celym prikazem.
        self.rc = rc or {}
        self.stderr = stderr or {}

    def _rc(self, cmd):
        val = self.rc.get(cmd[0], 0)
        return val(cmd) if callable(val) else val

    def run(self, cmd, *a, **kw):
        self.argv.append(cmd)
        if cmd[0] in self.missing:
            raise FileNotFoundError(cmd[0])

        class R:
            returncode = self._rc(cmd)
            stdout = "Enforcing\n" if cmd[0] == "getenforce" else ""
            stderr = self.stderr.get(cmd[0], "")
        return R()

    def of(self, binary):
        return [c for c in self.argv if c[0] == binary]


@pytest.fixture
def agent_tree(tmp_path):
    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    python_bin = venv_bin / "python3"
    python_bin.write_text("")
    (tmp_path / "sentinel_agent.py").write_text("")
    return str(python_bin), str(tmp_path)


def _patch(monkeypatch, calls):
    monkeypatch.setattr(init.subprocess, "run", calls.run)


def test_semanage_rules_are_persistent_and_applied(monkeypatch, agent_tree):
    python_bin, working_dir = agent_tree
    calls = _Calls()
    _patch(monkeypatch, calls)

    init._fix_selinux_context(python_bin, working_dir)

    specs = [c[-1] for c in calls.of("semanage")]
    assert specs == [re.escape(os.path.dirname(python_bin)) + "(/.*)?",
                     re.escape(os.path.join(working_dir, "sentinel_agent.py"))]
    assert all(c[:5] == ["semanage", "fcontext", "-a", "-t", "bin_t"] for c in calls.of("semanage"))
    assert calls.of("restorecon") == [["restorecon", "-R", working_dir]]
    # Persistentni cesta nesmi sahnout na chcon -- ten relabel nepreziie.
    assert calls.of("chcon") == []


def test_existing_rule_is_modified_not_duplicated(monkeypatch, agent_tree):
    python_bin, working_dir = agent_tree
    # Pravidlo z predchozi instalace: -a skonci chybou, -m projde.
    calls = _Calls(rc={"semanage": lambda cmd: 1 if cmd[2] == "-a" else 0},
                   stderr={"semanage": "ValueError: File context for /x already defined"})
    _patch(monkeypatch, calls)

    init._fix_selinux_context(python_bin, working_dir)

    assert [c[2] for c in calls.of("semanage")] == ["-a", "-m", "-a", "-m"]
    assert calls.of("restorecon") == [["restorecon", "-R", working_dir]]
    assert calls.of("chcon") == []


def test_falls_back_to_chcon_without_semanage(monkeypatch, agent_tree):
    python_bin, working_dir = agent_tree
    calls = _Calls(missing=["semanage"])
    _patch(monkeypatch, calls)

    init._fix_selinux_context(python_bin, working_dir)

    assert calls.of("restorecon") == []
    assert [c[-1] for c in calls.of("chcon")] == [
        python_bin, os.path.join(working_dir, "sentinel_agent.py")]


def test_failed_semanage_falls_back_to_chcon(monkeypatch, agent_tree):
    python_bin, working_dir = agent_tree
    calls = _Calls(rc={"semanage": 1}, stderr={"semanage": "libsemanage.semanage_access_check: access denied"})
    _patch(monkeypatch, calls)

    init._fix_selinux_context(python_bin, working_dir)

    assert len(calls.of("semanage")) == 1
    assert len(calls.of("chcon")) == 2


def test_noop_when_selinux_disabled(monkeypatch, agent_tree):
    python_bin, working_dir = agent_tree
    calls = _Calls(rc={"getenforce": 1})
    _patch(monkeypatch, calls)

    init._fix_selinux_context(python_bin, working_dir)

    assert calls.of("semanage") == []
    assert calls.of("chcon") == []

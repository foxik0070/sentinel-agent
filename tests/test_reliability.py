"""Agent reliability: config validation, dry-run, sd_notify (todo #25,#29,#30)."""
import os
import tempfile

import pytest

import sentinel_agent


def _build_with_config(text):
    path = tempfile.mktemp(suffix=".yaml")
    with open(path, "w") as f:
        f.write(text)
    sentinel_agent.CONFIG_FILE = path
    try:
        return sentinel_agent.SentinelAgent()
    finally:
        os.unlink(path)


def test_config_missing_token_exits():
    with pytest.raises(SystemExit) as exc:
        _build_with_config("sentinel_api:\n  url: http://x\n")
    assert exc.value.code == 1


def test_config_missing_url_exits():
    with pytest.raises(SystemExit):
        _build_with_config("sentinel_api:\n  token: abc\n")


def test_config_non_mapping_exits():
    with pytest.raises(SystemExit):
        _build_with_config("- just\n- a\n- list\n")


def test_sd_notify_noop_without_socket(agent, monkeypatch):
    # No NOTIFY_SOCKET in env -> must be a silent no-op, never raise.
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    agent._sd_notify("WATCHDOG=1")  # should not raise


def test_self_resources_disabled_by_default(agent):
    agent.config = {"agent_core": {"max_self_rss_mb": 0}}
    # limit 0 -> disabled, must return without exiting
    agent._check_self_resources()

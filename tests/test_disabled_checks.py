"""Vypnuta kontrola nesmi nechat svuj problem viset (PLUGIN_GATES)."""


def _issue(plugin, target, status="WARNING"):
    return {"plugin": plugin, "target": target, "status": status, "message": "x"}


def _run(agent, checks_cfg, issues):
    agent.config = {"checks": checks_cfg}
    agent.active_issues = {f"{i['plugin']}:{i['target']}": dict(i) for i in issues}
    pushed = []
    agent._save_state = lambda: None
    agent.push_to_sentinel = lambda ev: pushed.extend(ev)
    agent._apply_and_push([])
    return pushed


def test_disabled_check_issue_cleared_with_ok(agent):
    pushed = _run(agent, {"kernel": {"monitor_taint": False}},
                  [_issue("agent_kernel_taint_monitor", "core_kernel")])
    assert agent.active_issues == {}
    assert [(e["plugin"], e["status"]) for e in pushed] == [("agent_kernel_taint_monitor", "OK")]


def test_enabled_check_issue_kept(agent):
    pushed = _run(agent, {"kernel": {"monitor_oom": True}},
                  [_issue("agent_kernel_oom_monitor", "oom_killer", "CRITICAL")])
    assert "agent_kernel_oom_monitor:oom_killer" in agent.active_issues
    assert pushed[0]["status"] == "CRITICAL"


def test_plugin_without_gate_untouched(agent):
    _run(agent, {}, [_issue("agent_security_suspicious_activity", "suid")])
    assert "agent_security_suspicious_activity:suid" in agent.active_issues

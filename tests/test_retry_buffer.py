"""Retry buffer dedup and cap logic (push_to_sentinel, todo #22)."""
import pytest


def _evt(target, status, message):
    return {"plugin": "p", "target": target, "status": status, "message": message}


class _FailingSession:
    """Session stub whose post always raises, forcing the buffer path."""
    def post(self, *a, **kw):
        import requests
        raise requests.exceptions.ConnectionError("simulated outage")


@pytest.fixture
def offline_agent(agent):
    import requests  # noqa: F401
    agent.session = _FailingSession()
    agent.api_url = "http://127.0.0.1:1"
    agent.headers = {}
    agent.hostname = "testhost"
    agent.agent_version = "test"
    # _save_state is called on failure; make it a no-op for the unit test
    agent._save_state = lambda: None
    return agent


def test_failed_push_buffers_events(offline_agent):
    offline_agent.push_to_sentinel([_evt("svc", "CRITICAL", "down")])
    assert len(offline_agent.pending_events) == 1


def test_identical_reaffirmations_deduped(offline_agent):
    offline_agent.push_to_sentinel([_evt("svc", "CRITICAL", "down")])
    offline_agent.push_to_sentinel([_evt("svc", "CRITICAL", "down"),
                                    _evt("disk", "WARNING", "85%")])
    # "down" appears twice but is deduped; "85%" is new -> 2 buffered
    assert len(offline_agent.pending_events) == 2


def test_buffer_cap_keeps_newest(offline_agent):
    offline_agent.max_pending_events = 5
    offline_agent.push_to_sentinel([_evt(f"t{i}", "WARNING", f"m{i}") for i in range(10)])
    assert len(offline_agent.pending_events) == 5
    assert offline_agent.pending_events[-1]["target"] == "t9"


def test_distinct_transitions_preserved(offline_agent):
    offline_agent.push_to_sentinel([_evt("svc", "CRITICAL", "down")])
    offline_agent.push_to_sentinel([_evt("svc", "OK", "recovered")])
    statuses = [e["status"] for e in offline_agent.pending_events if e["target"] == "svc"]
    assert "CRITICAL" in statuses and "OK" in statuses

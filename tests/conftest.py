"""Shared pytest fixtures for Sentinel Agent unit tests.

Tests target the pure parsing/decoding logic. The agent is built via __new__ to
skip __init__ (which requires /etc/sentinel/agent_config.yaml), and only the
minimal state each tested method touches is populated.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel_agent import SentinelAgent  # noqa: E402


@pytest.fixture
def agent():
    a = SentinelAgent.__new__(SentinelAgent)
    a.config = {"checks": {"security": {}, "storage": {}, "kernel": {}}}
    a.last_reported_states = {}
    a.pending_events = []
    a.max_pending_events = 500
    return a

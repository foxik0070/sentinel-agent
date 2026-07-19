"""RPi throttle bitmask (todo #38), OOM regex (todo #27), promisc flag (todo #6)."""
import re

import pytest

from sentinel_agent import SentinelAgent


# --- RPi vcgencmd get_throttled bitmask decoding ---
def _throttle_status(value):
    flags = [(sev, d) for bit, sev, d in SentinelAgent.RPI_THROTTLE_BITS if value & (1 << bit)]
    if not flags:
        return "OK"
    return "CRITICAL" if any(s == "CRITICAL" for s, _ in flags) else "WARNING"


@pytest.mark.parametrize("value,expected", [
    (0x0, "OK"),
    (0x1, "CRITICAL"),       # under-voltage now
    (0x50000, "WARNING"),    # capping + throttling since boot
    (0xe0000, "WARNING"),    # capping + throttling + soft-temp since boot
    (0x50005, "CRITICAL"),   # under-voltage now + history
])
def test_rpi_throttle_decode(value, expected):
    assert _throttle_status(value) == expected


# --- OOM kill regex (old + new kernel formats) ---
@pytest.mark.parametrize("line,hits", [
    ("Out of memory: Kill process 1234 (stress) score 900 or sacrifice child", 1),
    ("Out of memory: Killed process 5678 (stress) total-vm:8000kB, anon-rss:100kB", 1),
    ("oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null)", 0),
    ("systemd[1]: Started session", 0),
])
def test_oom_regex(line, hits):
    assert len(re.findall(SentinelAgent.OOM_REGEX, line, re.IGNORECASE)) == hits


# --- Promiscuous mode flag (IFF_PROMISC = 0x100) ---
@pytest.mark.parametrize("flags,promisc", [
    (0x1003, False),   # UP + BROADCAST + MULTICAST
    (0x1103, True),    # + PROMISC
    (0x100, True),
    (0x9, False),      # loopback
])
def test_promisc_bit(flags, promisc):
    assert bool(flags & 0x100) is promisc

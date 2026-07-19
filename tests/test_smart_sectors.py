"""SMART reallocated/pending/uncorrectable sector parsing (check modul 10, todo #39)."""
import pytest

SATA_BAD = """
ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   100   100   036    Pre-fail  Always       -       48
197 Current_Pending_Sector  0x0012   100   100   000    Old_age   Always       -       16
198 Offline_Uncorrectable   0x0010   100   100   000    Old_age   Offline      -       0
"""

SATA_OK = """
  5 Reallocated_Sector_Ct   0x0033   100   100   036    Pre-fail  Always       -       0
197 Current_Pending_Sector  0x0012   100   100   000    Old_age   Always       -       0
"""

NVME_BAD = "Media and Data Integrity Errors:     3\nPercentage Used:                    2%"
NVME_OK = "Media and Data Integrity Errors:     0\nPercentage Used:                    2%"


def _status(agent, output):
    agent.last_reported_states.clear()
    events = agent._check_drive_sectors("/dev/test", output)
    return events[0]["status"] if events else "no-event"


def test_sata_failing_sectors(agent):
    assert _status(agent, SATA_BAD) == "CRITICAL"


def test_sata_clean(agent):
    assert _status(agent, SATA_OK) == "OK"


def test_nvme_integrity_errors(agent):
    assert _status(agent, NVME_BAD) == "CRITICAL"


def test_nvme_clean(agent):
    assert _status(agent, NVME_OK) == "OK"


def test_critical_message_lists_counts(agent):
    agent.last_reported_states.clear()
    events = agent._check_drive_sectors("/dev/test", SATA_BAD)
    msg = events[0]["message"]
    assert "48 reallocated sectors" in msg and "16 pending sectors" in msg


def test_delta_filter_suppresses_repeat(agent):
    agent.last_reported_states.clear()
    first = agent._check_drive_sectors("/dev/test", SATA_OK)
    second = agent._check_drive_sectors("/dev/test", SATA_OK)
    assert len(first) == 1 and second == []

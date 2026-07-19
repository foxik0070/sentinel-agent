"""Kernel version vs. known LPE CVE range logic (check 2.1, todo #17)."""
import pytest

from sentinel_agent import SentinelAgent


def _vulnerable_to(kver):
    return {
        nickname
        for _, nickname, ranges in SentinelAgent.KERNEL_LPE_CVES
        if any(lo <= kver < hi for lo, hi in ranges)
    }


CASES = [
    ((4, 4, 0), {"Dirty COW", "OverlayFS cap abuse (Ubuntu)", "nf_tables UAF"}),
    ((5, 10, 90), {"OverlayFS cap abuse (Ubuntu)", "Dirty Pipe", "nf_tables UAF"}),
    ((5, 15, 24), {"Dirty Pipe", "nf_tables UAF"}),
    ((5, 15, 25), {"nf_tables UAF"}),      # Dirty Pipe fixed in 5.15.25
    ((6, 1, 76), set()),                    # nf_tables fixed in 6.1.76
    ((6, 6, 14), {"nf_tables UAF"}),
    ((6, 6, 15), set()),                    # nf_tables fixed in 6.6.15
    ((6, 18, 34), set()),                   # current RPi kernel - clean
    # 4.8.3 fixed Dirty COW but still inside OverlayFS + nf_tables ranges
    ((4, 8, 3), {"OverlayFS cap abuse (Ubuntu)", "nf_tables UAF"}),
]


@pytest.mark.parametrize("kver,expected", CASES)
def test_cve_ranges(kver, expected):
    assert _vulnerable_to(kver) == expected


def test_dirty_cow_fixed_at_boundary():
    # 4.8.3 is the first fixed release - Dirty COW must not appear
    assert "Dirty COW" not in _vulnerable_to((4, 8, 3))
    assert "Dirty COW" in _vulnerable_to((4, 8, 2))


def test_kernel_version_parsing(agent):
    # os.uname().release is parsed by a regex; verify the shape on the real host.
    kver = agent._kernel_version()
    assert kver is None or (isinstance(kver, tuple) and len(kver) == 3)

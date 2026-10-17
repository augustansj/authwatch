"""Turn raw syslog-style auth lines into AuthEvent objects.

Expected line format (traditional syslog, also the default `journalctl` output):

    Oct 17 12:00:01 myhost sshd[1234]: Failed password for root from 203.0.113.5 port 52211 ssh2
    |--timestamp--| |host| |process|   |---------------------- message ----------------------|
"""

import re
from collections.abc import Iterable, Iterator
from datetime import datetime

from authwatch.models import AuthEvent, EventKind

HEADER_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w\-./]+)(?:\[\d+\])?:\s+"
    r"(?P<message>.*)$"
)

# Each entry maps a message regex to the EventKind it produces.
# Named groups `user`, `ip` and `detail` are copied onto the AuthEvent if present.
# Patterns are tried in order; the first match wins.
MESSAGE_PATTERNS: list[tuple[EventKind, re.Pattern[str]]] = [
    (
        EventKind.FAILED_PASSWORD,
        re.compile(r"^Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"),
    ),
    # TODO(you): ACCEPTED_LOGIN
    #   "Accepted password for alice from 198.51.100.7 port 50000 ssh2"
    #   "Accepted publickey for alice from 198.51.100.7 port 50000 ssh2: ED25519 SHA256:..."
    #   -> capture user, ip, and the method ("password"/"publickey") as `detail`
    #
    # TODO(you): INVALID_USER
    #   "Invalid user admin from 203.0.113.5 port 40000"
    #
    # TODO(you): SUDO_COMMAND (process will be "sudo")
    #   "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
    #   -> capture user and the command as `detail`
]


def parse_timestamp(ts: str, year: int) -> datetime:
    """Syslog timestamps have no year, so the caller supplies one."""
    return datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, year: int | None = None) -> AuthEvent | None:
    """Parse one log line. Returns None for lines we don't care about."""
    line = line.rstrip("\n")
    header = HEADER_RE.match(line)
    if not header:
        return None

    message = header["message"]
    for kind, pattern in MESSAGE_PATTERNS:
        m = pattern.search(message)
        if not m:
            continue
        groups = m.groupdict()
        return AuthEvent(
            timestamp=parse_timestamp(header["ts"], year or datetime.now().year),
            host=header["host"],
            process=header["process"],
            kind=kind,
            user=groups.get("user"),
            source_ip=groups.get("ip"),
            detail=groups.get("detail"),
            raw=line,
        )
    return None


def parse_lines(lines: Iterable[str], year: int | None = None) -> Iterator[AuthEvent]:
    for line in lines:
        event = parse_line(line, year)
        if event is not None:
            yield event

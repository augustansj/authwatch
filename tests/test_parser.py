from datetime import datetime

from conftest import todo

from authwatch.models import EventKind
from authwatch.parser import parse_line

FAILED = (
    "Oct 17 09:10:00 web01 sshd[2001]: Failed password for root from 203.0.113.5 port 40001 ssh2"
)


def test_failed_password():
    e = parse_line(FAILED, year=2026)
    assert e is not None
    assert e.kind is EventKind.FAILED_PASSWORD
    assert e.user == "root"
    assert e.source_ip == "203.0.113.5"
    assert e.host == "web01"
    assert e.process == "sshd"
    assert e.timestamp == datetime(2026, 10, 17, 9, 10, 0)


def test_failed_password_for_invalid_user():
    line = (
        "Oct 17 10:00:01 web01 sshd[3001]: "
        "Failed password for invalid user admin from 198.51.100.23 port 51000 ssh2"
    )
    e = parse_line(line, year=2026)
    assert e.kind is EventKind.FAILED_PASSWORD
    assert e.user == "admin"


def test_irrelevant_lines_return_none():
    assert parse_line("garbage") is None
    assert parse_line("Oct 17 08:00:05 web01 systemd-logind[400]: New session 12.") is None


@todo
def test_accepted_publickey():
    line = (
        "Oct 17 08:00:01 web01 sshd[1001]: "
        "Accepted publickey for alice from 192.0.2.10 port 50122 ssh2: ED25519 SHA256:abc"
    )
    e = parse_line(line, year=2026)
    assert e.kind is EventKind.ACCEPTED_LOGIN
    assert e.user == "alice"
    assert e.source_ip == "192.0.2.10"
    assert e.detail == "publickey"


@todo
def test_accepted_password():
    line = (
        "Oct 17 09:11:00 web01 sshd[2007]: Accepted password for root from 203.0.113.5 port 1 ssh2"
    )
    e = parse_line(line, year=2026)
    assert e.kind is EventKind.ACCEPTED_LOGIN
    assert e.detail == "password"


@todo
def test_invalid_user():
    e = parse_line("Oct 17 10:00:00 web01 sshd[3001]: Invalid user admin from 198.51.100.23 port 1")
    assert e.kind is EventKind.INVALID_USER
    assert e.user == "admin"
    assert e.source_ip == "198.51.100.23"


@todo
def test_sudo_command():
    line = (
        "Oct 17 11:30:00 web01 sudo[4002]:    alice : TTY=pts/0 ; PWD=/home/alice ; "
        "USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
    )
    e = parse_line(line, year=2026)
    assert e.kind is EventKind.SUDO_COMMAND
    assert e.process == "sudo"
    assert e.user == "alice"
    assert e.detail == "/usr/bin/cat /etc/shadow"

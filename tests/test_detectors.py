from datetime import datetime, timedelta

from conftest import todo

from authwatch.detectors import (
    Config,
    detect_brute_force,
    detect_password_spray,
    detect_sensitive_sudo,
    detect_success_after_failures,
)
from authwatch.models import AuthEvent, EventKind, Severity


def failure(ip: str, minute: int, user: str = "root") -> AuthEvent:
    return AuthEvent(
        timestamp=datetime(2026, 10, 17, 9, minute),
        host="h",
        process="sshd",
        kind=EventKind.FAILED_PASSWORD,
        user=user,
        source_ip=ip,
    )


def test_brute_force_fires_at_threshold():
    events = [failure("203.0.113.5", m) for m in range(5)]
    findings = detect_brute_force(events, Config(brute_force_threshold=5))
    assert len(findings) == 1
    assert findings[0].source_ip == "203.0.113.5"
    assert findings[0].count == 5


def test_brute_force_ignores_slow_attempts_outside_window():
    # 5 failures, but spread 10 minutes apart: never 5 inside a 5-minute window.
    events = [failure("203.0.113.5", m * 10) for m in range(5)]
    assert detect_brute_force(events, Config(brute_force_window=timedelta(minutes=5))) == []


def test_brute_force_is_per_ip():
    events = [failure(f"203.0.113.{i}", i) for i in range(10)]
    assert detect_brute_force(events, Config()) == []


def test_brute_force_on_sample_log(sample_events):
    findings = detect_brute_force(sample_events, Config())
    assert [f.source_ip for f in findings] == ["203.0.113.5"]


@todo
def test_success_after_failures(sample_events):
    findings = detect_success_after_failures(sample_events, Config())
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "success_after_failures"
    assert f.severity is Severity.HIGH
    assert f.source_ip == "203.0.113.5"
    assert f.user == "root"


@todo
def test_password_spray(sample_events):
    findings = detect_password_spray(sample_events, Config(spray_user_threshold=3))
    assert [f.source_ip for f in findings] == ["198.51.100.23"]
    assert findings[0].rule == "password_spray"


@todo
def test_sensitive_sudo(sample_events):
    findings = detect_sensitive_sudo(sample_events, Config())
    assert len(findings) == 1  # the /etc/shadow read, not the nginx restart
    assert findings[0].user == "alice"
    assert findings[0].rule == "sensitive_sudo"

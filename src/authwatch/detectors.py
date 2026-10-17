"""Detection rules. Each detector takes the full list of events and returns Findings.

To add a rule: write a function with the `Detector` signature and add it to DETECTORS.
"""

from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import timedelta

from authwatch.models import AuthEvent, EventKind, Finding, Severity


@dataclass(frozen=True)
class Config:
    brute_force_threshold: int = 5
    brute_force_window: timedelta = timedelta(minutes=5)
    spray_user_threshold: int = 3
    sensitive_paths: tuple[str, ...] = ("/etc/shadow", "/etc/sudoers", "/root/.ssh")


Detector = Callable[[Sequence[AuthEvent], Config], list[Finding]]


def _by_ip(events: Sequence[AuthEvent], kind: EventKind) -> dict[str, list[AuthEvent]]:
    grouped: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in events:
        if e.kind is kind and e.source_ip:
            grouped[e.source_ip].append(e)
    for evs in grouped.values():
        evs.sort(key=lambda e: e.timestamp)
    return grouped


def detect_brute_force(events: Sequence[AuthEvent], cfg: Config) -> list[Finding]:
    """>= threshold failed passwords from one IP within a sliding time window."""
    findings = []
    for ip, failures in _by_ip(events, EventKind.FAILED_PASSWORD).items():
        start = 0
        for end in range(len(failures)):
            while failures[end].timestamp - failures[start].timestamp > cfg.brute_force_window:
                start += 1
            window = failures[start : end + 1]
            if len(window) >= cfg.brute_force_threshold:
                findings.append(
                    Finding(
                        rule="ssh_brute_force",
                        severity=Severity.MEDIUM,
                        summary=f"{len(window)} failed logins from {ip} "
                        f"within {cfg.brute_force_window}",
                        source_ip=ip,
                        first_seen=window[0].timestamp,
                        last_seen=window[-1].timestamp,
                        count=len(window),
                        evidence=list(window),
                    )
                )
                break  # one finding per IP is enough
    return findings


def detect_success_after_failures(events: Sequence[AuthEvent], cfg: Config) -> list[Finding]:
    """An IP that failed several times and then logged in successfully.

    This is the "the brute force worked" signal, so severity should be HIGH.

    TODO(you):
      - group FAILED_PASSWORD events by IP (see _by_ip)
      - find ACCEPTED_LOGIN events from an IP with >= cfg.brute_force_threshold
        earlier failures
      - emit one Finding per (ip, user) with rule="success_after_failures"
    """
    return []


def detect_password_spray(events: Sequence[AuthEvent], cfg: Config) -> list[Finding]:
    """One IP trying many *different* usernames (spray), rather than one user many times.

    TODO(you):
      - consider both FAILED_PASSWORD and INVALID_USER events
      - count distinct usernames per IP
      - emit a Finding with rule="password_spray" when the count >= cfg.spray_user_threshold
    """
    return []


def detect_sensitive_sudo(events: Sequence[AuthEvent], cfg: Config) -> list[Finding]:
    """sudo commands that touch sensitive files (credential access, MITRE T1003.008).

    TODO(you):
      - look at SUDO_COMMAND events; the command is in event.detail
      - emit a Finding with rule="sensitive_sudo" if any cfg.sensitive_paths appears in it
    """
    return []


DETECTORS: list[Detector] = [
    detect_brute_force,
    detect_success_after_failures,
    detect_password_spray,
    detect_sensitive_sudo,
]


def run_all(events: Sequence[AuthEvent], cfg: Config | None = None) -> list[Finding]:
    cfg = cfg or Config()
    findings: list[Finding] = []
    for detector in DETECTORS:
        findings.extend(detector(events, cfg))
    return findings

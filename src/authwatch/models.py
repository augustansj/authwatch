"""Core data types shared by every layer of the pipeline.

parser  ->  AuthEvent  ->  detectors  ->  Finding  ->  report
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class EventKind(StrEnum):
    FAILED_PASSWORD = "failed_password"  # noqa: S105 (not a credential)
    ACCEPTED_LOGIN = "accepted_login"
    INVALID_USER = "invalid_user"
    SUDO_COMMAND = "sudo_command"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class AuthEvent:
    """One normalized line from an auth log."""

    timestamp: datetime
    host: str
    process: str
    kind: EventKind
    user: str | None = None
    source_ip: str | None = None
    detail: str | None = None  # e.g. auth method, or the sudo command
    raw: str = ""


@dataclass(frozen=True)
class Finding:
    """Something a detector thinks a human should look at."""

    rule: str
    severity: Severity
    summary: str
    source_ip: str | None = None
    user: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    count: int = 0
    evidence: list[AuthEvent] = field(default_factory=list, compare=False)

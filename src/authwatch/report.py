"""Render findings for humans (text) or machines (JSON)."""

import json
from collections import Counter
from collections.abc import Sequence

from authwatch.models import AuthEvent, Finding

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def _sorted(findings: Sequence[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER[f.severity.value], f.rule))


def render_text(events: Sequence[AuthEvent], findings: Sequence[Finding]) -> str:
    kinds = Counter(e.kind.value for e in events)
    header = (
        f"Parsed {len(events)} auth events: "
        + ", ".join(f"{k}={v}" for k, v in sorted(kinds.items()))
        if events
        else "Parsed 0 auth events"
    )
    lines = [header]

    if not findings:
        lines.append("No findings.")
        return "\n".join(lines)

    lines.append(f"\n{len(findings)} finding(s):")
    for f in _sorted(findings):
        lines.append(f"  [{f.severity.value.upper():6}] {f.rule}: {f.summary}")
    return "\n".join(lines)


def render_json(events: Sequence[AuthEvent], findings: Sequence[Finding]) -> str:
    def finding_to_dict(f: Finding) -> dict:
        return {
            "rule": f.rule,
            "severity": f.severity.value,
            "summary": f.summary,
            "source_ip": f.source_ip,
            "user": f.user,
            "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            "last_seen": f.last_seen.isoformat() if f.last_seen else None,
            "count": f.count,
            "evidence": [e.raw for e in f.evidence],
        }

    return json.dumps(
        {"event_count": len(events), "findings": [finding_to_dict(f) for f in _sorted(findings)]},
        indent=2,
    )

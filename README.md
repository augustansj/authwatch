# authwatch

A small CLI that reads Linux authentication logs and flags suspicious activity:
SSH brute force, password spraying, successful logins after repeated failures,
and sudo access to sensitive files.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

authwatch tests/fixtures/sample_auth.log

# On journald systems (Arch, Fedora, ...), pipe from journalctl:
journalctl -t sshd -t sudo --since today | authwatch
journalctl -t sshd -t sudo --since today | authwatch --format json
```

Exit codes: `0` means no findings, `1` means findings were reported, `2` means an input error.

## Architecture

```
 log lines ──► parser ──► AuthEvent[] ──► detectors ──► Finding[] ──► report ──► stdout
              parser.py    models.py     detectors.py    models.py    report.py
                                  ▲
                              cli.py wires it all together
```

- **parser**: turns text into structured `AuthEvent`s. It's the only module that knows the log format.
  Supporting a new format (JSON journald, auditd) means writing a new parser, nothing else.
- **detectors**: pure functions `(events, config) -> findings`. They do no I/O, which makes them easy to test.
  You add a rule by writing a function and appending it to `DETECTORS`.
- **report**: presentation only. Adding a new output (CSV, Slack webhook) never touches detection logic.

## Development

```bash
pytest          # run tests
ruff check .    # lint
ruff format .   # auto-format
```

Tests marked `@todo` are features that aren't built yet. They're expected to fail until you implement
them. See the `TODO(you)` comments in `parser.py` and `detectors.py`.

## Roadmap

- [x] Parse failed SSH passwords
- [x] Brute-force detection (sliding window)
- [ ] Parse accepted logins, invalid users, sudo commands
- [ ] Success-after-failures detection
- [ ] Password spray detection
- [ ] Sensitive sudo detection
- [ ] Map findings to MITRE ATT&CK IDs
- [ ] Read journald JSON directly (`journalctl -o json`)
- [ ] GeoIP / threat-intel enrichment for source IPs

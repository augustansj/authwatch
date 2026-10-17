"""Command-line entry point.

authwatch /var/log/auth.log
journalctl -t sshd -t sudo --since today | authwatch --format json
"""

import argparse
import fileinput
import sys
from datetime import timedelta

from authwatch import __version__
from authwatch.detectors import Config, run_all
from authwatch.parser import parse_lines
from authwatch.report import render_json, render_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="authwatch", description="Detect suspicious activity in Linux auth logs."
    )
    p.add_argument("files", nargs="*", help="log files to read (default: stdin)")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--year", type=int, help="year for syslog timestamps (default: current)")
    p.add_argument("--threshold", type=int, default=5, help="failures that count as brute force")
    p.add_argument("--window", type=int, default=300, help="brute-force window in seconds")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = Config(
        brute_force_threshold=args.threshold,
        brute_force_window=timedelta(seconds=args.window),
    )

    try:
        with fileinput.input(files=args.files or ("-",), encoding="utf-8", errors="replace") as f:
            events = list(parse_lines(f, year=args.year))
    except OSError as e:
        print(f"authwatch: {e}", file=sys.stderr)
        return 2

    findings = run_all(events, cfg)
    render = render_json if args.format == "json" else render_text
    print(render(events, findings))

    # Non-zero exit when something was found makes the tool usable in scripts/cron.
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())

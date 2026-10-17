from pathlib import Path

import pytest

from authwatch.parser import parse_lines

FIXTURES = Path(__file__).parent / "fixtures"

# Tests for features you haven't built yet are marked `todo`. They're expected to fail.
# Once your implementation makes one pass, pytest reports it as XPASS(strict) and
# fails, which is your signal to delete the marker.
todo = pytest.mark.xfail(reason="TODO: not implemented yet", strict=True)


@pytest.fixture
def sample_log() -> Path:
    return FIXTURES / "sample_auth.log"


@pytest.fixture
def sample_events(sample_log):
    with sample_log.open() as f:
        return list(parse_lines(f, year=2026))

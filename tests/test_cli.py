import json

from authwatch.cli import main


def test_text_output_and_exit_code(sample_log, capsys):
    code = main([str(sample_log), "--year", "2026"])
    out = capsys.readouterr().out
    assert code == 1  # findings present
    assert "ssh_brute_force" in out


def test_json_output(sample_log, capsys):
    main([str(sample_log), "--year", "2026", "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["event_count"] > 0
    assert any(f["rule"] == "ssh_brute_force" for f in data["findings"])


def test_missing_file_returns_2(capsys):
    assert main(["/nonexistent/auth.log"]) == 2
    assert "authwatch:" in capsys.readouterr().err

"""
Unit and integration tests for the Clawper CLI interface.
"""

import tempfile
from pathlib import Path

from click.testing import CliRunner

from clawper.cli import main


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "Clawper version" in result.output


def test_cli_init():
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        out_yaml = Path(tmpdir) / "clawper_test.yaml"
        result = runner.invoke(main, ["init", "--output", str(out_yaml)])
        assert result.exit_code == 0
        assert out_yaml.exists()
        assert "ExampleBox" in out_yaml.read_text()


def test_cli_status_and_report():
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        # Check empty status
        result_empty = runner.invoke(main, ["status", "--workspace", tmpdir])
        assert result_empty.exit_code == 0
        assert "No active or saved session" in result_empty.output

        # Run with mock agent and 1 flag required
        run_res = runner.invoke(main, [
            "run",
            "--workspace", tmpdir,
            "--agent", "mock",
            "--flags", "1",
            "--max-iterations", "2",
            "--prompt", "Capture flag",
            "--no-require-root",
        ])
        assert run_res.exit_code == 0

        # Check status after run
        status_res = runner.invoke(main, ["status", "--workspace", tmpdir])
        assert status_res.exit_code == 0
        assert "Session Status" in status_res.output

        # Check report command
        report_res = runner.invoke(main, ["report", "--workspace", tmpdir])
        assert report_res.exit_code == 0
        assert "CTF Writeup" in report_res.output

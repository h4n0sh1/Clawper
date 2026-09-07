"""
Unit tests for Clawper workspace manager and reporter.
"""

import tempfile
from pathlib import Path

from clawper.config import ClawperConfig, TargetConfig
from clawper.workspace.manager import WorkspaceManager
from clawper.workspace.reporter import CTFReporter


def test_workspace_initialization():
    with tempfile.TemporaryDirectory() as tmpdir:
        wm = WorkspaceManager(tmpdir)
        wm.initialize()

        assert (wm.root_dir / "recon").exists()
        assert (wm.root_dir / "exploits").exists()
        assert (wm.root_dir / "loot").exists()
        assert (wm.root_dir / "flags").exists()
        assert (wm.root_dir / "notes").exists()
        assert (wm.root_dir / "logs").exists()


def test_workspace_flags_persistence():
    with tempfile.TemporaryDirectory() as tmpdir:
        wm = WorkspaceManager(tmpdir)
        wm.initialize()

        wm.save_flag("e4d909c290d0fb1ca068ffaddf22cbd0", source="iteration_1", iteration=1, flag_type="user")
        wm.save_flag("f1e2d3c4b5a60718293a4b5c6d7e8f90", source="iteration_2", iteration=2, flag_type="root")

        # Check files created
        assert (wm.flags_dir / "flags.txt").exists()
        assert (wm.flags_dir / "flags.json").exists()
        assert (wm.flags_dir / "user.txt").exists()
        assert (wm.flags_dir / "root.txt").exists()

        flags = wm.get_captured_flags()
        assert len(flags) == 2
        assert any(f["flag"] == "e4d909c290d0fb1ca068ffaddf22cbd0" for f in flags)
        assert any(f["flag"] == "f1e2d3c4b5a60718293a4b5c6d7e8f90" for f in flags)


def test_workspace_state_save_and_load():
    with tempfile.TemporaryDirectory() as tmpdir:
        wm = WorkspaceManager(tmpdir)
        wm.initialize()

        state_data = {
            "session_id": "test1234",
            "iterations_completed": 3,
            "captured_flags": [{"flag": "flag{test}", "source": "test"}],
            "success": True,
        }
        wm.save_state(state_data)

        loaded = wm.load_state()
        assert loaded is not None
        assert loaded["session_id"] == "test1234"
        assert loaded["iterations_completed"] == 3
        assert loaded["success"] is True


def test_ctf_reporter():
    with tempfile.TemporaryDirectory() as tmpdir:
        w_dir = Path(tmpdir)
        config = ClawperConfig(
            target=TargetConfig(box_name="TestBox", ip="10.10.11.50", platform="htb"),
            workspace_dir=str(w_dir),
        )
        reporter = CTFReporter(w_dir, config)

        state = {
            "session_id": "session_abc",
            "started_at": 1000.0,
            "completed_at": 1200.0,
            "iterations_completed": 2,
            "success": True,
            "captured_flags": [
                {"flag": "e4d909c290d0fb1ca068ffaddf22cbd0", "flag_type": "user", "source": "user.txt", "iteration": 1},
                {"flag": "f1e2d3c4b5a60718293a4b5c6d7e8f90", "flag_type": "root", "source": "root.txt", "iteration": 2},
            ],
            "history": [
                {"iteration": 1, "status": "completed", "duration": 15.0, "commands_run": ["nmap -sC -sV 10.10.11.50"], "output_snippet": "Found web server"},
                {"iteration": 2, "status": "completed", "duration": 20.0, "commands_run": ["sudo -l", "cat /root/root.txt"], "output_snippet": "Rooted!"},
            ],
        }

        writeup = reporter.generate_writeup(state)
        assert "# CTF Writeup: TestBox" in writeup
        assert "e4d909c290d0fb1ca068ffaddf22cbd0" in writeup
        assert "f1e2d3c4b5a60718293a4b5c6d7e8f90" in writeup
        assert "nmap -sC -sV 10.10.11.50" in writeup
        assert "[COMPLETED - ALL CONDITIONS MET]" in writeup

        json_report = reporter.generate_json_report(state)
        assert "clawper_version" in json_report
        assert "TestBox" in json_report

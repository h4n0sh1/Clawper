"""
Workspace and state persistence manager.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


@dataclass
class FlagRecord:
    flag: str
    source: str
    discovered_at: float = field(default_factory=time.time)
    iteration: int = 0
    flag_type: str = "unknown"  # "user", "root", "generic"


class WorkspaceManager:
    """
    Manages CTF directories, persistence, state saving, and artifact tracking.
    """

    SUBDIRS = ["recon", "exploits", "loot", "flags", "notes", "logs"]

    def __init__(self, root_dir: str | Path = "./clawper_workspace"):
        self.root_dir = Path(root_dir).resolve()
        self.recon_dir = self.root_dir / "recon"
        self.exploits_dir = self.root_dir / "exploits"
        self.loot_dir = self.root_dir / "loot"
        self.flags_dir = self.root_dir / "flags"
        self.notes_dir = self.root_dir / "notes"
        self.logs_dir = self.root_dir / "logs"

    def initialize(self) -> None:
        """Create workspace directories if they do not exist."""
        self.root_dir.mkdir(parents=True, exist_ok=True)
        for subdir in self.SUBDIRS:
            (self.root_dir / subdir).mkdir(parents=True, exist_ok=True)

    def log_iteration(self, iteration: int, prompt: str, output: str, status: str) -> Path:
        """Log iteration prompt and response to disk."""
        log_file = self.logs_dir / f"iteration_{iteration:04d}.log"
        content = (
            f"=== ITERATION {iteration} [{status.upper()}] ===\n"
            f"TIMESTAMP: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"--- PROMPT ---\n{prompt}\n\n"
            f"--- AGENT OUTPUT ---\n{output}\n"
        )
        log_file.write_text(content, encoding="utf-8")
        return log_file

    def save_flag(self, flag: str, source: str = "unknown", iteration: int = 0, flag_type: str = "generic") -> None:
        """Persist a captured flag to disk."""
        flags_txt = self.flags_dir / "flags.txt"
        flags_json = self.flags_dir / "flags.json"

        # Update flags.txt
        existing_flags = set()
        if flags_txt.exists():
            existing_flags = set(flags_txt.read_text(encoding="utf-8").splitlines())
        if flag not in existing_flags:
            with open(flags_txt, "a", encoding="utf-8") as f:
                f.write(f"{flag}\n")

        # Update flags.json
        records: List[Dict[str, Any]] = []
        if flags_json.exists():
            try:
                records = json.loads(flags_json.read_text(encoding="utf-8"))
            except Exception:
                records = []

        # Avoid duplicate flag records
        if not any(r.get("flag") == flag for r in records):
            record = FlagRecord(flag=flag, source=source, iteration=iteration, flag_type=flag_type)
            records.append(asdict(record))
            flags_json.write_text(json.dumps(records, indent=2), encoding="utf-8")

        # Mirror to flags/user.txt or flags/root.txt only on an explicit type.
        # Sniffing the source string for "user"/"root" mislabels anything found
        # in a path that happens to contain those words.
        if flag_type == "user":
            (self.flags_dir / "user.txt").write_text(f"{flag}\n", encoding="utf-8")
        elif flag_type == "root":
            (self.flags_dir / "root.txt").write_text(f"{flag}\n", encoding="utf-8")

    def get_captured_flags(self) -> List[Dict[str, Any]]:
        """Retrieve all captured flag records."""
        flags_json = self.flags_dir / "flags.json"
        if flags_json.exists():
            try:
                return json.loads(flags_json.read_text(encoding="utf-8"))
            except Exception:
                pass

        flags_txt = self.flags_dir / "flags.txt"
        if flags_txt.exists():
            lines = [l.strip() for l in flags_txt.read_text(encoding="utf-8").splitlines() if l.strip()]
            return [{"flag": l, "source": "flags.txt", "iteration": 0, "flag_type": "generic"} for l in lines]

        return []

    def save_state(self, state: Dict[str, Any], filename: str = "clawper_state.json") -> Path:
        """Save engine state to JSON file."""
        state_path = self.root_dir / filename
        state_path.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
        return state_path

    def load_state(self, filename: str = "clawper_state.json") -> Optional[Dict[str, Any]]:
        """Load engine state from JSON file if it exists."""
        state_path = self.root_dir / filename
        if state_path.exists():
            try:
                return json.loads(state_path.read_text(encoding="utf-8"))
            except Exception:
                return None
        return None

    def list_artifacts(self) -> Dict[str, List[str]]:
        """List all files in workspace categories."""
        artifacts: Dict[str, List[str]] = {}
        for subdir in self.SUBDIRS:
            s_dir = self.root_dir / subdir
            if s_dir.exists():
                artifacts[subdir] = [f.name for f in s_dir.iterdir() if f.is_file()]
            else:
                artifacts[subdir] = []
        return artifacts

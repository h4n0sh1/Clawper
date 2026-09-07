"""
CTF Writeup and Report generator.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from clawper.config import ClawperConfig


class CTFReporter:
    """Generates Markdown writeups and JSON execution reports."""

    def __init__(self, workspace_dir: Path, config: ClawperConfig):
        self.workspace_dir = workspace_dir
        self.config = config

    def generate_writeup(self, state: Dict[str, Any], output_path: Optional[Path] = None) -> str:
        """Create a Markdown CTF writeup."""
        target_summary = self.config.target.summary()
        started_at = state.get("started_at", time.time())
        completed_at = state.get("completed_at", time.time())
        duration = int(completed_at - started_at) if (completed_at and started_at) else 0

        flags = state.get("captured_flags", [])
        iterations = state.get("iterations_completed", 0)
        success = state.get("success", False)

        lines = [
            f"# CTF Writeup: {self.config.target.box_name or 'Target Challenge'}",
            "",
            f"- **Target**: {target_summary}",
            f"- **Status**: {'[COMPLETED - ALL CONDITIONS MET]' if success else '[IN PROGRESS / PARTIAL]'}",
            f"- **Total Iterations**: {iterations}",
            f"- **Total Duration**: {duration} seconds",
            f"- **Date**: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(completed_at))}",
            "",
            "## 1. Executive Summary",
            "",
            f"The Clawper autonomous wrapper drove Claude Code to investigate and compromise `{target_summary}`.",
            f"All required success conditions were evaluated and **{'SATISFIED' if success else 'NOT YET SATISFIED'}**.",
            "",
            "## 2. Flags Captured",
            "",
        ]

        if flags:
            lines.append("| Flag | Type | Source | Iteration |")
            lines.append("| --- | --- | --- | --- |")
            for f in flags:
                flag_val = f.get("flag", str(f)) if isinstance(f, dict) else str(f)
                ftype = f.get("flag_type", "generic") if isinstance(f, dict) else "generic"
                fsrc = f.get("source", "output") if isinstance(f, dict) else "output"
                fiter = f.get("iteration", "-") if isinstance(f, dict) else "-"
                lines.append(f"| `{flag_val}` | {ftype} | {fsrc} | {fiter} |")
        else:
            lines.append("No flags captured yet.")

        lines.extend([
            "",
            "## 3. Attack Methodology & Timeline",
            "",
        ])

        history = state.get("history", [])
        if history:
            for item in history:
                it_num = item.get("iteration", 1)
                stat = item.get("status", "completed")
                dur = item.get("duration", 0)
                cmds = item.get("commands_run", [])
                lines.append(f"### Iteration {it_num} ({stat}, {dur:.1f}s)")
                if cmds:
                    lines.append("**Commands executed:**")
                    lines.append("```bash")
                    for c in cmds[:10]:
                        lines.append(c)
                    lines.append("```")
                # Add snippet of output summary
                snippet = item.get("output_snippet", "")
                if snippet:
                    lines.append(f"> {snippet}")
                lines.append("")
        else:
            lines.append("No iteration history recorded.")

        lines.extend([
            "## 4. Discovered Artifacts & Loot",
            "",
        ])

        recon_files = list((self.workspace_dir / "recon").glob("*")) if (self.workspace_dir / "recon").exists() else []
        loot_files = list((self.workspace_dir / "loot").glob("*")) if (self.workspace_dir / "loot").exists() else []

        lines.append(f"- **Recon Scans**: {len(recon_files)} files ({', '.join(f.name for f in recon_files[:5]) or 'none'})")
        lines.append(f"- **Loot & Hashes**: {len(loot_files)} files ({', '.join(f.name for f in loot_files[:5]) or 'none'})")

        lines.extend([
            "",
            "## 5. Conclusion & Recommendations",
            "",
            f"Autonomous run ended with success={success}. All conditions were rigorously verified by Clawper.",
            "",
            "---",
            "*Generated automatically by Clawper - Autonomous CTF Wrapper for Claude Code.*",
        ])

        writeup_content = "\n".join(lines)
        if output_path:
            output_path.write_text(writeup_content, encoding="utf-8")
        else:
            target_out = self.workspace_dir / self.config.execution.writeup_path
            target_out.write_text(writeup_content, encoding="utf-8")

        return writeup_content

    def generate_json_report(self, state: Dict[str, Any], output_path: Optional[Path] = None) -> str:
        """Create a machine-readable JSON execution report."""
        report = {
            "clawper_version": "0.1.0",
            "target": self.config.target.__dict__,
            "state": state,
            "config": self.config.to_dict(),
            "generated_at": time.time(),
        }
        content = json.dumps(report, indent=2, default=str)
        if output_path:
            output_path.write_text(content, encoding="utf-8")
        else:
            (self.workspace_dir / "report.json").write_text(content, encoding="utf-8")
        return content

"""
Flag detection and verification condition.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set

from clawper.conditions.base import ConditionResult, EvaluationContext, SuccessCondition
from clawper.config import FlagConditionConfig


class FlagCondition(SuccessCondition):
    """
    Evaluates whether required CTF flags have been obtained and verified.
    Scans agent output, history, and workspace files for flag patterns.
    """

    def __init__(self, config: Optional[FlagConditionConfig] = None, name: str = "FlagCondition"):
        super().__init__(name=name)
        self.config = config or FlagConditionConfig()
        self._compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.config.patterns]
        self.user_pattern = re.compile(self.config.user_flag_pattern, re.IGNORECASE) if self.config.user_flag_pattern else None
        self.root_pattern = re.compile(self.config.root_flag_pattern, re.IGNORECASE) if self.config.root_flag_pattern else None

    def _extract_from_text(self, text: str) -> Set[str]:
        """Extract all matching flags from raw text."""
        flags = set()
        if not text:
            return flags

        for pattern in self._compiled_patterns:
            matches = pattern.findall(text)
            for m in matches:
                # If regex returns tuples (groups), pick non-empty or full match
                if isinstance(m, tuple):
                    m = next((item for item in m if item), "")
                if m:
                    # Clean up quotes / whitespace
                    cleaned = m.strip().strip("'\"`")
                    # Filter out obvious false positives like all 0000s or common hashes if they don't look like flags
                    if len(cleaned) >= 8:
                        flags.add(cleaned)
        return flags

    def _scan_workspace_files(self, workspace_dir: Optional[Path]) -> Dict[str, Set[str]]:
        """Scan workspace directories and files for flag content."""
        found_in_files: Dict[str, Set[str]] = {}
        if not workspace_dir or not workspace_dir.exists():
            return found_in_files

        # Scan for flag files specifically (user.txt, root.txt, etc.)
        for file_path in workspace_dir.rglob("*"):
            if not file_path.is_file():
                continue
            # Skip hidden files or git directories
            if any(part.startswith(".") for part in file_path.parts):
                continue
            # Scan text files, json files, log files, or specific flag names
            fname_lower = file_path.name.lower()
            is_candidate = (
                any(flag_name in fname_lower for flag_name in self.config.flag_files)
                or fname_lower.endswith((".txt", ".json", ".log", ".out"))
            )
            if not is_candidate:
                continue

            try:
                # Limit size to 1MB to prevent scanning giant binaries
                if file_path.stat().st_size > 1024 * 1024:
                    continue
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                extracted = self._extract_from_text(content)
                if extracted:
                    found_in_files[str(file_path.relative_to(workspace_dir))] = extracted
            except Exception:
                continue

        return found_in_files

    def evaluate(self, context: EvaluationContext) -> ConditionResult:
        all_flags: Set[str] = set()
        sources: Dict[str, List[str]] = {}

        # 1. Check current agent output
        out_flags = self._extract_from_text(context.agent_output)
        if out_flags:
            all_flags.update(out_flags)
            sources["current_output"] = sorted(list(out_flags))

        # 2. Check previous agent outputs
        for idx, prev_out in enumerate(context.all_outputs):
            prev_flags = self._extract_from_text(prev_out)
            if prev_flags:
                all_flags.update(prev_flags)
                sources[f"output_iter_{idx+1}"] = sorted(list(prev_flags))

        # 3. Check workspace files
        file_flags_map = self._scan_workspace_files(context.workspace_dir)
        for rel_path, flags_in_file in file_flags_map.items():
            all_flags.update(flags_in_file)
            sources[f"file:{rel_path}"] = sorted(list(flags_in_file))

        # 4. Check already recorded flags in state
        state_flags = context.state.get("captured_flags", [])
        for sf in state_flags:
            if isinstance(sf, dict):
                flag_val = sf.get("flag") or sf.get("value")
                if flag_val:
                    all_flags.add(flag_val)
            elif isinstance(sf, str):
                all_flags.add(sf)

        # Check against specific flags if configured
        if self.config.specific_flags:
            missing_specific = [f for f in self.config.specific_flags if f not in all_flags]
            met_specific = len(missing_specific) == 0
        else:
            missing_specific = []
            met_specific = True

        # Check required count
        total_unique = len(all_flags)
        met_count = total_unique >= self.config.required_count

        # Check user/root flag distinction if enabled
        user_flag_found = False
        root_flag_found = False

        if self.config.require_user_flag:
            if self.user_pattern:
                user_flag_found = any(self.user_pattern.search(f) for f in all_flags)
            else:
                # Check if user.txt exists in file flags or output mentions user flag
                user_flag_found = any("user" in src.lower() for src in sources.keys()) or total_unique >= 1

        if self.config.require_root_flag:
            if self.root_pattern:
                root_flag_found = any(self.root_pattern.search(f) for f in all_flags)
            else:
                # Check if root.txt exists in file flags or output mentions root flag
                root_flag_found = any("root" in src.lower() for src in sources.keys()) or total_unique >= 2

        user_root_met = True
        if self.config.require_user_flag and not user_flag_found:
            user_root_met = False
        if self.config.require_root_flag and not root_flag_found:
            user_root_met = False

        met = met_count and met_specific and user_root_met

        details_parts = [
            f"Captured {total_unique}/{self.config.required_count} unique flags."
        ]
        if all_flags:
            details_parts.append(f"Flags: {', '.join(sorted(list(all_flags)))}")
        if self.config.specific_flags and missing_specific:
            details_parts.append(f"Missing specific flags: {', '.join(missing_specific)}")
        if self.config.require_user_flag:
            details_parts.append(f"User flag: {'[YES]' if user_flag_found else '[NO]'}")
        if self.config.require_root_flag:
            details_parts.append(f"Root flag: {'[YES]' if root_flag_found else '[NO]'}")

        return ConditionResult(
            name=self.name,
            met=met,
            details=" ".join(details_parts),
            data={
                "captured_flags": sorted(list(all_flags)),
                "sources": sources,
                "count": total_unique,
                "required_count": self.config.required_count,
                "user_flag_found": user_flag_found,
                "root_flag_found": root_flag_found,
            },
        )

"""
File presence verification condition.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from clawper.conditions.base import ConditionResult, EvaluationContext, SuccessCondition
from clawper.config import FileConditionConfig


class FileVerificationCondition(SuccessCondition):
    """
    Evaluates whether required files (proofs, hashes, dumps) exist in the workspace.
    """

    def __init__(self, config: Optional[FileConditionConfig] = None, name: str = "FileVerification"):
        super().__init__(name=name)
        self.config = config or FileConditionConfig()

    def evaluate(self, context: EvaluationContext) -> ConditionResult:
        if not self.config.enabled or not self.config.required_files:
            return ConditionResult(name=self.name, met=True, details="File verification disabled.")

        if not context.workspace_dir:
            return ConditionResult(name=self.name, met=False, details="Workspace directory not configured.")

        found = []
        missing = []

        for req_file in self.config.required_files:
            file_path = context.workspace_dir / req_file
            if file_path.exists() and file_path.is_file():
                found.append(req_file)
            else:
                # Also check matching anywhere in subdirectories
                matches = list(context.workspace_dir.rglob(req_file))
                if matches and any(m.is_file() for m in matches):
                    found.append(req_file)
                else:
                    missing.append(req_file)

        met = len(missing) == 0
        details = f"Found {len(found)}/{len(self.config.required_files)} required files."
        if missing:
            details += f" Missing: {', '.join(missing)}."

        return ConditionResult(
            name=self.name,
            met=met,
            details=details,
            data={"found": found, "missing": missing},
        )

"""
External validation script execution condition.
"""

from __future__ import annotations

import subprocess
from typing import Optional

from clawper.conditions.base import ConditionResult, EvaluationContext, SuccessCondition
from clawper.config import ScriptConditionConfig


class ScriptVerificationCondition(SuccessCondition):
    """
    Executes a custom shell command / script to test success criteria.
    Success is determined by matching the expected exit code.
    """

    def __init__(self, config: Optional[ScriptConditionConfig] = None, name: str = "ScriptVerification"):
        super().__init__(name=name)
        self.config = config or ScriptConditionConfig()

    def evaluate(self, context: EvaluationContext) -> ConditionResult:
        if not self.config.enabled or not self.config.command:
            return ConditionResult(name=self.name, met=True, details="Script verification disabled.")

        try:
            res = subprocess.run(
                self.config.command,
                shell=True,
                cwd=str(context.workspace_dir) if context.workspace_dir else None,
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
            )
            met = res.returncode == self.config.expected_exit_code
            output_snippet = (res.stdout.strip() or res.stderr.strip())[:200]
            details = (
                f"Command '{self.config.command}' returned {res.returncode} "
                f"(expected {self.config.expected_exit_code}). Output: {output_snippet}"
            )
            return ConditionResult(
                name=self.name,
                met=met,
                details=details,
                data={
                    "returncode": res.returncode,
                    "stdout": res.stdout,
                    "stderr": res.stderr,
                },
            )
        except subprocess.TimeoutExpired:
            return ConditionResult(
                name=self.name,
                met=False,
                details=f"Command '{self.config.command}' timed out after {self.config.timeout}s.",
            )
        except Exception as e:
            return ConditionResult(
                name=self.name,
                met=False,
                details=f"Command '{self.config.command}' error: {e}",
            )

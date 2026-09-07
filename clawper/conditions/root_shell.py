"""
Root / Administrator privilege escalation verification condition.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Optional

from clawper.conditions.base import ConditionResult, EvaluationContext, SuccessCondition
from clawper.config import RootConditionConfig


class RootVerificationCondition(SuccessCondition):
    """
    Evaluates whether root or administrative access has been attained.
    Can check output signatures, run verification commands, or check proof files.
    """

    def __init__(self, config: Optional[RootConditionConfig] = None, name: str = "RootVerification"):
        super().__init__(name=name)
        self.config = config or RootConditionConfig()

    def evaluate(self, context: EvaluationContext) -> ConditionResult:
        if not self.config.enabled:
            return ConditionResult(name=self.name, met=True, details="Root condition disabled (satisfied by default).")

        evidence = []
        is_root = False

        # 1. Output signature checking
        all_text = " ".join([context.agent_output] + context.all_outputs)
        for sig in self.config.root_signatures:
            if sig.lower() in all_text.lower():
                is_root = True
                evidence.append(f"Found root signature in output: '{sig}'")
                break

        # 2. Proof file check
        if self.config.proof_file and context.workspace_dir:
            proof_path = context.workspace_dir / self.config.proof_file
            if proof_path.exists():
                is_root = True
                evidence.append(f"Found root proof file: {self.config.proof_file}")

        # 3. Check command execution if specified
        if self.config.check_command:
            try:
                res = subprocess.run(
                    self.config.check_command,
                    shell=True,
                    cwd=str(context.workspace_dir) if context.workspace_dir else None,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if res.returncode == 0:
                    is_root = True
                    evidence.append(f"Root check command '{self.config.check_command}' succeeded (exit code 0)")
                else:
                    evidence.append(f"Root check command returned non-zero ({res.returncode}): {res.stderr.strip() or res.stdout.strip()}")
            except Exception as e:
                evidence.append(f"Root check command failed: {e}")

        details = "; ".join(evidence) if evidence else "No root privilege evidence detected."
        return ConditionResult(
            name=self.name,
            met=is_root,
            details=f"Root verification {'[PASSED]' if is_root else '[FAILED]'}: {details}",
            data={"evidence": evidence, "is_root": is_root},
        )

"""
Composite condition evaluator combining all active conditions.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from clawper.conditions.base import ConditionResult, EvaluationContext, SuccessCondition
from clawper.conditions.file_check import FileVerificationCondition
from clawper.conditions.flags import FlagCondition
from clawper.conditions.root_shell import RootVerificationCondition
from clawper.conditions.custom_script import ScriptVerificationCondition
from clawper.config import ClawperConfig


class CompositeCondition(SuccessCondition):
    """
    Evaluates multiple success conditions together.
    All enabled conditions must be satisfied for overall success.
    """

    def __init__(self, conditions: Optional[List[SuccessCondition]] = None, name: str = "CompositeCondition"):
        super().__init__(name=name)
        self.conditions: List[SuccessCondition] = conditions or []

    @classmethod
    def from_config(cls, config: ClawperConfig) -> "CompositeCondition":
        conditions: List[SuccessCondition] = []

        # 1. Flag condition (always enabled by default with target count)
        conditions.append(FlagCondition(config.flags, name="Flags"))

        # 2. Root condition
        if config.root.enabled:
            conditions.append(RootVerificationCondition(config.root, name="RootAccess"))

        # 3. File condition
        if config.files.enabled:
            conditions.append(FileVerificationCondition(config.files, name="RequiredFiles"))

        # 4. Script condition
        if config.script.enabled:
            conditions.append(ScriptVerificationCondition(config.script, name="CustomScript"))

        return cls(conditions=conditions)

    def add_condition(self, condition: SuccessCondition) -> None:
        self.conditions.append(condition)

    def evaluate(self, context: EvaluationContext) -> ConditionResult:
        sub_results: Dict[str, ConditionResult] = {}
        all_met = True
        missing_descriptions = []
        met_descriptions = []

        for cond in self.conditions:
            res = cond.evaluate(context)
            sub_results[cond.name] = res
            if not res.met:
                all_met = False
                missing_descriptions.append(f"[{cond.name}: NOT MET] {res.details}")
            else:
                met_descriptions.append(f"[{cond.name}: MET] {res.details}")

        summary_lines = []
        if all_met:
            summary_lines.append("ALL SUCCESS CONDITIONS SATISFIED!")
            summary_lines.extend(met_descriptions)
        else:
            summary_lines.append(f"SUCCESS CONDITIONS NOT MET ({len(missing_descriptions)} remaining):")
            summary_lines.extend(missing_descriptions)
            if met_descriptions:
                summary_lines.append("Satisfied conditions:")
                summary_lines.extend(met_descriptions)

        return ConditionResult(
            name=self.name,
            met=all_met,
            details="\n".join(summary_lines),
            data={
                "all_met": all_met,
                "sub_results": {k: v.__dict__ for k, v in sub_results.items()},
                "missing": missing_descriptions,
                "satisfied": met_descriptions,
            },
        )

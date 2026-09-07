"""
Success condition modules for Clawper.
"""

from clawper.conditions.base import ConditionResult, EvaluationContext, SuccessCondition
from clawper.conditions.composite import CompositeCondition
from clawper.conditions.custom_script import ScriptVerificationCondition
from clawper.conditions.file_check import FileVerificationCondition
from clawper.conditions.flags import FlagCondition
from clawper.conditions.root_shell import RootVerificationCondition

__all__ = [
    "SuccessCondition",
    "ConditionResult",
    "EvaluationContext",
    "FlagCondition",
    "RootVerificationCondition",
    "FileVerificationCondition",
    "ScriptVerificationCondition",
    "CompositeCondition",
]

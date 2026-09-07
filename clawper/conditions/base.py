"""
Base classes for success conditions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ConditionResult:
    """Result of evaluating a single condition."""
    name: str
    met: bool
    details: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.met


@dataclass
class EvaluationContext:
    """Context passed to condition evaluators."""
    agent_output: str = ""
    workspace_dir: Optional[Path] = None
    state: Dict[str, Any] = field(default_factory=dict)
    iteration: int = 0
    all_outputs: List[str] = field(default_factory=list)


class SuccessCondition(ABC):
    """Abstract base class for all success conditions."""

    def __init__(self, name: str = "BaseCondition"):
        self.name = name

    @abstractmethod
    def evaluate(self, context: EvaluationContext) -> ConditionResult:
        """Evaluate the condition against current context."""
        pass

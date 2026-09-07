"""
Base agent driver interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


@dataclass
class AgentResponse:
    """Standardized response from an agent iteration."""
    output: str = ""
    raw_output: str = ""
    commands_run: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    exit_code: int = 0
    duration_seconds: float = 0.0
    status: str = "completed"  # "completed", "errored", "timeout", "interrupted"
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_success(self) -> bool:
        return self.status == "completed" and self.exit_code == 0


class AgentDriver(ABC):
    """Abstract interface for agent execution engines."""

    def __init__(self, name: str = "BaseAgent"):
        self.name = name

    @abstractmethod
    def run_iteration(
        self,
        prompt: str,
        session_id: Optional[str] = None,
        workspace_dir: Optional[Path] = None,
        stream_callback: Optional[Callable[[str], None]] = None,
    ) -> AgentResponse:
        """Run a single prompt/iteration against the agent."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the agent binary / environment is installed and usable."""
        pass

    def cleanup(self) -> None:
        """Clean up any active processes or resources."""
        pass

"""
Base agent driver interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# Canonical agent iteration statuses, shared across the engine, prompts and
# agent drivers so all modules agree on the same literals.
STATUS_COMPLETED = "completed"
STATUS_ERRORED = "errored"
STATUS_TIMEOUT = "timeout"
STATUS_INTERRUPTED = "interrupted"
AGENT_ERROR_STATUSES = (STATUS_ERRORED, STATUS_TIMEOUT, STATUS_INTERRUPTED)

_STATUS_DESCRIPTIONS = {
    STATUS_TIMEOUT: "took too long to respond and was terminated",
    STATUS_ERRORED: "crashed or raised an error",
    STATUS_INTERRUPTED: "was interrupted before finishing",
}


def describe_agent_status(status: str) -> str:
    """Human-readable description of a non-completed agent status, for logs/prompts."""
    return _STATUS_DESCRIPTIONS.get(status, f"ended with status '{status}'")


@dataclass
class AgentResponse:
    """Standardized response from an agent iteration."""
    output: str = ""
    raw_output: str = ""
    commands_run: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    exit_code: int = 0
    duration_seconds: float = 0.0
    status: str = STATUS_COMPLETED  # "completed", "errored", "timeout", "interrupted"
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_success(self) -> bool:
        return self.status == STATUS_COMPLETED and self.exit_code == 0


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

    def reset_session(self) -> None:
        """Drop any in-process conversation continuity so the next iteration
        starts a fresh agent session. Default no-op; drivers that keep
        cross-iteration session state should override this."""
        return None

    def cleanup(self) -> None:
        """Clean up any active processes or resources."""
        pass

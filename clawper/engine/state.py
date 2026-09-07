"""
State tracking and persistence for the Clawper engine.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from clawper.agents.base import STATUS_COMPLETED


@dataclass
class IterationHistoryItem:
    iteration: int
    prompt_snippet: str
    output_snippet: str
    status: str
    duration: float
    commands_run: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    error_message: Optional[str] = None


@dataclass
class EngineState:
    """Represents the complete runtime state of a Clawper CTF session."""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    iterations_completed: int = 0
    captured_flags: List[Dict[str, Any]] = field(default_factory=list)
    history: List[Dict[str, Any]] = field(default_factory=list)
    success: bool = False
    condition_summary: str = ""
    last_output: str = ""
    stalls_count: int = 0
    phase: str = "recon"  # "recon", "enum", "exploit", "privesc", "looting", "completed"
    consecutive_errors: int = 0
    total_errors: int = 0
    last_error: Optional[str] = None
    last_agent_status: str = STATUS_COMPLETED

    def add_flag(self, flag: str, source: str = "output", iteration: int = 0, flag_type: str = "generic") -> bool:
        """Add flag if not already present. Returns True if flag is new."""
        for existing in self.captured_flags:
            if isinstance(existing, dict) and existing.get("flag") == flag:
                return False
            elif isinstance(existing, str) and existing == flag:
                return False

        self.captured_flags.append({
            "flag": flag,
            "source": source,
            "iteration": iteration,
            "flag_type": flag_type,
            "discovered_at": time.time(),
        })
        return True

    def record_iteration(
        self,
        iteration: int,
        prompt: str,
        output: str,
        status: str,
        duration: float,
        commands_run: Optional[List[str]] = None,
        error_message: Optional[str] = None,
    ) -> None:
        self.iterations_completed = iteration
        self.last_output = output

        # Keep output snippet around ~500 chars for clean summaries
        prompt_snip = (prompt[:250] + "...") if len(prompt) > 250 else prompt
        output_snip = (output[:500] + "...") if len(output) > 500 else output

        item = IterationHistoryItem(
            iteration=iteration,
            prompt_snippet=prompt_snip,
            output_snippet=output_snip,
            status=status,
            duration=duration,
            commands_run=commands_run or [],
            timestamp=time.time(),
            error_message=error_message,
        )
        self.history.append(asdict(item))

    def record_agent_error(self, error_message: str) -> None:
        """Track that an agent iteration failed/errored so the loop can react and recover."""
        self.consecutive_errors += 1
        self.total_errors += 1
        self.last_error = error_message

    def record_agent_success(self) -> None:
        """Reset the consecutive error streak after a successfully completed iteration."""
        self.consecutive_errors = 0
        self.last_error = None

    def update_phase(self, req_flags: int = 1, is_root: bool = False) -> None:
        num_flags = len(self.captured_flags)
        if self.success or (num_flags >= req_flags and is_root):
            self.phase = "completed"
        elif is_root or num_flags >= 1:
            self.phase = "privesc" if not is_root else "looting"
        elif self.iterations_completed >= 2:
            self.phase = "exploit"
        elif self.iterations_completed >= 1:
            self.phase = "enum"
        else:
            self.phase = "recon"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EngineState":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

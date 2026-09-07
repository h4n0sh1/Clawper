"""
Mock Agent Driver for testing and simulation.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, List, Optional, Sequence

from clawper.agents.base import AgentDriver, AgentResponse
from clawper.config import AgentConfig


class MockAgentDriver(AgentDriver):
    """
    Mock agent driver that returns pre-configured or stage-based responses.
    Useful for unit tests, offline validation, and benchmarks.
    """

    def __init__(
        self,
        responses: Optional[Sequence[str | AgentResponse]] = None,
        config: Optional[AgentConfig] = None,
        name: str = "MockAgent",
        delay_per_iteration: float = 0.0,
    ):
        super().__init__(name=name)
        self.config = config or AgentConfig(driver_type="mock")
        self.responses: List[str | AgentResponse] = list(responses) if responses else []
        self.current_step = 0
        self.delay_per_iteration = delay_per_iteration
        self.received_prompts: List[str] = []

    def is_available(self) -> bool:
        return True

    def set_responses(self, responses: Sequence[str | AgentResponse]) -> None:
        self.responses = list(responses)
        self.current_step = 0

    def run_iteration(
        self,
        prompt: str,
        session_id: Optional[str] = None,
        workspace_dir: Optional[Path] = None,
        stream_callback: Optional[Callable[[str], None]] = None,
    ) -> AgentResponse:
        self.received_prompts.append(prompt)

        if self.delay_per_iteration > 0:
            time.sleep(self.delay_per_iteration)

        if self.responses and self.current_step < len(self.responses):
            resp = self.responses[self.current_step]
            self.current_step += 1
            if isinstance(resp, AgentResponse):
                if stream_callback and resp.output:
                    for line in resp.output.splitlines(keepends=True):
                        stream_callback(line)
                return resp
            else:
                out_text = str(resp)
                if stream_callback:
                    for line in out_text.splitlines(keepends=True):
                        stream_callback(line)
                return AgentResponse(
                    output=out_text,
                    raw_output=out_text,
                    exit_code=0,
                    status="completed",
                    duration_seconds=0.01,
                )

        # Default fallback response if ran out of scripted responses
        fallback_text = (
            f"[MockAgent Step {self.current_step + 1}] Processing prompt.\n"
            f"No specific response configured for step {self.current_step + 1}."
        )
        self.current_step += 1
        if stream_callback:
            stream_callback(fallback_text)

        return AgentResponse(
            output=fallback_text,
            raw_output=fallback_text,
            exit_code=0,
            status="completed",
            duration_seconds=0.01,
        )

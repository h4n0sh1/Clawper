"""
Agent driver modules for Clawper.
"""

from typing import Optional

from clawper.agents.base import AgentDriver, AgentResponse
from clawper.agents.claude_code import ClaudeCodeDriver
from clawper.agents.custom_command import CommandAgentDriver
from clawper.agents.mock import MockAgentDriver
from clawper.config import AgentConfig


def create_agent_driver(config: Optional[AgentConfig] = None) -> AgentDriver:
    """Factory function to instantiate the configured agent driver."""
    cfg = config or AgentConfig()
    dtype = (cfg.driver_type or "claude_code").lower()

    if dtype in ("claude_code", "claude"):
        return ClaudeCodeDriver(cfg)
    elif dtype in ("mock", "test", "sim"):
        return MockAgentDriver(config=cfg)
    elif dtype in ("command", "cmd", "custom"):
        return CommandAgentDriver(cfg)
    else:
        raise ValueError(f"Unknown agent driver type: '{cfg.driver_type}'. Supported: claude_code, mock, command")


__all__ = [
    "AgentDriver",
    "AgentResponse",
    "ClaudeCodeDriver",
    "MockAgentDriver",
    "CommandAgentDriver",
    "create_agent_driver",
]

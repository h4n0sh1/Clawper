"""
Clawper - Autonomous & Unattended CTF Wrapper for Claude Code.
"""

__version__ = "0.1.0"
__author__ = "Clawper Team"

from clawper.config import ClawperConfig, TargetConfig, AgentConfig, ExecutionConfig
from clawper.engine.supervisor import ClawperEngine

__all__ = [
    "ClawperConfig",
    "TargetConfig",
    "AgentConfig",
    "ExecutionConfig",
    "ClawperEngine",
    "__version__",
]

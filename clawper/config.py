"""
Configuration models and loaders for Clawper.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml


@dataclass
class TargetConfig:
    """Target environment and metadata."""
    host: Optional[str] = None
    ip: Optional[str] = None
    domain: Optional[str] = None
    box_name: Optional[str] = None
    platform: str = "generic"  # e.g., "htb", "thm", "prolab", "generic"
    scope: List[str] = field(default_factory=list)
    credentials: Dict[str, str] = field(default_factory=dict)
    hints: List[str] = field(default_factory=list)

    def summary(self) -> str:
        parts = []
        if self.box_name:
            parts.append(f"Box: {self.box_name}")
        if self.ip:
            parts.append(f"IP: {self.ip}")
        if self.host:
            parts.append(f"Host: {self.host}")
        if self.domain:
            parts.append(f"Domain: {self.domain}")
        if self.platform:
            parts.append(f"Platform: {self.platform}")
        return " | ".join(parts) if parts else "Generic CTF Target"


@dataclass
class FlagConditionConfig:
    """Configuration for flag detection and verification."""
    required_count: int = 1
    # Built-in or custom regex patterns
    # e.g. ["^[a-f0-9]{32}$", "HTB\\{[^\\}]+\\}", "flag\\{[^\\}]+\\}", "CTF\\{[^\\}]+\\}"]
    patterns: List[str] = field(default_factory=lambda: [
        r"[a-f0-9]{32}",              # HTB standard MD5 format
        r"HTB\{[a-zA-Z0-9_\-\.\!@#\$%\^&\*]+\}",  # HTB format
        r"THM\{[a-zA-Z0-9_\-\.\!@#\$%\^&\*]+\}",  # THM format
        r"flag\{[a-zA-Z0-9_\-\.\!@#\$%\^&\*]+\}", # Standard flag
        r"CTF\{[a-zA-Z0-9_\-\.\!@#\$%\^&\*]+\}",  # CTF format
    ])
    # Exact flag strings required if known beforehand (optional)
    specific_flags: List[str] = field(default_factory=list)
    # Target files to look for flags in on local/target workspace
    flag_files: List[str] = field(default_factory=lambda: [
        "user.txt", "root.txt", "flag.txt", "flags.txt",
    ])
    # Distinction between user and root flags
    require_root_flag: bool = False
    require_user_flag: bool = False
    user_flag_pattern: Optional[str] = None
    root_flag_pattern: Optional[str] = None


@dataclass
class RootConditionConfig:
    """Configuration for root / admin privilege verification."""
    enabled: bool = False
    # Method to verify root: "output_check", "command", "file_proof"
    verification_method: str = "output_check"
    check_command: Optional[str] = None
    proof_file: Optional[str] = None
    # Substrings or regex indicating root in agent execution
    root_signatures: List[str] = field(default_factory=lambda: [
        "uid=0(root)",
        "root@",
        "whoami: root",
        "NT AUTHORITY\\SYSTEM",
        "nt authority\\system",
    ])


@dataclass
class FileConditionConfig:
    """Configuration for required file creation / proof verification."""
    enabled: bool = False
    required_files: List[str] = field(default_factory=list)


@dataclass
class ScriptConditionConfig:
    """Configuration for running an external validation script / command."""
    enabled: bool = False
    command: Optional[str] = None
    expected_exit_code: int = 0
    timeout: int = 30


@dataclass
class AgentConfig:
    """Agent driver configuration."""
    driver_type: str = "claude_code"  # "claude_code", "mock", "command"
    binary_path: str = "claude"
    cli_flags: List[str] = field(default_factory=lambda: [
        "--dangerously-skip-permissions",
    ])
    timeout_per_run: int = 600  # seconds per iteration (default 10 min)
    resume_session: bool = True
    custom_command: Optional[str] = None
    environment: Dict[str, str] = field(default_factory=dict)
    model: Optional[str] = None
    # Stream the agent's actions live (tool calls, text, results) as they happen.
    # Uses `claude --output-format stream-json --verbose` under the hood.
    stream_json: bool = True


@dataclass
class ExecutionConfig:
    """Loop supervisor and unattended execution settings."""
    # If 0 or None, loop runs indefinitely until success conditions are met
    max_iterations: int = 0
    # Delay in seconds between iterations
    loop_delay: float = 2.0
    # Auto-nudge strategy when agent gets stuck or prematurely says done
    auto_nudge: bool = True
    # Auto-detect stall if consecutive iterations make no progress
    stall_detection_threshold: int = 3
    # CTF writeup output path
    writeup_path: str = "WRITEUP.md"
    # State file path
    state_file: str = "clawper_state.json"
    # Auto-save loot/scans
    save_loot: bool = True


@dataclass
class ClawperConfig:
    """Master Clawper configuration."""
    prompt: str = "Root the target box, obtain all flags (user and root), and document your steps."
    target: TargetConfig = field(default_factory=TargetConfig)
    flags: FlagConditionConfig = field(default_factory=FlagConditionConfig)
    root: RootConditionConfig = field(default_factory=RootConditionConfig)
    files: FileConditionConfig = field(default_factory=FileConditionConfig)
    script: ScriptConditionConfig = field(default_factory=ScriptConditionConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    workspace_dir: str = "./clawper_workspace"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ClawperConfig":
        target = TargetConfig(**data.get("target", {})) if "target" in data else TargetConfig()
        flags = FlagConditionConfig(**data.get("flags", {})) if "flags" in data else FlagConditionConfig()
        root = RootConditionConfig(**data.get("root", {})) if "root" in data else RootConditionConfig()
        files = FileConditionConfig(**data.get("files", {})) if "files" in data else FileConditionConfig()
        script = ScriptConditionConfig(**data.get("script", {})) if "script" in data else ScriptConditionConfig()
        agent = AgentConfig(**data.get("agent", {})) if "agent" in data else AgentConfig()
        execution = ExecutionConfig(**data.get("execution", {})) if "execution" in data else ExecutionConfig()

        return cls(
            prompt=data.get("prompt", cls.prompt),
            target=target,
            flags=flags,
            root=root,
            files=files,
            script=script,
            agent=agent,
            execution=execution,
            workspace_dir=data.get("workspace_dir", cls.workspace_dir),
        )

    @classmethod
    def from_yaml(cls, file_path: str | Path) -> "ClawperConfig":
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls.from_dict(data)

    @classmethod
    def from_json(cls, file_path: str | Path) -> "ClawperConfig":
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_yaml(self, file_path: Optional[str | Path] = None) -> str:
        dumped = yaml.safe_dump(self.to_dict(), default_flow_style=False, sort_keys=False)
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(dumped)
        return dumped

    def to_json(self, file_path: Optional[str | Path] = None) -> str:
        dumped = json.dumps(self.to_dict(), indent=2)
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(dumped)
        return dumped

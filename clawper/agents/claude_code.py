"""
Claude Code CLI agent driver.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

from clawper.agents.base import AgentDriver, AgentResponse
from clawper.config import AgentConfig


class ClaudeCodeDriver(AgentDriver):
    """
    Driver that executes Claude Code via the `claude` CLI.
    Runs non-interactively with `--dangerously-skip-permissions` and `-p` prompt.
    """

    def __init__(self, config: Optional[AgentConfig] = None, name: str = "ClaudeCode"):
        super().__init__(name=name)
        self.config = config or AgentConfig()
        self._current_process: Optional[subprocess.Popen] = None
        self._session_count = 0

    def is_available(self) -> bool:
        """Check if `claude` CLI binary is available on system."""
        binary = self.config.binary_path
        return shutil.which(binary) is not None

    def _build_cmd(self, prompt: str, resume: bool = False) -> List[str]:
        cmd = [self.config.binary_path]

        # Flags like --dangerously-skip-permissions
        for flag in self.config.cli_flags:
            if flag and flag not in cmd:
                cmd.append(flag)

        if self.config.model:
            cmd.extend(["--model", self.config.model])

        if resume and self.config.resume_session and self._session_count > 0:
            # If supported, add resume flag
            if "--resume" not in cmd:
                cmd.append("--resume")

        # Non-interactive prompt argument
        cmd.extend(["-p", prompt])
        return cmd

    def run_iteration(
        self,
        prompt: str,
        session_id: Optional[str] = None,
        workspace_dir: Optional[Path] = None,
        stream_callback: Optional[Callable[[str], None]] = None,
    ) -> AgentResponse:
        start_time = time.time()
        cwd = str(workspace_dir) if workspace_dir else os.getcwd()

        # Build command
        cmd = self._build_cmd(prompt, resume=(self._session_count > 0))
        self._session_count += 1

        env = os.environ.copy()
        if self.config.environment:
            env.update(self.config.environment)

        output_chunks: List[str] = []
        commands_run: List[str] = []
        tools_used: List[str] = []
        status = "completed"
        error_msg = None
        exit_code = 0

        try:
            self._current_process = subprocess.Popen(
                cmd,
                cwd=cwd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )

            # Read stream in real-time
            if self._current_process.stdout:
                for line in iter(self._current_process.stdout.readline, ""):
                    output_chunks.append(line)
                    if stream_callback:
                        stream_callback(line)

                    # Light heuristic extraction of commands / tools from CLI output
                    stripped = line.strip()
                    if stripped.startswith("$ ") or stripped.startswith("Running: "):
                        commands_run.append(stripped)
                    elif "Tool:" in stripped or "tool_call:" in stripped:
                        tools_used.append(stripped)

            self._current_process.wait(timeout=self.config.timeout_per_run)
            exit_code = self._current_process.returncode

        except subprocess.TimeoutExpired:
            status = "timeout"
            error_msg = f"Claude Code process timed out after {self.config.timeout_per_run} seconds."
            if self._current_process:
                self._current_process.kill()
                self._current_process.wait()
            exit_code = -1
        except FileNotFoundError:
            status = "errored"
            error_msg = f"Binary '{self.config.binary_path}' not found in PATH."
            exit_code = 127
        except Exception as e:
            status = "errored"
            error_msg = f"Failed to execute Claude Code: {str(e)}"
            exit_code = 1
        finally:
            self._current_process = None

        duration = time.time() - start_time
        full_output = "".join(output_chunks)

        return AgentResponse(
            output=full_output,
            raw_output=full_output,
            commands_run=commands_run,
            tools_used=tools_used,
            exit_code=exit_code,
            duration_seconds=duration,
            status=status,
            error_message=error_msg,
            metadata={"session_count": self._session_count, "command": cmd},
        )

    def cleanup(self) -> None:
        if self._current_process and self._current_process.poll() is None:
            try:
                self._current_process.terminate()
                self._current_process.wait(timeout=2)
            except Exception:
                try:
                    self._current_process.kill()
                except Exception:
                    pass
            self._current_process = None

"""
Generic command / external agent driver.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import Callable, Optional

from clawper.agents.base import AgentDriver, AgentResponse
from clawper.config import AgentConfig


class CommandAgentDriver(AgentDriver):
    """
    Executes a custom CLI command or script as the agent driver.
    The prompt is passed via environment variable `CLAWPER_PROMPT` or stdin.
    """

    def __init__(self, config: Optional[AgentConfig] = None, name: str = "CommandAgent"):
        super().__init__(name=name)
        self.config = config or AgentConfig()
        self._current_process: Optional[subprocess.Popen] = None

    def is_available(self) -> bool:
        if not self.config.custom_command:
            return False
        cmd_parts = shlex.split(self.config.custom_command)
        if not cmd_parts:
            return False
        import shutil
        return shutil.which(cmd_parts[0]) is not None

    def run_iteration(
        self,
        prompt: str,
        session_id: Optional[str] = None,
        workspace_dir: Optional[Path] = None,
        stream_callback: Optional[Callable[[str], None]] = None,
    ) -> AgentResponse:
        if not self.config.custom_command:
            return AgentResponse(
                status="errored",
                error_message="No custom command specified in configuration.",
                exit_code=1,
            )

        start_time = time.time()
        cwd = str(workspace_dir) if workspace_dir else os.getcwd()

        env = os.environ.copy()
        env["CLAWPER_PROMPT"] = prompt
        if session_id:
            env["CLAWPER_SESSION_ID"] = session_id
        if self.config.environment:
            env.update(self.config.environment)

        output_chunks = []
        status = "completed"
        error_msg = None
        exit_code = 0

        try:
            self._current_process = subprocess.Popen(
                self.config.custom_command,
                shell=True,
                cwd=cwd,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )

            # Write prompt to stdin then close stdin
            if self._current_process.stdin:
                try:
                    self._current_process.stdin.write(prompt)
                    self._current_process.stdin.close()
                except Exception:
                    pass

            if self._current_process.stdout:
                for line in iter(self._current_process.stdout.readline, ""):
                    output_chunks.append(line)
                    if stream_callback:
                        stream_callback(line)

            self._current_process.wait(timeout=self.config.timeout_per_run)
            exit_code = self._current_process.returncode

        except subprocess.TimeoutExpired:
            status = "timeout"
            error_msg = f"Command timed out after {self.config.timeout_per_run}s."
            if self._current_process:
                self._current_process.kill()
                self._current_process.wait()
            exit_code = -1
        except Exception as e:
            status = "errored"
            error_msg = f"Command execution failed: {e}"
            exit_code = 1
        finally:
            self._current_process = None

        duration = time.time() - start_time
        full_output = "".join(output_chunks)

        return AgentResponse(
            output=full_output,
            raw_output=full_output,
            exit_code=exit_code,
            duration_seconds=duration,
            status=status,
            error_message=error_msg,
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

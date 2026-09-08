"""
Claude Code CLI agent driver.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from clawper.agents.base import AgentDriver, AgentResponse
from clawper.config import AgentConfig


# Substrings that indicate the CLI rejected our session-continuation attempt
# (e.g. resume with no/stale id, or no prior conversation to continue).
_SESSION_ERROR_SIGNATURES = (
    "--resume requires a valid session id",
    "--resume requires a valid session",
    "no conversation found",
    "no conversation to continue",
    "session id or session title",
    "invalid session id",
)


def _first_meaningful_line(command: str) -> str:
    """Return the first substantive line of a shell command (skip cd/echo/loops)."""
    lines = [l.strip() for l in (command or "").splitlines()]
    noise = ("cd ", "echo ", ": ", "#", "export ", "for ", "do ", "done",
             "if ", "fi", "else", "while ", "sleep ")
    subst = [l for l in lines if l and not l.startswith(noise)]
    return (subst[0] if subst else (lines[0] if lines else "")).strip()


class ClaudeCodeDriver(AgentDriver):
    """
    Driver that executes Claude Code via the `claude` CLI.
    Runs non-interactively with `--dangerously-skip-permissions` and `-p` prompt.

    Cross-iteration continuity uses `--continue` (continues the most recent
    conversation in the workspace directory), which — unlike `--resume` — does
    not require an explicit session id in print mode. If continuation fails for
    any session-related reason, the driver transparently retries once with a
    fresh session so the loop never gets stuck.

    Real-time visibility: when `stream_json` is enabled (default), the driver
    runs the CLI with `--output-format stream-json --verbose` and parses each
    event as it arrives, emitting a concise human-readable line per agent action
    (tool call, reasoning text, tool result, flag) through `stream_callback` —
    so an operator watching the terminal sees what the agent is doing live,
    like a chat transcript.
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

    def reset_session(self) -> None:
        """Force the next iteration to start a brand-new Claude conversation
        (no --continue), dropping the accumulated transcript that the safety
        filter keeps flagging."""
        self._session_count = 0

    def _stream_json_enabled(self) -> bool:
        # Default ON; a config may disable it via agent.stream_json: false.
        return bool(getattr(self.config, "stream_json", True))

    def _build_cmd(self, prompt: str, resume: bool = False) -> List[str]:
        cmd = [self.config.binary_path]

        # Flags like --dangerously-skip-permissions
        for flag in self.config.cli_flags:
            if flag and flag not in cmd:
                cmd.append(flag)

        if self.config.model:
            cmd.extend(["--model", self.config.model])

        # Live, event-by-event output so the operator can watch in real time.
        if self._stream_json_enabled():
            for f in ("--output-format", "stream-json", "--verbose"):
                if f not in cmd:
                    cmd.append(f)

        if resume and self.config.resume_session and self._session_count > 0:
            # Continue the most recent conversation in the cwd. `--continue`
            # works in print mode without an explicit session id, whereas
            # `--resume` demands one and hard-errors otherwise.
            if "--continue" not in cmd and "--resume" not in cmd:
                cmd.append("--continue")

        # Non-interactive prompt argument (kept last)
        cmd.extend(["-p", prompt])
        return cmd

    def _looks_like_session_error(self, output: str, exit_code: int) -> bool:
        if exit_code == 0:
            return False
        low = (output or "").lower()
        return any(sig in low for sig in _SESSION_ERROR_SIGNATURES)

    # ---- stream-json rendering -------------------------------------------------

    @staticmethod
    def _format_tool_use(block: Dict) -> str:
        name = block.get("name", "?")
        inp = block.get("input", {}) or {}
        if name == "Bash":
            return f"⚙  bash  $ {_first_meaningful_line(inp.get('command',''))[:160]}"
        if name in ("Read", "Write", "Edit", "NotebookEdit"):
            return f"⚙  {name.lower():5} {str(inp.get('file_path',''))[:120]}"
        if name == "Grep":
            return f"⚙  grep  {str(inp.get('pattern',''))[:70]} {str(inp.get('path','') or '')[:50]}"
        if name in ("Glob",):
            return f"⚙  glob  {str(inp.get('pattern',''))[:90]}"
        # generic: show first couple of args compactly
        args = ", ".join(f"{k}={str(v)[:40]}" for k, v in list(inp.items())[:2])
        return f"⚙  {name}  {args}"

    def _render_event(self, obj: Dict) -> List[str]:
        """Turn one stream-json event into zero or more display lines."""
        out: List[str] = []
        etype = obj.get("type")
        if etype == "assistant":
            for b in (obj.get("message", {}) or {}).get("content", []) or []:
                bt = b.get("type")
                if bt == "tool_use":
                    out.append(self._format_tool_use(b))
                elif bt == "text":
                    txt = (b.get("text") or "").strip()
                    if txt:
                        out.append(f"💬 {txt[:400]}")
        elif etype == "user":
            # tool results — keep to a short signal so the feed stays readable
            for b in (obj.get("message", {}) or {}).get("content", []) or []:
                if b.get("type") == "tool_result":
                    content = b.get("content", "")
                    if isinstance(content, list):
                        content = " ".join(
                            c.get("text", "") for c in content if isinstance(c, dict)
                        )
                    line = (str(content).strip().splitlines() or [""])[0]
                    if line:
                        out.append(f"   ↳ {line[:150]}")
        elif etype == "result":
            if obj.get("is_error"):
                out.append(f"✗ iteration error: {str(obj.get('result',''))[:160]}")
        return out

    def _exec(
        self,
        cmd: List[str],
        cwd: str,
        env: Dict[str, str],
        stream_callback: Optional[Callable[[str], None]],
    ) -> Tuple[str, int, str, Optional[str], List[str], List[str]]:
        """Run one CLI invocation to completion, streaming output.

        Returns (full_output, exit_code, status, error_msg, commands_run, tools_used).
        """
        raw_chunks: List[str] = []          # raw text kept for flag detection
        commands_run: List[str] = []
        tools_used: List[str] = []
        status = "completed"
        error_msg: Optional[str] = None
        exit_code = 0
        stream_json = self._stream_json_enabled()

        def emit(line: str) -> None:
            if stream_callback and line:
                stream_callback(line if line.endswith("\n") else line + "\n")

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

            if self._current_process.stdout:
                for line in iter(self._current_process.stdout.readline, ""):
                    raw_chunks.append(line)
                    parsed = None
                    if stream_json:
                        s = line.strip()
                        if s.startswith("{"):
                            try:
                                parsed = json.loads(s)
                            except Exception:
                                parsed = None

                    if parsed is not None:
                        for disp in self._render_event(parsed):
                            emit(disp)
                            if disp.startswith("⚙  bash"):
                                commands_run.append(disp)
                            elif disp.startswith("⚙"):
                                tools_used.append(disp)
                    else:
                        # Non-JSON (plain text mode, or an API/CLI error line) — show it.
                        emit(line.rstrip("\n"))
                        stripped = line.strip()
                        if stripped.startswith("$ ") or stripped.startswith("Running: "):
                            commands_run.append(stripped)

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
        except Exception as e:  # noqa: BLE001
            status = "errored"
            error_msg = f"Failed to execute Claude Code: {str(e)}"
            exit_code = 1
        finally:
            self._current_process = None

        full_output = "".join(raw_chunks)
        if exit_code not in (0, -1) and status == "completed":
            status = "errored"
            if not error_msg:
                error_msg = f"Claude Code exited with code {exit_code}."
        return full_output, exit_code, status, error_msg, commands_run, tools_used

    def run_iteration(
        self,
        prompt: str,
        session_id: Optional[str] = None,
        workspace_dir: Optional[Path] = None,
        stream_callback: Optional[Callable[[str], None]] = None,
    ) -> AgentResponse:
        start_time = time.time()
        cwd = str(workspace_dir) if workspace_dir else os.getcwd()

        env = os.environ.copy()
        if self.config.environment:
            env.update(self.config.environment)

        wanted_resume = self._session_count > 0
        cmd = self._build_cmd(prompt, resume=wanted_resume)
        self._session_count += 1

        (full_output, exit_code, status, error_msg,
         commands_run, tools_used) = self._exec(cmd, cwd, env, stream_callback)

        # Self-heal: if we tried to continue a session and the CLI rejected it
        # (stale/missing session, nothing to continue), retry once from a fresh
        # session so the supervisor loop keeps making progress instead of
        # failing identically every iteration.
        retried_fresh = False
        if wanted_resume and self._looks_like_session_error(full_output, exit_code):
            retried_fresh = True
            fresh_cmd = self._build_cmd(prompt, resume=False)
            if stream_callback:
                stream_callback(
                    "[clawper] session continuation failed; retrying with a fresh session...\n"
                )
            (full_output, exit_code, status, error_msg,
             commands_run, tools_used) = self._exec(fresh_cmd, cwd, env, stream_callback)
            cmd = fresh_cmd

        duration = time.time() - start_time

        return AgentResponse(
            output=full_output,
            raw_output=full_output,
            commands_run=commands_run,
            tools_used=tools_used,
            exit_code=exit_code,
            duration_seconds=duration,
            status=status,
            error_message=error_msg,
            metadata={
                "session_count": self._session_count,
                "command": cmd,
                "retried_fresh": retried_fresh,
            },
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

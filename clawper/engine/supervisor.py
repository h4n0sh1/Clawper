"""
Supervisor engine that manages the autonomous CTF execution loop.
"""

from __future__ import annotations

import signal
import sys
import time
import traceback
from pathlib import Path
from typing import Callable, Dict, List, Optional

from clawper.agents.base import AgentDriver, AgentResponse, STATUS_COMPLETED, describe_agent_status
from clawper.agents import create_agent_driver
from clawper.conditions.base import ConditionResult, EvaluationContext
from clawper.conditions.composite import CompositeCondition
from clawper.config import ClawperConfig
from clawper.engine.state import EngineState
from clawper.prompts.builder import PromptBuilder
from clawper.workspace.manager import WorkspaceManager
from clawper.workspace.reporter import CTFReporter


class ClawperEngine:
    """
    Autonomous and Unattended CTF Execution Supervisor.
    Never stops prompting the agent until all defined success conditions are verified.
    """

    def __init__(
        self,
        config: ClawperConfig,
        agent_driver: Optional[AgentDriver] = None,
        on_status_update: Optional[Callable[[str, EngineState], None]] = None,
        on_stream_output: Optional[Callable[[str], None]] = None,
        on_flag_found: Optional[Callable[[str, str], None]] = None,
    ):
        self.config = config
        self.workspace = WorkspaceManager(config.workspace_dir)
        self.conditions = CompositeCondition.from_config(config)
        self.prompt_builder = PromptBuilder(config)
        self.agent = agent_driver or create_agent_driver(config.agent)
        self.reporter = CTFReporter(self.workspace.root_dir, config)

        self.on_status_update = on_status_update
        self.on_stream_output = on_stream_output
        self.on_flag_found = on_flag_found

        self.state = EngineState()
        self._all_outputs: List[str] = []
        self._stop_requested = False
        self._previous_flags_count = 0

    def _setup_signal_handlers(self) -> None:
        """Register signal handlers to gracefully save state on interruption."""
        def handle_interrupt(signum, frame):
            self._notify_status("Interruption signal received. Saving state and finalizing...")
            self._stop_requested = True

        try:
            signal.signal(signal.SIGINT, handle_interrupt)
            signal.signal(signal.SIGTERM, handle_interrupt)
        except Exception:
            # Signal handling might fail in non-main threads or specific environments
            pass

    def _notify_status(self, message: str) -> None:
        if self.on_status_update:
            self.on_status_update(message, self.state)

    def _handle_stream(self, chunk: str) -> None:
        if self.on_stream_output:
            self.on_stream_output(chunk)

    def _evaluate_conditions(self, current_output: str, iteration: int) -> ConditionResult:
        """Evaluate all conditions using current output, history, workspace, and state."""
        context = EvaluationContext(
            agent_output=current_output,
            workspace_dir=self.workspace.root_dir,
            state=self.state.to_dict(),
            iteration=iteration,
            all_outputs=list(self._all_outputs),
        )
        return self.conditions.evaluate(context)

    def _sync_flags(self, condition_result: ConditionResult, iteration: int) -> None:
        """Extract flags from condition result and sync with state & workspace."""
        flags_data = condition_result.data.get("sub_results", {}).get("Flags", {}).get("data", {})
        captured = flags_data.get("captured_flags", [])

        for flag in captured:
            is_new = self.state.add_flag(
                flag=flag,
                source=f"iteration_{iteration}",
                iteration=iteration,
                flag_type="user" if "user" in flag.lower() else ("root" if "root" in flag.lower() else "generic"),
            )
            if is_new:
                self.workspace.save_flag(flag, source=f"iteration_{iteration}", iteration=iteration)
                self._notify_status(f"NEW FLAG DISCOVERED: {flag}")
                if self.on_flag_found:
                    self.on_flag_found(flag, f"iteration_{iteration}")

    def _run_agent_safely(self, prompt: str, workspace_dir: Path) -> AgentResponse:
        """
        Invoke the agent driver, guarding against ANY exception it may raise.
        Clawper must never crash because of a misbehaving agent: any unhandled
        error is converted into an "errored" AgentResponse so the supervisor
        loop can log it and keep prompting until the flags are found.
        """
        start_time = time.time()
        try:
            return self.agent.run_iteration(
                prompt=prompt,
                session_id=self.state.session_id,
                workspace_dir=workspace_dir,
                stream_callback=self._handle_stream,
            )
        except Exception as exc:
            duration = time.time() - start_time
            tb = traceback.format_exc()
            self._notify_status(
                f"ERROR: Agent '{self.agent.name}' raised an unhandled exception: {exc}. "
                "Treating this iteration as failed and continuing the loop.\n"
                f"{tb}"
            )
            return AgentResponse(
                output="",
                raw_output="",
                exit_code=1,
                duration_seconds=duration,
                status="errored",
                error_message=f"{exc}\n{tb}",
            )

    def run(self) -> EngineState:
        """
        Execute the autonomous loop until all success conditions are met.
        The loop will NEVER terminate unless success conditions are fully verified,
        or max_iterations is reached (if configured > 0), or interrupted.
        """
        self._setup_signal_handlers()
        self.workspace.initialize()

        # Try resuming existing state if present
        saved_state = self.workspace.load_state()
        if saved_state:
            self.state = EngineState.from_dict(saved_state)
            self._notify_status(f"Resumed previous session: {self.state.session_id}")

        self._notify_status(f"Starting Clawper Autonomous Session for: {self.config.target.summary()}")
        self._notify_status(f"Success Condition: {self.config.flags.required_count} flags required | Root required: {self.config.root.enabled}")

        # Check if conditions are already satisfied prior to running
        initial_eval = self._evaluate_conditions("", self.state.iterations_completed)
        self._sync_flags(initial_eval, self.state.iterations_completed)
        if initial_eval.met:
            self.state.success = True
            self.state.completed_at = time.time()
            self._notify_status("Success conditions already satisfied from existing workspace/state!")
            self._finalize()
            return self.state

        iteration = self.state.iterations_completed
        last_output = self.state.last_output
        consecutive_stalls = 0

        while not self._stop_requested:
            iteration += 1

            # Check max_iterations safeguard if set (> 0)
            if self.config.execution.max_iterations > 0 and iteration > self.config.execution.max_iterations:
                self._notify_status(f"Reached configured max iterations limit ({self.config.execution.max_iterations}). Stopping loop.")
                break

            self._notify_status(f"\n>>> ITERATION {iteration} (Phase: {self.state.phase.upper()}) <<<")

            # Build prompt: Initial prompt for iteration 1, continuation prompt for iteration > 1
            if iteration == 1 and not last_output:
                current_prompt = self.prompt_builder.build_initial_prompt(
                    success_conditions_summary=self.conditions.name,
                    workspace_dir=self.workspace.root_dir,
                )
            else:
                current_prompt = self.prompt_builder.build_continuation_prompt(
                    iteration=iteration,
                    condition_result=initial_eval,
                    last_output=last_output,
                    state=self.state.to_dict(),
                    consecutive_stalls=consecutive_stalls,
                    agent_status=self.state.history[-1]["status"] if self.state.history else STATUS_COMPLETED,
                    agent_error=self.state.last_error,
                )

            # Prompt agent (any exception raised by the agent is caught and treated as a failed iteration)
            self._notify_status(f"Dispatching prompt to agent ({self.agent.name})...")
            agent_response = self._run_agent_safely(current_prompt, self.workspace.root_dir)

            # An agent that stops processing without serving all flags (errored, timed out,
            # or interrupted) is treated as an error: log it, but NEVER stop the loop for it.
            if agent_response.status != STATUS_COMPLETED:
                self.state.record_agent_error(agent_response.error_message or f"Agent {describe_agent_status(agent_response.status)}")
                self._notify_status(
                    f"AGENT ERROR (iteration {iteration}, status={agent_response.status}): "
                    f"{agent_response.error_message or 'no additional details'}. "
                    f"Consecutive errors: {self.state.consecutive_errors}. Retrying with a fresh prompt."
                )
            else:
                self.state.record_agent_success()

            # Record raw output and logs
            last_output = agent_response.output
            self._all_outputs.append(last_output)
            self.workspace.log_iteration(iteration, current_prompt, last_output, agent_response.status)

            # Update state history
            self.state.record_iteration(
                iteration=iteration,
                prompt=current_prompt,
                output=last_output,
                status=agent_response.status,
                duration=agent_response.duration_seconds,
                commands_run=agent_response.commands_run,
                error_message=agent_response.error_message,
            )

            # Evaluate success conditions
            eval_result = self._evaluate_conditions(last_output, iteration)
            self._sync_flags(eval_result, iteration)
            initial_eval = eval_result

            # Check for stalls (no new flags found)
            current_flags_count = len(self.state.captured_flags)
            if current_flags_count == self._previous_flags_count:
                consecutive_stalls += 1
            else:
                consecutive_stalls = 0
                self._previous_flags_count = current_flags_count

            self.state.stalls_count = consecutive_stalls
            self.state.condition_summary = eval_result.details

            # Update tactical phase
            is_root = eval_result.data.get("sub_results", {}).get("RootAccess", {}).get("met", False)
            self.state.update_phase(req_flags=self.config.flags.required_count, is_root=is_root)

            # Save state continuously
            self.workspace.save_state(self.state.to_dict())

            # Check if all success conditions are met
            if eval_result.met:
                self.state.success = True
                self.state.completed_at = time.time()
                self._notify_status("\n========================================================")
                self._notify_status("VICTORY! ALL SUCCESS CONDITIONS RIGOROUSLY SATISFIED!")
                self._notify_status("========================================================")
                self._notify_status(eval_result.details)
                break
            else:
                self._notify_status(f"Condition evaluation: Incomplete ({len(self.state.captured_flags)}/{self.config.flags.required_count} flags).")
                self._notify_status("Wrapper will prompt the agent again until all conditions are satisfied.")

            # Pause briefly between iterations if configured. Back off with a longer
            # delay after consecutive agent errors to avoid hammering a broken agent,
            # while still never giving up on the loop itself. A minimum base is used
            # for the backoff even when loop_delay is 0, so error retries are always throttled.
            base_delay = self.config.execution.loop_delay
            if self.state.consecutive_errors > 0:
                effective_base = base_delay if base_delay > 0 else 1.0
                delay = min(effective_base * self.state.consecutive_errors, 30.0)
                self._notify_status(
                    f"Backing off for {delay:.1f}s before retrying after {self.state.consecutive_errors} consecutive agent error(s)."
                )
                time.sleep(delay)
            elif base_delay > 0:
                time.sleep(base_delay)

        self._finalize()
        return self.state

    def _finalize(self) -> None:
        """Clean up agent, save state, and generate reports."""
        try:
            self.agent.cleanup()
        except Exception as exc:
            self._notify_status(f"WARNING: Agent cleanup raised an exception (ignored): {exc}")

        if not self.state.completed_at:
            self.state.completed_at = time.time()

        self.workspace.save_state(self.state.to_dict())

        # Generate writeup and json reports
        writeup_path = self.workspace.root_dir / self.config.execution.writeup_path
        self.reporter.generate_writeup(self.state.to_dict(), writeup_path)
        self.reporter.generate_json_report(self.state.to_dict())

        self._notify_status(f"Session finished. Writeup saved to {writeup_path}")

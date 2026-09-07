"""
Unit and integration tests for ClawperEngine supervisor loop.
"""

import tempfile
from pathlib import Path

from clawper.agents.mock import MockAgentDriver
from clawper.config import (
    ClawperConfig,
    ExecutionConfig,
    FlagConditionConfig,
    RootConditionConfig,
    TargetConfig,
)
from clawper.engine.supervisor import ClawperEngine


def test_clawper_engine_never_stops_until_success():
    """
    Test that Clawper keeps prompting the agent across multiple iterations
    even when the agent prematurely claims it is done, until all conditions are satisfied.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        config = ClawperConfig(
            target=TargetConfig(box_name="TestCTF", ip="10.10.11.100"),
            flags=FlagConditionConfig(required_count=2),
            root=RootConditionConfig(enabled=True),
            execution=ExecutionConfig(loop_delay=0.0, max_iterations=10),
            workspace_dir=tmpdir,
        )

        mock_responses = [
            # Iteration 1: Recon only
            "Running nmap scan on 10.10.11.100. Open ports: 80, 22. Found web application.",
            # Iteration 2: User exploit & user flag
            "Exploited SQLi in web application. Gained low-privilege shell. user flag: 11111111222222223333333344444444",
            # Iteration 3: Agent prematurely claims it is done or gives up
            "I have finished investigating the machine. I cannot find any further vulnerabilities.",
            # Iteration 4: Agent continues, exploits SUID and grabs root flag + root proof
            "Found SUID binary /usr/bin/find. Executed root privesc. uid=0(root). root flag: aaaaaaaabbbbbbbbccccccccdddddddd",
        ]

        agent = MockAgentDriver(responses=mock_responses)
        statuses = []
        flags_found = []

        engine = ClawperEngine(
            config=config,
            agent_driver=agent,
            on_status_update=lambda msg, st: statuses.append(msg),
            on_flag_found=lambda f, src: flags_found.append(f),
        )

        final_state = engine.run()

        # Verify it went through all 4 iterations to meet conditions
        assert final_state.success is True
        assert final_state.iterations_completed == 4
        assert len(final_state.captured_flags) == 2
        assert len(flags_found) == 2
        assert "11111111222222223333333344444444" in [f["flag"] for f in final_state.captured_flags]
        assert "aaaaaaaabbbbbbbbccccccccdddddddd" in [f["flag"] for f in final_state.captured_flags]

        # Verify writeup was generated
        writeup_file = Path(tmpdir) / "WRITEUP.md"
        assert writeup_file.exists()
        assert "TestCTF" in writeup_file.read_text()


def test_clawper_engine_max_iterations_safeguard():
    with tempfile.TemporaryDirectory() as tmpdir:
        config = ClawperConfig(
            flags=FlagConditionConfig(required_count=2),
            execution=ExecutionConfig(loop_delay=0.0, max_iterations=2),
            workspace_dir=tmpdir,
        )

        mock_responses = [
            "Recon on port 80.",
            "Found user flag: 11111111222222223333333344444444",
            "Should not be reached because max_iterations=2",
        ]

        agent = MockAgentDriver(responses=mock_responses)
        engine = ClawperEngine(config=config, agent_driver=agent)
        final_state = engine.run()

        assert final_state.success is False
        assert final_state.iterations_completed == 2
        assert len(final_state.captured_flags) == 1


def test_clawper_engine_existing_conditions_met():
    with tempfile.TemporaryDirectory() as tmpdir:
        w_dir = Path(tmpdir)
        # Pre-populate flags
        (w_dir / "user.txt").write_text("11111111222222223333333344444444")
        (w_dir / "root.txt").write_text("aaaaaaaaabbbbbbbbccccccccdddddddd")

        config = ClawperConfig(
            flags=FlagConditionConfig(required_count=2),
            execution=ExecutionConfig(loop_delay=0.0),
            workspace_dir=tmpdir,
        )

        mock_responses = ["Should not run"]
        agent = MockAgentDriver(responses=mock_responses)
        engine = ClawperEngine(config=config, agent_driver=agent)
        final_state = engine.run()

        assert final_state.success is True
        assert final_state.iterations_completed == 0
        assert len(final_state.captured_flags) == 2

"""
Unit tests for Clawper agent drivers.
"""

from clawper.agents import create_agent_driver
from clawper.agents.base import AgentResponse
from clawper.agents.claude_code import ClaudeCodeDriver
from clawper.agents.custom_command import CommandAgentDriver
from clawper.agents.mock import MockAgentDriver
from clawper.config import AgentConfig


def test_mock_agent_driver():
    mock_responses = [
        "Step 1: Recon scan finished. Found port 80, 22.",
        "Step 2: User shell acquired. Flag: 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d",
    ]
    driver = MockAgentDriver(responses=mock_responses)
    assert driver.is_available() is True

    stream_chunks = []
    resp1 = driver.run_iteration("Run recon", stream_callback=lambda c: stream_chunks.append(c))
    assert resp1.status == "completed"
    assert "Step 1" in resp1.output
    assert len(stream_chunks) > 0

    resp2 = driver.run_iteration("Exploit web")
    assert resp2.status == "completed"
    assert "Step 2" in resp2.output
    assert "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d" in resp2.output

    # Fallback step
    resp3 = driver.run_iteration("Root the box")
    assert "MockAgent Step 3" in resp3.output


def test_command_agent_driver():
    config = AgentConfig(
        driver_type="command",
        custom_command="python3 -c \"import os; print('ECHO: ' + os.environ.get('CLAWPER_PROMPT', ''))\"",
    )
    driver = CommandAgentDriver(config)
    resp = driver.run_iteration("Hello Clawper Agent")
    assert resp.status == "completed"
    assert "ECHO: Hello Clawper Agent" in resp.output


def test_claude_code_driver_cmd_builder():
    config = AgentConfig(
        driver_type="claude_code",
        binary_path="claude",
        cli_flags=["--dangerously-skip-permissions"],
        model="claude-3-5-sonnet-20241022",
    )
    driver = ClaudeCodeDriver(config)
    cmd = driver._build_cmd("Test prompt", resume=False)
    assert "claude" in cmd
    assert "--dangerously-skip-permissions" in cmd
    assert "--model" in cmd
    assert "claude-3-5-sonnet-20241022" in cmd
    assert "-p" in cmd
    assert "Test prompt" in cmd


def test_agent_factory():
    driver1 = create_agent_driver(AgentConfig(driver_type="mock"))
    assert isinstance(driver1, MockAgentDriver)

    driver2 = create_agent_driver(AgentConfig(driver_type="claude_code"))
    assert isinstance(driver2, ClaudeCodeDriver)

    driver3 = create_agent_driver(AgentConfig(driver_type="command", custom_command="echo hello"))
    assert isinstance(driver3, CommandAgentDriver)

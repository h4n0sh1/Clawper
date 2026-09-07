"""
Unit tests for Clawper prompt builder and templates.
"""

from pathlib import Path

from clawper.conditions.base import ConditionResult
from clawper.config import ClawperConfig, FlagConditionConfig, TargetConfig
from clawper.prompts.builder import PromptBuilder


def test_prompt_builder_initial():
    config = ClawperConfig(
        prompt="Compromise the domain controller and loot NTDS.dit",
        target=TargetConfig(
            ip="10.10.11.201",
            box_name="DC01",
            platform="prolab",
            credentials={"guest": "guest123"},
            hints=["Kerberoasting possible on svc_sql"],
        ),
    )
    builder = PromptBuilder(config)
    prompt = builder.build_initial_prompt(
        success_conditions_summary="Flags count >= 2",
        workspace_dir=Path("/tmp/clawper_workspace"),
    )

    assert "DC01" in prompt
    assert "10.10.11.201" in prompt
    assert "guest:guest123" in prompt
    assert "Kerberoasting possible on svc_sql" in prompt
    assert "Compromise the domain controller" in prompt
    assert "AUTONOMOUS EXECUTION" in prompt


def test_prompt_builder_continuation_anti_giving_up():
    config = ClawperConfig(
        target=TargetConfig(box_name="Lame", ip="10.10.10.3"),
        flags=FlagConditionConfig(required_count=2),
    )
    builder = PromptBuilder(config)

    cond_res = ConditionResult(name="Flags", met=False, details="Captured 1/2 flags.")
    last_output = "I have finished the investigation and could not proceed further. Let me know."
    state = {
        "captured_flags": [{"flag": "e4d909c290d0fb1ca068ffaddf22cbd0", "flag_type": "user"}],
    }

    continuation = builder.build_continuation_prompt(
        iteration=2,
        condition_result=cond_res,
        last_output=last_output,
        state=state,
        consecutive_stalls=0,
    )

    assert "MISSION CONTINUATION: Box: Lame | IP: 10.10.10.3" in continuation
    assert "WARNING: You indicated you may be finished or cannot proceed" in continuation
    assert "Privilege Escalation" in continuation
    assert "e4d909c290d0fb1ca068ffaddf22cbd0" in continuation


def test_prompt_builder_stall_pivot_directive():
    config = ClawperConfig(
        target=TargetConfig(box_name="StallBox", ip="10.10.10.99"),
        flags=FlagConditionConfig(required_count=1),
    )
    builder = PromptBuilder(config)

    cond_res = ConditionResult(name="Flags", met=False, details="Captured 0/1 flags.")
    last_output = "Still scanning web service."
    state = {"captured_flags": []}

    continuation = builder.build_continuation_prompt(
        iteration=4,
        condition_result=cond_res,
        last_output=last_output,
        state=state,
        consecutive_stalls=3,
    )

    assert "PIVOT DIRECTIVE (Stall detected" in continuation

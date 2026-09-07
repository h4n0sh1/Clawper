"""
Unit tests for Clawper success conditions.
"""

import tempfile
from pathlib import Path

from clawper.conditions.base import EvaluationContext
from clawper.conditions.composite import CompositeCondition
from clawper.conditions.custom_script import ScriptVerificationCondition
from clawper.conditions.file_check import FileVerificationCondition
from clawper.conditions.flags import FlagCondition
from clawper.conditions.root_shell import RootVerificationCondition
from clawper.config import (
    ClawperConfig,
    FileConditionConfig,
    FlagConditionConfig,
    RootConditionConfig,
    ScriptConditionConfig,
)


def test_flag_condition_regex_detection():
    config = FlagConditionConfig(required_count=2)
    condition = FlagCondition(config)

    # Output with HTB md5 format and standard CTF{} format
    output = """
    Found user flag: 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d
    Also found root flag: flag{super_secret_root_flag_12345}
    """
    ctx = EvaluationContext(agent_output=output)
    res = condition.evaluate(ctx)

    assert res.met is True
    assert len(res.data["captured_flags"]) == 2
    assert "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d" in res.data["captured_flags"]
    assert "flag{super_secret_root_flag_12345}" in res.data["captured_flags"]


def test_flag_condition_from_workspace_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        w_dir = Path(tmpdir)
        user_txt = w_dir / "user.txt"
        user_txt.write_text("e4d909c290d0fb1ca068ffaddf22cbd0\n")

        config = FlagConditionConfig(required_count=1)
        condition = FlagCondition(config)

        ctx = EvaluationContext(agent_output="No flag in output", workspace_dir=w_dir)
        res = condition.evaluate(ctx)

        assert res.met is True
        assert "e4d909c290d0fb1ca068ffaddf22cbd0" in res.data["captured_flags"]


def test_flag_condition_insufficient_flags():
    config = FlagConditionConfig(required_count=2)
    condition = FlagCondition(config)

    output = "Found user flag: 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d"
    ctx = EvaluationContext(agent_output=output)
    res = condition.evaluate(ctx)

    assert res.met is False
    assert res.data["count"] == 1


def test_flag_condition_specific_flags():
    config = FlagConditionConfig(
        required_count=2,
        specific_flags=["flag{flag_one}", "flag{flag_two}"],
    )
    condition = FlagCondition(config)

    output = "Found: flag{flag_one} and flag{wrong_flag}"
    ctx = EvaluationContext(agent_output=output)
    res = condition.evaluate(ctx)

    assert res.met is False  # Missing flag{flag_two}

    output2 = "Found: flag{flag_one} and flag{flag_two}"
    ctx2 = EvaluationContext(agent_output=output2)
    res2 = condition.evaluate(ctx2)
    assert res2.met is True


def test_root_verification_condition():
    config = RootConditionConfig(enabled=True)
    condition = RootVerificationCondition(config)

    ctx_no_root = EvaluationContext(agent_output="uid=1000(john) gid=1000(john)")
    res_no_root = condition.evaluate(ctx_no_root)
    assert res_no_root.met is False

    ctx_root = EvaluationContext(agent_output="uid=0(root) gid=0(root) groups=0(root)")
    res_root = condition.evaluate(ctx_root)
    assert res_root.met is True


def test_file_verification_condition():
    with tempfile.TemporaryDirectory() as tmpdir:
        w_dir = Path(tmpdir)
        config = FileConditionConfig(
            enabled=True,
            required_files=["proof.txt", "loot/shadow.txt"],
        )
        condition = FileVerificationCondition(config)

        ctx = EvaluationContext(workspace_dir=w_dir)
        res = condition.evaluate(ctx)
        assert res.met is False

        # Create the required files
        (w_dir / "proof.txt").write_text("proof data")
        (w_dir / "loot").mkdir()
        (w_dir / "loot" / "shadow.txt").write_text("root:$6$...")

        res2 = condition.evaluate(ctx)
        assert res2.met is True


def test_script_verification_condition():
    config = ScriptConditionConfig(
        enabled=True,
        command="python3 -c 'exit(0)'",
        expected_exit_code=0,
    )
    condition = ScriptVerificationCondition(config)
    res = condition.evaluate(EvaluationContext())
    assert res.met is True

    config_fail = ScriptConditionConfig(
        enabled=True,
        command="python3 -c 'exit(1)'",
        expected_exit_code=0,
    )
    condition_fail = ScriptVerificationCondition(config_fail)
    res_fail = condition_fail.evaluate(EvaluationContext())
    assert res_fail.met is False


def test_composite_condition():
    clawper_config = ClawperConfig(
        flags=FlagConditionConfig(required_count=2),
        root=RootConditionConfig(enabled=True),
    )
    composite = CompositeCondition.from_config(clawper_config)

    # 1. Output has 1 flag and non-root -> Fails
    ctx1 = EvaluationContext(agent_output="Flag: 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d\nuid=1000(user)")
    res1 = composite.evaluate(ctx1)
    assert res1.met is False

    # 2. Output has 2 flags and root -> Passes
    ctx2 = EvaluationContext(
        agent_output="User: 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d\nRoot: 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d\nuid=0(root)"
    )
    res2 = composite.evaluate(ctx2)
    assert res2.met is True

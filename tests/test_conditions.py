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

    # A wrapped flag (flag{...}) proves itself wherever it appears, so it is
    # credited straight from output. A bare 32-hex is only a flag when it is read
    # out of an actual flag file -- a "Found user flag: <hex>" label in prose is
    # not enough (it is usually a hash), so that hex is supplied via root.txt.
    with tempfile.TemporaryDirectory() as tmpdir:
        w_dir = Path(tmpdir)
        (w_dir / "root.txt").write_text("9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d\n")
        output = "Also found root flag: flag{super_secret_root_flag_12345}"
        res = condition.evaluate(EvaluationContext(agent_output=output, workspace_dir=w_dir))

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

    # One genuine flag (read from user.txt) is below the required count of 2.
    with tempfile.TemporaryDirectory() as tmpdir:
        w_dir = Path(tmpdir)
        (w_dir / "user.txt").write_text("9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d\n")
        res = condition.evaluate(
            EvaluationContext(agent_output="No flag here", workspace_dir=w_dir)
        )

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

    # 2. Two flags (read from user.txt/root.txt) and root proof -> Passes
    with tempfile.TemporaryDirectory() as tmpdir:
        w_dir = Path(tmpdir)
        (w_dir / "user.txt").write_text("9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d\n")
        (w_dir / "root.txt").write_text("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d\n")
        ctx2 = EvaluationContext(agent_output="uid=0(root)", workspace_dir=w_dir)
        res2 = composite.evaluate(ctx2)
    assert res2.met is True


def test_flag_condition_ignores_unlabelled_hashes():
    """Bare 32-hex strings in console output are not flags.

    secretsdump / hashcat / md5sum output is full of them; treating them as
    captures used to satisfy required_count and, worse, mark the user and root
    flags as found.
    """
    config = FlagConditionConfig(
        required_count=2, require_user_flag=True, require_root_flag=True
    )
    condition = FlagCondition(config)

    output = """
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    svc_deploy:1104:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
    md5sum payload.exe -> 5d41402abc4b2a76b9719d911017c592
    """
    res = condition.evaluate(EvaluationContext(agent_output=output))

    assert res.met is False
    assert res.data["captured_flags"] == []
    assert res.data["count"] == 0
    assert len(res.data["candidate_flags"]) >= 3
    assert res.data["user_flag_found"] is False
    assert res.data["root_flag_found"] is False


def test_flag_condition_types_flags_by_provenance():
    """user.txt / root.txt decide the type -- never the flag value itself."""
    with tempfile.TemporaryDirectory() as tmpdir:
        w_dir = Path(tmpdir)
        flags_dir = w_dir / "flags"
        flags_dir.mkdir()
        (flags_dir / "user.txt").write_text("11111111222222223333333344444444\n")
        (flags_dir / "root.txt").write_text("aaaaaaaabbbbbbbbccccccccdddddddd\n")

        config = FlagConditionConfig(
            required_count=2, require_user_flag=True, require_root_flag=True
        )
        res = FlagCondition(config).evaluate(
            EvaluationContext(agent_output="", workspace_dir=w_dir)
        )

        assert res.met is True
        types = {r["flag"]: r["flag_type"] for r in res.data["flag_records"]}
        assert types["11111111222222223333333344444444"] == "user"
        assert types["aaaaaaaabbbbbbbbccccccccdddddddd"] == "root"


def test_flag_condition_requires_root_flag_not_just_count():
    """Two user-side flags must not satisfy a required root flag."""
    config = FlagConditionConfig(
        required_count=2, require_user_flag=True, require_root_flag=True
    )
    condition = FlagCondition(config)

    # Both flags are read from user.txt -> both typed "user"; no root flag file
    # exists, so the required root flag is unmet even though the count is 2.
    with tempfile.TemporaryDirectory() as tmpdir:
        w_dir = Path(tmpdir)
        (w_dir / "user.txt").write_text(
            "11111111222222223333333344444444\n"
            "55555555666666667777777788888888\n"
        )
        res = condition.evaluate(
            EvaluationContext(agent_output="", workspace_dir=w_dir)
        )

    assert res.data["count"] == 2
    assert res.data["user_flag_found"] is True
    assert res.data["root_flag_found"] is False
    assert res.met is False

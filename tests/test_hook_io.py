# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: hook_io reads hook input, parses flags, orders the judgement and fails closed.
from __future__ import annotations

import argparse
import io
import json
from pathlib import Path

import pytest
from lib import hook_io
from lib.config import ConfigError
from lib.hook_io import EVERY_TOOL, Flag

FLAGS = {
    "--on": Flag(),
    "--one": Flag(values=frozenset({"a", "b"})),
    "--many": Flag(values=frozenset({"x", "y", "z"}), many=True),
    "--name": Flag(pattern=r"[a-z]+"),
}
PARSER = hook_io.build_parser("probe", FLAGS)
BASH = frozenset({"Bash"})


def _seen(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    return f"judged {hook_input['tool_name']} {vars(flags)}"


def _never(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    raise AssertionError("judge must not run")


def _boom(hook_input: dict[str, object], flags: argparse.Namespace) -> str | None:
    raise KeyError("missing field")


def _call(hook_input: dict[str, object], *argv: str, judge: hook_io.Judge = _seen) -> str | None:
    return hook_io.evaluate(hook_input, list(argv), judge, BASH, PARSER).reason


def _closed(cause: str) -> str:
    return f"hook probe failed closed ({cause})"


@pytest.mark.parametrize(
    ("text", "want"),
    [
        ('{"tool_name": "Bash"}', {"tool_name": "Bash"}),
        ("", {}),
        ("   ", {}),
        ("not json", {}),
        ("[1]", {}),
        ('"text"', {}),
    ],
)
def test_read_input_reads_an_object_or_nothing(
    monkeypatch: pytest.MonkeyPatch, text: str, want: dict[str, object]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(text))
    assert hook_io.read_input() == want


def test_emit_prints_one_decision_line(capsys: pytest.CaptureFixture[str]) -> None:
    assert hook_io.emit(None) == 0
    assert hook_io.emit("no. Next: stop.") == 0
    lines = capsys.readouterr().out.splitlines()
    assert [json.loads(line) for line in lines] == [
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": "",
            }
        },
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "no. Next: stop.",
            }
        },
    ]


def test_failed_closed_carries_the_full_cause() -> None:
    assert hook_io.failed_closed("x", ValueError("bad value")) == (
        "hook x failed closed (ValueError: bad value)"
    )
    assert (
        hook_io.failed_closed("x", "unknown flag --y") == "hook x failed closed (unknown flag --y)"
    )


def test_parser_is_named_for_the_hook() -> None:
    assert PARSER.prog == "probe"


def test_missing_or_bad_tool_name_denies_first() -> None:
    for hook_input in ({}, {"tool_name": ""}, {"tool_name": 3}, {"tool_input": {}}):
        assert _call(hook_input, "--bogus") == _closed("hook input has no tool_name")


def test_flags_parse_before_the_tool_filter() -> None:
    assert _call({"tool_name": "Read"}, "--bogus") == _closed("unknown flag --bogus")
    assert _call({"tool_name": "Read"}, judge=_never) is None


@pytest.mark.parametrize(
    ("argv", "cause"),
    [
        (["--bogus"], "unknown flag --bogus"),
        (["--bogus=1"], "unknown flag --bogus=1"),
        (["--o"], "unknown flag --o"),
        (["stray"], "unexpected argument stray"),
        (["--one"], "flag --one needs a value"),
        (["--one", "c"], "flag --one value c is not one of a, b"),
        (["--many", "x,w"], "flag --many value w is not one of x, y, z"),
        (["--many", ""], "flag --many value  is not one of x, y, z"),
        (["--name", "A1"], "flag --name value A1 does not match [a-z]+"),
        (["--on", "--on"], "flag --on is given twice"),
        (["--one", "a", "--one=b"], "flag --one is given twice"),
        (["--on=1"], "flag --on takes no value"),
    ],
)
def test_bad_flags_deny_with_the_cause(argv: list[str], cause: str) -> None:
    assert _call({"tool_name": "Bash"}, *argv) == _closed(cause)


def test_good_flags_reach_the_judge() -> None:
    got = _call({"tool_name": "Bash"}, "--on", "--one=b", "--many", "z,x", "--name", "ok")
    assert got == "judged Bash {'on': True, 'one': 'b', 'many': ('z', 'x'), 'name': 'ok'}"
    got = _call({"tool_name": "Bash"})
    assert got == "judged Bash {'on': False, 'one': None, 'many': None, 'name': None}"


def test_every_tool_judges_every_tool() -> None:
    decision = hook_io.evaluate({"tool_name": "Anything"}, [], _seen, EVERY_TOOL, PARSER)
    assert not decision.allow and str(decision.reason).startswith("judged Anything")


def test_tool_input_must_be_an_object() -> None:
    hook_input: dict[str, object] = {"tool_name": "Bash", "tool_input": ["ls"]}
    assert _call(hook_input) == _closed("tool_input is not an object")
    assert str(_call({"tool_name": "Bash", "tool_input": {}})).startswith("judged")


def test_a_raising_judge_denies_with_its_exception() -> None:
    assert _call({"tool_name": "Bash"}, judge=_boom) == _closed("KeyError: 'missing field'")


def test_run_emits_a_deny_when_evaluation_itself_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken(*args: object) -> str | None:
        raise OSError("disk gone")

    monkeypatch.setattr(hook_io, "evaluate", broken)
    monkeypatch.setattr("sys.stdin", io.StringIO('{"tool_name": "Bash"}'))
    assert hook_io.run(_seen, BASH, PARSER) == 0
    out = json.loads(capsys.readouterr().out)["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny"
    assert out["permissionDecisionReason"] == _closed("OSError: disk gone")


def test_run_passes_argv_and_stdin_through(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO('{"tool_name": "Bash"}'))
    monkeypatch.setattr("sys.argv", ["probe.py", "--on"])
    assert hook_io.run(_seen, BASH, PARSER) == 0
    reason = json.loads(capsys.readouterr().out)["hookSpecificOutput"]["permissionDecisionReason"]
    assert reason.startswith("judged Bash {'on': True")


def test_hook_config_reads_the_project_config(tmp_path: Path) -> None:
    data = tmp_path / ".claude" / "daedalus"
    data.mkdir(parents=True)
    (data / "config.json").write_text('{"charter_root": "/c"}', encoding="utf-8")
    assert hook_io.hook_config(str(tmp_path)).charter_root == Path("/c")
    (data / "config.json").write_text("{bad", encoding="utf-8")
    with pytest.raises(ConfigError):
        hook_io.hook_config(str(tmp_path))

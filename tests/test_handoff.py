# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0273, 0284: past the context limit a bound agent in a run may only write its hand-off.
from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import enforce_agent_jail
import handback_check
import pytest
from lib import agent_files, handoff, storage
from lib.config import Config
from lib.context_size import Handling, Reason, SizeResult, Unmeasured
from lib.operator_file import CONTEXT_LIMIT, OperatorError, load_user, validate
from lib.train_scope import KNOWN_AGENTS

from tests.conftest import REPO_ROOT, audit_records
from tests.handoff_cases import (
    AGENT_ID,
    OTHER_ID,
    PAST,
    SESSION,
    Case,
    assert_refused,
    check,
    make_case,
    sized,
)

pytestmark = pytest.mark.usefixtures("plugin_data")
AGENTS = REPO_ROOT / "agents"
BOUND = sorted(KNOWN_AGENTS - {"main"})
WRITERS = [a for a in BOUND if "Write" in agent_files.load(AGENTS / f"{a}.md").tools]
NO_WRITE = [a for a in BOUND if a not in WRITERS]


@pytest.fixture
def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Case:
    return make_case(tmp_path, monkeypatch)


def _operator(case: Case, doc: dict[str, object]) -> None:
    path = case.home / ".claude" / "daedalus" / "operator.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


def _raises(*_: object) -> SizeResult:
    raise AssertionError("the reader was called")


def _jail(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    payload: dict[str, object],
    reader: Callable[[object, object, object], SizeResult],
) -> tuple[int, str]:
    monkeypatch.setattr(handoff, "context_size", reader)
    code = enforce_agent_jail._judge(payload, str(payload.get("agent_type") or "main"))
    return code, capsys.readouterr().err


def _last_record(case: Case) -> dict[str, Any]:
    return audit_records(case.repo / ".claude" / "daedalus" / "audit" / f"{SESSION}.jsonl")[-1]


def _write(case: Case, path: str) -> dict[str, object]:
    return {"file_path": path, "content": "done; left; files; next; none"}


# Item 1: the setting.


@pytest.mark.parametrize("value", [-1, True, False, 1.5, 250000.0, "250000", [1]])
def test_a_bad_limit_is_refused_with_a_next_line(value: object) -> None:
    with pytest.raises(OperatorError, match="context_limit") as raised:
        validate({"context_limit": value}, "operator.json")
    assert str(raised.value).count("Next:") == 1


@pytest.mark.parametrize("value", [0, None, 1, 400000])
def test_a_good_limit_is_kept_null_included(value: object) -> None:
    assert validate({"context_limit": value}, "operator.json") == {"context_limit": value}


def test_the_limit_defaults_to_250000(case: Case) -> None:
    assert load_user().context_limit == CONTEXT_LIMIT == 250000
    assert handoff.limit_for(Config()) == 250000


@pytest.mark.parametrize("value", [0, None])
def test_the_limit_off_never_calls_the_reader(case: Case, value: object) -> None:
    _operator(case, {"context_limit": value})
    payload = case.payload("coder", "Read", {"file_path": str(case.repo / "a")})
    assert handoff.check(payload, "coder", Config(), REPO_ROOT, _raises) == handoff.GO


@pytest.mark.parametrize("value", [0, None])
def test_a_project_override_turns_the_limit_off(case: Case, value: object) -> None:
    config = Config(
        operator=validate({"context_limit": value}, "config.json", "personal_overrides.")
    )
    payload = case.payload("coder", "Read", {"file_path": str(case.repo / "a")})
    assert handoff.check(payload, "coder", config, REPO_ROOT, _raises) == handoff.GO


def test_a_project_override_raises_and_lowers_the_limit(case: Case) -> None:
    _operator(case, {"context_limit": 300000})
    payload = case.payload("coder", "Read", {"file_path": str(case.repo / "a")})
    assert check(payload, 350000).step is handoff.Step.REFUSE
    higher = Config(operator={"context_limit": 400000})
    assert check(payload, 350000, higher) == handoff.GO
    lower = Config(operator={"context_limit": 200000})
    assert check(payload, 250000, lower).step is handoff.Step.REFUSE
    assert check(payload, 200000, lower) == handoff.GO


# Item 2: the check.


def test_exactly_at_the_limit_is_not_past_and_one_above_is(case: Case) -> None:
    payload = case.payload("coder", "Read", {"file_path": str(case.repo / "a")})
    assert check(payload, CONTEXT_LIMIT) == handoff.GO
    assert_refused(check(payload, CONTEXT_LIMIT + 1))


ALLOWED = [r for r in Reason if r.handling is Handling.ALLOW_WARN]
REFUSED = [r for r in Reason if r.handling is Handling.REFUSE]


def test_three_reasons_warn_and_eight_refuse() -> None:
    assert (len(ALLOWED), len(REFUSED)) == (3, 8)


@pytest.mark.parametrize("reason", list(Reason), ids=lambda r: r.name)
def test_each_unmeasured_reason_warns_or_refuses_by_its_handling(
    case: Case, reason: Reason
) -> None:
    payload = case.payload("coder", "Read", {"file_path": str(case.repo / "a")})
    outcome = handoff.check(payload, "coder", Config(), REPO_ROOT, lambda *_: Unmeasured(reason))
    assert outcome.text is not None and reason.label in outcome.text
    if reason.handling is Handling.ALLOW_WARN:
        assert outcome.step is handoff.Step.WARN
    else:
        assert_refused(outcome)
        assert str(case.home / ".claude" / "projects") in outcome.text


def test_a_warned_routed_call_runs_and_is_recorded_as_warn(
    case: Case, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = case.payload("verifier", "Read", {"file_path": str(case.repo / "README.md")})
    reason = Reason.NO_USAGE_YET
    code, err = _jail(monkeypatch, capsys, payload, lambda *_: Unmeasured(reason))
    assert code == 0 and err == "", err
    record = _last_record(case)
    assert record["decision"] == "warn"
    assert record["reason"] == "jail: " + handoff.W_UNMEASURED.format(label=reason.label)


def test_a_warned_call_the_route_refuses_stays_refused(
    case: Case, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = case.payload("web-researcher", "Bash", {"command": "ls"})
    code, _ = _jail(monkeypatch, capsys, payload, lambda *_: Unmeasured(Reason.NO_TRANSCRIPT))
    assert code == 2 and _last_record(case)["decision"] == "block"


def test_a_refused_reason_blocks_through_the_jail(
    case: Case, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = case.payload("coder", "Read", {"file_path": str(case.repo / "README.md")})
    code, err = _jail(monkeypatch, capsys, payload, lambda *_: Unmeasured(Reason.SYMLINK))
    assert code == 2 and "(symlink)" in err and err.count("Next:") == 1
    assert _last_record(case)["decision"] == "block"


def test_the_main_session_is_never_checked(
    case: Case, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = case.payload("main", "Read", {"file_path": str(case.repo / "README.md")})
    del payload["agent_id"], payload["agent_type"]
    code, _ = _jail(monkeypatch, capsys, payload, _raises)
    assert code == 0


def test_an_agent_from_elsewhere_is_never_checked(
    case: Case, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = case.payload("general-purpose", "Read", {"file_path": str(case.repo / "README.md")})
    code, _ = _jail(monkeypatch, capsys, payload, _raises)
    assert code == 0


def test_an_agent_outside_a_run_is_never_checked(case: Case) -> None:
    (case.repo / ".claude" / "daedalus" / "train.active").unlink()
    payload = case.payload("coder", "Read", {"file_path": str(case.repo / "a")})
    assert handoff.check(payload, "coder", Config(), REPO_ROOT, _raises) == handoff.GO


def test_a_real_transcript_past_the_limit_refuses(
    case: Case, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    folder = case.home / ".claude" / "projects" / "p" / SESSION / "subagents"
    folder.mkdir(parents=True)
    usage = {"input_tokens": PAST, "output_tokens": 0}
    usage |= {"cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}
    entry = {"type": "assistant", "message": {"model": "claude-opus-5-5", "usage": usage}}
    (folder / f"agent-{AGENT_ID}.jsonl").write_text(json.dumps(entry) + "\n", encoding="utf-8")
    payload = case.payload("coder", "Read", {"file_path": str(case.repo / "README.md")})
    monkeypatch.setattr(enforce_agent_jail, "_approved", lambda _payload: 0)
    code = enforce_agent_jail._judge(payload, "coder")
    err = capsys.readouterr().err
    assert code == 2 and f"at {PAST}" in err and str(case.handoff()) in err


@pytest.mark.parametrize("value", ["absent", None])
def test_no_transcript_path_warns_and_never_calls_the_reader(case: Case, value: object) -> None:
    payload = case.payload("coder", "Read", {"file_path": str(case.repo / "a")})
    if value == "absent":
        del payload["transcript_path"]
    else:
        payload["transcript_path"] = value
    outcome = handoff.check(payload, "coder", Config(), REPO_ROOT, _raises)
    assert outcome == handoff.Outcome(handoff.Step.WARN, handoff.W_NO_TRANSCRIPT_PATH)


@pytest.mark.parametrize("value", [5, "", "relative/s.jsonl", ["/x.jsonl"]])
def test_an_unusable_transcript_path_still_goes_to_the_reader_and_refuses(
    case: Case, value: object
) -> None:
    payload = case.payload("coder", "Read", {"file_path": str(case.repo / "a")})
    payload["transcript_path"] = value
    outcome = handoff.check(payload, "coder", Config(), REPO_ROOT)
    assert_refused(outcome)
    assert outcome.text is not None and Reason.NO_PATH.label in outcome.text


def test_a_call_without_a_transcript_path_runs_with_a_warn_record(
    case: Case, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = case.payload("verifier", "Read", {"file_path": str(case.repo / "README.md")})
    del payload["transcript_path"]
    code, _ = _jail(monkeypatch, capsys, payload, _raises)
    record = _last_record(case)
    assert code == 0 and record["decision"] == "warn"
    assert record["reason"] == f"jail: {handoff.W_NO_TRANSCRIPT_PATH}"


def test_a_malformed_settings_file_refuses_a_bound_agent_with_the_wizard_text(
    case: Case, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = case.home / ".claude" / "daedalus" / "operator.json"
    path.parent.mkdir(parents=True)
    path.write_text('{"context_limit": -5}\n', encoding="utf-8")
    payload = case.payload("coder", "Read", {"file_path": str(case.repo / "README.md")})
    code, err = _jail(monkeypatch, capsys, payload, _raises)
    assert code == 2 and err.count("Next:") == 1
    assert "~/.claude/daedalus/operator.json" in err and "context limit could not be read" in err
    assert err.rstrip().endswith(
        "Next: repair ~/.claude/daedalus/operator.json with the settings wizard, /daedalus:setup."
    )
    record = _last_record(case)
    assert record["decision"] == "block" and "context limit could not be read" in record["reason"]


def test_a_malformed_settings_file_leaves_main_and_an_agent_outside_a_run_alone(
    case: Case, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = case.home / ".claude" / "daedalus" / "operator.json"
    path.parent.mkdir(parents=True)
    path.write_text("{", encoding="utf-8")
    main = case.payload("main", "Read", {"file_path": str(case.repo / "README.md")})
    del main["agent_id"], main["agent_type"]
    assert _jail(monkeypatch, capsys, main, _raises)[0] == 0
    (case.repo / ".claude" / "daedalus" / "train.active").unlink()
    agent = case.payload("coder", "Read", {"file_path": str(case.repo / "a")})
    assert handoff.check(agent, "coder", Config(), REPO_ROOT, _raises) == handoff.GO


# Items 3, 4 and 6: one admitted row, the refusal texts, every agent kind.


@pytest.mark.parametrize("agent", WRITERS)
def test_the_admitted_handoff_write_carries_the_plugin_approval(
    case: Case, agent: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = case.payload(agent, "Write", _write(case, str(case.handoff())))
    monkeypatch.setattr(handoff, "context_size", sized(PAST))
    assert enforce_agent_jail._judge(payload, agent) == 0
    out = json.loads(capsys.readouterr().out)["hookSpecificOutput"]
    assert out == {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "permissionDecisionReason": "Daedalus approval list: handoff-write (0253)",
    }


@pytest.mark.parametrize("agent", WRITERS)
def test_a_sibling_write_past_the_limit_carries_no_approval(
    case: Case, agent: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(handoff, "context_size", sized(PAST))
    for target in _siblings(case):
        payload = case.payload(agent, "Write", _write(case, target))
        assert enforce_agent_jail._judge(payload, agent) == 2
        assert capsys.readouterr().out == ""


def test_an_allowed_agent_call_below_the_limit_carries_no_approval(
    case: Case, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = case.payload("verifier", "Read", {"file_path": str(case.repo / "README.md")})
    monkeypatch.setattr(handoff, "context_size", sized(1000))
    assert enforce_agent_jail._judge(payload, "verifier") == 0
    assert capsys.readouterr().out == ""


def test_the_kinds_split_by_their_tools_line() -> None:
    assert sorted(WRITERS + NO_WRITE) == BOUND
    assert NO_WRITE == ["releaser", "verifier", "web-researcher"]
    assert all(handoff.holds_write(a, REPO_ROOT) == (a in WRITERS) for a in BOUND)


def test_the_allow_table_is_one_typed_row() -> None:
    assert handoff.PAST_LIMIT_ROWS == (handoff.AllowRow("Write", "file_path"),)


@pytest.mark.parametrize("agent", WRITERS)
def test_the_handoff_write_is_admitted_past_the_limit(
    case: Case, agent: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = case.handoff()
    payload = case.payload(agent, "Write", _write(case, str(path)))
    code, err = _jail(monkeypatch, capsys, payload, sized(PAST))
    assert code == 0, err
    record = _last_record(case)
    assert record["decision"] == "allow" and record["reason"] == f"jail: {handoff.ADMITTED}"
    assert path.parent.is_dir() and (path.parent.stat().st_mode & 0o777) == 0o700


@pytest.mark.parametrize("tokens", [CONTEXT_LIMIT, 1000])
@pytest.mark.parametrize("agent", WRITERS)
def test_the_handoff_write_is_refused_at_or_below_the_limit(
    case: Case,
    agent: str,
    tokens: int,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = case.payload(agent, "Write", _write(case, str(case.handoff())))
    code, err = _jail(monkeypatch, capsys, payload, sized(tokens))
    assert code == 2 and "context is past" not in err


@pytest.mark.parametrize("agent", NO_WRITE)
@pytest.mark.parametrize(
    ("tool", "field"), [("Write", "file_path"), ("Read", "file_path"), ("Bash", "command")]
)
def test_an_agent_without_write_is_refused_every_call_with_the_inline_text(
    case: Case,
    agent: str,
    tool: str,
    field: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    value = str(case.handoff()) if field == "file_path" else "ls"
    payload = case.payload(agent, tool, {field: value})
    code, err = _jail(monkeypatch, capsys, payload, sized(PAST))
    want = handoff.R_PAST_LIMIT_INLINE.format(limit=CONTEXT_LIMIT, tokens=PAST)
    assert code == 2 and want in err and "[STATUS: HANDOFF] inline" in err
    assert not storage.TMP_ROOT.exists()


def _siblings(case: Case) -> list[str]:
    path = case.handoff()
    link = path.parent / "link.md"
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(path)
    return [
        str(path.parent / f"{OTHER_ID}.md"),
        f"{path.parent}/../{path.parent.name}/{path.name}",
        str(path.parent),
        str(link),
    ]


@pytest.mark.parametrize("agent", BOUND)
def test_a_sibling_of_the_handoff_file_is_refused_past_the_limit(case: Case, agent: str) -> None:
    for target in _siblings(case):
        assert_refused(check(case.payload(agent, "Write", _write(case, target))))


@pytest.mark.parametrize("agent", WRITERS)
def test_a_link_planted_at_the_handoff_path_is_refused(case: Case, agent: str) -> None:
    path = case.handoff()
    path.parent.mkdir(parents=True)
    path.symlink_to(case.repo / "elsewhere.md")
    outcome = check(case.payload(agent, "Write", _write(case, str(path))))
    assert_refused(outcome)
    assert outcome.text is not None and "cannot be written" in outcome.text


def test_the_refusal_names_the_path_the_five_things_and_one_next_line(case: Case) -> None:
    path = case.handoff()
    outcome = check(case.payload("coder", "Bash", {"command": "ls"}))
    assert_refused(outcome)
    assert outcome.text == handoff.R_PAST_LIMIT.format(limit=CONTEXT_LIMIT, tokens=PAST, path=path)
    for part in ("what is done", "what is left", "the files touched", "the next step", "open"):
        assert part in outcome.text
    assert outcome.text.endswith(f"`[STATUS: HANDOFF] path={path}`.")


def test_once_written_the_only_call_left_is_the_handback(case: Case) -> None:
    path = case.handoff()
    path.parent.mkdir(parents=True)
    path.write_text("done\n", encoding="utf-8")
    outcome = check(case.payload("coder", "Read", {"file_path": str(path)}))
    assert_refused(outcome)
    assert outcome.text is not None and "the only call left is the hand-back" in outcome.text
    again = check(case.payload("coder", "Write", _write(case, str(path))))
    assert again.step is handoff.Step.ADMIT


def test_no_other_input_field_changes_the_decision(case: Case) -> None:
    path = str(case.handoff())
    extra = {"file_path": path, "content": "x", "notebook_path": "/etc/passwd", "old_string": "y"}
    assert check(case.payload("coder", "Write", extra)).step is handoff.Step.ADMIT


# Item 5 and ruling A: the hand-back check judges the HANDOFF line.


def _handback(case: Case, agent: str, message: str, event: str = "PreToolUse") -> dict[str, Any]:
    out: dict[str, Any] = {
        "hook_event_name": event,
        "session_id": SESSION,
        "cwd": str(case.repo),
        "agent_id": AGENT_ID,
        "agent_type": f"daedalus:{agent}",
    }
    if event == "SubagentStop":
        return out | {"last_assistant_message": message}
    return out | {"tool_name": "SubagentHandback", "tool_input": {"message": message}}


@pytest.mark.parametrize("event", ["PreToolUse", "SubagentStop"])
@pytest.mark.parametrize("agent", WRITERS)
def test_a_path_handoff_passes_with_its_own_written_file(
    case: Case, agent: str, event: str
) -> None:
    path = case.handoff()
    reply = f"Notes.\n[STATUS: HANDOFF] path={path}\n"
    found = handback_check.judge(_handback(case, agent, reply, event))
    assert found is not None and "missing, empty, a link or not a file" in found
    path.parent.mkdir(parents=True)
    path.write_text("", encoding="utf-8")
    assert handback_check.judge(_handback(case, agent, reply, event)) is not None
    path.write_text("done\n", encoding="utf-8")
    assert handback_check.judge(_handback(case, agent, reply, event)) is None


@pytest.mark.parametrize("agent", WRITERS)
def test_a_path_handoff_naming_another_file_is_refused(case: Case, agent: str) -> None:
    path = case.handoff()
    path.parent.mkdir(parents=True)
    (path.parent / f"{OTHER_ID}.md").write_text("done\n", encoding="utf-8")
    for line in (
        f"[STATUS: HANDOFF] path={path.parent / f'{OTHER_ID}.md'}",
        "[STATUS: HANDOFF] inline",
        "[STATUS: HANDOFF]",
    ):
        found = handback_check.judge(_handback(case, agent, f"x\n{line}"))
        assert found is not None and found.count("Next:") == 1 and str(path) in found


def test_a_path_handoff_through_a_link_is_refused(case: Case) -> None:
    path = case.handoff()
    path.parent.mkdir(parents=True)
    (case.repo / "real.md").write_text("done\n", encoding="utf-8")
    path.symlink_to(case.repo / "real.md")
    found = handback_check.judge(_handback(case, "coder", f"[STATUS: HANDOFF] path={path}"))
    assert found is not None and "a link" in found


def test_a_path_handoff_with_a_folder_at_the_path_is_refused(case: Case) -> None:
    path = case.handoff()
    path.mkdir(parents=True)
    found = handback_check.judge(_handback(case, "coder", f"[STATUS: HANDOFF] path={path}"))
    assert found is not None and "not a file" in found


@pytest.mark.parametrize("event", ["PreToolUse", "SubagentStop"])
@pytest.mark.parametrize("agent", NO_WRITE)
def test_an_inline_handoff_needs_its_heading_and_a_line(case: Case, agent: str, event: str) -> None:
    good = "## Hand-off\nDone: a. Left: b.\n\n[STATUS: HANDOFF] inline"
    assert handback_check.judge(_handback(case, agent, good, event)) is None
    for bad in (
        "Done.\n[STATUS: HANDOFF] inline",
        "## Hand-off\n\n[STATUS: HANDOFF] inline",
        "## Hand-off\nDone.\n[STATUS: HANDOFF] path=/tmp/x.md",
        "## Handoff\nDone.\n[STATUS: HANDOFF] inline",
    ):
        found = handback_check.judge(_handback(case, agent, bad, event))
        assert found is not None and found.count("Next:") == 1, bad
    assert not storage.TMP_ROOT.exists()


def test_a_judges_handoff_leaves_no_pass_marker(case: Case) -> None:
    reply = "## Hand-off\nDone.\n[STATUS: HANDOFF] inline"
    assert handback_check.judge(_handback(case, "verifier", reply)) is None
    assert not (case.tmp_root / str(os.geteuid()) / handback_check.PASS_FEATURE).exists()


def test_other_last_lines_are_untouched_by_the_handoff_rule(case: Case) -> None:
    reply = "## Hand-off\nx\n[STATUS: RESEARCH] done"
    assert handback_check.judge(_handback(case, "web-researcher", reply)) is None
    late = "[STATUS: HANDOFF] inline\nthen more"
    assert handback_check.judge(_handback(case, "web-researcher", late)) is None


def test_an_unbound_agents_handoff_line_is_not_judged(case: Case) -> None:
    reply = "[STATUS: HANDOFF] inline"
    assert handback_check.judge(_handback(case, "general-purpose", reply)) is None


def test_both_checks_build_the_path_with_one_function() -> None:
    text = (REPO_ROOT / "scripts" / "handback_check.py").read_text(encoding="utf-8")
    assert (
        "handoff.handoff_path(hook_input)" in text
        and "tmp_dir(" not in text.split("def handoff_problem", 1)[1].split("def judge", 1)[0]
    )

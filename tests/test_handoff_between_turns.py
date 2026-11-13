# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0284: between an agent's turns the run records its size, refuses a resume past the context
# limit, admits one hand-off write, and starts a new coder from the hand-off.
from __future__ import annotations

import io
import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import handback_check
import pytest
from lib import handoff, storage, train_runner, train_state, train_summary, unit_binding, workspace
from lib.operator_file import CONTEXT_LIMIT

from tests.conftest import REPO_ROOT, SCRIPTS_DIR, git
from tests.test_records_in_one_call import (
    TRAIN,
    _built,
    _cli,
    _fixture,
    _hook,
    _ok,
    _scratch,
    _verdict,
    fixed,  # noqa: F401
)
from tests.test_workspace_train import REFUTED_REPLY, VERIFIED_REPLY

pytestmark = pytest.mark.usefixtures("isolated_env", "fixed")
OLD, NEW, THIRD, JUDGE = "a0000000000000old", "a0000000000000new", "a00000000000third", "a0judge"
SESSION = "sess-turns"
PAST = CONTEXT_LIMIT + 1
U1 = f"{TRAIN}-u1"
YIELD = "[STATUS: YIELD_WEB] q"
INLINE = "Verdict pending.\n## Hand-off\nDone: rows 1-3.\nLeft: row 4.\n\n[STATUS: HANDOFF] inline"


@pytest.fixture
def tmp_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "tmproot"
    monkeypatch.setattr(storage, "TMP_ROOT", root)
    return root


def _limit(value: object) -> None:
    path = Path(os.environ["HOME"]) / ".claude" / "daedalus" / "operator.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"context_limit": value}), encoding="utf-8")


def _bound(tmp_path: Path, agent: str = OLD) -> Path:
    # A run whose unit U1 is dispatched and bound to the coder `agent`.
    root = _fixture(tmp_path / "repo")
    _ok(train_runner.dispatch_unit(root, "U1"))
    assert unit_binding.record_dispatch(root, TRAIN, U1) is None
    assert unit_binding.claim(root, TRAIN, agent, U1) is None
    return root


def _sized(root: Path, agent: str, tokens: int, file: str | None = None) -> None:
    train_state.record_return(root, TRAIN, U1, agent, {"tokens": tokens}, file)


def _unit(root: Path, name: str = U1) -> dict[str, Any]:
    return next(u for u in train_state.units(train_state.load(root, TRAIN)) if u["name"] == name)


def _refused(outcome: train_runner.Outcome, *words: str) -> str:
    text = "\n".join(outcome.lines)
    assert outcome.code == 1 and text.count("Next:") == 1, text
    assert all(word in text for word in words), text
    return text


def _transcript(agent: str, tokens: int) -> str:
    home = Path(os.environ["HOME"])
    folder = home / ".claude" / "projects" / "p" / SESSION / "subagents"
    folder.mkdir(parents=True, exist_ok=True)
    usage = {"input_tokens": tokens, "output_tokens": 0}
    usage |= {"cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}
    entry = {"type": "assistant", "message": {"model": "claude-opus-5-5", "usage": usage}}
    (folder / f"agent-{agent}.jsonl").write_text(json.dumps(entry) + "\n", encoding="utf-8")
    return str(home / ".claude" / "projects" / "p" / f"{SESSION}.jsonl")


def _return(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    root: Path,
    agent: str,
    reply: str,
    kind: str = "coder",
    transcript: str | None = None,
) -> str:
    # The return hook as the client runs it: one SubagentHandback payload on stdin.
    payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "session_id": SESSION,
        "cwd": str(root),
        "agent_id": agent,
        "agent_type": f"daedalus:{kind}",
        "tool_name": "SubagentHandback",
        "tool_input": {"message": reply},
    }
    if transcript is not None:
        payload["transcript_path"] = transcript
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    assert handback_check.main() == 0
    return capsys.readouterr().out


def _path_handoff(root: Path, agent: str, text: str = "done; left; next\n") -> Path:
    path = handoff.handoff_path({"agent_id": agent, "cwd": str(root)})
    assert path is not None
    storage.make_tmp_dir(handoff.FEATURE, str(root))
    path.write_text(text, encoding="utf-8")
    return path


# Item 1: the size at each return.


@pytest.mark.usefixtures("tmp_root")
def test_a_return_records_the_measured_size_on_the_unit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _bound(tmp_path)
    out = _return(monkeypatch, capsys, root, OLD, YIELD, "coder", _transcript(OLD, 1234))
    assert "block" not in out
    assert _unit(root)[train_state.SIZES] == {OLD: {"tokens": 1234}}
    # A larger later return replaces the size.
    _return(monkeypatch, capsys, root, OLD, YIELD, "coder", _transcript(OLD, 5000))
    assert _unit(root)[train_state.SIZES] == {OLD: {"tokens": 5000}}


@pytest.mark.usefixtures("tmp_root")
def test_a_smaller_later_measurement_keeps_the_larger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _bound(tmp_path)
    _return(monkeypatch, capsys, root, OLD, YIELD, "coder", _transcript(OLD, PAST))
    _return(monkeypatch, capsys, root, OLD, YIELD, "coder", _transcript(OLD, 99))
    assert _unit(root)[train_state.SIZES] == {OLD: {"tokens": PAST}}
    _refused(train_runner.dispatch_unit(root, "U1", OLD), "past the context limit")


@pytest.mark.usefixtures("tmp_root")
def test_an_unmeasured_first_return_then_a_measured_one_stores_the_tokens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _bound(tmp_path)
    _return(monkeypatch, capsys, root, OLD, YIELD)
    assert _unit(root)[train_state.SIZES] == {OLD: {"reason": "path not derivable"}}
    _return(monkeypatch, capsys, root, OLD, YIELD, "coder", _transcript(OLD, 77))
    assert _unit(root)[train_state.SIZES] == {OLD: {"tokens": 77}}


@pytest.mark.usefixtures("tmp_root")
def test_a_stop_with_no_transcript_after_a_measured_handback_keeps_the_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _bound(tmp_path)
    path = _path_handoff(root, OLD)
    reply = f"Notes.\n[STATUS: HANDOFF] path={path}"
    _return(monkeypatch, capsys, root, OLD, reply, "coder", _transcript(OLD, PAST))
    # The stop that follows the hand-back carries the same reply and no transcript path.
    payload: dict[str, object] = {
        "hook_event_name": "SubagentStop",
        "session_id": SESSION,
        "cwd": str(root),
        "agent_id": OLD,
        "agent_type": "daedalus:coder",
        "last_assistant_message": reply,
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    assert handback_check.main() == 0
    assert "block" not in capsys.readouterr().out
    cell = {"tokens": PAST, "reason": "path not derivable"}
    assert _unit(root)[train_state.SIZES] == {OLD: cell}
    assert _unit(root)[train_state.HANDOFFS][0]["tokens"] == PAST
    code, out = _cli(root, "dispatch", "--unit", "U1", "--warm", OLD)
    assert code == 1 and f"recorded {PAST} tokens" in out, out


@pytest.mark.usefixtures("tmp_root")
def test_an_unmeasured_return_records_the_reason_and_refuses_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _bound(tmp_path)
    out = _return(monkeypatch, capsys, root, OLD, YIELD)
    assert "block" not in out and "deny" not in out
    assert _unit(root)[train_state.SIZES] == {OLD: {"reason": "path not derivable"}}
    # A dispatch on an unmeasured coder runs as before.
    assert train_runner.dispatch_unit(root, "U1", OLD).code == 0


@pytest.mark.usefixtures("tmp_root")
def test_an_agent_with_no_unit_records_no_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _bound(tmp_path)
    before = train_state.load(root, TRAIN)
    _return(monkeypatch, capsys, root, JUDGE, "[VERDICT: VERIFIED] claims=1", "verifier")
    assert train_state.load(root, TRAIN) == before


# Item 2: the hand-off reply.


@pytest.mark.usefixtures("tmp_root")
def test_a_path_handoff_is_recorded_with_its_size_and_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _bound(tmp_path)
    path = _path_handoff(root, OLD)
    reply = f"Notes.\n[STATUS: HANDOFF] path={path}"
    _return(monkeypatch, capsys, root, OLD, reply, "coder", _transcript(OLD, PAST))
    want = {"old": OLD, "tokens": PAST, "file": str(path), "new": None}
    assert _unit(root)[train_state.HANDOFFS] == [want]
    # The same reply again, as the stop after the hand-back, records nothing new.
    _return(monkeypatch, capsys, root, OLD, reply, "coder", _transcript(OLD, PAST))
    assert _unit(root)[train_state.HANDOFFS] == [want]


def test_an_inline_handoff_is_saved_to_the_agents_own_file_and_recorded(
    tmp_path: Path,
    tmp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root = _bound(tmp_path)
    _return(monkeypatch, capsys, root, JUDGE, INLINE, "verifier")
    path = handoff.handoff_path({"agent_id": JUDGE, "cwd": str(root)})
    assert path is not None and path.is_relative_to(tmp_root)
    assert path.read_text(encoding="utf-8") == "## Hand-off\nDone: rows 1-3.\nLeft: row 4.\n"
    assert stat.S_IMODE(os.lstat(path).st_mode) == handoff.FILE_MODE and handoff.written(path)
    assert stat.S_IMODE(os.lstat(path.parent).st_mode) == 0o700
    # A verifier holds no unit binding, so its hand-off is recorded run-wide.
    state = train_state.load(root, TRAIN)
    assert state[train_state.HANDOFFS] == [
        {"old": JUDGE, "tokens": None, "file": str(path), "new": None, "unit": None}
    ]


@pytest.mark.usefixtures("tmp_root")
@pytest.mark.parametrize("form", ["other", "missing", "empty"])
def test_a_refused_handoff_reply_records_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], form: str
) -> None:
    root = _bound(tmp_path)
    own = handoff.handoff_path({"agent_id": OLD, "cwd": str(root)})
    assert own is not None
    if form == "other":
        named = _path_handoff(root, NEW)
    elif form == "empty":
        named = _path_handoff(root, OLD, "")
    else:
        named = own
    before = train_state.load(root, TRAIN)
    reply = f"x\n[STATUS: HANDOFF] path={named}"
    out = _return(monkeypatch, capsys, root, OLD, reply, "coder", _transcript(OLD, PAST))
    assert "deny" in out and str(own) in out
    assert train_state.load(root, TRAIN) == before


@pytest.mark.usefixtures("tmp_root")
def test_a_refused_inline_reply_saves_no_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _bound(tmp_path)
    out = _return(monkeypatch, capsys, root, JUDGE, "Done.\n[STATUS: HANDOFF] inline", "verifier")
    assert "deny" in out
    path = handoff.handoff_path({"agent_id": JUDGE, "cwd": str(root)})
    assert path is not None and not path.exists()
    assert train_state.HANDOFFS not in train_state.load(root, TRAIN)


@pytest.mark.usefixtures("tmp_root")
def test_two_handoffs_on_one_unit_chain_old_to_new(tmp_path: Path) -> None:
    root = _bound(tmp_path)
    _sized(root, OLD, PAST, "/tmp/old.md")
    _sized(root, NEW, PAST + 5, "/tmp/new.md")
    _sized(root, THIRD, 10)
    entries = _unit(root)[train_state.HANDOFFS]
    assert [(e["old"], e["new"]) for e in entries] == [(OLD, NEW), (NEW, THIRD)]
    assert [e["tokens"] for e in entries] == [PAST, PAST + 5]


@pytest.mark.usefixtures("tmp_root")
def test_a_stopped_and_resumed_run_keeps_sizes_and_handoffs(tmp_path: Path) -> None:
    root = _bound(tmp_path)
    _sized(root, OLD, PAST, "/tmp/old.md")
    before = _unit(root)
    _, ok = workspace.stop(root, "break", None)
    assert ok
    workspace.resume(root)
    after = _unit(root)
    assert after[train_state.SIZES] == before[train_state.SIZES] == {OLD: {"tokens": PAST}}
    assert after[train_state.HANDOFFS] == before[train_state.HANDOFFS]


# Item 3: every resume path refuses a coder past the limit.


def _resume_paths(root: Path) -> dict[str, train_runner.Outcome]:
    return {
        "dispatch --warm": train_runner.dispatch_unit(root, "U1", OLD),
        "route REFUTED": train_runner.route_unit(root, "U1", "REFUTED"),
        "route --rows": train_runner.route_unit(root, "U1", "REFUTED", rows=2),
    }


def test_each_resume_path_refuses_a_coder_past_the_limit(tmp_path: Path) -> None:
    root = _bound(tmp_path)
    path = _built(root, "U1")
    _verdict(root, path, REFUTED_REPLY)
    _sized(root, OLD, PAST)
    for name, outcome in _resume_paths(root).items():
        text = _refused(outcome, f"recorded {PAST} tokens", "--handoff-write")
        assert f"`{handoff.WRITE_LINE}`" in text and "dispatch --repo" in text, name
    # Neither the choice nor the coder model was recorded by a refused resume.
    assert len(_unit(root)["coders"]) == 1


def test_finish_unit_warm_refuses_a_coder_past_the_limit(tmp_path: Path) -> None:
    root = _bound(tmp_path)
    _verdict(root, _built(root, "U1"), VERIFIED_REPLY)
    _sized(root, OLD, PAST)
    outcome = train_runner.finish_unit(root, "U1", "U2", [], OLD)
    _refused(outcome, f"coder {OLD} recorded {PAST} tokens", "--unit U2 --warm")


def test_an_audit_fix_unit_resume_meets_the_same_refusal(tmp_path: Path) -> None:
    from tests.test_fix_units import _fix, _merged
    from tests.test_fix_units import _fixture as fix_fixture

    root = _merged(fix_fixture(tmp_path / "repo"))
    _ok(_fix(root))
    # Audit step 8: the fix unit's worktree is made before its coder resumes on it.
    workspace.create(root, f"{TRAIN}-fix1-u1", f"daedalus/{TRAIN}")
    train_state.record_return(root, TRAIN, U1, OLD, {"tokens": PAST}, None)
    outcome = train_runner.dispatch_unit(root, "fix1-u1", OLD)
    _refused(outcome, "--unit fix1-u1 --warm")
    _ok(train_runner.dispatch_unit(root, "fix1-u1", OLD, handoff_write=True))
    _refused(train_runner.dispatch_unit(root, "fix1-u1", OLD, handoff_write=True), "once")


def test_a_defined_runs_warm_resume_meets_the_same_refusal(tmp_path: Path) -> None:
    root = _bound(tmp_path)
    _sized(root, OLD, PAST)
    state = train_state.load(root, TRAIN)
    session = SimpleNamespace(repo=root, train_id=TRAIN, state=state)
    with pytest.raises(train_runner.RunnerError, match="past the context limit"):
        train_runner._warm_from(session, _unit(root), OLD, [])  # type: ignore[arg-type]
    _limit(0)
    assert train_runner._warm_from(session, _unit(root), OLD, []) == ""  # type: ignore[arg-type]


def test_the_handoff_write_resume_runs_once_per_agent_per_unit(tmp_path: Path) -> None:
    root = _bound(tmp_path)
    _sized(root, OLD, PAST)
    before = train_state.load(root, TRAIN)
    code, out = _cli(root, "dispatch", "--unit", "U1", "--warm", OLD, "--handoff-write")
    assert code == 0 and out == (
        f"handoff-write U1: resume coder {OLD} once with `{handoff.WRITE_LINE}`\n"
    ), out
    after = train_state.load(root, TRAIN)
    assert _unit(root)[train_state.HANDOFF_RESUMES] == [OLD]
    # The mark is the only change: no choice, no model record, no brief rewrite.
    assert after["choices"] == before["choices"]
    code, out = _cli(root, "dispatch", "--unit", "U1", "--warm", OLD, "--handoff-write")
    assert code == 1 and "already resumed once" in out and out.count("Next:") == 1
    # A plain resume stays refused after the hand-off write.
    _refused(train_runner.dispatch_unit(root, "U1", OLD), "past the context limit")


def test_the_handoff_write_needs_warm_and_a_coder_past_the_limit(tmp_path: Path) -> None:
    root = _bound(tmp_path)
    _refused(train_runner.dispatch_unit(root, "U1", None, handoff_write=True), "--warm")
    _sized(root, OLD, 10)
    _refused(train_runner.dispatch_unit(root, "U1", OLD, handoff_write=True), "not past")


# Item 4: the new coder starts from the hand-off.


def test_a_cold_dispatch_refuses_while_the_old_coder_has_no_handoff(tmp_path: Path) -> None:
    root = _bound(tmp_path)
    _sized(root, OLD, PAST)
    _refused(train_runner.dispatch_unit(root, "U1"), "no hand-off of it is recorded")


def test_the_new_coders_brief_is_the_units_brief_plus_the_handoff_line(tmp_path: Path) -> None:
    root = _bound(tmp_path)
    brief = _scratch(root) / "briefs" / "u1.md"
    original = brief.read_text(encoding="utf-8").splitlines()
    unit = _unit(root)
    model, klass = unit["coders"][-1]["model"], unit["coders"][-1]["class"]
    path = _built(root, "U1")
    _verdict(root, path, REFUTED_REPLY)
    _ok(train_runner.refuted(root, "U1"))
    _sized(root, OLD, PAST, "/tmp/h/old.md")
    line = _ok(train_runner.dispatch_unit(root, "U1"))[0]
    assert line.endswith(" rows=needed handoff=/tmp/h/old.md"), line
    rows = brief.read_text(encoding="utf-8").splitlines()
    at = next(i for i, row in enumerate(original) if row.startswith("Worktree: ")) + 1
    assert rows == [*original[:at], "Hand-off: /tmp/h/old.md", *original[at:]]
    after = _unit(root)
    # The refutation count, class and model carry over.
    assert len(after["refutations"]) == 1
    assert {(c["model"], c["class"]) for c in after["coders"]} == {(model, klass)}
    # The old coder retired from the unit, so a new coder's first write binds it.
    assert unit_binding.claim(root, TRAIN, OLD, U1) is not None
    assert unit_binding.claim(root, TRAIN, NEW, U1) is None
    _sized(root, NEW, 50)
    assert _unit(root)[train_state.HANDOFFS][0]["new"] == NEW
    # A second hand-off replaces the brief's one Hand-off line.
    _sized(root, NEW, PAST, "/tmp/h/new.md")
    _ok(train_runner.dispatch_unit(root, "U1"))
    rows = brief.read_text(encoding="utf-8").splitlines()
    assert [r for r in rows if r.startswith("Hand-off: ")] == ["Hand-off: /tmp/h/new.md"]


@pytest.mark.usefixtures("tmp_root")
def test_the_whole_handoff_path_end_to_end_through_the_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _bound(tmp_path)
    # The coder returns past the limit; the hook records its size on the unit.
    _return(monkeypatch, capsys, root, OLD, YIELD, "coder", _transcript(OLD, PAST))
    assert _unit(root)[train_state.SIZES] == {OLD: {"tokens": PAST}}
    code, out = _cli(root, "dispatch", "--unit", "U1", "--warm", OLD)
    assert code == 1 and "--handoff-write" in out and out.count("Next:") == 1, out
    code, out = _cli(root, "dispatch", "--unit", "U1", "--warm", OLD, "--handoff-write")
    assert code == 0 and out.startswith("handoff-write U1: "), out
    code, out = _cli(root, "dispatch", "--unit", "U1", "--warm", OLD, "--handoff-write")
    assert code == 1 and "already resumed once" in out, out
    # The coder writes its hand-off file and hands back; the hook records the hand-off.
    path = _path_handoff(root, OLD)
    reply = f"Wrote it.\n[STATUS: HANDOFF] path={path}"
    out = _return(monkeypatch, capsys, root, OLD, reply, "coder", _transcript(OLD, PAST))
    assert "deny" not in out
    assert _unit(root)[train_state.HANDOFFS] == [
        {"old": OLD, "tokens": PAST, "file": str(path), "new": None}
    ]
    code, out = _cli(root, "dispatch", "--unit", "U1")
    assert code == 0 and out.splitlines()[0].endswith(f" handoff={path}"), out
    brief = (_scratch(root) / "briefs" / "u1.md").read_text(encoding="utf-8")
    assert f"\nHand-off: {path}\n" in brief
    # The new coder's first write binds the unit; its first return fills `new`.
    assert unit_binding.claim(root, TRAIN, NEW, U1) is None
    _return(monkeypatch, capsys, root, NEW, YIELD, "coder", _transcript(NEW, 40))
    assert _unit(root)[train_state.HANDOFFS][0]["new"] == NEW
    assert _unit(root)[train_state.SIZES][NEW] == {"tokens": 40}


# Item 5: the state print and the summary.


def test_the_state_print_lists_each_handoff(tmp_path: Path) -> None:
    # `state` prints for a run started from a definition, as its fix unit lines do (0271).
    from tests.test_train_runner import PROBE, _probe_stage, _started, _write_train

    repo = tmp_path.resolve() / "defined"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "commit", "-q", "--allow-empty", "-m", "init")
    plugin = tmp_path.resolve() / "plugin"
    (plugin / "scripts").mkdir(parents=True)
    (plugin / "trains").mkdir()
    (plugin / "agents").symlink_to(REPO_ROOT / "agents")
    (plugin / "scripts" / "probe.py").write_text(PROBE)
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    train = train_state.active_train(repo)
    assert train is not None
    before = _ok(train_runner.state_lines(repo, plugin))
    assert not [ln for ln in before if ln.startswith("hand-off:")]
    train_state.add_unit(repo, train, f"{train}-u1", "b", repo / "wt")
    train_state.record_return(repo, train, f"{train}-u1", OLD, {"tokens": PAST}, "/tmp/h/o.md")
    train_state.record_return(repo, train, f"{train}-u1", NEW, {"tokens": 7}, None)
    train_state.record_return(repo, train, None, JUDGE, {"reason": "x"}, "/tmp/h/judge.md")
    after = _ok(train_runner.state_lines(repo, plugin))
    assert after == [
        *before,
        f"hand-off: unit u1 old {OLD} new {NEW} size {PAST} file /tmp/h/o.md",
        f"hand-off: unit none old {JUDGE} new none size unmeasured file /tmp/h/judge.md",
    ]


def test_the_summary_lists_each_handoff_and_no_section_without_one(tmp_path: Path) -> None:
    root = _bound(tmp_path)
    command = f"python3 {SCRIPTS_DIR / 'daedalus_train.py'} summary --repo {root}"
    summary = root / "docs" / ".tmp" / "daedalus" / f"{TRAIN}-summary.md"
    _hook(root, hook_event_name="PreToolUse", tool_name="Bash", tool_input={"command": command})
    _ok(train_runner.summary(root))
    assert "## Hand-offs" not in summary.read_text(encoding="utf-8")
    _sized(root, OLD, PAST, "/tmp/h/old.md")
    _sized(root, NEW, 7)
    train_state.record_return(root, TRAIN, None, JUDGE, {"reason": "x"}, "/tmp/h/judge.md")
    _hook(root, hook_event_name="PreToolUse", tool_name="Bash", tool_input={"command": command})
    _ok(train_runner.summary(root))
    text = summary.read_text(encoding="utf-8")
    assert (
        "## Hand-offs\n"
        f"- unit u1 old {OLD} new {NEW} size {PAST} file old.md\n"
        f"- unit none old {JUDGE} new none size unmeasured file judge.md\n"
    ) in text
    state = train_state.load(root, TRAIN)
    assert train_summary._handoffs(state, TRAIN, root)[0] == "## Hand-offs"


# Item 6: the limit off.


@pytest.mark.parametrize("value", [0, None])
def test_with_the_limit_off_nothing_refuses(tmp_path: Path, value: object) -> None:
    _limit(value)
    root = _bound(tmp_path)
    path = _built(root, "U1")
    _verdict(root, path, REFUTED_REPLY)
    _sized(root, OLD, PAST)
    for name, outcome in _resume_paths(root).items():
        assert outcome.code == 0, (name, outcome.lines)
    assert _unit(root)[train_state.SIZES] == {OLD: {"tokens": PAST}}
    assert train_runner.dispatch_unit(root, "U1").code == 0
    assert train_state.HANDOFF_RESUMES not in _unit(root)


@pytest.mark.usefixtures("tmp_root")
def test_with_the_limit_off_a_return_still_records_its_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _limit(None)
    root = _bound(tmp_path)
    _return(monkeypatch, capsys, root, OLD, YIELD, "coder", _transcript(OLD, PAST))
    assert _unit(root)[train_state.SIZES] == {OLD: {"tokens": PAST}}

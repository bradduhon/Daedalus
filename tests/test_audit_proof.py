# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import os
from functools import partial
from pathlib import Path
from typing import Any

import pytest
from lib import audit, train_state
from lib.audit_proof import (
    ProofError,
    approved,
    hooks_live,
    newest_log,
    push_proof,
    read_chain,
    tip_problem,
)

from tests.conftest import append_handback, replay_auditor, write_train_marker
from tests.conftest import git as _git

NEEDLE = "daedalus_workspace.py begin"
TRAIN = "20261016-120000"
MARKED = "20261017-120000"
AUDITOR = "daedalus:security-auditor"


@pytest.fixture
def project_data(project_data: Path, repo_cwd: Path) -> Path:
    write_train_marker(repo_cwd)
    train_state.save(repo_cwd, TRAIN, {"train_id": TRAIN, "start_seq": 0})
    return project_data


def _bash(hook_input: Any, command: str, **kw: Any) -> None:
    audit.audit_append(hook_input(tool_input={"command": command}, **kw))


def test_hooks_live_passes_when_the_newest_bash_record_is_this_command(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _bash(hook_input, "git status --porcelain")
    _bash(hook_input, f"python3 /p/scripts/{NEEDLE} --repo .")
    line = hooks_live(repo_cwd, NEEDLE)
    assert line == "OK hooks live: session sess-test, chain intact (2 records)"


def test_hooks_live_ignores_newer_non_bash_and_post_records(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _bash(hook_input, f"python3 /p/scripts/{NEEDLE}")
    audit.audit_append(hook_input(hook_event_name="PostToolUse", tool_input={"command": "ls"}))
    audit.audit_append(hook_input(tool_name="Read", tool_input={"file_path": "/x"}))
    assert hooks_live(repo_cwd, NEEDLE).startswith("OK hooks live:")


def test_hooks_live_refuses_when_another_command_is_newest(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _bash(hook_input, f"python3 /p/scripts/{NEEDLE}")
    _bash(hook_input, "ls")
    with pytest.raises(ProofError) as info:
        hooks_live(repo_cwd, NEEDLE)
    assert str(info.value).startswith("NOT LIVE:")
    assert "Next: run the Daedalus health check (/daedalus:doctor)." in str(info.value)


def test_hooks_live_refuses_without_a_log(project_data: Path, repo_cwd: Path) -> None:
    with pytest.raises(ProofError) as info:
        hooks_live(repo_cwd, NEEDLE)
    assert str(info.value).startswith("NOT LIVE:")


def test_hooks_live_reports_a_broken_chain(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _bash(hook_input, f"python3 /p/scripts/{NEEDLE}")
    log = audit.log_path("sess-test", str(repo_cwd))
    rec = json.loads(log.read_text().splitlines()[0])
    rec["tool_name"] = "Write"
    log.write_text(json.dumps(rec) + "\n")
    with pytest.raises(ProofError) as info:
        hooks_live(repo_cwd, NEEDLE)
    assert str(info.value).startswith("BROKEN")


def test_hooks_live_mark_writes_start_seq_once(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # issue 57: no state file is left alone; the first marked call sets start_seq.
    _bash(hook_input, f"python3 /p/scripts/{NEEDLE}")
    assert hooks_live(repo_cwd, NEEDLE, mark=True).startswith("OK hooks live:")
    assert not train_state.state_path(repo_cwd, MARKED).exists()
    train_state.save(repo_cwd, MARKED, {"train_id": MARKED})
    _bash(hook_input, f"python3 /p/scripts/{NEEDLE}")
    hooks_live(repo_cwd, NEEDLE, mark=True)
    assert train_state.load(repo_cwd, MARKED)["start_seq"] == 2
    _bash(hook_input, f"python3 /p/scripts/{NEEDLE}")
    hooks_live(repo_cwd, NEEDLE, mark=True)
    hooks_live(repo_cwd, NEEDLE)
    assert train_state.load(repo_cwd, MARKED)["start_seq"] == 2


def test_hooks_live_without_mark_writes_nothing(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    train_state.save(repo_cwd, MARKED, {"train_id": MARKED})
    _bash(hook_input, f"python3 /p/scripts/{NEEDLE}")
    hooks_live(repo_cwd, NEEDLE)
    assert "start_seq" not in train_state.load(repo_cwd, MARKED)


def test_newest_log_is_by_mtime(project_data: Path, hook_input: Any, repo_cwd: Path) -> None:
    _bash(hook_input, "a", session_id="old")
    _bash(hook_input, "b", session_id="new")
    old = audit.log_path("old", str(repo_cwd))
    os.utime(old, (1, 1))
    assert newest_log(repo_cwd).stem == "new"
    assert [r["seq"] for r in read_chain(newest_log(repo_cwd))] == [1]


def _stop(hook_input: Any, verdict: str, agent_type: str = AUDITOR) -> None:
    audit.audit_append(
        hook_input(
            hook_event_name="SubagentStop",
            tool_name=None,
            tool_input=None,
            agent_type=agent_type,
            agent_id="a1",
            last_assistant_message=verdict,
        )
    )


def _summary_write(hook_input: Any, repo_cwd: Path) -> None:
    path = f"{repo_cwd}/docs/.tmp/daedalus/{TRAIN}-summary.md"
    audit.audit_append(hook_input(tool_name="Write", tool_input={"file_path": path}))


def _summary(
    repo_cwd: Path, text: str = "Session sess-test: .claude/daedalus/audit/sess-test.jsonl\n"
) -> None:
    path = repo_cwd / "docs" / ".tmp" / "daedalus" / f"{TRAIN}-summary.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"# Build Train {TRAIN}\n{text}", encoding="utf-8")


def _train(hook_input: Any, repo_cwd: Path, verdict: str) -> None:
    _stop(hook_input, verdict)
    _summary_write(hook_input, repo_cwd)
    _summary(repo_cwd)


def _refused(repo_cwd: Path, train: str = TRAIN) -> str:
    with pytest.raises(ProofError) as info:
        approved(repo_cwd, train)
    return str(info.value)


def _judged(repo: Path, status: str = "approved") -> str:
    # 59: a commit on the integration branch and the verdict recorded on it.
    _git(repo, "commit", "-q", "--allow-empty", "-m", "unit")
    _git(repo, "branch", "-f", f"daedalus/{TRAIN}", "HEAD")
    tip = _git(repo, "rev-parse", "HEAD").stdout.strip()
    verdict = {"status": status, "tip": tip, "round": 1, "seq": 1}
    train_state.update(repo, TRAIN, verdict=verdict)
    return tip


def _ok(seq: int, tip: str) -> str:
    return (
        f"OK approved: approved verdict, train {TRAIN}, session sess-test, "
        f"auditor record seq {seq}, judged tip {tip[:12]}"
    )


def test_approved_passes_on_an_approved_final_round(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    tip = _judged(repo_cwd)
    _train(hook_input, repo_cwd, f"[VERDICT: APPROVED] tip={tip} ok")
    assert approved(repo_cwd, TRAIN) == _ok(1, tip)


def test_approved_refuses_a_rejected_final_round(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _stop(hook_input, "[VERDICT: APPROVED] first")
    _train(hook_input, repo_cwd, "[VERDICT: REJECTED] a.py:1 high")
    message = _refused(repo_cwd)
    assert message.startswith("NOT APPROVED:")
    assert message.endswith(
        "Next: run /daedalus:build-train; this train has no approved audit in its log."
    )


def test_approved_ignores_auditor_stops_after_the_summary_write(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _train(hook_input, repo_cwd, "[VERDICT: REJECTED] a.py:1 high")
    _stop(hook_input, "[VERDICT: APPROVED] late")
    assert _refused(repo_cwd).startswith("NOT APPROVED:")


def test_approved_requires_the_namespaced_agent_type(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _stop(hook_input, "[VERDICT: APPROVED] ok", agent_type="security-auditor")
    _summary_write(hook_input, repo_cwd)
    _summary(repo_cwd)
    assert _refused(repo_cwd).startswith("NOT APPROVED:")


def test_approved_refuses_a_missing_summary(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _stop(hook_input, "[VERDICT: APPROVED] ok")
    _summary_write(hook_input, repo_cwd)
    assert _refused(repo_cwd).startswith("NOT APPROVED:")


def test_approved_refuses_a_summary_without_a_session_line(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _stop(hook_input, "[VERDICT: APPROVED] ok")
    _summary_write(hook_input, repo_cwd)
    _summary(repo_cwd, "Audit log: none\n")
    assert _refused(repo_cwd).startswith("NOT APPROVED:")


def test_approved_refuses_a_summary_write_never_logged(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _stop(hook_input, "[VERDICT: APPROVED] ok")
    _summary(repo_cwd)
    assert _refused(repo_cwd).startswith("NOT APPROVED:")


def test_approved_refuses_a_bad_train_id(project_data: Path, repo_cwd: Path) -> None:
    message = _refused(repo_cwd, "../x")
    assert message == (
        "NOT APPROVED: train id ../x is not YYYYMMDD-HHMMSS. "
        "Next: pass the id from a summary file name in docs/.tmp/daedalus/."
    )


def test_approved_reports_a_broken_build_log(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _train(hook_input, repo_cwd, "[VERDICT: APPROVED] ok")
    log = audit.log_path("sess-test", str(repo_cwd))
    lines = log.read_text().splitlines()
    log.write_text(lines[1] + "\n")
    assert _refused(repo_cwd).startswith("BROKEN")


def test_approved_passes_on_a_closing_verdict_line(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # 41: B1, a hand-back sentence first and the verdict as the last line.
    tip = _judged(repo_cwd)
    reply = f"The audit found no defect in the two units.\n[VERDICT: APPROVED] tip={tip}"
    _train(hook_input, repo_cwd, reply)
    assert approved(repo_cwd, TRAIN).startswith("OK approved:")


def test_approved_refuses_a_reply_with_no_verdict_line(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _train(hook_input, repo_cwd, "The audit is finished.")
    assert "is not [VERDICT: APPROVED]" in _refused(repo_cwd)


def test_approved_reads_the_tail_of_a_long_reply(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # 41: B3, the head holds no verdict, so the pass comes from the tail.
    tip = _judged(repo_cwd)
    _train(hook_input, repo_cwd, "x" * 3000 + f"\n[VERDICT: APPROVED] tip={tip}")
    assert approved(repo_cwd, TRAIN).startswith("OK approved:")


def test_approved_refuses_any_rejected_line(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _train(hook_input, repo_cwd, "[VERDICT: REJECTED] a.py:1 high\nnotes\n[VERDICT: APPROVED]")
    assert "carries a [VERDICT: REJECTED] line" in _refused(repo_cwd)


def test_approved_refuses_a_rejected_line_in_the_tail(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # 41: B-2, the tail is scanned for rejected lines, not only the head.
    _train(
        hook_input,
        repo_cwd,
        "[VERDICT: APPROVED]\n" + "x" * 3000 + "\n[VERDICT: REJECTED] a.py:1 high\nend",
    )
    assert "carries a [VERDICT: REJECTED] line" in _refused(repo_cwd)


def _hand_chain(repo_cwd: Path, stop: dict[str, object]) -> None:
    # 41: B5/B6, chain-valid records written without build_record.
    path = f"{repo_cwd}/docs/.tmp/daedalus/{TRAIN}-summary.md"
    write: dict[str, object] = {"tool_name": "Write", "tool_input": {"file_path": path}}
    first: dict[str, object] = {"event": "SubagentStop", "agent_type": AUDITOR, **stop}
    prev, lines = audit.GENESIS, []
    for seq, rec in enumerate((first, write), start=1):
        rec.update(seq=seq, prev_hash=prev)
        rec["hash"] = prev = audit.record_hash(rec)
        lines.append(json.dumps(rec))
    log = audit.log_path("sess-test", str(repo_cwd))
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("\n".join(lines) + "\n")
    _summary(repo_cwd)


def test_approved_refuses_a_tail_that_is_not_text(project_data: Path, repo_cwd: Path) -> None:
    _hand_chain(
        repo_cwd,
        {
            "last_message_head": "[VERDICT: APPROVED] ok",
            "last_message_tail": ["[VERDICT: APPROVED]"],
        },
    )
    message = _refused(repo_cwd)
    assert message.startswith("NOT APPROVED:")
    assert "(record seq 1) has a last_message_tail that is not text" in message


def test_approved_passes_a_record_from_before_the_tail_field(
    project_data: Path, repo_cwd: Path
) -> None:
    tip = _judged(repo_cwd)
    _hand_chain(repo_cwd, {"last_message_head": f"[VERDICT: APPROVED] tip={tip} ok"})
    assert approved(repo_cwd, TRAIN) == _ok(1, tip)


_handback = partial(append_handback, tool_response={"success": True})


def _start(repo_cwd: Path, seq: int) -> None:
    train_state.update(repo_cwd, TRAIN, start_seq=seq)


def test_approved_finds_the_verdict_in_the_auditor_hand_back(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # issue 57: Train A's stop records hold only a relay; the verdict is in the hand-back call.
    tip = _judged(repo_cwd)
    replayed = replay_auditor(repo_cwd, "sess-test")
    _summary_write(hook_input, repo_cwd)
    _summary(repo_cwd)
    assert replayed[-2]["tool_input"] == {"message": "[VERDICT: APPROVED]"}
    # 59: the hand-back verdict is found, and its line names no tip, so it refuses.
    assert f"verdict names tip none, not the recorded tip {tip[:12]}" in _refused(repo_cwd)


def test_approved_reads_the_tip_from_the_auditor_hand_back(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    tip = _judged(repo_cwd)
    replay_auditor(repo_cwd, "sess-test")
    _handback(hook_input, f"[VERDICT: APPROVED] tip={tip}")
    _summary_write(hook_input, repo_cwd)
    _summary(repo_cwd)
    seq = len(read_chain(audit.log_path("sess-test", str(repo_cwd)))) - 1
    assert approved(repo_cwd, TRAIN) == _ok(seq, tip)


def test_approved_refuses_train_a_without_its_hand_back_records(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # issue 57: the bug as Train A met it; the stop records alone carry no verdict line.
    replay_auditor(repo_cwd, "sess-test", handbacks=False)
    _summary_write(hook_input, repo_cwd)
    _summary(repo_cwd)
    assert "is not [VERDICT: APPROVED]" in _refused(repo_cwd)


def test_approved_ignores_a_verdict_before_start_seq(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # issue 57: an earlier train's approval in the same session log never counts.
    replay_auditor(repo_cwd, "sess-test")
    _bash(hook_input, "python3 /p/scripts/verify_audit_chain.py --hooks-live")
    _start(repo_cwd, len(read_chain(audit.log_path("sess-test", str(repo_cwd)))))
    _stop(hook_input, "The audit is finished.")
    _summary_write(hook_input, repo_cwd)
    _summary(repo_cwd)
    assert "(record seq 8) is not [VERDICT: APPROVED]" in _refused(repo_cwd)
    _start(repo_cwd, 8)
    assert "no daedalus:security-auditor reply after seq 8" in _refused(repo_cwd)


def test_approved_refuses_without_start_seq(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    train_state.save(repo_cwd, TRAIN, {"train_id": TRAIN})
    _train(hook_input, repo_cwd, "[VERDICT: APPROVED] ok")
    assert "records no start_seq" in _refused(repo_cwd)


def test_approved_newer_rejection_still_wins(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # 0089: a rejection in the newest turn wins over its own approving relay and older rounds.
    replay_auditor(repo_cwd, "sess-test")
    _handback(hook_input, "[VERDICT: REJECTED] a.py:1 high")
    _stop(hook_input, "[VERDICT: APPROVED] relayed")
    _summary_write(hook_input, repo_cwd)
    _summary(repo_cwd)
    assert "carries a [VERDICT: REJECTED] line" in _refused(repo_cwd)


def test_approved_reads_a_hand_back_with_no_stop_yet(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # issue 57: a hand-back after the newest stop is the newest turn; no older round stands in.
    replay_auditor(repo_cwd, "sess-test")
    _handback(hook_input, "[VERDICT: REJECTED] a.py:1 high")
    _summary_write(hook_input, repo_cwd)
    _summary(repo_cwd)
    assert "carries a [VERDICT: REJECTED] line" in _refused(repo_cwd)


def test_approved_refuses_a_hand_back_message_that_is_not_text(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _handback(hook_input, "[VERDICT: APPROVED]")
    audit.audit_append(
        hook_input(
            hook_event_name="PostToolUse",
            tool_name="SubagentHandback",
            tool_input={"message": ["[VERDICT: APPROVED]"]},
            agent_type=AUDITOR,
            agent_id="a1",
        )
    )
    _train(hook_input, repo_cwd, "[VERDICT: APPROVED] ok")
    assert "(record seq 2) has a tool_input.message that is not text" in _refused(repo_cwd)


LEDGER = "docs/decisions.md"


def _repo_ledger(project_data: Path, repo: Path, path: str = LEDGER) -> None:
    # spec 3.5: a repo-local ledger, so its commit lands on the integration branch.
    decl = {
        "path": path,
        "format": "markdown-table-row",
        "id_scheme": "{seq:04d}-{repo}-{type}",
        "sequence_source": "last-row-id",
    }
    (project_data / "config.json").write_text(json.dumps({"ledger": decl}), encoding="utf-8")
    (repo / "docs").mkdir(exist_ok=True)


def _commit(repo: Path, *files: str) -> str:
    for name in files:
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(path.read_text() + "row\n" if path.exists() else "row\n")
        _git(repo, "add", name)
    _git(repo, "commit", "-q", "--allow-empty", "-m", "next")
    _git(repo, "branch", "-f", f"daedalus/{TRAIN}", "HEAD")
    return _git(repo, "rev-parse", "HEAD").stdout.strip()


@pytest.mark.parametrize("named", ["{tip}", "", "{other}", "{upper}", "{tip} tip={other}"], ids=str)
def test_verdict_tip_must_be_the_recorded_tip(
    project_data: Path, hook_input: Any, repo_cwd: Path, named: str
) -> None:
    # 59: the auditor's tip= equals the recorded tip; none, another, uppercase or two refuse.
    tip = _judged(repo_cwd)
    words = named.format(tip=tip, other="b" * 40, upper=tip.upper())
    line = "[VERDICT: APPROVED]" + (f" tip={words}" if words else "")
    _train(hook_input, repo_cwd, f"{line}\nnotes\n[VERDICT: APPROVED] tip={tip}")
    if named == "{tip}":
        assert approved(repo_cwd, TRAIN) == _ok(1, tip)
    else:
        assert "verdict names tip none, not the recorded tip" in _refused(repo_cwd)


def test_approved_refuses_a_rejected_or_absent_recorded_verdict(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    tip = _judged(repo_cwd, status="rejected")
    _train(hook_input, repo_cwd, f"[VERDICT: APPROVED] tip={tip}")
    assert "records no approved verdict" in _refused(repo_cwd)


def test_the_single_ledger_commit_on_the_judged_tip_passes(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # spec 3.5: the train's own ledger commit is the one move past the judged tip that passes.
    _repo_ledger(project_data, repo_cwd)
    tip = _judged(repo_cwd)
    _train(hook_input, repo_cwd, f"[VERDICT: APPROVED] tip={tip}")
    ledger_tip = _commit(repo_cwd, LEDGER)
    assert ledger_tip != tip
    assert approved(repo_cwd, TRAIN) == _ok(1, tip)
    assert tip_problem(repo_cwd, tip, ledger_tip) is None


@pytest.mark.parametrize(
    "files", [(LEDGER, LEDGER), (LEDGER, "src/app.py"), ("src/app.py",), ()], ids=str
)
def test_any_other_move_past_the_judged_tip_refuses(
    project_data: Path, hook_input: Any, repo_cwd: Path, files: tuple[str, ...]
) -> None:
    # spec 3.5: two commits, or one that changes any path but the ledger, refuse.
    _repo_ledger(project_data, repo_cwd)
    tip = _judged(repo_cwd)
    _train(hook_input, repo_cwd, f"[VERDICT: APPROVED] tip={tip}")
    if files[:2] == (LEDGER, LEDGER):
        _commit(repo_cwd, LEDGER)
        moved = _commit(repo_cwd, LEDGER)
        want = "is not one plain commit on top of it"
    else:
        moved = _commit(repo_cwd, *files)
        want = "with a commit that changes more than the ledger"
    message = _refused(repo_cwd)
    assert f"the tip {moved[:12]} moved past the judged tip {tip[:12]}" in message
    assert want in message


def test_a_ledger_commit_refuses_when_the_ledger_is_not_in_the_repo(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # spec 3.5: a ledger under a Charter outside the repo leaves no commit that may pass.
    _repo_ledger(project_data, repo_cwd, str(repo_cwd.parent / "charter" / "decisions.md"))
    tip = _judged(repo_cwd)
    _train(hook_input, repo_cwd, f"[VERDICT: APPROVED] tip={tip}")
    _commit(repo_cwd, LEDGER)
    assert "with a commit that changes more than the ledger" in _refused(repo_cwd)


def test_push_proof_takes_the_exception_path_on_the_current_tip(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # 62: no approved verdict, and an exception ruling bound to the integration tip passes.
    tip = _judged(repo_cwd, status="rejected")
    _train(hook_input, repo_cwd, f"[VERDICT: REJECTED] tip={tip} a.py:1 high")
    assert _refused(repo_cwd).startswith("NOT APPROVED:")
    train_state.update(repo_cwd, TRAIN, exception={"ledger_id": "0113-DAE-PLT", "tip": tip})
    assert push_proof(repo_cwd, TRAIN) == (
        f"OK approved: exception 0113-DAE-PLT, train {TRAIN}, integration tip {tip[:12]}"
    )
    moved = _commit(repo_cwd, "src/app.py")
    with pytest.raises(ProofError) as info:
        push_proof(repo_cwd, TRAIN)
    assert str(info.value).startswith("NOT APPROVED:") and moved != tip


def test_push_proof_prefers_the_approved_verdict(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    tip = _judged(repo_cwd)
    _train(hook_input, repo_cwd, f"[VERDICT: APPROVED] tip={tip}")
    train_state.update(repo_cwd, TRAIN, exception={"ledger_id": "0113-DAE-PLT", "tip": tip})
    assert push_proof(repo_cwd, TRAIN) == _ok(1, tip)


def test_approved_reads_the_bound_of_the_summary_session(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # issue 60: a push session's hooks-live moves start_seq, and the build session keeps its bound.
    tip = _judged(repo_cwd)
    train_state.save(repo_cwd, TRAIN, {**train_state.load(repo_cwd, TRAIN), "start_seq": None})
    _bash(hook_input, "python3 /p/scripts/verify_audit_chain.py --hooks-live")
    train_state.mark_start(repo_cwd, TRAIN, 1, "sess-test")
    _train(hook_input, repo_cwd, f"[VERDICT: APPROVED] tip={tip}")
    train_state.mark_start(repo_cwd, TRAIN, 40, "sess-push")
    state = train_state.load(repo_cwd, TRAIN)
    assert state["start_seq"] == 40 and state["audit_session"] == "sess-push"
    assert approved(repo_cwd, TRAIN) == _ok(2, tip)
    _summary(repo_cwd, "Session sess-other: .claude/daedalus/audit/sess-other.jsonl\n")
    _bash(hook_input, "x", session_id="sess-other")
    assert "records no start_seq for session sess-other" in _refused(repo_cwd)

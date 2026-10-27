# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import itertools
import json
import os
from functools import partial
from pathlib import Path
from typing import Any

import pytest
from lib import audit, train_state
from lib.audit_proof import (
    VERDICT_APPROVED,
    VERDICT_BOTH,
    VERDICT_REJECTED,
    ProofError,
    approved,
    hooks_live,
    live_summary,
    newest_log,
    push_proof,
    read_chain,
    stop_verdict,
    summary_anchor,
    tip_problem,
)

from tests.conftest import SCRIPTS_DIR, append_handback, replay_auditor, write_train_marker
from tests.conftest import git as _git
from tests.test_operator_gates import exempt_round

NEEDLE = "daedalus_workspace.py begin"
TRAIN = "20261016-120000"
MARKED = "20261017-120000"
AUDITOR = "daedalus:security-auditor"
BOTH_REFUSAL = "auditor reply at seq 1 carries both verdicts. Next: rerun the audit round."


@pytest.fixture
def project_data(project_data: Path, repo_cwd: Path) -> Path:
    write_train_marker(repo_cwd)
    # 73: the proof anchors on the recorded verdict seq; refusal tests grade the turn before it.
    verdict = {"status": "approved", "tip": "0" * 40, "round": 1, "seq": 1}
    train_state.save(repo_cwd, TRAIN, {"train_id": TRAIN, "start_seq": 0, "verdict": verdict})
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


SCRIPT = SCRIPTS_DIR / "daedalus_train.py"
_USES = itertools.count(1)


def _summary_cmd(repo: Path) -> str:
    return f"python3 {SCRIPT} summary --repo {repo}"


def _written(train: str = TRAIN) -> dict[str, object]:
    line = (
        f"summary written train={train} path=docs/.tmp/daedalus/{train}-summary.md ledger=pending"
    )
    return {"stdout": f"{line}\n", "stderr": ""}


def _summary_run(
    hook_input: Any,
    repo_cwd: Path,
    command: str | None = None,
    response: dict[str, object] | None = None,
    post: str | None = "PostToolUse",
    **kw: Any,
) -> None:
    # W3.2: the summary command's PreToolUse Bash record and its PostToolUse written line.
    use = f"toolu_sum{next(_USES)}"
    tool_input = {"command": command or _summary_cmd(repo_cwd)}
    audit.audit_append(hook_input(tool_input=tool_input, tool_use_id=use, **kw))
    if post is not None:
        done = hook_input(
            hook_event_name=post,
            tool_input=tool_input,
            tool_use_id=use,
            tool_response=_written() if response is None else response,
            **kw,
        )
        audit.audit_append(done)


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
    _summary_run(hook_input, repo_cwd)
    _summary(repo_cwd)


def _refused(repo_cwd: Path, train: str = TRAIN) -> str:
    with pytest.raises(ProofError) as info:
        approved(repo_cwd, train)
    return str(info.value)


def _judged(repo: Path, status: str = "approved", seq: int = 1) -> str:
    # 59: a commit on the integration branch and the verdict recorded on it.
    _git(repo, "commit", "-q", "--allow-empty", "-m", "unit")
    _git(repo, "branch", "-f", f"daedalus/{TRAIN}", "HEAD")
    tip = _git(repo, "rev-parse", "HEAD").stdout.strip()
    _record_seq(repo, seq, status, tip)
    return tip


def _record_seq(repo: Path, seq: int, status: str = "approved", tip: str | None = None) -> None:
    # 73: the verdict record_verdict writes, naming the auditor record it graded.
    old = train_state.load(repo, TRAIN)["verdict"]
    verdict = {"status": status, "tip": tip or old["tip"], "round": 1, "seq": seq}
    train_state.update(repo, TRAIN, verdict=verdict)


def _log_len(repo: Path) -> int:
    return len(read_chain(audit.log_path("sess-test", str(repo))))


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
    assert message.endswith("Next: run /daedalus:run; this train has no approved audit in its log.")


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
    _summary_run(hook_input, repo_cwd)
    _summary(repo_cwd)
    assert _refused(repo_cwd).startswith("NOT APPROVED:")


def test_approved_refuses_a_missing_summary(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _stop(hook_input, "[VERDICT: APPROVED] ok")
    _summary_run(hook_input, repo_cwd)
    assert _refused(repo_cwd).startswith("NOT APPROVED:")


def test_approved_refuses_a_summary_without_a_session_line(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    _stop(hook_input, "[VERDICT: APPROVED] ok")
    _summary_run(hook_input, repo_cwd)
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
    # spec 3.6, pin D3 -> D1: the stop's verdict_lines carry both kinds, the narrower refusal.
    _train(hook_input, repo_cwd, "[VERDICT: REJECTED] a.py:1 high\nnotes\n[VERDICT: APPROVED]")
    assert BOTH_REFUSAL in _refused(repo_cwd)


def test_approved_refuses_a_reply_with_only_a_rejected_line(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # 41, spec 3.6: one verdict kind, REJECTED, keeps the rejected-line refusal.
    _train(hook_input, repo_cwd, "[VERDICT: REJECTED] a.py:1 high\nnotes\n[VERDICT: REJECTED]")
    (stop,) = [r for r in read_chain(audit.log_path("sess-test", str(repo_cwd))) if r["seq"] == 1]
    assert stop["verdict_lines"] == ["[VERDICT: REJECTED] a.py:1 high", "[VERDICT: REJECTED]"]
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
    assert BOTH_REFUSAL in _refused(repo_cwd)


def _hand_chain(repo_cwd: Path, stop: dict[str, object]) -> None:
    # 41: B5/B6, chain-valid records written without build_record.
    run: dict[str, object] = {
        "event": "PreToolUse",
        "tool_name": "Bash",
        "agent_type": "main",
        "tool_use_id": "u1",
        "tool_input": {"command": _summary_cmd(repo_cwd)},
    }
    done = {**run, "event": "PostToolUse", "result_head": json.dumps(_written())}
    first: dict[str, object] = {"event": "SubagentStop", "agent_type": AUDITOR, **stop}
    prev, lines = audit.GENESIS, []
    for seq, rec in enumerate((first, run, done), start=1):
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
    _record_seq(repo_cwd, replayed[-2]["seq"])
    _summary_run(hook_input, repo_cwd)
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
    seq = _log_len(repo_cwd)
    _record_seq(repo_cwd, seq)
    _summary_run(hook_input, repo_cwd)
    _summary(repo_cwd)
    assert approved(repo_cwd, TRAIN) == _ok(seq, tip)


def test_approved_refuses_train_a_without_its_hand_back_records(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # issue 57: the bug as Train A met it; the stop records alone carry no verdict line.
    replay_auditor(repo_cwd, "sess-test", handbacks=False)
    _summary_run(hook_input, repo_cwd)
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
    _summary_run(hook_input, repo_cwd)
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
    _summary_run(hook_input, repo_cwd)
    _summary(repo_cwd)
    assert "carries a [VERDICT: REJECTED] line" in _refused(repo_cwd)


def test_approved_reads_a_hand_back_with_no_stop_yet(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # issue 57: a hand-back after the newest stop is the newest turn; no older round stands in.
    replay_auditor(repo_cwd, "sess-test")
    _handback(hook_input, "[VERDICT: REJECTED] a.py:1 high")
    _summary_run(hook_input, repo_cwd)
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


def _odd_ledger(repo: Path, kind: str) -> str:
    # 59: a ledger-only commit that leaves the ledger executable or a symlink.
    path = repo / LEDGER
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "exec":
        path.write_text("row\n")
        path.chmod(0o755)
    else:
        path.symlink_to("../README.md")
    _git(repo, "add", LEDGER)
    _git(repo, "commit", "-q", "-m", "ledger")
    _git(repo, "branch", "-f", f"daedalus/{TRAIN}", "HEAD")
    return _git(repo, "rev-parse", "HEAD").stdout.strip()


@pytest.mark.parametrize("kind", ["exec", "link"])
def test_a_ledger_commit_passes_only_with_a_regular_non_executable_ledger(
    project_data: Path, hook_input: Any, repo_cwd: Path, kind: str
) -> None:
    # 59, 0131: every ledger-only check applies the _docs_only mode test.
    from lib import audit_proof

    _repo_ledger(project_data, repo_cwd)
    tip = _judged(repo_cwd)
    _train(hook_input, repo_cwd, f"[VERDICT: APPROVED] tip={tip}")
    moved = _odd_ledger(repo_cwd, kind)
    assert "changes more than the ledger, or its file mode" in _refused(repo_cwd)
    assert audit_proof.ledger_parent(repo_cwd, moved) is None
    assert "changes more than the four public docs" in str(
        audit_proof._docs_moves(repo_cwd, tip, moved)
    )


def test_a_regular_ledger_commit_passes_every_ledger_only_check(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # 59, 0131: a new or edited regular ledger file still passes.
    from lib import audit_proof

    _repo_ledger(project_data, repo_cwd)
    tip = _judged(repo_cwd)
    moved = _commit(repo_cwd, LEDGER)
    assert audit_proof.ledger_parent(repo_cwd, moved) == tip
    assert audit_proof._docs_moves(repo_cwd, tip, moved) is None
    again = _commit(repo_cwd, LEDGER)
    assert audit_proof.ledger_parent(repo_cwd, again) == moved


def test_a_ledger_commit_refuses_when_the_ledger_is_not_in_the_repo(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # spec 3.5: a ledger under a Charter outside the repo leaves no commit that may pass.
    _repo_ledger(project_data, repo_cwd, str(repo_cwd.parent / "charter" / "decisions.md"))
    tip = _judged(repo_cwd)
    _train(hook_input, repo_cwd, f"[VERDICT: APPROVED] tip={tip}")
    _commit(repo_cwd, LEDGER)
    assert "with a commit that changes more than the ledger" in _refused(repo_cwd)


def test_push_proof_takes_the_exemption_path_on_the_current_tip(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # 62, 0133: no approved verdict, and every finding of the rejected round exempted passes.
    tip = _judged(repo_cwd, status="rejected")
    _train(hook_input, repo_cwd, f"[VERDICT: REJECTED] tip={tip} a.py:1 high")
    assert _refused(repo_cwd).startswith("NOT APPROVED:")
    exempt_round(repo_cwd, TRAIN, tip)
    assert push_proof(repo_cwd, TRAIN) == (
        f"OK approved: every finding exempted, train {TRAIN}, round 1, integration tip {tip[:12]}"
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
    entry = {"ledger_id": "0113-DAE-PLT", "tip": tip, "tracking": "issue"}
    train_state.update(repo_cwd, TRAIN, exemptions={"1": {"a.py:1": entry}})
    assert push_proof(repo_cwd, TRAIN) == _ok(1, tip)


def test_approved_reads_the_bound_of_the_summary_session(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # issue 60: a push session's hooks-live moves start_seq, and the build session keeps its bound.
    tip = _judged(repo_cwd, seq=2)
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


def test_train_c_shape_proves_round_two(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # 73, W3.2: a summary command between round 1 and round 2, a second one after round 2.
    # Each summary call is two records, its PreToolUse and its PostToolUse.
    tip = _judged(repo_cwd, seq=4)
    _stop(hook_input, f"[VERDICT: REJECTED] tip={tip} a.py:1 high")
    _summary_run(hook_input, repo_cwd)
    _stop(hook_input, f"[VERDICT: APPROVED] tip={tip}")
    _summary_run(hook_input, repo_cwd)
    _summary(repo_cwd)
    assert approved(repo_cwd, TRAIN) == _ok(4, tip)
    assert push_proof(repo_cwd, TRAIN) == _ok(4, tip)


def test_no_summary_write_after_the_recorded_verdict_refuses(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # pin D1 -> D5, W3.2: the summary call before the verdict record never anchors the proof.
    tip = _judged(repo_cwd, seq=4)
    _stop(hook_input, f"[VERDICT: REJECTED] tip={tip} a.py:1 high")
    _summary_run(hook_input, repo_cwd)
    _stop(hook_input, f"[VERDICT: APPROVED] tip={tip}")
    _summary(repo_cwd)
    assert _refused(repo_cwd) == (
        "NOT APPROVED: no summary Write after the recorded verdict at seq 4. "
        "Next: rewrite the summary with daedalus_train.py summary --repo <repo>, then rerun the "
        "proof."
    )


def test_a_graded_turn_other_than_the_recorded_one_refuses(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # pin D1 -> D5: a later auditor turn before the Write is not the verdict the train recorded.
    tip = _judged(repo_cwd, seq=1)
    _stop(hook_input, f"[VERDICT: APPROVED] tip={tip}")
    _stop(hook_input, f"[VERDICT: APPROVED] tip={tip} again")
    _summary_run(hook_input, repo_cwd)
    _summary(repo_cwd)
    assert _refused(repo_cwd) == (
        "NOT APPROVED: the graded auditor turn at seq 2 is not the recorded verdict at seq 1. "
        "Next: rerun the audit round."
    )


def test_a_summary_write_never_anchors_the_proof(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # W3.2: a Write of the summary file by any agent no longer satisfies the proof.
    tip = _judged(repo_cwd, seq=1)
    _stop(hook_input, f"[VERDICT: APPROVED] tip={tip}")
    _summary_write(hook_input, repo_cwd)
    audit.audit_append(
        hook_input(
            tool_name="Write",
            agent_type="daedalus:orchestrator",
            agent_id="o1",
            tool_input={"file_path": f"{repo_cwd}/docs/.tmp/daedalus/{TRAIN}-summary.md"},
        )
    )
    _summary(repo_cwd)
    assert "no summary Write after the recorded verdict at seq 1" in _refused(repo_cwd)
    _summary_run(hook_input, repo_cwd)
    assert approved(repo_cwd, TRAIN) == _ok(1, tip)


REFUSED_CALLS = {
    "a grep naming it": "grep -n 'daedalus_train.py summary' {script}",
    "an echo of it": "echo python3 {script} summary --repo {repo}",
    "a compound command": "cd {repo} && python3 {script} summary --repo {repo}",
    "another action": "python3 {script} summaryx --repo {repo}",
    "a help call": "python3 {script} summary --help",
    "a trailing help flag": "python3 {script} summary --repo {repo} --help",
    "an abbreviated flag": "python3 {script} summary --rep {repo}",
    "the two-space spelling": "python3 {script}  summary --repo {repo}",
    "a tab between words": "python3\t{script} summary --repo {repo}",
    "a worktree copy": "python3 {repo}/.claude/worktrees/u1/scripts/daedalus_train.py summary "
    "--repo {repo}",
    "another plugin path": "python3 /p/scripts/daedalus_train.py summary --repo {repo}",
    "a relative script": "python3 scripts/daedalus_train.py summary --repo {repo}",
    "another repo": "python3 {script} summary --repo {repo}/../other",
    "an unclosed quote": "python3 '{script} summary --repo {repo}",
}


@pytest.mark.parametrize("command", REFUSED_CALLS.values(), ids=REFUSED_CALLS.keys())
def test_only_the_plugins_own_summary_call_anchors(
    project_data: Path, hook_input: Any, repo_cwd: Path, command: str
) -> None:
    # W3.2: each call below printed the written line, and still none anchors the proof.
    tip = _judged(repo_cwd, seq=1)
    _stop(hook_input, f"[VERDICT: APPROVED] tip={tip}")
    _summary_run(hook_input, repo_cwd, command.format(script=SCRIPT, repo=repo_cwd))
    _summary(repo_cwd)
    assert "no summary Write after the recorded verdict at seq 1" in _refused(repo_cwd)


@pytest.mark.parametrize(
    ("label", "kw"),
    [
        ("a repo-coder's call", {"agent_type": "daedalus:repo-coder", "agent_id": "c1"}),
        ("a failed call", {"post": "PostToolUseFailure"}),
        ("a call with no result record", {"post": None}),
        ("a refused call", {"response": {"stdout": "x. Next: rerun summary.\n"}}),
        ("another train's line", {"response": _written("20261001-000000")}),
    ],
)
def test_a_summary_call_that_did_not_write_this_train_never_anchors(
    project_data: Path, hook_input: Any, repo_cwd: Path, label: str, kw: dict[str, Any]
) -> None:
    tip = _judged(repo_cwd, seq=1)
    _stop(hook_input, f"[VERDICT: APPROVED] tip={tip}")
    _summary_run(hook_input, repo_cwd, **kw)
    _summary(repo_cwd)
    assert "no summary Write after the recorded verdict at seq 1" in _refused(repo_cwd), label


@pytest.mark.parametrize(
    "command",
    [
        "python3 ${{CLAUDE_PLUGIN_ROOT}}/scripts/daedalus_train.py summary --repo {repo}",
        "python3 {script} summary --repo={repo}",
        "/usr/bin/python3 {script} summary --repo {repo}",
    ],
)
def test_the_main_session_and_orchestrator_forms_anchor(
    project_data: Path, hook_input: Any, repo_cwd: Path, command: str
) -> None:
    tip = _judged(repo_cwd, seq=1)
    _stop(hook_input, f"[VERDICT: APPROVED] tip={tip}")
    orchestrator = {"agent_type": "daedalus:orchestrator", "agent_id": "o1"}
    _summary_run(hook_input, repo_cwd, command.format(script=SCRIPT, repo=repo_cwd), **orchestrator)
    _summary(repo_cwd)
    assert approved(repo_cwd, TRAIN) == _ok(1, tip)


@pytest.mark.parametrize("decision", ["block", "ask"])
def test_a_refused_summary_command_never_anchors(decision: str) -> None:
    command: dict[str, object] = {
        "seq": 2,
        "event": "PreToolUse",
        "tool_name": "Bash",
        "agent_type": "main",
        "tool_use_id": "u1",
        "decision": decision,
        "tool_input": {"command": _summary_cmd(Path("/r"))},
    }
    done = {**command, "seq": 3, "event": "PostToolUse", "result_head": json.dumps(_written())}
    assert summary_anchor([command, done], 1) is None
    assert summary_anchor([{**command, "decision": "allow"}, done], 1) == 2


def test_summary_anchor_returns_the_first_written_call_after_the_verdict() -> None:
    def run(seq: int, use: str, command: str = _summary_cmd(Path("/r"))) -> list[dict[str, object]]:
        pre = {
            "seq": seq,
            "event": "PreToolUse",
            "tool_name": "Bash",
            "agent_type": "main",
            "tool_use_id": use,
            "tool_input": {"command": command},
        }
        post = {
            **pre,
            "seq": seq + 1,
            "event": "PostToolUse",
            "result_head": json.dumps(_written()),
        }
        return [pre, post]

    records = [
        *run(1, "a"),
        *run(3, "b", "ls"),
        {"seq": 5, "tool_name": "Write", "tool_input": {"file_path": f"/r/{TRAIN}-summary.md"}},
        *run(6, "c"),
        *run(8, "d"),
    ]
    assert summary_anchor(records, 1) == 6
    assert summary_anchor(records, 0) == 1
    assert summary_anchor(records, 6) == 8
    assert summary_anchor(records, 8) is None
    assert summary_anchor(records, 0, repo=Path("/other"), train_id=TRAIN) is None
    assert summary_anchor(records, 0, repo=Path("/r"), train_id=TRAIN) == 1


def test_live_summary_and_the_anchor_share_one_spelling(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # W3.2: a call the anchor refuses is refused before the command writes anything.
    two = f"python3 {SCRIPT}  summary --repo {repo_cwd}"
    _bash(hook_input, two)
    with pytest.raises(ProofError, match="not the summary command the push proof anchors on"):
        live_summary(repo_cwd)
    _bash(hook_input, _summary_cmd(repo_cwd))
    assert live_summary(repo_cwd).stem == "sess-test"


def test_a_reply_with_both_verdict_kinds_refuses(project_data: Path, repo_cwd: Path) -> None:
    # spec 3.6, pin D3 -> D1: the full-reply verdict lines carry both kinds.
    tip = _judged(repo_cwd)
    lines = [f"[VERDICT: APPROVED] tip={tip}", f"[VERDICT: REJECTED] tip={tip} a.py:1 high"]
    _hand_chain(
        repo_cwd,
        {"last_message_head": lines[0], "last_message_tail": lines[0], "verdict_lines": lines},
    )
    assert _refused(repo_cwd) == (
        "NOT APPROVED: auditor reply at seq 1 carries both verdicts. Next: rerun the audit round."
    )


def test_a_hand_back_with_both_verdict_kinds_refuses(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    # issue 57: the hand-back's whole message is read for its verdict lines.
    tip = _judged(repo_cwd)
    _handback(hook_input, f"[VERDICT: APPROVED] tip={tip}\nx\n[VERDICT: REJECTED] a.py:1 high")
    _summary_run(hook_input, repo_cwd)
    _summary(repo_cwd)
    assert "auditor reply at seq 1 carries both verdicts" in _refused(repo_cwd)


def test_verdict_lines_catch_a_rejection_outside_the_head_and_tail(
    project_data: Path, repo_cwd: Path
) -> None:
    # pin D3 -> D1: a REJECTED line mid-reply is in verdict_lines though head and tail approve.
    tip = _judged(repo_cwd)
    head = f"[VERDICT: REJECTED] tip={tip} a.py:1 high"
    _hand_chain(
        repo_cwd,
        {
            "last_message_head": "notes",
            "last_message_tail": f"[VERDICT: APPROVED] tip={tip}",
            "verdict_lines": [head],
        },
    )
    assert "carries a [VERDICT: REJECTED] line" in _refused(repo_cwd)


@pytest.mark.parametrize("field", [None, "approved"], ids=["no field", "approved only"])
def test_a_record_without_both_kinds_reads_as_today(
    project_data: Path, repo_cwd: Path, field: str | None
) -> None:
    # spec 3.6: a record from before D3 reads its head and tail; one kind passes as today.
    tip = _judged(repo_cwd)
    line = f"[VERDICT: APPROVED] tip={tip}"
    stop: dict[str, object] = {"last_message_head": line, "last_message_tail": line}
    if field is not None:
        stop["verdict_lines"] = [line]
    _hand_chain(repo_cwd, stop)
    assert approved(repo_cwd, TRAIN) == _ok(1, tip)


def test_verdict_lines_that_are_not_text_refuse(project_data: Path, repo_cwd: Path) -> None:
    line = "[VERDICT: APPROVED] ok"
    _hand_chain(
        repo_cwd,
        {"last_message_head": line, "last_message_tail": line, "verdict_lines": [line, 3]},
    )
    assert "(record seq 1) has a verdict_lines that is not text" in _refused(repo_cwd)


def test_stop_verdict_reads_verdict_lines_and_falls_back() -> None:
    approve, reject = "[VERDICT: APPROVED] tip=x", "[VERDICT: REJECTED] a.py:1 high"
    base = {"last_message_head": approve, "last_message_tail": approve}
    assert stop_verdict(base) == VERDICT_APPROVED
    assert stop_verdict({**base, "verdict_lines": [approve]}) == VERDICT_APPROVED
    assert stop_verdict({**base, "verdict_lines": [reject]}) == VERDICT_REJECTED
    assert stop_verdict({**base, "verdict_lines": [approve, reject]}) == VERDICT_BOTH
    assert stop_verdict({**base, "verdict_lines": "x"}) is None

# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# Plan 11 A: the token economy reader over small synthetic transcripts, never a real one.
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import token_economy as te
from lib import writer_mode

from tests.conftest import SCRIPTS_DIR

SESSION = "sess-tok"
TRAIN = "20261015-120000"


def _line(kind: str, ts: str, **extra: object) -> dict[str, object]:
    return {"type": kind, "timestamp": f"2026-10-15T12:{ts}Z", "sessionId": SESSION, **extra}


def _prompt(ts: str, text: str) -> dict[str, object]:
    return _line("user", ts, message={"role": "user", "content": text})


def _reply(ts: str, msg_id: str, out: int, cr: int = 0) -> dict[str, object]:
    usage = {
        "input_tokens": 2,
        "output_tokens": out,
        "cache_creation_input_tokens": 10,
        "cache_read_input_tokens": cr,
    }
    return _line("assistant", ts, message={"id": msg_id, "role": "assistant", "usage": usage})


def _agent(
    home: Path, agent_id: str, agent_type: str, lines: list[dict[str, object]], **meta: object
) -> Path:
    folder = home / SESSION / "subagents"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"agent-{agent_id}.jsonl"
    path.write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")
    meta = {"agentType": agent_type, **meta}
    path.with_suffix(".meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return path


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "cfg"))
    return te.projects_dir() / te._slug(tmp_path / "repo")


def _train(home: Path) -> None:
    _agent(
        home,
        "orch",
        "daedalus:orchestrator",
        [_prompt("00:00.000", f"Run train {TRAIN}"), _reply("00:05.000", "m1", 100)],
        description=f"Run Build Train {TRAIN}",
    )
    coder = [
        _prompt("01:00.000", f"unit A1.\nWorktree: /r/.claude/worktrees/{TRAIN}-a1"),
        _reply("01:10.000", "c1", 40),
        _reply("01:20.000", "c2", 60),
        _prompt("02:00.000", "Another session: FIX. The verifier refuted one row."),
        _reply("02:30.000", "c3", 5),
        _prompt(
            "05:00.000", f"RESUME on a new unit, A3.\nWorktree: /r/.claude/worktrees/{TRAIN}-a3"
        ),
        _reply("05:30.000", "c4", 7),
    ]
    _agent(home, "coder", "daedalus:coder", coder, parentAgentId="orch")
    audit = [
        _prompt("06:00.000", "Phase 3 audit, round 1."),
        _reply("06:40.000", "u1", 9),
        _prompt("07:00.000", "Audit round 2 for the train."),
        _reply("07:20.000", "u2", 3),
    ]
    _agent(home, "aud", "daedalus:auditor", audit, parentAgentId="orch")
    _agent(home, "loose", "general-purpose", [_prompt("00:00.000", f"Review {TRAIN}")])


def test_columns_are_pinned() -> None:
    # Plan 11 A item 4: a column change is a deliberate edit of this one tuple and this test.
    assert te.COLUMNS == (
        "run type",
        "run id",
        "phase",
        "agent",
        "model",
        "unit or round",
        "turns",
        "input",
        "output",
        "cache write",
        "cache read",
        "wall time",
    )
    assert te.header()[0] == "| " + " | ".join(te.COLUMNS) + " |"


def test_dedup_takes_the_last_line_of_each_message_id(tmp_path: Path) -> None:
    lines = [
        _prompt("00:00.000", "go"),
        _reply("00:01.000", "m1", 10, cr=100),
        _reply("00:02.000", "m1", 50, cr=300),
        _reply("00:03.000", "m2", 1),
    ]
    path = _agent(tmp_path, "x", "daedalus:charter-docs", lines)
    (seg,) = te.read_segments(path, "charter-docs")
    assert seg.usage.turns == 2
    assert seg.usage.tokens == [4, 51, 20, 300]
    assert seg.usage.seconds == 3.0


def test_warm_resume_splits_at_the_new_unit_prompt(home: Path) -> None:
    _train(home)
    runs, files = te.session_runs(SESSION, home.parents[2] / "repo", [])
    assert files == 4
    run, _session = runs
    coder = {r.label: r for r in run.rows if r.agent == "coder"}
    # The FIX prompt names no unit, so it stays on A1; the RESUME prompt opens A3.
    assert sorted(coder) == ["a1", "a3"]
    assert coder["a1"].usage.turns == 3 and coder["a1"].usage.tokens[1] == 105
    assert coder["a3"].usage.turns == 1 and coder["a3"].usage.tokens[1] == 7
    assert coder["a1"].usage.seconds == 50.0
    rounds = {r.label for r in run.rows if r.kind == "round"}
    assert rounds == {"round 1", "round 2"}


def test_missing_values_print_none(home: Path) -> None:
    _train(home)
    runs, _ = te.session_runs(SESSION, home.parents[2] / "repo", [])
    text = te.render(runs, f"session {SESSION}")
    assert f"| Build Train | {TRAIN} | none | orchestrator | - | none | 1 | 2 | 100 |" in text
    assert f"| Build Train | {TRAIN} | 2 | coder | - | a1 | 3 | 6 | 105 | 30 | 0 | 0m50s |" in text
    assert f"| Build Train | {TRAIN} | total | 3 agents | - | 2 units, 2 rounds | 7 |" in text
    assert "agents outside any run" not in text
    row = te.table_row(["x", None, "", 1, 2, 3, 4, 5, 6, 7, 8, 9])
    assert row == "| x | none | none | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |"
    push = te.Run(te.PUSH, TRAIN)
    assert te.mean_row(push, "unit").endswith(
        "| 0 units | none | none | none | none | none | none |"
    )
    assert "||" not in text and "|  |" not in text


def test_history_reads_total_rows_from_saved_files(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    saved = repo / "docs" / ".tmp" / "daedalus" / TRAIN / "tokens.md"
    saved.parent.mkdir(parents=True)
    total = f"| Build Train | {TRAIN} | total | 3 agents | - | 2 units, 0 rounds | 7 | 1 | 2 |"
    saved.write_text(
        "\n".join(
            [
                *te.header(),
                f"| Build Train | {TRAIN} | 2 | coder | opus | a1 | 3 | 6 | 105 | 30 | 0 | 0m50s |",
                total + " none | 4 | 1m00s |",
                f"| Build Train | {TRAIN} | mean | per unit | - | 2 units | 1 | 1 | 1 | 1 | 1"
                " | 1s |",
            ]
        ),
        encoding="utf-8",
    )
    # 0187: a report saved before the model column reads with - in its model cell.
    old_run = "20261014-120000"
    old = repo / "docs" / ".tmp" / "daedalus" / old_run / "tokens.md"
    old.parent.mkdir(parents=True)
    old.write_text(
        f"| Build Train | {old_run} | total | 1 agents | 1 units, 0 rounds | 2 |"
        " 1 | 1 | 1 | 1 | 9s |\n",
        encoding="utf-8",
    )
    text = te.history(repo)
    rows = [line for line in text.splitlines() if line.startswith("| Build Train | ")]
    assert rows == [
        f"| Build Train | {old_run} | total | 1 agents | - | 1 units, 0 rounds | 2 | 1 | 1 | 1 | 1"
        " | 9s |",
        total + " none | 4 | 1m00s |",
    ]
    assert te.history(tmp_path / "empty").startswith("no saved token report found. Next:")


def test_session_without_transcripts_exits_one(home: Path, tmp_path: Path) -> None:
    (tmp_path / "repo").mkdir()
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "token_economy.py"), "report", "--session", SESSION],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path / "repo",
    )
    assert result.returncode == 1
    assert result.stderr.startswith("token_economy: no agent transcript names session")
    assert "Next:" in result.stderr


def test_audit_lines_without_transcripts_is_one_line(home: Path, tmp_path: Path) -> None:
    lines = te.audit_lines(SESSION, tmp_path / "repo", [])
    assert lines[0] == "## Token economy"
    assert lines[2].startswith(f"no agent transcript found for session {SESSION}")
    assert len(lines) == 3


def test_audit_lines_carry_the_session_group(home: Path, tmp_path: Path) -> None:
    _train(home)
    lines = te.audit_lines(SESSION, tmp_path / "repo", [])
    # 0187: the refuted line follows the table; the coders' transcripts name no model.
    assert lines[-2:] == ["", "refuted: - 0/2 units"]
    head = f"| session | {SESSION} | "
    assert lines[-4].startswith(head + "total | 1 agents | - | 0 units, 0 rounds |")
    assert lines[-3].startswith(head + "mean | per unit | - | 0 units | none |")
    runs, _ = te.session_runs(SESSION, tmp_path / "repo", [])
    assert [r.label for r in runs[-1].rows] == ["loose"]
    assert not any("outside any run" in line for line in lines)


def test_agents_outside_any_run_group_under_the_session(home: Path) -> None:
    # 0163: main-session agents are a run of type session, one row each, means none.
    _train(home)
    _agent(
        home, "loose2", "general-purpose", [_prompt("09:00.000", "w"), _reply("09:04.000", "g", 8)]
    )
    runs, _ = te.session_runs(SESSION, home.parents[2] / "repo", [])
    session = runs[-1]
    assert (session.run_type, session.run_id) == (te.SESSION, SESSION)
    assert sorted(r.agent_id for r in session.rows) == ["loose", "loose2"]
    assert {(r.phase, r.kind) for r in session.rows} == {(None, None)}
    assert sorted(r.label for r in session.rows) == ["loose", "loose2"]
    text = te.render(runs, f"session {SESSION}")
    assert f"| session | {SESSION} | none | general-purpose | - | loose2 | 1 | 2 | 8 |" in text
    total = te.totals_row(session)
    assert total.startswith(
        f"| session | {SESSION} | total | 2 agents | - | 0 units, 0 rounds | 1 |"
    )
    for kind in ("unit", "round"):
        assert te.mean_row(session, kind).endswith(
            f"| 0 {kind}s | none | none | none | none | none | none |"
        )


def test_unit_mean_counts_coders_only() -> None:
    # Plan 11 A: the hand reports divided coder rows by units; a verifier row stays in the total.
    run = te.Run(te.BUILD, TRAIN)
    for agent, out in (("coder", 40), ("verifier", 4)):
        usage = te.Usage(turns=2, tokens=[2, out, 10, 100], seconds=60.0)
        run.rows.append(te.Row(agent, te.BUILD, TRAIN, "2", agent, "a1", "unit", usage, None))
    mean = te.mean_row(run, "unit")
    head = f"| Build Train | {TRAIN} | mean | per unit | - | 1 units |"
    assert mean == head + " 2 | 2 | 40 | 10 | 100 | 1m00s |"
    assert "| 4 | 4 | 44 | 20 | 200 |" in te.totals_row(run)


def test_turn_line_follows_the_means_with_the_coder_target(home: Path) -> None:
    # item 15: the coder mean against the target, after the table; no line for a run without coders.
    _train(home)
    runs, _ = te.session_runs(SESSION, home.parents[2] / "repo", [])
    lines = te.render(runs, f"session {SESSION}").splitlines()
    want = f"turns per coder unit: 2 (target {te.CODER_TURN_TARGET})"
    assert lines[-3:] == ["", want, "refuted: - 0/2 units"]
    assert lines.index(want) > max(i for i, ln in enumerate(lines) if "| mean |" in ln)
    assert te.turn_lines([te.Run(te.PUSH, TRAIN)]) == []


def test_turn_line_names_the_run_when_several_runs_have_coders() -> None:
    runs = []
    for run_id, turns in ((TRAIN, 30), ("20261016-120000", 11)):
        run = te.Run(te.BUILD, run_id)
        usage = te.Usage(turns=turns, tokens=[0, 0, 0, 0])
        run.rows.append(te.Row("c", te.BUILD, run_id, "2", te.CODER, "a1", "unit", usage, None))
        runs.append(run)
    assert te.turn_lines(runs) == [
        f"turns per coder unit: 30 (target 24) in Build Train {TRAIN}",
        "turns per coder unit: 11 (target 24) in Build Train 20261016-120000",
    ]


def test_turn_target_matches_the_coder_rule() -> None:
    # item 15: one number, stated in the coder's turn rule and read by the report.
    coder = " ".join((SCRIPTS_DIR.parent / "agents" / "coder.md").read_text().split())
    assert f"A unit takes at most {te.CODER_TURN_TARGET} turns" in coder


SONNET, OPUS = "claude-sonnet-4-6", "claude-opus-4-8"


def _said(
    ts: str, msg_id: str, model: str, text: str = "", handback: str = ""
) -> dict[str, object]:
    reply = _reply(ts, msg_id, 3)
    message = reply["message"]
    assert isinstance(message, dict)
    content: list[dict[str, object]] = [{"type": "text", "text": text}] if text else []
    if handback:
        block: dict[str, object] = {"type": "tool_use", "name": "SubagentHandback"}
        block["input"] = {"message": handback}
        content.append(block)
    message.update(model=model, content=content)
    return reply


def _unit_prompt(ts: str, unit: str) -> dict[str, object]:
    return _prompt(ts, f"Unit worktree: /r/.claude/worktrees/{TRAIN}-{unit}")


def _escalated_train(home: Path) -> None:
    # 0187: a1 is refuted twice on sonnet, then a fresh opus coder takes it; a2 passes on sonnet.
    _agent(
        home,
        "orch",
        "daedalus:orchestrator",
        [_prompt("00:00.000", f"Run train {TRAIN}"), _said("00:05.000", "o1", OPUS)],
        description=f"Run Build Train {TRAIN}",
    )
    sonnet = [
        _prompt("01:00.000", f"Worktree: /r/.claude/worktrees/{TRAIN}-a1"),
        _said("01:10.000", "s1", SONNET, "[STATUS: COMPLETE] branch=a1"),
        _prompt("02:10.000", "FIX. The verifier refuted: row 1"),
        _said("02:20.000", "s2", SONNET, "[STATUS: COMPLETE] branch=a1"),
        _prompt("06:00.000", f"Worktree: /r/.claude/worktrees/{TRAIN}-a2"),
        _said("06:10.000", "s3", SONNET, "[STATUS: COMPLETE] branch=a2"),
    ]
    _agent(home, "cs", "daedalus:coder", sonnet, parentAgentId="orch")
    opus = [
        _prompt("04:00.000", f"Worktree: /r/.claude/worktrees/{TRAIN}-a1"),
        _said("04:10.000", "p1", OPUS, "[STATUS: COMPLETE] branch=a1"),
    ]
    _agent(home, "co", "daedalus:coder", opus, parentAgentId="orch")
    refuted = "[VERDICT: REFUTED] row 1 code\n| row |\n[VERDICT: REFUTED] row 1 code"
    checks = [
        _unit_prompt("02:00.000", "a1"),
        _said("02:05.000", "v1", OPUS, refuted),
        _unit_prompt("03:00.000", "a1"),
        _said("03:05.000", "v2", OPUS, handback=refuted),
        _unit_prompt("05:00.000", "a1"),
        _said("05:05.000", "v3", OPUS, "[VERDICT: VERIFIED] claims=3"),
        _unit_prompt("07:00.000", "a2"),
        _said("07:05.000", "v4", OPUS, "[VERDICT: VERIFIED] claims=2"),
    ]
    _agent(home, "ver", "daedalus:verifier", checks, parentAgentId="orch")


def test_model_column_and_refuted_line_for_an_escalated_unit(home: Path) -> None:
    # 0187: the model cell comes from each transcript; the refuted line counts per coder model.
    _escalated_train(home)
    runs, _ = te.session_runs(SESSION, home.parents[2] / "repo", [])
    (run,) = runs
    coders = {(r.agent_id, r.label): r.model for r in run.rows if r.agent == te.CODER}
    assert coders == {("cs", "a1"): "sonnet", ("cs", "a2"): "sonnet", ("co", "a1"): "opus"}
    assert te.refuted_counts(run) == {"sonnet": (1, 2), "opus": (0, 1)}
    text = te.render(runs, f"session {SESSION}")
    assert f"| Build Train | {TRAIN} | 2 | coder | opus | a1 | 1 | 2 | 3 | 10 | 0 | 0m10s |" in text
    assert f"| Build Train | {TRAIN} | total | 4 agents | - | 2 units, 0 rounds |" in text
    assert text.splitlines()[-1] == "refuted: sonnet 1/2 units, opus 0/1 units"
    lines = te.audit_lines(SESSION, home.parents[2] / "repo", [])
    assert lines[-1] == "refuted: sonnet 1/2 units, opus 0/1 units"


def test_model_word_reads_a_transcript_model_id() -> None:
    assert [te.model_word(m) for m in (SONNET, OPUS, "claude-haiku-4-5")] == [
        "sonnet",
        "opus",
        "haiku",
    ]
    assert te.model_word("<synthetic>") is None and te.model_word(None) is None
    assert te.model_word("gpt-x") == "gpt-x"


@pytest.mark.parametrize(
    ("kind", "run_type"),
    [(writer_mode.DERIVED, te.DOC), (writer_mode.PUBLIC_DOCS, te.SESSION)],
)
def test_a_root_writer_roots_a_document_run_only_in_its_derived_kind(
    home: Path, kind: str, run_type: str
) -> None:
    # 0190: the writer's bound kind decides the run type: derived roots a doc run, public a session.
    repo = home.parents[2] / "repo"
    path = writer_mode.records_path(repo, TRAIN)
    path.parent.mkdir(parents=True)
    writer_mode._write(path, [], {"w1": kind})
    lines = [
        _prompt("00:00.000", f"Write the document for run {TRAIN}"),
        _reply("00:05.000", "m", 4),
    ]
    _agent(home, "w1", "daedalus:writer", lines)
    runs, _ = te.session_runs(SESSION, repo, [])
    [run] = [r for r in runs if any(row.agent == "writer" for row in r.rows)]
    assert run.run_type == run_type


def test_budget_lines_sum_coder_and_verifier_tokens_per_unit() -> None:
    # 0209: a unit's tokens are its coder and verifier rows; an auditor round never counts.
    run = te.Run(te.BUILD, TRAIN)
    for agent, label, kind, tokens in (
        ("coder", "a1", "unit", [10, 20, 30, 40]),
        ("verifier", "a1", "unit", [1, 1, 1, 1]),
        ("coder", "a2", "unit", [1, 1, 1, 1]),
        ("auditor", "1", "round", [500, 500, 500, 500]),
    ):
        usage = te.Usage(turns=1, tokens=tokens)
        run.rows.append(te.Row(agent, te.BUILD, TRAIN, "2", agent, label, kind, usage, None))
    assert te.unit_totals(run) == {"a1": 104, "a2": 4}
    assert te.budget_lines([run], 100) == (
        ["over budget: unit a1 104 tokens, budget 100", "budget: 1/2 units over"],
        1,
    )
    assert te.budget_lines([run], 104) == (["budget: 0/2 units over"], 0)
    assert te.budget_lines([run], None) == ([], 0)


def _gate(tmp_path: Path, budget: object) -> subprocess.CompletedProcess[str]:
    data = tmp_path / "repo" / ".claude" / "daedalus"
    data.mkdir(parents=True, exist_ok=True)
    (data / "config.json").write_text(json.dumps({"limits": {"task_tokens": budget}}))
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "token_economy.py"), "report"]
        + ["--session", SESSION, "--gate"],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path / "repo",
    )


def test_the_gate_exits_one_only_when_a_unit_is_over_budget(home: Path, tmp_path: Path) -> None:
    # 0209: the report always prints; --gate fails on an over-budget unit, never while it is off.
    _train(home)
    over = _gate(tmp_path, 100)
    assert over.returncode == 1, over.stderr
    assert over.stdout.splitlines()[-2:] == [
        "over budget: unit a1 141 tokens, budget 100",
        "budget: 1/2 units over",
    ]
    under = _gate(tmp_path, 1000)
    assert (under.returncode, under.stdout.splitlines()[-1]) == (0, "budget: 0/2 units over")
    off = _gate(tmp_path, None)
    assert off.returncode == 0 and "budget:" not in off.stdout
    bad = _gate(tmp_path, 0)
    assert bad.returncode == 1 and "limits.task_tokens must be a whole number" in bad.stderr


def _main_session(home: Path) -> Path:
    # 0208, issue 181: the main session starts the coders and the verifier itself, no orchestrator.
    repo = home.parents[2] / "repo"
    trains = repo / ".claude" / "daedalus" / "trains"
    trains.mkdir(parents=True, exist_ok=True)
    units = {f"{TRAIN}-a2": {"agent_id": "mc2"}, f"{TRAIN}-a9": {"retired": ["mc2", "old"]}}
    (trains / f"{TRAIN}.bindings.json").write_text(json.dumps({"units": units}))
    coder = [
        _prompt("01:00.000", f"Brief: b.md\nWorktree: /r/.claude/worktrees/{TRAIN}-a1"),
        _reply("01:10.000", "c1", 40),
        _reply("01:20.000", "c2", 60),
    ]
    _agent(home, "mc1", "daedalus:coder", coder, description="Coder: A1")
    unbound = [_prompt("03:00.000", f"Brief: /r/docs/.tmp/daedalus/{TRAIN}/briefs/a2.md")]
    unbound.append(_reply("03:10.000", "d1", 20))
    _agent(home, "mc2", "daedalus:coder", unbound, description="Coder: A2")
    verifier = [
        _prompt("02:00.000", f"Branch: daedalus-unit/{TRAIN}-a1\nDiff base: abc"),
        _reply("02:10.000", "v1", 5),
        _prompt("04:00.000", f"Next unit, same rules.\nBranch: daedalus-unit/{TRAIN}-a2"),
        _reply("04:10.000", "v2", 3),
    ]
    _agent(home, "mv", "daedalus:verifier", verifier, description="Verifier: A1")
    gp = [_prompt("05:00.000", f"Review daedalus/{TRAIN}"), _reply("05:05.000", "g", 8)]
    _agent(home, "gp", "general-purpose", gp)
    return repo


def test_main_session_agents_open_the_train_they_name(home: Path) -> None:
    # 0208, issue 181: a parentless coder and verifier naming a train id are its Build Train rows.
    runs, _ = te.session_runs(SESSION, _main_session(home), [])
    run, session = runs
    assert (run.run_type, run.run_id) == (te.BUILD, TRAIN)
    rows = {(r.agent_id, r.label) for r in run.rows}
    assert rows == {("mc1", "a1"), ("mc2", "a2"), ("mv", "a1"), ("mv", "a2")}
    assert {(r.phase, r.kind) for r in run.rows} == {("2", "unit")}
    assert [r.agent_id for r in session.rows] == ["gp"]
    head = f"| Build Train | {TRAIN} | mean | per unit | - | 2 units |"
    assert te.mean_row(run, "unit") == head + " 2 | 3 | 60 | 15 | 0 | 0m15s |"
    lines = te.render(runs, f"session {SESSION}", 100).splitlines()
    assert f"turns per coder unit: 2 (target {te.CODER_TURN_TARGET})" in lines
    assert lines[-2:] == ["over budget: unit a1 141 tokens, budget 100", "budget: 1/2 units over"]


def test_a_reused_verifier_yields_one_row_per_unit(home: Path) -> None:
    # issue 181: a warm verifier keeps the per-unit split read_segments makes on its prompts.
    runs, _ = te.session_runs(SESSION, _main_session(home), [])
    checks = {r.label: r for r in runs[0].rows if r.agent == te.VERIFIER}
    assert sorted(checks) == ["a1", "a2"]
    assert [checks[u].usage.tokens[1] for u in ("a1", "a2")] == [5, 3]
    assert {r.agent_id for r in checks.values()} == {"mv"}


def test_bindings_name_a_unit_no_prompt_names(home: Path) -> None:
    # issue 181: the holder wins over a retired entry; a missing bindings file names nothing.
    repo = _main_session(home)
    assert te.unit_binding.bound_units(repo, TRAIN) == {"mc2": f"{TRAIN}-a2", "old": f"{TRAIN}-a9"}
    assert te.unit_binding.bound_units(repo, "20261016-120000") == {}

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
    _agent(home, "coder", "daedalus:repo-coder", coder, parentAgentId="orch")
    audit = [
        _prompt("06:00.000", "Phase 3 audit, round 1."),
        _reply("06:40.000", "u1", 9),
        _prompt("07:00.000", "Audit round 2 for the train."),
        _reply("07:20.000", "u2", 3),
    ]
    _agent(home, "aud", "daedalus:security-auditor", audit, parentAgentId="orch")
    _agent(home, "loose", "general-purpose", [_prompt("00:00.000", f"Review {TRAIN}")])


def test_columns_are_pinned() -> None:
    # Plan 11 A item 4: a column change is a deliberate edit of this one tuple and this test.
    assert te.COLUMNS == (
        "run type",
        "run id",
        "phase",
        "agent",
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
    coder = {r.label: r for r in run.rows if r.agent == "repo-coder"}
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
    assert f"| Build Train | {TRAIN} | none | orchestrator | none | 1 | 2 | 100 |" in text
    assert f"| Build Train | {TRAIN} | 2 | repo-coder | a1 | 3 | 6 | 105 | 30 | 0 | 0m50s |" in text
    assert f"| Build Train | {TRAIN} | total | 3 agents | 2 units, 2 rounds | 7 |" in text
    assert "agents outside any run" not in text
    row = te.table_row(["x", None, "", 1, 2, 3, 4, 5, 6, 7, 8])
    assert row == "| x | none | none | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |"
    push = te.Run(te.PUSH, TRAIN)
    assert te.mean_row(push, "unit").endswith(
        "| 0 units | none | none | none | none | none | none |"
    )
    assert "||" not in text and "|  |" not in text


def test_history_reads_total_rows_from_saved_files(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    saved = repo / "docs" / ".tmp" / "daedalus" / TRAIN / "tokens.md"
    saved.parent.mkdir(parents=True)
    total = f"| Build Train | {TRAIN} | total | 3 agents | 2 units, 0 rounds | 7 | 1 | 2 | none |"
    saved.write_text(
        "\n".join(
            [
                *te.header(),
                f"| Build Train | {TRAIN} | 2 | repo-coder | a1 | 3 | 6 | 105 | 30 | 0 | 0m50s |",
                total + " 4 | 1m00s |",
                f"| Build Train | {TRAIN} | mean | per unit | 2 units | 1 | 1 | 1 | 1 | 1 | 1s |",
            ]
        ),
        encoding="utf-8",
    )
    text = te.history(repo)
    rows = [line for line in text.splitlines() if line.startswith(f"| Build Train | {TRAIN}")]
    assert rows == [total + " 4 | 1m00s |"]
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
    assert lines[-2].startswith(f"| session | {SESSION} | total | 1 agents | 0 units, 0 rounds |")
    assert lines[-1].startswith(f"| session | {SESSION} | mean | per unit | 0 units | none |")
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
    assert f"| session | {SESSION} | none | general-purpose | loose2 | 1 | 2 | 8 |" in text
    total = te.totals_row(session)
    assert total.startswith(f"| session | {SESSION} | total | 2 agents | 0 units, 0 rounds | 1 |")
    for kind in ("unit", "round"):
        assert te.mean_row(session, kind).endswith(
            f"| 0 {kind}s | none | none | none | none | none | none |"
        )


def test_unit_mean_counts_coders_only() -> None:
    # Plan 11 A: the hand reports divided coder rows by units; a verifier row stays in the total.
    run = te.Run(te.BUILD, TRAIN)
    for agent, out in (("repo-coder", 40), ("verifier", 4)):
        usage = te.Usage(turns=2, tokens=[2, out, 10, 100], seconds=60.0)
        run.rows.append(te.Row(agent, te.BUILD, TRAIN, "2", agent, "a1", "unit", usage, None))
    mean = te.mean_row(run, "unit")
    assert (
        mean
        == f"| Build Train | {TRAIN} | mean | per unit | 1 units | 2 | 2 | 40 | 10 | 100 | 1m00s |"
    )
    assert "| 4 | 4 | 44 | 20 | 200 |" in te.totals_row(run)

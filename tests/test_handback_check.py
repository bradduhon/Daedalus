# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# RCP, 0128: the SubagentStop receipts check on a coder's COMPLETE reply (pin RCP -> VER).
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import handback_check
import pytest
from lib.repo_root import TRAIN_MARKER

from tests.conftest import SCRIPTS_DIR

SHA = "0123456789abcdef0123456789abcdef01234567"
COMPLETE = (
    "[STATUS: COMPLETE] branch=daedalus-unit/t-rcp packet_version=1 files=a.py "
    "tests=3 passed ledger_notes=none contract=79b4b559baba standards=ca88d4cc81ad"
)
COMMIT = f"- commit {SHA} Add the hand-back check"
TEST = "- test python3 -m pytest -q => 3 passed in 0.10s"
TYPECHECK = "- typecheck python3 -m mypy scripts => Success: no issues found in 9 source files"
YIELD = "- yield COMPLIANCE may the check log replies => orchestrator"
DEVIATION = "- deviation .venv absent | ran python3 -m pytest -q"
HUNT = "- hunt a leading option => refused"
HUNT_FIXED = "- hunt a here-string => admitted, fixed in 0123abc"


def _reply(*lines: str) -> str:
    return "\n".join(lines)


def _stop(reply: object, agent: str | None = "daedalus:coder", **extra: object) -> dict:
    payload: dict[str, object] = {
        "hook_event_name": "SubagentStop",
        "session_id": "s",
        "cwd": "/work/repo",
        "agent_id": "a1",
        "last_assistant_message": reply,
        **extra,
    }
    if agent is not None:
        payload["agent_type"] = agent
    return payload


@pytest.mark.parametrize(
    "lines",
    [
        ("## Receipts", COMMIT, TEST, COMPLETE),
        ("Done.", "", "## Receipts", COMMIT, TEST, TYPECHECK, YIELD, DEVIATION, COMPLETE),
        ("## Receipts", TEST, COMMIT, f"{COMMIT} two", TEST, COMPLETE + " adversarial=pass"),
        ("## Receipts", "- note x", "## Receipts", COMMIT, TEST, COMPLETE),
        # 227: hunt receipts of both outcomes, and ` hunt=<n>` before the closing ` turns=<n>`.
        ("## Receipts", COMMIT, TEST, HUNT, HUNT_FIXED, COMPLETE + " hunt=2 turns=9"),
        (
            "## Receipts",
            COMMIT,
            TEST,
            HUNT,
            COMPLETE + " adversarial=pass audit_tests=pass hunt=1 turns=12",
        ),
        ("## Receipts", COMMIT, TEST, f"- hunt `a => b` => admitted, fixed in {SHA}", COMPLETE),
    ],
)
def test_a_whole_block_passes(lines: tuple[str, ...]) -> None:
    assert handback_check.receipts_problem(_reply(*lines)) is None
    assert handback_check.judge(_stop(_reply(*lines) + "\n\n")) is None


def test_a_missing_block_is_refused() -> None:
    got = handback_check.receipts_problem(_reply("All done, tests pass.", COMPLETE))
    assert got == "the COMPLETE reply has no `## Receipts` line above its status line"


@pytest.mark.parametrize(
    ("lines", "missing"),
    [
        (("## Receipts", TEST), "commit"),
        (("## Receipts", COMMIT, TYPECHECK), "test"),
        (("## Receipts",), "commit and no test"),
    ],
)
def test_a_block_without_a_commit_or_test_line_is_refused(
    lines: tuple[str, ...], missing: str
) -> None:
    got = handback_check.receipts_problem(_reply(*lines, COMPLETE))
    assert got == f"the receipts block has no {missing} line"


@pytest.mark.parametrize(
    "between",
    [
        "The unit adds a check.",  # pin RCP -> VER: narrative between header and block lines
        "",  # pin RCP -> VER: a blank line is no pinned shape
        "  - commit " + SHA + " indented",
        "- commit 0123abc short sha",
        "- commit " + SHA.upper() + " upper hex",
        "- test python3 -m pytest -q",  # pin RCP -> VER: no `=> <last output line>`
        "- test python3 -m pytest -q => ",
        "- typecheck => Success",
        "- yield WEB => orchestrator",
        "- deviation a.py reason without a bar",
        "- claim scripts/a.py:3 adds the check",
        "* commit " + SHA + " star bullet",
        # 227: a hunt line in another shape.
        "- hunt a subshell => admitted",
        "- hunt a subshell => passed",
        "- hunt a subshell",
        "- hunt => refused",
        "- hunt a subshell => refused, mostly",
        "- hunt a subshell => admitted, fixed in 0123ab",
        "- hunt a subshell => admitted, fixed in 0123ABC",
        f"- hunt a subshell => admitted, fixed in {SHA}0",
        "- hunt  a subshell => refused",
        "- hunts a subshell => refused",
    ],
)
def test_text_between_the_header_and_the_lines_is_refused(between: str) -> None:
    reply = _reply("## Receipts", between, COMMIT, TEST, COMPLETE)
    got = handback_check.receipts_problem(reply)
    assert got == f"the receipts block holds a line of another shape: {between.rstrip()!r}"


@pytest.mark.parametrize(
    "tail",
    [
        " hunt=2",  # no closing turns=<n>
        " turns=9 hunt=2",
        " hunt=2 adversarial=pass turns=9",
        " hunt=two turns=9",
        " hunt= turns=9",
        " hunt=2 hunt=2 turns=9",
        " hunt=-1 turns=9",
        " hunt=2 turns=9 x",
    ],
)
def test_a_hunt_field_out_of_place_is_refused(tail: str) -> None:
    # 227: ` hunt=<n>` sits directly before the closing ` turns=<n>`, once.
    reply = _reply("## Receipts", COMMIT, TEST, HUNT, COMPLETE + tail)
    assert handback_check.receipts_problem(reply) == (
        "the COMPLETE line carries `hunt=` other than as ` hunt=<n>` before ` turns=<n>`"
    )
    assert handback_check.judge(_stop(reply)) is not None


@pytest.mark.parametrize(
    ("hunts", "field", "problem"),
    [
        ((HUNT, HUNT_FIXED), 2, None),
        ((), 0, None),
        ((HUNT,), 2, "the COMPLETE line carries hunt=2 but the receipts block holds 1 hunt lines"),
        (
            (HUNT, HUNT_FIXED),
            1,
            "the COMPLETE line carries hunt=1 but the receipts block holds 2 hunt lines",
        ),
        ((), 1, "the COMPLETE line carries hunt=1 but the receipts block holds 0 hunt lines"),
    ],
)
def test_the_hunt_count_equals_the_hunt_lines(
    hunts: tuple[str, ...], field: int, problem: str | None
) -> None:
    # 227: ` hunt=<n>` counts the block's hunt receipts.
    reply = _reply("## Receipts", COMMIT, TEST, *hunts, COMPLETE + f" hunt={field} turns=4")
    assert handback_check.receipts_problem(reply) == problem


def test_text_between_the_block_and_the_complete_line_is_refused() -> None:
    reply = _reply("## Receipts", COMMIT, TEST, "", "Thanks.", COMPLETE)
    assert handback_check.receipts_problem(reply) == (
        "the receipts block holds a line of another shape: ''"
    )


def test_a_long_bad_line_is_shown_cut() -> None:
    bad = "x" * 300
    got = handback_check.receipts_problem(_reply("## Receipts", bad, COMMIT, TEST, COMPLETE))
    assert got == f"the receipts block holds a line of another shape: {'x' * 120 + '...'!r}"


@pytest.mark.parametrize(
    "reply",
    [
        "[STATUS: YIELD_WEB] what does SubagentStop send",
        "Blocked.\n[STATUS: YIELD_CONTRACT] pin 2 mismatch",
        "[STATUS: YIELD_COMPLIANCE] may I log the reply",
        "[STATUS: YIELD_STANDARDS] which comment cap applies",
        f"{COMPLETE}\nand a trailing note",  # pin RCP -> VER: the last line is no COMPLETE line
        "progress note",
        "",
    ],
)
def test_replies_that_do_not_end_in_complete_pass(reply: str) -> None:
    assert handback_check.receipts_problem(reply) is None
    assert handback_check.judge(_stop(reply)) is None


def test_the_refusal_carries_one_next_line_naming_the_shape() -> None:
    got = handback_check.judge(_stop(_reply("done", COMPLETE)))
    assert got is not None
    assert got.startswith("Daedalus hand-back check: the COMPLETE reply has no `## Receipts`")
    assert got.count("Next:") == 1 and "\n" not in got
    assert got.endswith(f"Next: end the reply with {handback_check.SHAPE}.")
    for shape in (
        "- commit <40 hex> <subject>",
        "- deviation <file or behaviour> | <reason>",
        "- hunt <form> => admitted, fixed in <7 to 40 hex>",
        "` hunt=<n>` directly before its closing ` turns=<n>`",
    ):
        assert shape in got


@pytest.mark.parametrize("agent", ["coder", "daedalus:coder"])
def test_the_check_binds_the_coder(agent: str) -> None:
    assert handback_check.judge(_stop(_reply("done", COMPLETE), agent)) is not None


@pytest.mark.parametrize(
    "agent", ["orchestrator", "daedalus:orchestrator", "daedalus:verifier", "charter-docs", "x"]
)
def test_other_agents_pass(agent: str) -> None:
    # RCP: the check binds coders only, not the orchestrator's reports.
    assert handback_check.judge(_stop(_reply("done", COMPLETE), agent)) is None


def test_other_events_and_non_text_replies_pass() -> None:
    bare = _reply("done", COMPLETE)
    assert handback_check.judge({**_stop(bare), "hook_event_name": "Stop"}) is None
    assert handback_check.judge({**_stop(bare), "hook_event_name": "PreToolUse"}) is None
    assert handback_check.judge(_stop(None)) is None
    assert handback_check.judge(_stop(["done", COMPLETE])) is None


def test_a_stop_without_agent_type_takes_the_started_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from lib import audit

    seen: list[tuple[Path, str]] = []

    def started(path: Path, agent_id: str) -> str | None:
        seen.append((path, agent_id))
        return "daedalus:coder"

    monkeypatch.setattr(audit, "_started_type", started)
    assert handback_check.judge(_stop(_reply("done", COMPLETE), None)) is not None
    assert seen == [(audit.log_path("s", "/work/repo"), "a1")]
    monkeypatch.setattr(audit, "_started_type", lambda path, agent_id: None)
    assert handback_check.judge(_stop(_reply("done", COMPLETE), None)) is None


def test_a_stop_with_a_bad_session_id_and_no_agent_type_passes() -> None:
    assert handback_check.judge(_stop(_reply("done", COMPLETE), None, session_id="../x")) is None


def _run(stdin: str) -> subprocess.CompletedProcess[str]:
    script = str(SCRIPTS_DIR / "handback_check.py")
    return subprocess.run(
        [sys.executable, script], input=stdin, capture_output=True, text=True, check=False
    )


def test_the_script_blocks_in_a_train(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / TRAIN_MARKER).parent.mkdir(parents=True)
    (tmp_path / TRAIN_MARKER).write_text("20261026-002310\n", encoding="utf-8")
    stop = _stop(_reply("done", COMPLETE), cwd=str(tmp_path))
    got = _run(json.dumps(stop))
    assert got.returncode == 0
    out = json.loads(got.stdout)
    assert out["decision"] == "block"
    assert out["reason"] == handback_check.judge(stop)
    whole = _stop(_reply("## Receipts", COMMIT, TEST, COMPLETE), cwd=str(tmp_path))
    assert _run(json.dumps(whole)).stdout == ""


def test_the_script_steps_aside_outside_a_train(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    got = _run(json.dumps(_stop(_reply("done", COMPLETE), cwd=str(tmp_path))))
    assert (got.returncode, got.stdout) == (0, "")


@pytest.mark.parametrize("stdin", ["", "not json", "[1, 2]", "{}"])
def test_the_script_never_blocks_on_bad_input(stdin: str) -> None:
    got = _run(stdin)
    assert (got.returncode, got.stdout) == (0, "")


# RCP, train 20261026-002310 pick 4: the same check on the SubagentHandback tool's message.
def _handback(message: object, agent: str | None = "daedalus:coder", **extra: object) -> dict:
    payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "tool_name": "SubagentHandback",
        "tool_input": {"message": message},
        "session_id": "s",
        "cwd": "/work/repo",
        "agent_id": "a1",
        **extra,
    }
    if agent is not None:
        payload["agent_type"] = agent
    return payload


# Pin RCP -> VER: the shape this train's coders hand back, narrative above the header allowed.
CODER_MESSAGE = _reply(
    "The unit added the check; the verifier judges the diff.",
    "",
    "## Receipts",
    COMMIT,
    f"- commit {SHA[::-1]} Name cite.py and handback_check.py in the README tree",
    "- test daedalus_confine.py --unit <worktree> -- python3 -m pytest -q => 5914 passed, "
    "1 skipped, 19 deselected in 138.45s (0:02:18)",
    TYPECHECK,
    "- deviation README.md (outside the files list) | tests/test_docs.py needs the tree line",
    "- deviation hook errors | a broken check never stalls the train",
    COMPLETE + " adversarial=pass",
)


def test_a_coder_handback_message_with_narrative_above_the_block_passes() -> None:
    assert handback_check.receipts_problem(CODER_MESSAGE) is None
    assert handback_check.judge(_handback(CODER_MESSAGE)) is None
    assert handback_check.judge(_stop(CODER_MESSAGE)) is None


def test_a_handback_message_without_a_block_is_refused_with_the_stop_reason() -> None:
    bare = _reply("All done.", COMPLETE)
    got = handback_check.judge(_handback(bare))
    assert got is not None and got == handback_check.judge(_stop(bare))
    assert got.count("Next:") == 1


@pytest.mark.parametrize(
    "message",
    ["[STATUS: YIELD_WEB] what does SubagentHandback send", "progress", "", None, ["x"]],
)
def test_handback_yields_and_non_text_messages_pass(message: object) -> None:
    assert handback_check.judge(_handback(message)) is None


@pytest.mark.parametrize("agent", ["daedalus:orchestrator", "daedalus:verifier", "x"])
def test_handback_of_other_agents_passes(agent: str) -> None:
    assert handback_check.judge(_handback(_reply("done", COMPLETE), agent)) is None


def test_other_tools_and_a_bad_tool_input_pass() -> None:
    bare = _reply("done", COMPLETE)
    assert handback_check.judge({**_handback(bare), "tool_name": "Bash"}) is None
    assert handback_check.judge({**_handback(bare), "tool_input": bare}) is None
    assert handback_check.judge({**_handback(bare), "hook_event_name": "PostToolUse"}) is None


def test_the_script_denies_a_handback_in_a_train(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / TRAIN_MARKER).parent.mkdir(parents=True)
    (tmp_path / TRAIN_MARKER).write_text("20261026-002310\n", encoding="utf-8")
    call = _handback(_reply("done", COMPLETE), cwd=str(tmp_path))
    out = json.loads(_run(json.dumps(call)).stdout)
    assert out == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": handback_check.judge(call),
        }
    }
    # 0205: a passing hand-back in a run goes out as its digest, the whole reply saved on disk.
    assert _run(json.dumps(_handback(CODER_MESSAGE, cwd=str(tmp_path)))).stdout == ""
    long = _reply(*["The unit wired the check into the hand-back path."] * 12, CODER_MESSAGE)
    out = json.loads(_run(json.dumps(_handback(long, cwd=str(tmp_path)))).stdout)
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"
    short = out["hookSpecificOutput"]["updatedInput"]["message"]
    report = Path(short.splitlines()[0].split()[1])
    assert report.read_text(encoding="utf-8") == long
    assert report.parent == tmp_path / "docs/.tmp/daedalus/20261026-002310/evidence/replies"
    assert short.splitlines()[2:] == CODER_MESSAGE.splitlines()[2:]


def test_the_script_steps_aside_on_a_handback_outside_a_train(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    got = _run(json.dumps(_handback(_reply("done", COMPLETE), cwd=str(tmp_path))))
    assert (got.returncode, got.stdout) == (0, "")


def _files(value: str) -> str:
    # 209: a whole reply whose COMPLETE line carries this files= value.
    line = COMPLETE.replace("files=a.py ", f"files={value} ")
    return _reply("## Receipts", COMMIT, TEST, line)


@pytest.mark.parametrize(
    ("value", "entry"),
    [
        ("/work/repo/.claude/worktrees/u1/a.py", "/work/repo/.claude/worktrees/u1/a.py"),
        ("a.py,/etc/passwd", "/etc/passwd"),
        ("a.py, scripts/../../b.py", "scripts/../../b.py"),
        ("../b.py", "../b.py"),
        ("..", ".."),
        ("~/b.py", "~/b.py"),
        ("scripts/a.py,//host/b.py", "//host/b.py"),
        ("C:\\x\\b.py", "C:\\x\\b.py"),
        ("$HOME/b.py", "$HOME/b.py"),
    ],
)
def test_a_files_entry_outside_the_worktree_is_refused(
    tmp_path: Path, value: str, entry: str
) -> None:
    # 209: absolute, dotted or expanded entries are refused by name, under any root.
    got = handback_check.receipts_problem(_files(value), tmp_path)
    assert got is not None and got.startswith(handback_check.FILES_LEAD), got
    assert repr(entry) in got and "relative to the worktree root" in got, got
    said = handback_check.judge(_stop(_files(value)))
    assert said is not None and said.count("Next:") == 1, said
    assert said.endswith(f"Next: {handback_check.FILES_NEXT}."), said


@pytest.mark.parametrize(
    "value",
    [
        "a.py",
        "scripts/lib/jail.py,tests/test_jail.py,README.md",
        "agents/orchestrator.md, scripts/lib/train_summary.py, skills/catalog/SKILL.md",
        "agents/framework-specialist.md,agents/cis-specialist.md(deleted),README.md",
        "(21 files, see diff)",
        "46 changed vs bbcfd30: 3 new (tests/payloads.py, tests/live.py), tests/conftest.py",
        "tests/test_jail.py::test_a, scripts/lib/jail.py:2965",
        ".claude-plugin/plugin.json,VERSION",
    ],
)
def test_relative_files_entries_pass(tmp_path: Path, value: str) -> None:
    # 209: every relative list, prose and annotations included, passes unchanged.
    assert handback_check.receipts_problem(_files(value), tmp_path) is None
    assert handback_check.judge(_stop(_files(value))) is None


def test_a_link_out_of_the_bound_unit_worktree_is_refused(tmp_path: Path) -> None:
    # 209, issue 29: the root is the worktree of the coder's bound unit, not the hook cwd.
    from lib import train_state
    from lib.unit_binding import claim, record_dispatch

    repo, train = tmp_path / "repo", "20261026-002310"
    worktree = repo / ".claude" / "worktrees" / "u1"
    worktree.mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / TRAIN_MARKER).parent.mkdir(parents=True)
    (repo / TRAIN_MARKER).write_text(f"{train}\n", encoding="utf-8")
    train_state.save(
        repo, train, {"train_id": train, "units": [{"name": "u1", "path": str(worktree)}]}
    )
    assert record_dispatch(repo, train, "u1") is None and claim(repo, train, "a1", "u1") is None
    (tmp_path / "outside").mkdir()
    (worktree / "out").symlink_to(tmp_path / "outside")
    got = handback_check.judge(_stop(_files("a.py,out/b.py"), cwd=str(repo)))
    assert got is not None and "'out/b.py'" in got, got
    assert (
        handback_check.judge(_stop(_files("a.py,out/b.py"), cwd=str(repo), agent_id="a2")) is None
    )
    assert handback_check.judge(_stop(_files("a.py,in/b.py"), cwd=str(repo))) is None


# 0281: a failing judge verdict whose finding lacks its rule, a place or its search is refused.
CELLS = " | rule: a refusal names its rule | places: scripts/x.py:4 | search: git grep -n refuse"
TIP = "tip=" + "a" * 40
VERIFIER_KEY = "Unit worktree: /work/repo/.claude/worktrees/u1"


def _refuted(*rows: str) -> str:
    line = "[VERDICT: REFUTED] " + "; ".join(rows)
    return _reply(line, VERIFIER_KEY, "| claim | verdict |", "corrected=0", line)


def _rejected(*findings: str) -> str:
    head = f"[VERDICT: REJECTED] {TIP}"
    return _reply(head, *findings, "## Compliance", "none", head)


ROW = "code | req 1 | MISSING | none | req 1"
NODE = "audit/round1/test_scope_x.py::test_y high scope: the write lands"


@pytest.mark.parametrize("event", [_stop, _handback])
def test_a_finding_with_one_place_and_its_search_passes(event: object) -> None:
    assert callable(event)
    assert handback_check.judge(event(_refuted(ROW + CELLS), "daedalus:verifier")) is None
    assert handback_check.judge(event(_rejected(NODE + CELLS), "daedalus:auditor")) is None
    doc = " | rule: a step names its command | places: docs/guide.md:Install | search: rg -n step"
    assert handback_check.judge(event(_refuted(ROW + doc), "verifier")) is None


@pytest.mark.parametrize(
    ("cells", "field"),
    [
        (" | rule: r | places: scripts/x.py:4", "no search cell"),
        (" | rule: r | search: git grep -n r", "no places cell"),
        (" | places: scripts/x.py:4 | search: git grep -n r", "no rule cell"),
    ],
)
def test_a_verifier_row_without_a_cell_is_refused(cells: str, field: str) -> None:
    reply = _refuted(ROW + CELLS, ROW + cells)
    got = handback_check.judge(_handback(reply, "daedalus:verifier"))
    assert got is not None and "\n" not in got
    assert got.startswith(f"Daedalus hand-back check: row 2 '{ROW + cells}' has {field}.")
    assert got.count("Next:") == 1
    assert got.endswith("rows joined by `; ` and no other `;`.")
    assert "row 1" not in got


@pytest.mark.parametrize(
    ("cells", "field"),
    [
        (" | rule: r | places: scripts/x.py:4", "no search cell"),
        (" | rule: r | search: git grep -n r", "no places cell"),
        (" | places: scripts/x.py:4 | search: git grep -n r", "no rule cell"),
    ],
)
def test_an_auditor_finding_without_a_cell_is_refused(cells: str, field: str) -> None:
    no_test = "no-test: daedalus/t a.py:3 medium contract: drift; reason: prose" + cells
    got = handback_check.judge(_stop(_rejected(NODE + CELLS, no_test), "daedalus:auditor"))
    assert got is not None
    assert f"finding 2 '{no_test}' has {field}." in got
    assert "finding 1" not in got and got.count("Next:") == 1


def test_every_finding_lacking_a_cell_is_named() -> None:
    got = handback_check.judge(_stop(_refuted(ROW, ROW + CELLS, ROW), "verifier"))
    assert got is not None
    assert "row 1 " in got and "row 3 " in got and "row 2 " not in got
    assert "no rule cell and no places cell and no search cell" in got


def test_a_failing_verdict_with_no_readable_finding_is_refused() -> None:
    bare = "[VERDICT: REFUTED]"
    got = handback_check.judge(_stop(_reply(bare, VERIFIER_KEY, bare), "verifier"))
    assert got is not None and "holds no row" in got
    semi = handback_check.judge(_stop(_refuted(ROW + CELLS.replace("refuse", "a;b")), "verifier"))
    assert semi is not None and "holds no row" in semi
    prose = handback_check.judge(_stop(_rejected("The write lands."), "auditor"))
    assert prose is not None and "lists no finding line" in prose


def test_passing_verdicts_and_other_replies_are_unchanged() -> None:
    verified = "[VERDICT: VERIFIED] claims=3"
    assert handback_check.judge(_stop(_reply(verified, VERIFIER_KEY, verified), "verifier")) is None
    approved = f"[VERDICT: APPROVED] {TIP}"
    reply = _reply(approved, "Clean.", "## Compliance", "none", approved)
    assert handback_check.judge(_stop(reply, "auditor")) is None
    assert (
        handback_check.judge(_stop(_reply("[ROWS] n=1", "row", "[ROWS] n=1"), "verifier")) is None
    )
    # 0281: the cells bind judges only; a coder's REFUTED-looking text is judged by its receipts.
    assert handback_check.judge(_stop(_refuted(ROW), "orchestrator")) is None


def test_the_script_blocks_a_judge_in_a_train(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / TRAIN_MARKER).parent.mkdir(parents=True)
    (tmp_path / TRAIN_MARKER).write_text("20261026-002310\n", encoding="utf-8")
    stop = _stop(_refuted(ROW), "daedalus:verifier", cwd=str(tmp_path))
    out = json.loads(_run(json.dumps(stop)).stdout)
    assert out["decision"] == "block" and out["reason"] == handback_check.judge(stop)
    whole = _stop(_rejected(NODE + CELLS), "daedalus:auditor", cwd=str(tmp_path))
    assert _run(json.dumps(whole)).stdout == ""


def _train_repo(tmp_path: Path, listed: list[str] | None) -> Path:
    # 0281: a train whose round 1 findings file lists the given keys, or no file at all.
    from lib import train_state
    from lib.audit_proof import findings_path

    repo, train = tmp_path / "repo", "20261026-002310"
    (repo / ".git").mkdir(parents=True)
    (repo / TRAIN_MARKER).parent.mkdir(parents=True)
    (repo / TRAIN_MARKER).write_text(f"{train}\n", encoding="utf-8")
    train_state.save(repo, train, {"train_id": train})
    if listed is not None:
        path = findings_path(repo, train, 1)
        path.parent.mkdir(parents=True)
        path.write_text("".join(f"{key} | high | scope\n" for key in listed), encoding="utf-8")
    return repo


def test_a_rejected_reply_listing_fewer_findings_than_its_file_is_refused(tmp_path: Path) -> None:
    repo = _train_repo(tmp_path, ["audit/round1/test_scope_x.py::test_y", "a.py:3 contract"])
    reply = _rejected(NODE + CELLS, "**a.py:3** the contract drifts")
    got = handback_check.judge(_handback(reply, "daedalus:auditor", cwd=str(repo)))
    assert got is not None
    assert "lists 1 finding lines but the round's findings file lists 2" in got
    assert handback_check.round_findings(str(repo)) == 2


def test_a_rejected_reply_matching_its_file_passes(tmp_path: Path) -> None:
    repo = _train_repo(tmp_path, ["audit/round1/test_scope_x.py::test_y"])
    reply = _rejected(NODE + CELLS)
    assert handback_check.judge(_handback(reply, "daedalus:auditor", cwd=str(repo))) is None


def test_an_unreadable_findings_file_leaves_the_count_unjudged(tmp_path: Path) -> None:
    repo = _train_repo(tmp_path, None)
    assert handback_check.round_findings(str(repo)) is None
    assert handback_check.round_findings("relative/path") is None
    reply = _rejected(NODE + CELLS)
    assert handback_check.judge(_handback(reply, "daedalus:auditor", cwd=str(repo))) is None

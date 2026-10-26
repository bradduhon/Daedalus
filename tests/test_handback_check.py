# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# RCP, 0128: the SubagentStop receipts check on a repo-coder's COMPLETE reply (pin RCP -> VER).
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


def _reply(*lines: str) -> str:
    return "\n".join(lines)


def _stop(reply: object, agent: str | None = "daedalus:repo-coder", **extra: object) -> dict:
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
        "The unit adds a check.",  # narrative between the header and the block lines
        "",  # a blank line is no pinned shape
        "  - commit " + SHA + " indented",
        "- commit 0123abc short sha",
        "- commit " + SHA.upper() + " upper hex",
        "- test python3 -m pytest -q",  # no `=> <last output line>`
        "- test python3 -m pytest -q => ",
        "- typecheck => Success",
        "- yield WEB => orchestrator",
        "- deviation a.py reason without a bar",
        "- claim scripts/a.py:3 adds the check",
        "* commit " + SHA + " star bullet",
    ],
)
def test_text_between_the_header_and_the_lines_is_refused(between: str) -> None:
    reply = _reply("## Receipts", between, COMMIT, TEST, COMPLETE)
    got = handback_check.receipts_problem(reply)
    assert got == f"the receipts block holds a line of another shape: {between.rstrip()!r}"


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
        f"{COMPLETE}\nand a trailing note",  # the last line is no COMPLETE line
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
    for shape in ("- commit <40 hex> <subject>", "- deviation <file or behaviour> | <reason>"):
        assert shape in got


@pytest.mark.parametrize("agent", ["repo-coder", "daedalus:repo-coder"])
def test_the_check_binds_the_repo_coder(agent: str) -> None:
    assert handback_check.judge(_stop(_reply("done", COMPLETE), agent)) is not None


@pytest.mark.parametrize(
    "agent", ["orchestrator", "daedalus:orchestrator", "daedalus:verifier", "charter-docs", "x"]
)
def test_other_agents_pass(agent: str) -> None:
    # RCP: the check binds repo-coders only, not the orchestrator's reports.
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
        return "daedalus:repo-coder"

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

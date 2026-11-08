# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from lib import reply_digest

TRAIN = "20261102-011912"
NOW = datetime(2026, 11, 2, 1, 2, 3, tzinfo=UTC)
TABLE = [f"code | claim {n} | MATCH | line {n} | req {n}" for n in range(40)]
VERIFIED = "[VERDICT: VERIFIED] claims=40"
REFUTED = "[VERDICT: REFUTED] code | claim 3 | MISSING | none | req 3"


def _digest(tmp_path: Path, agent: str, message: str) -> str | None:
    return reply_digest.digest(agent, message, tmp_path, TRAIN, "a1c64c2e", NOW)


def _report(short: str) -> Path:
    line = next(ln for ln in short.splitlines() if ln.startswith("report: "))
    return Path(line.split()[1])


@pytest.mark.parametrize("verdict", [VERIFIED, REFUTED])
def test_a_verifier_reply_keeps_its_verdict_and_corrected_lines(
    tmp_path: Path, verdict: str
) -> None:
    message = "\n".join([verdict, *TABLE, "corrected=2", verdict])
    short = _digest(tmp_path, "verifier", message)
    assert short is not None
    lines = short.splitlines()
    assert (lines[0], lines[2:]) == (verdict, ["corrected=2", verdict])
    report = _report(short)
    assert report.read_text(encoding="utf-8") == message
    sha = hashlib.sha256(message.encode("utf-8")).hexdigest()
    assert lines[1] == f"report: {report} sha256={sha} lines={len(message.splitlines())}"
    folder = tmp_path / "docs/.tmp/daedalus" / TRAIN / "evidence/replies"
    assert report == folder / "verifier-a1c64c2e-20261102T010203000000Z.md"


@pytest.mark.parametrize("verdict", [VERIFIED, REFUTED, "[ROWS] n=40"])
def test_a_verifier_digest_keeps_the_key_line_second(tmp_path: Path, verdict: str) -> None:
    # 0231: the merge gate reads the unit key from the line after the opening line.
    key = "Unit worktree: /repo/.claude/worktrees/t-u1"
    message = "\n".join([verdict, key, *TABLE, "corrected=0", verdict])
    short = _digest(tmp_path, "verifier", message)
    if verdict.startswith("[ROWS]"):
        assert short is None
        return
    assert short is not None
    lines = short.splitlines()
    assert lines[:2] == [verdict, key] and lines[3:] == ["corrected=0", verdict]
    assert lines[2].startswith("report: ")


def test_a_contract_spec_reply_keeps_the_heading_and_version(tmp_path: Path) -> None:
    packet = ["## Locked Contract Packet", "- **packet_version**: 5", *TABLE]
    short = _digest(tmp_path, "contract-spec", "\n".join(["Saved.", *packet]))
    assert short is not None
    assert short.splitlines()[1:] == packet[:2]


def test_a_charter_docs_reply_keeps_its_status_line(tmp_path: Path) -> None:
    last = "[STATUS: COMMITTED] b8e8063 ids=0004-GEO-PLT"
    short = _digest(tmp_path, "charter-docs", "\n".join([*TABLE, last]))
    assert short is not None and short.splitlines()[1:] == [last]


@pytest.mark.parametrize(
    ("agent", "message"),
    [
        ("auditor", "\n".join([VERIFIED, *TABLE, VERIFIED])),
        ("orchestrator", "\n".join([*TABLE, "[STATUS: STOP] reason=x next=y"])),
        ("verifier", "\n".join([VERIFIED, *TABLE])),
        ("verifier", "\n".join(TABLE)),
        ("coder", "\n".join([*TABLE, "[STATUS: YIELD_WEB] what is x"])),
        ("contract-spec", "\n".join(TABLE)),
        ("verifier", f"{VERIFIED}\ncorrected=0\n{VERIFIED}"),
        ("verifier", ""),
    ],
)
def test_other_agents_off_contract_and_short_replies_pass_whole(
    tmp_path: Path, agent: str, message: str
) -> None:
    assert _digest(tmp_path, agent, message) is None
    assert not (tmp_path / "docs").exists()

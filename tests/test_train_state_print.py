# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# W3.2: each section of the train summary, rendered from a state fixture and audit records.
from __future__ import annotations

import copy
import os
import re
from pathlib import Path
from typing import Any

import pytest
from lib import audit
from lib.plan_record import Version
from lib.train_summary import (
    NO_NOTES,
    NOT_RUN,
    Notes,
    SessionLog,
    SummaryError,
    load_logs,
    parse_notes,
    public,
    render,
)

from tests.conftest import write_train_marker

TRAIN = "20261021-014310"
REPO = Path("/r/Daedalus")
CHARTER = REPO / "docs" / "private"
TIP = "e" * 40
U1 = f"{REPO}/.claude/worktrees/{TRAIN}-u1"
U2 = f"{REPO}/.claude/worktrees/{TRAIN}-u2"
COMPLETE = (
    f"Done.\n[STATUS: COMPLETE] branch=daedalus-unit/{TRAIN}-u1 packet_version=3 "
    "files=scripts/a.py, tests/test_a.py tests=pytest 10 passed | mypy ok ledger_notes=none "
    "contract=aaaaaaaaaaaa standards=bbbbbbbbbbbb"
)
NOTES = (
    "Task: build the summary command\n"
    "Codes: --repo DAE --type PLT\n"
    "## Rulings\n"
    "Fan out the coders? Follow Plugin (0120-DAE-PLT)\n"
    "Deviation: up to five coders at once, against the one-agent rule (0120-DAE-PLT)\n"
    "## Blocks\n"
    "Friction: none\n"
    "Habit: repo-coder, workspace_integrity, a read of the plugin data folder\n"
)


def _unit(name: str, path: str) -> dict[str, object]:
    return {"name": f"{TRAIN}-{name}", "branch": f"daedalus-unit/{TRAIN}-{name}", "path": path}


STATE: dict[str, object] = {
    "train_id": TRAIN,
    "base_branch": "main",
    "base_sha": "a" * 40,
    "charter_root": str(CHARTER),
    "charter_base": "charter/inputs",
    "ledger_line": f"ledger: {CHARTER}/decisions.md (config, markdown-table-row, seq=119)",
    "packet_version": 3,
    "contract_path": f"{CHARTER}/specs/plan-8.md",
    "units": [
        _unit("u1", U1),
        _unit("u2", U2),
        _unit("audit", f"{REPO}/.claude/worktrees/{TRAIN}-audit"),
    ],
    "verdict": {"status": "approved", "tip": TIP, "round": 3, "seq": 9},
    "audit_rounds": {"1": {"t.py::test_x": {"severity": "high", "class": "injection"}}, "2": {}},
    "audit_session": "sess-a",
    "ledger": {"sha": "c" * 40, "ids": ["0127-DAE-PLT", "0128-DAE-PLT"]},
}


def _stop(seq: int, agent: str, text: str, agent_id: str = "x") -> dict[str, object]:
    return {
        "seq": seq,
        "event": "SubagentStop",
        "agent_type": f"daedalus:{agent}",
        "agent_id": agent_id,
        "last_message_head": text,
        "last_message_tail": text,
    }


def _handback(seq: int, agent: str, message: str, agent_id: str = "x") -> dict[str, object]:
    return {
        "seq": seq,
        "event": "PostToolUse",
        "tool_name": "SubagentHandback",
        "agent_type": f"daedalus:{agent}",
        "agent_id": agent_id,
        "tool_input": {"message": message},
    }


def _pre(seq: int, agent: str, tool: str, agent_id: str, **tool_input: object) -> dict[str, object]:
    return {
        "seq": seq,
        "event": "PreToolUse",
        "tool_name": tool,
        "agent_type": f"daedalus:{agent}",
        "agent_id": agent_id,
        "tool_input": dict(tool_input),
        "decision": "allow",
    }


RECORDS: list[dict[str, object]] = [
    _handback(1, "repo-coder", COMPLETE, "c1"),
    _pre(2, "repo-coder", "Bash", "c2", command=f"git -C {U2} commit -m 'WIP: yield'"),
    _stop(3, "repo-coder", "[STATUS: YIELD_STANDARDS] which rule covers /opt/x/rules/py.md?", "c2"),
    _stop(4, "standards-rules-specialist", "[STATUS: STANDARD] python.md:10", "s1"),
    _stop(5, "nist-specialist", "[STATUS: COMPLIANCE] AU-9 PASS, AU-3 PASS", "n1"),
    _pre(6, "orchestrator", "Agent", "o1", prompt=f"Check it.\nUnit worktree: {U1}\nGo."),
    _stop(
        7, "verifier", "[VERDICT: VERIFIED] claims=12\nrows\n[VERDICT: VERIFIED] claims=12", "v1"
    ),
    {**_pre(8, "orchestrator", "Write", "o1", file_path="/x"), "decision": "block"},
    _handback(
        9,
        "security-auditor",
        f"[VERDICT: APPROVED] tip={TIP}\nThe merged tip holds\nat {U1}/scripts/a.py.\n\n"
        f"Second paragraph.\n[VERDICT: APPROVED] tip={TIP}",
        "a1",
    ),
]


def _text(
    tmp_path: Path,
    state: dict[str, object] | None = None,
    notes: Notes | None = None,
    records: list[dict[str, object]] | None = None,
    version: Version | None = None,
    policy: bool = False,
) -> str:
    log = SessionLog("sess-a", tmp_path / "sess-a.jsonl", records or RECORDS)
    found = notes if notes is not None else parse_notes(NOTES, "notes")
    return render(REPO, TRAIN, state or STATE, [log], found, policy, version)


def _section(text: str, head: str) -> list[str]:
    body = text.split(f"\n## {head}\n", 1)[1]
    return body.split("\n## ", 1)[0].splitlines()


def test_header_lines_come_from_state_and_the_notes(tmp_path: Path) -> None:
    lines = _text(tmp_path).splitlines()
    assert lines[:9] == [
        f"# Build Train {TRAIN}",
        "Task: build the summary command",
        f"Base: main @ {'a' * 40}. Integration branch: daedalus/{TRAIN}.",
        f"charter: private, branch daedalus/{TRAIN}, charter base: charter/inputs "
        "(ledger under charter_root)",
        "Packet: v3. Ledger: private/decisions.md.",
        "Contract: private/specs/plan-8.md v3",
        f"Ledger ids: 0127-DAE-PLT,0128-DAE-PLT in commit {'c' * 40}.",
        "[POLICY: none declared]",
        "## Rulings",
    ]
    assert "[POLICY: declared, gate not yet shipped]" in _text(tmp_path, policy=True)


def test_header_without_a_charter_is_repo_local(tmp_path: Path) -> None:
    state = copy.deepcopy(STATE)
    del state["charter_root"]
    state["ledger_line"] = f"ledger: {REPO}/docs/decisions.md (probed, markdown-table-row, seq=1)"
    state["contract_path"] = f"{REPO}/contracts/c.md"
    lines = _text(tmp_path, state).splitlines()
    assert "charter: none (repo-local ledger)" in lines
    assert "Packet: v3. Ledger: Daedalus/docs/decisions.md." in lines
    assert "Contract: contracts/c.md v3" in lines


def test_ledger_ids_read_pending_without_the_ledger_record(tmp_path: Path) -> None:
    # pin D1 -> E4: the Ledger ids line reads the ledger record, else pending.
    state = copy.deepcopy(STATE)
    del state["ledger"]
    assert "Ledger ids: pending. Codes: --repo DAE --type PLT." in _text(tmp_path, state)
    assert "\nLedger ids: pending.\n" in _text(tmp_path, state, Notes())
    state["ledger"] = {"sha": "short", "ids": ["0127-DAE-PLT"]}
    with pytest.raises(SummaryError, match="names no commit sha or no ids"):
        _text(tmp_path, state)


def test_version_class_line_and_its_migration(tmp_path: Path) -> None:
    # pin D4 -> D5: only a plan with a version line; class X needs the notes' Migration line.
    assert "Version class:" not in _text(tmp_path)
    minor = Version("3.4.0", "Y", "adds the summary command", "E4")
    assert "\nVersion class: 3.4.0 Y: adds the summary command\n" in _text(tmp_path, version=minor)
    major = Version("4.0.0", "X", "moves the manifest", "E9")
    with pytest.raises(SummaryError, match="Migration"):
        _text(tmp_path, version=major)
    notes = parse_notes(NOTES.replace("## Rulings", "Migration: edit config.json\n## Rulings"), "n")
    assert "\nMigration: edit config.json\n" in _text(tmp_path, notes=notes, version=major)


def test_rulings_come_from_the_notes_file(tmp_path: Path) -> None:
    assert _section(_text(tmp_path), "Rulings") == [
        "Fan out the coders? Follow Plugin (0120-DAE-PLT)",
        "Deviation: up to five coders at once, against the one-agent rule (0120-DAE-PLT)",
    ]
    assert _section(_text(tmp_path, notes=Notes()), "Rulings") == [NO_NOTES]
    empty = parse_notes("Task: t\n## Rulings\n", "n")
    assert _section(_text(tmp_path, notes=empty), "Rulings") == ["none"]


def test_units_table_reads_each_coder_complete_line(tmp_path: Path) -> None:
    rows = _section(_text(tmp_path), "Units")
    assert rows[:2] == ["| Unit | Branch | Packet | Files | Tests |", "|---|---|---|---|---|"]
    assert rows[2] == (
        f"| u1 | daedalus-unit/{TRAIN}-u1 | v3 | scripts/a.py, tests/test\\_a.py | "
        "pytest 10 passed \\| mypy ok |"
    )
    assert rows[3] == f"| u2 | daedalus-unit/{TRAIN}-u2 | - | - | - |"
    assert len(rows) == 4


def test_verification_lists_one_verdict_per_verified_unit(tmp_path: Path) -> None:
    assert _section(_text(tmp_path), "Verification") == ["- u1: \\[VERDICT: VERIFIED\\] claims=12"]
    assert _section(_text(tmp_path, records=RECORDS[:6]), "Verification") == ["none"]


def test_yields_name_the_unit_kind_question_and_answerer(tmp_path: Path) -> None:
    assert _section(_text(tmp_path), "Yields") == [
        "- u2: YIELD_STANDARDS which rule covers py.md? (answered by standards-rules-specialist)"
    ]
    assert _section(_text(tmp_path, records=RECORDS[:1]), "Yields") == ["none"]


def test_compliance_lists_each_specialist_reply(tmp_path: Path) -> None:
    assert _section(_text(tmp_path), "Compliance") == ["- nist-specialist: AU-9 PASS, AU-3 PASS"]
    assert _section(_text(tmp_path, records=RECORDS[:1]), "Compliance") == [NOT_RUN]


def test_audit_section_names_the_verdict_the_paragraph_and_each_round(tmp_path: Path) -> None:
    assert _section(_text(tmp_path), "Audit") == [
        f"[VERDICT: APPROVED] tip={TIP} on the merged integration tip after 3 round(s).",
        f"Auditor: The merged tip holds at .claude/worktrees/{TRAIN}-u1/scripts/a.py.",
        "Round 1: rejected, 1 finding(s) (1 high)",
        "Round 2: no findings recorded",
        "Round 3: approved",
    ]


def test_audit_section_reads_a_state_written_by_older_code(tmp_path: Path) -> None:
    # A verdict without a seq and no round records, as a pre-D1 train wrote them.
    state = copy.deepcopy(STATE)
    state["verdict"] = {"status": "approved", "tip": TIP, "round": 2}
    del state["audit_rounds"], state["ledger"]
    assert _section(_text(tmp_path, state), "Audit") == [
        f"[VERDICT: APPROVED] tip={TIP} on the merged integration tip after 2 round(s).",
        "Round 1: not recorded in train state",
        "Round 2: approved",
    ]


def test_audit_section_after_a_rejection_an_exception_and_no_verdict(tmp_path: Path) -> None:
    state = copy.deepcopy(STATE)
    state["verdict"] = {"status": "rejected", "tip": TIP, "round": 1, "seq": 9}
    state["audit_rounds"] = {"1": {"t.py::test_x": {"severity": "high"}}}
    assert (
        _section(_text(tmp_path, state), "Audit")[0]
        == f"[VERDICT: REJECTED] tip={TIP} after 1 round(s)."
    )
    state["exception"] = {"ledger_id": "0130-DAE-PLT", "tip": TIP}
    waived = _section(_text(tmp_path, state), "Audit")
    assert waived[:2] == [
        f"The operator's exception (0130-DAE-PLT) on tip {TIP} after 1 rejected round(s).",
        "- t.py::test\\_x: tracked-risk issue not recorded",
    ]
    notes = parse_notes(NOTES + "## Waived\nt.py::test_x: tracked-risk issue filed\n", "n")
    assert (
        _section(_text(tmp_path, state, notes), "Audit")[1]
        == "t.py::test_x: tracked-risk issue filed"
    )
    del state["verdict"], state["exception"], state["audit_rounds"]
    assert _section(_text(tmp_path, state), "Audit") == ["Verdict: pending"]


def test_blocks_carry_the_notes_lists_and_the_recorded_tally(tmp_path: Path) -> None:
    assert _section(_text(tmp_path), "Blocks") == [
        "Friction: none",
        "Habit: repo-coder, workspace_integrity, a read of the plugin data folder",
        "Recorded blocks per hook:",
        "- unprefixed, orchestrator: 1",
    ]
    assert _section(_text(tmp_path, notes=Notes(), records=RECORDS[:1]), "Blocks") == [
        f"Friction: {NO_NOTES}",
        f"Habit: {NO_NOTES}",
        "Recorded blocks per hook:",
        "- none",
    ]


def test_audit_log_names_the_running_session_first_and_its_totals(tmp_path: Path) -> None:
    first = SessionLog("sess-push", tmp_path / "sess-push.jsonl", RECORDS[:1])
    build = SessionLog("sess-a", tmp_path / "sess-a.jsonl", RECORDS)
    text = render(REPO, TRAIN, STATE, [first, build], parse_notes(NOTES, "n"), False, None)
    rows = _section(text, "Audit log")
    assert rows[:2] == [
        "Session sess-push: .claude/daedalus/audit/sess-push.jsonl",
        "Session sess-a: .claude/daedalus/audit/sess-a.jsonl",
    ]
    assert re.findall(r"^Session ([\w-]+):", text, re.MULTILINE)[0] == "sess-push"
    assert "### Audit totals, session sess-a" in rows
    assert "| SubagentStop | 4 |" in rows and "skipped fork stops: 0" in rows


HOSTILE = (
    "Worktree:/opt/u/.claude/rules/python.md key=/srv/x/y.md ~/proj/a/b.md \\~/proj/c.md "
    "(/var/tmp/z.md) '/etc/one' /root"
)


def _path_tokens(text: str) -> list[str]:
    # Independent of the filter: split on whitespace and every mark that can precede a path.
    tokens = re.split(r"[\s:=,;()\[\]\"'`|<>*]+", text)
    return [t.lstrip("\\") for t in tokens if t.lstrip("\\").startswith(("/", "~/"))]


def test_the_summary_carries_no_absolute_path(tmp_path: Path) -> None:
    # W3.2: a public PR body; every path in state and in agent text goes relative or to its name.
    hostile = _stop(10, "cis-specialist", f"[STATUS: COMPLIANCE] {HOSTILE}", "k1")
    notes = parse_notes(NOTES + f"## Waived\n{HOSTILE}\n", "n")
    text = _text(tmp_path, notes=notes, records=[*RECORDS, hostile])
    assert _path_tokens(text) == []
    for prefix in ("/r/", "/opt", "/srv", "/var", "/etc", "/root", "~/"):
        assert prefix not in text, prefix
    compliance = _section(text, "Compliance")[1]
    assert compliance.startswith("- cis-specialist: Worktree:python.md key=y.md b.md")


def test_public_keeps_plugin_commands_and_urls() -> None:
    line = f"see /daedalus:doctor, https://x.io/a/b, {REPO}/src/a.py and /tmp/q/z.txt:12"
    assert public(line, REPO, None) == (
        "see /daedalus:doctor, https://x.io/a/b, src/a.py and z.txt:12"
    )
    assert public(f"{CHARTER}/specs/x.md", REPO, CHARTER) == "private/specs/x.md"
    assert public(HOSTILE, REPO, None) == (
        "Worktree:python.md key=y.md b.md c.md (z.md) 'one' root"
    )
    assert _path_tokens(public("scripts/lib/a.py tests/x/y.py docs/.tmp/z", REPO, None)) == []
    assert public("scripts/lib/a.py and/or 1/2", REPO, None) == "scripts/lib/a.py and/or 1/2"


@pytest.mark.parametrize(
    "row",
    [
        "  Session evil: x",
        "\tSession evil: x",
        " \t Session evil: .claude/daedalus/audit/evil.jsonl",
    ],
)
@pytest.mark.parametrize("section", ["Rulings", "Blocks", "Waived"])
def test_an_indented_session_row_is_refused(row: str, section: str) -> None:
    with pytest.raises(SummaryError, match=re.escape("starts with `Session <id>:`")):
        parse_notes(f"Task: t\n## {section}\n{row}\n", "n")


@pytest.mark.parametrize("row", ["  ## Audit log", "\t## Audit log", "# Audit log", "### Rulings"])
def test_an_indented_or_unknown_heading_is_refused(row: str) -> None:
    with pytest.raises(SummaryError, match="opens section"):
        parse_notes(f"Task: t\n## Rulings\n{row}\n", "n")


def test_render_refuses_a_session_line_outside_the_audit_log(tmp_path: Path) -> None:
    # W3.2: a second guard after the notes check; the proof reads the first Session line.
    spoof = Notes(True, {"Task": "t"}, {"Rulings": ["Session evil: x"]})
    with pytest.raises(SummaryError, match="outside its audit log section"):
        _text(tmp_path, notes=spoof)


def test_load_logs_puts_the_running_session_first_then_the_rest_oldest_first(
    project_data: Path, hook_input: Any, repo_cwd: Path
) -> None:
    write_train_marker(repo_cwd, TRAIN)
    for at, session in enumerate(("s-run", "s-new", "s-old", "s-gone")):
        audit.audit_append(hook_input(session_id=session))
        log = audit.log_path(session, str(repo_cwd))
        os.utime(log, (100 - at, 100 - at))
    audit.log_path("s-gone", str(repo_cwd)).unlink()
    state = {"audit_bounds": {"s-gone": 1, "s-new": 1, "s-old": 1}, "audit_session": "s-new"}
    found = [log.session for log in load_logs(repo_cwd, state, "s-run")]
    assert found == ["s-run", "s-old", "s-new"]
    assert [log.session for log in load_logs(repo_cwd, state, None)] == ["s-new", "s-old"]
    assert [log.session for log in load_logs(repo_cwd, state, "../x")] == ["s-new", "s-old"]


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        ("Session s1: .claude/daedalus/audit/s1.jsonl\n", "Session <id>:"),
        ("Task: t\n## Rulings\nSession s1: x\n", "Session <id>:"),
        ("Task: t\n## Other\n", "section 'Other'"),
        ("Task: t\n## Rulings\n## Rulings\n", "section 'Rulings'"),
        ("Owner: me\n", "is not one of the lines"),
        ("Task: a\nTask: b\n", "is not one of the lines"),
        ("Codes: --repo D --type\n", "Codes line"),
    ],
)
def test_notes_refuse_lines_outside_their_shape(text: str, needle: str) -> None:
    with pytest.raises(SummaryError, match=re.escape(needle)) as info:
        parse_notes(text, "summary-notes.md")
    assert "Next:" in str(info.value)

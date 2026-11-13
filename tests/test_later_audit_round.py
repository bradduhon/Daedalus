# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0278: an audit round after a rejected one is a new auditor that reads the fix's range only.
from __future__ import annotations

from pathlib import Path

import handback_check
import pytest
from lib import train_runner, train_state

from tests.conftest import CFG, CWD, REPO_ROOT, git
from tests.hook_chain import decide
from tests.payloads import _b
from tests.test_auditor_model import PLUMBING_LINE, REASON, _check_file, _merged, _model, _run
from tests.test_fix_units import _reqs
from tests.test_records_in_one_call import SESSION, TRAIN, _hook, _ok
from tests.test_records_in_one_call import fixed as fixed  # noqa: F401

pytestmark = pytest.mark.usefixtures("isolated_env", "fixed")
AUDITOR = "daedalus:auditor"
NODE_ONE = "audit/round1/test_scope_guard.py::test_refused"
NO_TEST_ONE = "web/u2.html:1 scope"
ROW_ONE = (
    f"{NODE_ONE} high scope: x is refused | rule: x is refused at the guard | "
    "places: u1.txt:1, scripts/lib/jail.py:guard | search: git grep -n x"
)
ROW_TWO = (
    f"no-test: daedalus/{TRAIN} web/u2.html:1 medium scope: the page grew; reason: layout | "
    "rule: only listed files change | places: web/u2.html:1 | search: git diff --name-only"
)
PLACES_ROUND_ONE = [
    "u1.txt:1 | rule: x is refused at the guard",
    "scripts/lib/jail.py:guard | rule: x is refused at the guard",
    "web/u2.html:1 | rule: only listed files change",
]
NODE_TWO = "audit/round2/test_scope_guard.py::test_still_refused"
ROW_ROUND_TWO = (
    f"{NODE_TWO} high scope: x is still admitted | rule: x is refused at the guard | "
    "places: u1.txt:2 | search: git grep -n x"
)
ALL_CLASS_OK = ("U1 | Plumbing | class ok", "U2 | Plumbing | class ok")


def _tip(root: Path) -> str:
    return git(root, "rev-parse", f"daedalus/{TRAIN}").stdout.strip()


def _reply(tip: str, *rows: str) -> str:
    line = f"[VERDICT: REJECTED] tip={tip}"
    return "\n".join([line, *rows, "## Compliance", "| row | PASS |", line]) + "\n"


def _auditor_turn(root: Path, agent: str, reply: str) -> None:
    # The auditor's hand-back and its stop, through the hook writer, as one turn.
    _hook(
        root,
        hook_event_name="PostToolUse",
        tool_name="SubagentHandback",
        tool_input={"message": reply},
        agent_id=agent,
        agent_type=AUDITOR,
    )
    _hook(
        root,
        hook_event_name="SubagentStop",
        agent_id=agent,
        agent_type=AUDITOR,
        last_assistant_message=reply,
    )


def _findings(root: Path, round_: int, *rows: str) -> Path:
    path = train_runner.findings_path(root, TRAIN, round_)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{row}\n" for row in rows), encoding="utf-8")
    return path


def _verdict(root: Path, round_: int, tip: str, path: Path) -> list[str]:
    # The verdict command's own Bash record comes first, as the jail appends it.
    command = f"python3 /p/scripts/daedalus_train.py verdict --repo {root}"
    _hook(root, hook_event_name="PreToolUse", tool_name="Bash", tool_input={"command": command})
    return _ok(train_runner.record_verdict(root, "rejected", round_, tip=tip, findings=path))


def _round_one_rejected(tmp_path: Path) -> tuple[Path, str]:
    root = _merged(_run(tmp_path / "repo"), "U1", "U2")
    train_state.update(root, TRAIN, start_seq=0, audit_bounds={SESSION: 0})
    _check_file(root, *ALL_CLASS_OK)
    code, lines = _model(root)
    # Round 1 prints neither line.
    assert code == 0 and lines[:2] == ["sonnet", PLUMBING_LINE], lines
    assert not any(ln.startswith(("Range: ", "Place: ")) for ln in lines)
    judged = _tip(root)
    _auditor_turn(root, "auditor-round-1", _reply(judged, ROW_ONE, ROW_TWO))
    path = _findings(root, 1, f"{NODE_ONE} | high | scope", f"{NO_TEST_ONE} | medium | scope")
    assert _verdict(root, 1, judged, path) == ["recorded rejected round=1 findings=2"]
    return root, judged


def _fix(root: Path, uid: str, files: tuple[str, ...], fixes: str, key: str, cls: str) -> None:
    reqs = _reqs(root, f"Make `{key}` pass.")
    place = "tests/test_u1.py:test_f1" if cls != "Plumbing" else None
    reason = REASON if place else None
    fix = train_runner.FixUnit(uid, "repair", files, (fixes,), (key,), (), reqs, cls, place, reason)
    _ok(train_runner.fix_unit(root, fix))
    _merged(root, uid)


def test_a_rejected_round_records_each_place_its_auditor_named(tmp_path: Path) -> None:
    root, _ = _round_one_rejected(tmp_path)
    state = train_state.load(root, TRAIN)
    assert state[train_state.AUDIT_PLACES] == {"1": PLACES_ROUND_ONE}
    assert state[train_state.AUDITOR_MODELS] == {"1": "sonnet"}


def test_an_empty_range_is_refused_and_leaves_the_state(tmp_path: Path) -> None:
    root, _ = _round_one_rejected(tmp_path)
    before = train_state.state_path(root, TRAIN).read_bytes()
    code, lines = _model(root)
    assert code == 1 and len(lines) == 1, lines
    assert lines[0].startswith(f"daedalus/{TRAIN} has no commit since round 1 judged its tip")
    assert lines[0].count("Next:") == 1 and "merge the fix units with finish-unit" in lines[0]
    assert train_state.state_path(root, TRAIN).read_bytes() == before


def test_a_judged_tip_that_is_not_an_ancestor_is_refused_and_leaves_the_state(
    tmp_path: Path,
) -> None:
    root, judged = _round_one_rejected(tmp_path)
    side = git(root, "commit-tree", f"{judged}^{{tree}}", "-m", "side").stdout.strip()

    def rewrite(state: dict[str, object]) -> None:
        verdict = train_state.record(state, train_state.VERDICT)
        state[train_state.VERDICT] = {**verdict, "tip": side}

    train_state.change(root, TRAIN, rewrite)
    _check_file(root, *ALL_CLASS_OK)
    before = train_state.state_path(root, TRAIN).read_bytes()
    code, lines = _model(root)
    assert code == 1 and len(lines) == 1, lines
    assert f"the tip {side[:12]} round 1 judged is not an ancestor of daedalus/{TRAIN}" in lines[0]
    assert lines[0].count("Next:") == 1 and "stop the run with this line" in lines[0]
    assert train_state.state_path(root, TRAIN).read_bytes() == before


def test_round_two_reads_two_fix_units_and_a_new_auditor_passes_its_checks(
    tmp_path: Path,
) -> None:
    root, judged = _round_one_rejected(tmp_path)
    _fix(root, "fix1-u1", ("tests/test_u1.py",), "U1", NODE_ONE, "AuthN")
    _fix(root, "fix1-u2", ("web/u2.html",), "U2", NO_TEST_ONE, "Plumbing")
    _check_file(root, *ALL_CLASS_OK, "fix1-u1 | AuthN | class ok", "fix1-u2 | Plumbing | class ok")
    now = _tip(root)
    code, lines = _model(root)
    assert code == 0, lines
    # The AuthN fix unit raises round 2's auditor; each round keeps its own model.
    assert lines[0] == "opus"
    assert lines[-4:] == [f"Range: {judged}..{now}", *(f"Place: {p}" for p in PLACES_ROUND_ONE)]
    state = train_state.load(root, TRAIN)
    assert state[train_state.AUDITOR_MODELS] == {"1": "sonnet", "2": "opus"}
    merged = git(root, "log", "--format=%s", f"{judged}..{now}").stdout
    assert "Merge fix1-u1 for train" in merged and "Merge fix1-u2 for train" in merged, merged
    # A new auditor agent, never the round 1 one, replies for round 2.
    reply = _reply(now, ROW_ROUND_TWO)
    assert handback_check.findings_problem("auditor", reply, (2, 1)) is None
    _auditor_turn(root, "auditor-round-2", reply)
    path = _findings(root, 2, f"{NODE_TWO} | high | scope")
    assert _verdict(root, 2, now, path) == ["recorded rejected round=2 findings=1"]
    state = train_state.load(root, TRAIN)
    assert state[train_state.VERDICT]["round"] == 2  # type: ignore[index]
    assert state[train_state.AUDIT_PLACES]["2"] == [  # type: ignore[index]
        "u1.txt:2 | rule: x is refused at the guard"
    ]


@pytest.mark.parametrize(
    "command",
    [
        f"git -C {CWD}/.claude/worktrees/20261015-120000-audit diff {'a' * 40}..{'b' * 40}",
        f"git -C {CWD}/.claude/worktrees/20261015-120000-audit log {'a' * 40}..{'b' * 40}",
    ],
)
def test_the_auditor_may_read_a_rounds_range(command: str) -> None:
    assert decide(_b("auditor", command), CFG).allow, command


def test_the_auditor_file_carries_the_later_round_rule_in_four_sentences() -> None:
    text = (REPO_ROOT / "agents" / "auditor.md").read_text(encoding="utf-8")
    section = text.split("\n## Later round\n", 1)[1]
    rule = " ".join(section.split())
    assert "\n## " not in section and rule.count(". ") + 1 <= 4, rule
    for part in ("`Range: <sha>..<sha>`", "whether it is fixed", "Read nothing else"):
        assert part in rule, part


def test_every_later_audit_round_is_a_new_auditor_never_a_resume() -> None:
    audit = " ".join((REPO_ROOT / "skills" / "audit" / "SKILL.md").read_text().split())
    step = audit.split("5. Choose the auditor's model", 1)[1].split("### Short form", 1)[0]
    assert "A round after the first is a new `auditor` dispatch on the model" in step
    assert "`Range:` and `Place:` lines unchanged; it is never a resume (0278)" in step
    assert "resumes the same auditor" not in audit
    recovery = audit.split("### Recovery round", 1)[1]
    assert "dispatch a new `auditor` on the model step 5's command prints" in recovery
    release = " ".join((REPO_ROOT / "skills" / "release" / "SKILL.md").read_text().split())
    assert "This round is a new `auditor` dispatch on the model that command prints" in release
    orchestrator = " ".join((REPO_ROOT / "agents" / "orchestrator.md").read_text().split())
    assert "The auditor never stays warm across rounds: every audit round is a new" in orchestrator

# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0230: each composed record call leaves the run folder the call sequence it replaces leaves.
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, tzinfo
from pathlib import Path
from typing import Any

import pytest
from lib import audit, train_runner, train_state, unit_binding, workspace

from tests.conftest import REPO_ROOT, git
from tests.helpers import phase_text
from tests.test_workspace_train import LEDGER, REFUTED_REPLY, VERIFIED_REPLY

pytestmark = pytest.mark.usefixtures("isolated_env")
SESSION = "sess-fold"
TRAIN = "20261108-120000"
UNIT_ONE = (
    "unit: U1 | title: guard | files: scripts/lib/jail.py, tests/test_u1.py | base: integration"
)
UNIT_TWO = (
    "unit: U2 | title: page | files: web/u2.html | base: integration | "
    "operator_checks: The page shows the title"
)
PLAN = (
    "# plan\n\n```plan\n"
    f"{UNIT_ONE}\n{UNIT_TWO}\n"
    "edge: U1 -> U2 | kind: serial | why: U2 reads the guard U1 adds\n"
    "graph: units=2 critical_path=2 width=1 overlap_only=\n"
    "```\n"
    "\n### U1: guard\n\nScope: the jail only.\n\nRequirements:\n1. Refuse x.\n2. Admit y.\n"
    "\n### U2: page\n\nRequirements:\n1. Write `web/u2.html`.\n"
)
SECTIONS = {
    "U1": "### U1: guard\n\nScope: the jail only.\n\nRequirements:\n1. Refuse x.\n2. Admit y.",
    "U2": "### U2: page\n\nRequirements:\n1. Write `web/u2.html`.",
}
CONTRACT = "packet v1\n"
STANDARDS = "## Standards Packet\n- a rule\n\nPick ledger ids: pick 1 = 0101-DAE-PLT\n"
COLD_U1 = ("a cold coder for unit U1, parallel", "a warm resume")
COLD_COST = "the coder reads its brief and files from empty"
HEX40 = "[0-9a-f]{40}"
NOTES = [
    "Deviation: U1 kept its warm coder after a friction row (choice record).",
    "Friction: coder, the git grammar, git revert in a unit worktree was refused.",
]


class _Clock(datetime):
    @classmethod
    def now(cls, tz: tzinfo | None = None) -> _Clock:
        return cls(2026, 11, 8, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def fixed(monkeypatch: pytest.MonkeyPatch) -> None:
    # 0230: one train id and fixed git dates, so two fixture copies make the same shas.
    monkeypatch.setattr(workspace, "datetime", _Clock)
    for key in ("GIT_AUTHOR_DATE", "GIT_COMMITTER_DATE"):
        monkeypatch.setenv(key, "2026-11-08T12:00:00+00:00")


def _scratch(root: Path) -> Path:
    return root / "docs" / ".tmp" / "daedalus" / TRAIN


def _fixture(root: Path) -> Path:
    # 0230: a locked run with a recorded plan, a Standards Packet and an audit session.
    root.mkdir(parents=True)
    git(root, "init", "-q", "-b", "main")
    data = root / ".claude" / "daedalus"
    data.mkdir(parents=True)
    (data / ".gitignore").write_text("*\n")
    (root / "docs").mkdir()
    (root / "docs" / "decisions.md").write_text(LEDGER)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "init")
    assert workspace.begin(root)[0].startswith(f"train: {TRAIN} ")
    (root / "contracts").mkdir()
    (root / "contracts" / "api.md").write_text(CONTRACT)
    workspace.lock(root, "contracts/api.md", 1)
    _scratch(root).mkdir()
    (_scratch(root) / "plan.md").write_text(PLAN)
    (_scratch(root) / "standards-packet.md").write_text(STANDARDS)
    assert train_runner.record_plan(root, _scratch(root) / "plan.md").code == 0
    train_state.update(root, TRAIN, audit_session=SESSION)
    _hook(root, hook_event_name="SessionStart")
    return root


def _pair(tmp_path: Path) -> tuple[Path, Path]:
    return _fixture(tmp_path / "seq" / "repo"), _fixture(tmp_path / "one" / "repo")


def _snapshot(root: Path) -> dict[str, str]:
    # 0230: the run folder, the train state and bindings, the refs and the operator view.
    shot: dict[str, str] = {}
    for folder in (root / train_state.STATE_DIR, _scratch(root)):
        for path in sorted(folder.rglob("*")):
            if path.is_file() and not path.name.endswith(".lock"):
                text = path.read_text(encoding="utf-8")
                shot[path.relative_to(root).as_posix()] = text.replace(str(root), "<repo>")
    refs = git(root, "for-each-ref", "--format=%(refname) %(objectname)").stdout
    trees = git(root, "worktree", "list", "--porcelain").stdout.replace(str(root), "<repo>")
    shot["refs"], shot["worktrees"] = refs, trees
    shot["progress"] = "\n".join(train_runner.progress(root).lines)
    return shot


def _skill_line(name: str, pattern: str) -> str:
    found = re.search(pattern, (REPO_ROOT / "skills" / name / "SKILL.md").read_text())
    assert found is not None, pattern
    return found.group(1)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _packs(*names: str) -> str:
    return "Packs: " + ", ".join(f"{REPO_ROOT}/packs/coder/{n}/rules.md" for n in names)


def _hand_brief(root: Path, uid: str, path: Path, packs: str | None) -> Path:
    # build step 4, written from the recipe text alone: the brief the dispatch call must match.
    standards = _scratch(root) / "standards-packet.md"
    head = [
        f"Contract: {root}/contracts/api.md sha256={_sha(root / 'contracts' / 'api.md')}",
        f"Standards: {standards} sha256={_sha(standards)}",
        "Pick ledger ids: pick 1 = 0101-DAE-PLT",
        f"Worktree: {path}",
    ]
    if packs is not None:
        head.append(_skill_line("build", r"`(Scope: [^`]+)`"))
        head.append(_skill_line("build", r"\n   - (Hunt: [^\n]+)"))
        head.append(packs)
    priorities = _skill_line("build", r"`(Priorities: [^`]+)`").replace(
        "<standards packet path>", str(standards)
    )
    reminder = _skill_line("build", r'this reminder: "([^"]+)"').replace("<path>", str(path))
    brief = _scratch(root) / "briefs" / f"{uid.lower()}.md"
    brief.parent.mkdir(parents=True, exist_ok=True)
    body = "\n\n".join(["\n".join(head), SECTIONS[uid], priorities, reminder]) + "\n"
    brief.write_text(body, encoding="utf-8")
    return brief


def _hand_dispatch(
    root: Path, uid: str, chose: tuple[str, str], cost: str, packs: str | None
) -> Path:
    # build steps 1, 2, 4 and 5 as four separate calls.
    assert train_runner.choice(root, chose[0], chose[1], cost).code == 0
    path = workspace.create(root, f"{TRAIN}-{uid.lower()}", f"daedalus/{TRAIN}")
    assert train_runner.coder_model(root, uid).code == 0
    _hand_brief(root, uid, path, packs)
    return path


def _hook(root: Path, **fields: Any) -> None:
    assert audit.audit_append({"session_id": SESSION, "cwd": str(root), **fields}) is not None


def _verdict(root: Path, path: Path, reply: str) -> None:
    prompt = f"Check every claim.\nUnit worktree: {path}\n"
    tool_input = {"subagent_type": "daedalus:verifier", "prompt": prompt}
    _hook(root, hook_event_name="PreToolUse", tool_name="Agent", tool_input=tool_input)
    _hook(
        root,
        hook_event_name="SubagentStop",
        agent_id="agent-verifier",
        agent_type="daedalus:verifier",
        last_assistant_message=reply,
    )


def _built(root: Path, uid: str) -> Path:
    # 0230: the unit's coder committed one file in its worktree.
    path = root / ".claude" / "worktrees" / f"{TRAIN}-{uid.lower()}"
    (path / f"{uid.lower()}.txt").write_text("x\n")
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", f"build {uid}")
    return path


def _ok(outcome: train_runner.Outcome) -> list[str]:
    assert outcome.code == 0, outcome.lines
    return outcome.lines


@pytest.mark.usefixtures("fixed")
def test_dispatch_leaves_what_choice_create_model_and_the_brief_leave(tmp_path: Path) -> None:
    seq, one = _pair(tmp_path)
    shell = _packs("secure-architecture", "adversarial-coding", "shell-semantics")
    path = _hand_dispatch(seq, "U1", COLD_U1, COLD_COST, shell)
    lines = _ok(train_runner.dispatch_unit(one, "U1"))
    assert _snapshot(seq) == _snapshot(one)
    brief = _scratch(one) / "briefs" / "u1.md"
    worktree = str(path).replace(str(seq), str(one))
    assert lines[0] == f"dispatch U1: model=opus worktree={worktree} brief={brief} rows=needed"
    contract = f"{one}/contracts/api.md"
    lock = str(train_state.load(one, TRAIN)["lock_sha"])
    assert lines[1:-1] == [
        "ROWS MODE.",
        f"Unit worktree: {worktree}",
        f"Brief: {brief}",
        f"Spec: {contract}",
        shell,
        f"Base: {lock}",
    ]
    assert lines[-1] in phase_text("verify")


@pytest.mark.usefixtures("fixed")
def test_dispatch_of_a_unit_outside_the_class_prints_one_line(tmp_path: Path) -> None:
    seq, one = _pair(tmp_path)
    warm = ("a warm resume of coder agent-u1 for unit U2, serial after U1", "a cold coder")
    _hand_dispatch(seq, "U2", warm, "the coder keeps the context of the unit it built", None)
    lines = _ok(train_runner.dispatch_unit(one, "U2", "agent-u1"))
    assert _snapshot(seq) == _snapshot(one)
    shape = rf"dispatch U2: model=sonnet worktree={one}/\S+-u2 brief=\S+/briefs/u2\.md rows=none"
    assert len(lines) == 1 and re.fullmatch(shape, lines[0]), lines


def _routed_pair(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    seq, one = _pair(tmp_path)
    for root in (seq, one):
        _ok(train_runner.dispatch_unit(root, "U1"))
        assert unit_binding.record_dispatch(root, TRAIN, f"{TRAIN}-u1") is None
        assert unit_binding.claim(root, TRAIN, "agent-opus", f"{TRAIN}-u1") is None
    return seq, one, _built(seq, "U1"), _built(one, "U1")


@pytest.mark.usefixtures("fixed")
def test_route_leaves_what_refuted_model_and_choice_leave(tmp_path: Path) -> None:
    seq, one, seq_path, one_path = _routed_pair(tmp_path)
    fix = ("a fix pass by unit U1's own coder", "a fresh coder")
    fix_cost = "one warm fix pass; the coder keeps its context"
    fresh = (
        "a fresh coder on the escalated model for unit U1",
        "another fix pass by its own coder",
    )
    fresh_cost = "the fresh coder reads the brief, the unit's commits and the verifier's rows"
    for count, (chose, cost, word) in enumerate(
        [(fix, fix_cost, "fix"), (fresh, fresh_cost, "fresh")], start=1
    ):
        _verdict(seq, seq_path, REFUTED_REPLY)
        _verdict(one, one_path, REFUTED_REPLY)
        assert _ok(train_runner.refuted(seq, "U1")) == [f"refuted U1: {count}"]
        _ok(train_runner.coder_model(seq, "U1"))
        _ok(train_runner.choice(seq, chose[0], chose[1], cost))
        line = _ok(train_runner.route_unit(one, "U1", "REFUTED"))
        assert line == [f"route U1: {word} model=opus refutations={count} checks=0"]
        assert _snapshot(seq) == _snapshot(one)
    # verify step 5: the third refutation goes to the operator, with no choice recorded.
    _verdict(one, one_path, REFUTED_REPLY)
    before = _snapshot(one)
    line = _ok(train_runner.route_unit(one, "U1", "REFUTED"))
    assert line == ["route U1: operator model=opus refutations=3 checks=0"]
    after = _snapshot(one)
    state = f".claude/daedalus/trains/{TRAIN}.json"
    assert {k for k in before if before[k] != after[k]} == {state}
    unit = train_state.units(train_state.load(one, TRAIN))[0]
    assert len(unit["refutations"]) == 3 and len(unit["coders"]) == 2  # type: ignore[arg-type]


@pytest.mark.usefixtures("fixed")
def test_route_of_a_red_rows_file_records_a_fix_pass_and_no_refutation(tmp_path: Path) -> None:
    seq, one, _, _ = _routed_pair(tmp_path)
    _ok(train_runner.coder_model(seq, "U1"))
    chose = "a fix pass by unit U1's own coder on 2 failing rows"
    cost = "one warm fix pass before any verifier turn"
    _ok(train_runner.choice(seq, chose, "a verifier dispatch", cost))
    line = _ok(train_runner.route_unit(one, "U1", "REFUTED", rows=2))
    assert line == ["route U1: fix model=opus refutations=0 checks=0"]
    assert _snapshot(seq) == _snapshot(one)
    assert train_state.units(train_state.load(one, TRAIN))[0].get("refutations") is None


@pytest.mark.usefixtures("fixed")
def test_route_verified_lists_the_operator_checks(tmp_path: Path) -> None:
    root = _fixture(tmp_path / "repo")
    manifest = {"dev_server": {"url": "http://localhost:5173", "check": "The scene loads"}}
    (root / "service-manifest.json").write_text(json.dumps(manifest))
    _ok(train_runner.dispatch_unit(root, "U2"))
    _verdict(root, _built(root, "U2"), VERIFIED_REPLY)
    lines = _ok(train_runner.route_unit(root, "U2", "VERIFIED"))
    assert lines == [
        "route U2: verified model=sonnet refutations=0 checks=2",
        "operator check | http://localhost:5173 | The page shows the title",
        "operator check | http://localhost:5173 | The scene loads",
    ]


def test_constants_match_the_recipe_text() -> None:
    build, verify = phase_text("build"), phase_text("verify")
    assert f"   - {train_runner.HUNT_LINE}\n" in build
    assert f"`{train_runner.SCOPE_LINE}`" in build
    assert train_runner.REMINDER.replace("{path}", "<path>") in build
    assert train_runner.ROWS_ASK in verify
    listed = _skill_line("build", r"files list may hold any of ([^\n]+?) \(0226\)")
    named = re.findall(r"`([^`]+)`", listed)
    assert tuple(named) == train_runner.CLASS_FILES

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
from lib import audit, jail, train_runner, train_state, unit_binding, workspace
from lib.train_summary import parse_notes

from tests.conftest import CFG, CWD, REPO_ROOT, git, run_cli
from tests.helpers import phase_text
from tests.hook_chain import decide
from tests.payloads import _b
from tests.test_workspace_train import LEDGER, REFUTED_REPLY, VERIFIED_REPLY, keyed

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
    assert train_runner.unit_model(root, "coder", uid).code == 0
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
        last_assistant_message=keyed(reply, path),
    )


def _built(root: Path, uid: str) -> Path:
    # 0230: the unit's coder committed one file in its worktree.
    path = root / ".claude" / "worktrees" / f"{TRAIN}-{uid.lower()}"
    (path / f"{uid.lower()}.txt").write_text("x\n")
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", f"build {uid}")
    # 0271: the coder's COMPLETE line names the locked contract, as the merge gate reads it.
    contract = hashlib.sha256(CONTRACT.encode()).hexdigest()[:12]
    line = (
        f"[STATUS: COMPLETE] branch=daedalus-unit/{TRAIN}-{uid.lower()} packet_version=1 "
        f"files={uid.lower()}.txt tests=1 passed ledger_notes=none contract={contract}"
    )
    _hook(
        root,
        hook_event_name="SubagentStop",
        agent_id=f"agent-coder-{uid.lower()}",
        agent_type="daedalus:coder",
        last_assistant_message=line,
    )
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
    assert lines[0] == f"dispatch U1: model=sonnet worktree={worktree} brief={brief} rows=needed"
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
    # 0267: the first and the second refutation are each a warm fix pass on the unit's model.
    for count in (1, 2):
        _verdict(seq, seq_path, REFUTED_REPLY)
        _verdict(one, one_path, REFUTED_REPLY)
        assert _ok(train_runner.refuted(seq, "U1")) == [f"refuted U1: {count}"]
        _ok(train_runner.unit_model(seq, "coder", "U1"))
        _ok(train_runner.choice(seq, fix[0], fix[1], fix_cost))
        line = _ok(train_runner.route_unit(one, "U1", "REFUTED"))
        assert line == [f"route U1: fix model=sonnet refutations={count} checks=0"]
        assert _snapshot(seq) == _snapshot(one)
    # verify step 5: the third refutation goes to the operator, with no choice recorded.
    _verdict(one, one_path, REFUTED_REPLY)
    before = _snapshot(one)
    line = _ok(train_runner.route_unit(one, "U1", "REFUTED"))
    assert line == ["route U1: operator model=sonnet refutations=3 checks=0"]
    after = _snapshot(one)
    state = f".claude/daedalus/trains/{TRAIN}.json"
    assert {k for k in before if before[k] != after[k]} == {state}
    unit = train_state.units(train_state.load(one, TRAIN))[0]
    assert len(unit["refutations"]) == 3 and len(unit["coders"]) == 1  # type: ignore[arg-type]


@pytest.mark.usefixtures("fixed")
def test_route_of_a_red_rows_file_records_a_fix_pass_and_no_refutation(tmp_path: Path) -> None:
    seq, one, _, _ = _routed_pair(tmp_path)
    _ok(train_runner.unit_model(seq, "coder", "U1"))
    chose = "a fix pass by unit U1's own coder on 2 failing rows"
    cost = "one warm fix pass before any verifier turn"
    _ok(train_runner.choice(seq, chose, "a verifier dispatch", cost))
    line = _ok(train_runner.route_unit(one, "U1", "REFUTED", rows=2))
    assert line == ["route U1: fix model=sonnet refutations=0 checks=0"]
    assert _snapshot(seq) == _snapshot(one)
    assert train_state.units(train_state.load(one, TRAIN))[0].get("refutations") is None


@pytest.mark.usefixtures("fixed")
def test_route_verified_lists_the_operator_checks(tmp_path: Path) -> None:
    root = _fixture(tmp_path / "repo")
    site = {"url": "http://localhost:5173", "instructions": "The scene loads"}
    manifest = {"local_testing": site}
    (root / "service-manifest.json").write_text(json.dumps(manifest))
    _ok(train_runner.dispatch_unit(root, "U2"))
    _verdict(root, _built(root, "U2"), VERIFIED_REPLY)
    lines = _ok(train_runner.route_unit(root, "U2", "VERIFIED"))
    assert lines == [
        "route U2: verified model=sonnet refutations=0 checks=2",
        "operator check | http://localhost:5173 | The page shows the title",
        "operator check | http://localhost:5173 | The scene loads",
    ]


def _coder_commits(path: Path, name: str) -> str:
    (path / name).write_text("late\n")
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", f"late {name}")
    return git(path, "rev-parse", "HEAD").stdout.strip()


@pytest.mark.usefixtures("fixed")
def test_a_coder_commit_after_the_verified_route_is_refused_at_the_merge(tmp_path: Path) -> None:
    # 77: route records the tip the VERIFIED reply judged; the merge refuses a tip that moved.
    root = _fixture(tmp_path / "repo")
    _ok(train_runner.dispatch_unit(root, "U1"))
    path = _built(root, "U1")
    judged = git(path, "rev-parse", "HEAD").stdout.strip()
    _verdict(root, path, VERIFIED_REPLY)
    _ok(train_runner.route_unit(root, "U1", "VERIFIED"))
    tips = train_state.units(train_state.load(root, TRAIN))[0][workspace.VERIFIED_TIPS]
    assert list(tips.values()) == [judged]  # type: ignore[union-attr]
    moved = _coder_commits(path, "late.txt")
    # 77: a second route on the same reply keeps the first tip.
    _ok(train_runner.route_unit(root, "U1", "VERIFIED"))
    before = _snapshot(root)
    refused = train_runner.finish_unit(root, "U1")
    assert refused.code == 1, refused.lines
    said = "\n".join(refused.lines)
    assert f"branch moved to {moved[:12]} after its VERIFIED reply at seq " in said
    assert f"judged {judged[:12]}" in said and said.count("Next:") == 1
    assert _snapshot(root) == before and path.is_dir()
    # 77: the verifier reads the new tip, route records it, and the merge takes the unit.
    _verdict(root, path, VERIFIED_REPLY)
    _ok(train_runner.route_unit(root, "U1", "VERIFIED"))
    line = _ok(train_runner.finish_unit(root, "U1"))
    assert len(line) == 1 and re.fullmatch(rf"finish U1: merged={HEX40} next=none", line[0])
    assert git(root, "merge-base", "--is-ancestor", moved, f"daedalus/{TRAIN}").returncode == 0


@pytest.mark.usefixtures("fixed")
def test_a_wave_merge_refuses_a_unit_whose_tip_moved_after_its_verified_route(
    tmp_path: Path,
) -> None:
    # 77: the one-unit wave merge shares the gate while another unit still builds.
    root = _fixture(tmp_path / "repo")
    _ok(train_runner.dispatch_unit(root, "U1"))
    _ok(train_runner.dispatch_unit(root, "U2"))
    path = _built(root, "U1")
    _verdict(root, path, VERIFIED_REPLY)
    _ok(train_runner.route_unit(root, "U1", "VERIFIED"))
    _built(root, "U2")
    _coder_commits(path, "late.txt")
    base = git(root, "rev-parse", f"daedalus/{TRAIN}").stdout.strip()
    with pytest.raises(workspace.WorkspaceError, match="after its VERIFIED reply"):
        workspace.merge(root, ["U1"])
    assert git(root, "rev-parse", f"daedalus/{TRAIN}").stdout.strip() == base


@pytest.mark.usefixtures("fixed")
def test_a_run_with_no_judged_tip_on_record_still_merges_and_is_told(tmp_path: Path) -> None:
    # 77: a run recorded before the route kept a tip merges as before, with one line saying so.
    root = _fixture(tmp_path / "repo")
    _ok(train_runner.dispatch_unit(root, "U1"))
    _ok(train_runner.dispatch_unit(root, "U2"))
    path = _built(root, "U1")
    _verdict(root, path, VERIFIED_REPLY)
    tip = git(path, "rev-parse", "HEAD").stdout.strip()
    _built(root, "U2")
    lines = _ok(train_runner.finish_unit(root, "U1"))
    assert re.fullmatch(rf"finish U1: merged={HEX40} next=none", lines[0]), lines
    told = re.fullmatch(
        r"no judged tip: unit u1 merged on its VERIFIED reply at seq \d+ with no judged tip on "
        r"record, as in a run recorded before issue 77\. Its tip (\w+) was not compared\.",
        lines[1],
    )
    assert len(lines) == 2 and told is not None and told.group(1) == tip[:12], lines


@pytest.mark.usefixtures("fixed")
def test_finish_unit_leaves_what_finish_notes_and_the_next_dispatch_leave(
    tmp_path: Path,
) -> None:
    seq, one = _pair(tmp_path)
    for root in (seq, one):
        _ok(train_runner.dispatch_unit(root, "U1"))
        _verdict(root, _built(root, "U1"), VERIFIED_REPLY)
        # 77: verify step 5 routes the verdict, which records the judged tip, before the merge.
        _ok(train_runner.route_unit(root, "U1", "VERIFIED"))
    workspace.finish(seq)
    notes = "## Rulings\n" + NOTES[0] + "\n## Blocks\n" + NOTES[1] + "\n"
    (_scratch(seq) / "summary-notes.md").write_text(notes, encoding="utf-8")
    warm = ("a warm resume of coder agent-u1 for unit U2, serial after U1", "a cold coder")
    _hand_dispatch(seq, "U2", warm, "the coder keeps the context of the unit it built", None)
    lines = _ok(train_runner.finish_unit(one, "u1", "U2", NOTES, "agent-u1"))
    assert _snapshot(seq) == _snapshot(one)
    shape = rf"finish u1: merged={HEX40} next=U2 dispatch U2: model=sonnet \S+ \S+ rows=none"
    assert len(lines) == 1 and re.fullmatch(shape, lines[0]), lines
    sha = git(one, "rev-parse", f"daedalus/{TRAIN}").stdout.strip()
    assert f"merged={sha} " in lines[0]


@pytest.mark.usefixtures("fixed")
def test_finish_unit_merges_one_unit_while_another_still_builds(tmp_path: Path) -> None:
    root = _fixture(tmp_path / "repo")
    _ok(train_runner.dispatch_unit(root, "U1"))
    _ok(train_runner.dispatch_unit(root, "U2"))
    _verdict(root, _built(root, "U1"), VERIFIED_REPLY)
    u2 = _built(root, "U2")
    line = _ok(train_runner.finish_unit(root, "U1"))
    assert re.fullmatch(rf"finish U1: merged={HEX40} next=none", line[0]), line
    assert u2.is_dir() and train_state.load(root, TRAIN)["merged"] is False


@pytest.mark.usefixtures("fixed")
def test_finish_unit_refreshes_a_recorded_audit_worktree(tmp_path: Path) -> None:
    root = _fixture(tmp_path / "repo")
    audit_path = workspace.create(root, f"{TRAIN}-audit", f"daedalus/{TRAIN}")
    _ok(train_runner.dispatch_unit(root, "U1"))
    _verdict(root, _built(root, "U1"), VERIFIED_REPLY)
    line = _ok(train_runner.finish_unit(root, "U1"))
    sha = line[0].split("merged=")[1].split()[0]
    assert git(audit_path, "rev-parse", "HEAD").stdout.strip() == sha


@pytest.mark.usefixtures("fixed")
def test_finish_unit_refuses_a_fix_unit_while_another_waits(tmp_path: Path) -> None:
    # 0121: a fix unit is outside the plan, so it merges only by the finish, last of its round.
    root = _fixture(tmp_path / "repo")
    _ok(train_runner.dispatch_unit(root, "U1"))
    _built(root, "U1")
    fix = workspace.create(root, f"{TRAIN}-fix1-u1", f"daedalus/{TRAIN}")
    (fix / "f.txt").write_text("f\n")
    git(fix, "add", "-A")
    git(fix, "commit", "-q", "-m", "fix")
    refused = train_runner.finish_unit(root, "fix1-u1")
    assert refused.code == 1 and "not a unit of the recorded plan, and u1" in refused.lines[0]
    assert "Next:" in refused.lines[0] and fix.is_dir()


@pytest.mark.usefixtures("fixed")
def test_dispatch_refuses_a_unit_that_already_merged(tmp_path: Path) -> None:
    root = _fixture(tmp_path / "repo")
    _ok(train_runner.dispatch_unit(root, "U1"))
    _verdict(root, _built(root, "U1"), VERIFIED_REPLY)
    _ok(train_runner.finish_unit(root, "U1"))
    again = train_runner.dispatch_unit(root, "U1")
    assert again.code == 1 and "is gone" in again.lines[0] and "Next:" in again.lines[0]


def test_notes_land_in_their_section_of_an_existing_file(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    path = root / "docs" / ".tmp" / "daedalus" / TRAIN / "summary-notes.md"
    path.parent.mkdir(parents=True)
    path.write_text("Task: t\n## Blocks\nFriction: none\n\n## Waived\nNone.\n")
    placed = train_runner._note_lines(NOTES)
    train_runner._append_notes(root, TRAIN, placed)
    text = path.read_text()
    assert text == (
        f"Task: t\n## Rulings\n{NOTES[0]}\n## Blocks\nFriction: none\n{NOTES[1]}\n\n"
        "## Waived\nNone.\n"
    )
    assert parse_notes(text, "notes").sections["Rulings"] == [NOTES[0]]
    with pytest.raises(train_runner.RunnerError, match="Next:"):
        train_runner._note_lines(["Summary: anything"])


def _cli(root: Path, *args: str) -> tuple[int, str]:
    done = run_cli("daedalus_train.py", *args, "--repo", str(root), cwd=root)
    return done.returncode, done.stdout


@pytest.mark.usefixtures("fixed")
@pytest.mark.parametrize(
    "args",
    [
        ("dispatch", "--unit", "U9"),
        ("route", "--unit", "U1", "--verdict", "VERIFIED"),
        ("route", "--unit", "U1", "--verdict", "REFUTED"),
        ("route", "--unit", "U1", "--verdict", "REFUTED", "--rows", "0"),
        ("finish-unit", "--unit", "U1"),
        ("finish-unit", "--unit", "U1", "--warm", "agent-u1"),
        ("finish-unit", "--unit", "U1", "--note", "Summary: x"),
    ],
)
def test_a_refused_composed_call_exits_1_with_a_next_line(
    tmp_path: Path, args: tuple[str, ...]
) -> None:
    root = _fixture(tmp_path / "repo")
    _ok(train_runner.dispatch_unit(root, "U1"))
    _built(root, "U1")
    code, out = _cli(root, *args)
    assert code == 1 and "Next:" in out, out


SUBCOMMANDS = (
    "dispatch --unit U1",
    "route --unit U1 --verdict REFUTED",
    "finish-unit --unit U1 --next U2",
)
REFUSED = (
    "auditor",
    "charter-docs",
    "coder",
    "comparer",
    "contract-spec",
    "planner",
    "releaser",
    "verifier",
    "web-researcher",
    "writer",
)


@pytest.mark.parametrize("sub", SUBCOMMANDS)
def test_the_main_session_and_the_orchestrator_alone_run_the_composed_calls(
    marked_repo: Path, sub: str
) -> None:
    # 0230: admitted where choice and model are, refused for every other agent class.
    script = f"python3 {REPO_ROOT}/scripts/daedalus_train.py"
    for form in (sub, "choice --chose a --over b --cost c", "model --agent coder --unit U1"):
        assert jail.admitted(f"{script} {form} --repo {marked_repo}", "main", str(marked_repo))
        assert decide(_b("orchestrator", f"{script} {form} --repo {CWD}"), CFG).allow, form
    command = f"{script} {sub} --repo {CWD}"
    for agent in REFUSED:
        assert not decide(_b(agent, command), CFG).allow, agent


def test_constants_match_the_recipe_text() -> None:
    build, verify = phase_text("build"), phase_text("verify")
    assert f"   - {train_runner.HUNT_LINE}\n" in build
    assert f"`{train_runner.SCOPE_LINE}`" in build
    assert train_runner.REMINDER.replace("{path}", "<path>") in build
    assert train_runner.ROWS_ASK in verify
    listed = _skill_line("build", r"files list may hold any of ([^\n]+?) \(0226\)")
    named = re.findall(r"`([^`]+)`", listed)
    assert tuple(named) == train_runner.CLASS_FILES


def test_the_recipe_steps_make_one_call_each() -> None:
    build, verify = phase_text("build"), phase_text("verify")
    plugin = "python3 <plugin root>/scripts/daedalus_train.py"
    assert f"`{plugin} dispatch --repo <repo> --unit <unit id>`" in build
    assert f"`{plugin} finish-unit --repo <repo> --unit <unit id>`" in build
    assert f"`{plugin} route --repo <repo> --unit <unit id> --verdict REFUTED --rows <n>`" in build
    assert f"`{plugin} route --repo <repo> --unit <unit id> --verdict REFUTED`" in verify
    assert f"`{plugin} route --repo <repo> --unit <unit id> --verdict VERIFIED`" in verify
    for text in (build, verify):
        assert "State Block row" in text

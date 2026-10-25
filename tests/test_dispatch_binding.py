# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import hashlib
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from lib import dispatch_binding, jail, train_state
from lib.config import Config
from lib.unit_binding import bindings_path, claim
from lib.workspace import create, mark_train

from tests.conftest import git as _git
from tests.conftest import main_warning
from tests.hook_chain import judge as decide

TRAIN = "20261016-120000"
OTHER = "20261015-090000"
CODER = "daedalus:repo-coder"
PLANS = Path(__file__).resolve().parent / "fixtures" / "plans"
VALID = PLANS / "valid.md"
NEXT = "Next: run /daedalus:plan"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def plan_file(repo: Path, folder: str, source: Path = VALID) -> Path:
    path = repo / "docs" / ".tmp" / "daedalus" / folder / "plan.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, path)
    return path


def record_plan(repo: Path, train: str, path: str, sha256: object) -> None:
    train_state.update(repo, train, plan={"path": path, "sha256": sha256})


def seed_plan(repo: Path, train: str, source: Path = VALID) -> Path:
    # spec 4.1: a coder dispatch during a train needs this record; A4 writes it in a live train.
    path = plan_file(repo, train, source)
    record_plan(repo, train, str(path), _sha(path))
    return path


@pytest.fixture
def unit(repo_cwd: Path, project_data: Path) -> Path:
    ident = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    _git(repo_cwd, *ident, "commit", "-q", "--allow-empty", "-m", "base")
    _git(repo_cwd, "branch", f"daedalus/{TRAIN}")
    train_state.save(repo_cwd, TRAIN, {"train_id": TRAIN})
    mark_train(repo_cwd, TRAIN)
    made = create(repo_cwd, "u1", f"daedalus/{TRAIN}")
    jail._registered_worktrees.cache_clear()
    return made


def _dispatch(repo: Path, worktree: Path, subagent: str = CODER) -> dict[str, Any]:
    prompt = f"Build the unit.\nWorktree: {worktree}\n"
    tool_input = {"description": "unit", "prompt": prompt, "subagent_type": subagent}
    return {"tool_name": "Agent", "tool_input": tool_input, "cwd": str(repo), "session_id": "s"}


def _ok(repo: Path, worktree: Path) -> None:
    d = decide(_dispatch(repo, worktree), Config())
    assert d.allow, d.reason


def _refused(repo: Path, worktree: Path, *needles: str) -> str:
    d = decide(_dispatch(repo, worktree), Config())
    assert not d.allow
    reason = str(d.reason)
    assert NEXT in reason and all(n in reason for n in needles), reason
    assert not bindings_path(repo, TRAIN).exists(), "a refused dispatch is never recorded"
    return reason


def test_coder_dispatch_without_a_plan_record_is_refused(repo_cwd: Path, unit: Path) -> None:
    _refused(repo_cwd, unit, "records no plan")
    seed_plan(repo_cwd, TRAIN)
    _ok(repo_cwd, unit)


def test_coder_dispatch_with_a_stale_plan_hash_is_refused(repo_cwd: Path, unit: Path) -> None:
    path = seed_plan(repo_cwd, TRAIN)
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\nA late edit.\n")
    _refused(repo_cwd, unit, "changed after it was recorded")


def test_plan_hash_is_over_the_file_bytes(repo_cwd: Path, unit: Path) -> None:
    # spec 4.1: prose outside the fenced block still moves the hash.
    path = seed_plan(repo_cwd, TRAIN)
    path.write_text(path.read_text(encoding="utf-8").replace("for the reader", "for anyone"))
    _refused(repo_cwd, unit, "changed after it was recorded")
    text = path.read_text(encoding="utf-8")
    block = text[text.index("```plan") : text.rindex("```") + 3]
    record_plan(repo_cwd, TRAIN, str(path), hashlib.sha256(block.encode()).hexdigest())
    _refused(repo_cwd, unit, "changed after it was recorded")
    record_plan(repo_cwd, TRAIN, str(path), _sha(path))
    _ok(repo_cwd, unit)


@pytest.mark.parametrize(
    ("source", "needle"),
    [
        ("graph_mismatch.md", "the graph line says"),
        ("serial_cycle.md", "cycle"),
        ("unit_without_files.md", "lists no files"),
    ],
)
def test_coder_dispatch_with_an_invalid_plan_is_refused(
    repo_cwd: Path, unit: Path, source: str, needle: str
) -> None:
    seed_plan(repo_cwd, TRAIN, PLANS / source)
    _refused(repo_cwd, unit, "defect", needle)


def test_plan_validates_against_the_trains_builder_limit(repo_cwd: Path, unit: Path) -> None:
    # spec 4.1: valid.md declares width=3, which a two-builder train computes as 2.
    seed_plan(repo_cwd, TRAIN)
    train_state.update(repo_cwd, TRAIN, max_concurrent_builders=2)
    _refused(repo_cwd, unit, "width=2")


def test_coder_dispatch_with_a_valid_plan_is_allowed(repo_cwd: Path, unit: Path) -> None:
    seed_plan(repo_cwd, TRAIN)
    _ok(repo_cwd, unit)
    assert bindings_path(repo_cwd, TRAIN).exists(), "the allowed dispatch is recorded"


def test_non_coder_dispatch_needs_no_plan(repo_cwd: Path, unit: Path) -> None:
    for agent in ("daedalus:security-auditor", "daedalus:charter-docs", "Explore"):
        d = decide(_dispatch(repo_cwd, unit, agent), Config())
        assert d.allow, (agent, d.reason)


@pytest.mark.parametrize(
    ("subagent", "gated"),
    [
        (CODER, True),
        ("repo-coder", True),
        ("daedalus-probe:repo-coder", True),
        ("other:repo-coder", True),
        ("daedalus:x:repo-coder", True),
        ("daedalus:repo-coder-x", False),
    ],
)
def test_coder_plan_gate_fails_closed_on_any_namespace(
    repo_cwd: Path, unit: Path, subagent: str, gated: bool
) -> None:
    # issue 29: a repo-coder under any namespace meets the coder plan gate.
    tool_input = _dispatch(repo_cwd, unit, subagent)["tool_input"]
    reason = dispatch_binding._dispatch_reason(tool_input, str(repo_cwd))
    assert (reason is not None and "records no plan" in reason) is gated, reason


@pytest.mark.parametrize(
    ("subagent", "binds"),
    [(CODER, True), ("repo-coder", True), ("other:repo-coder", False)],
)
def test_only_the_train_scope_namespace_records_a_binding(
    repo_cwd: Path, unit: Path, subagent: str, binds: bool
) -> None:
    # W1.3: train_scope's namespace check decides which coder dispatch binds a unit.
    seed_plan(repo_cwd, TRAIN)
    tool_input = _dispatch(repo_cwd, unit, subagent)["tool_input"]
    assert dispatch_binding._dispatch_reason(tool_input, str(repo_cwd)) is None
    assert bindings_path(repo_cwd, TRAIN).exists() is binds


@pytest.mark.parametrize(
    ("bound", "needle"),
    [(True, "is bound to coder agent-1"), (False, "was already dispatched to a coder")],
)
def test_a_foreign_coder_meets_the_once_check(
    repo_cwd: Path, unit: Path, bound: bool, needle: str
) -> None:
    # issue 29: a unit a Daedalus coder holds refuses a coder under any namespace.
    seed_plan(repo_cwd, TRAIN)
    ours = _dispatch(repo_cwd, unit)["tool_input"]
    assert dispatch_binding._dispatch_reason(ours, str(repo_cwd)) is None
    if bound:
        assert claim(repo_cwd, TRAIN, "agent-1", "u1") is None
    before = bindings_path(repo_cwd, TRAIN).read_bytes()
    foreign = _dispatch(repo_cwd, unit, "other:repo-coder")["tool_input"]
    reason = dispatch_binding._dispatch_reason(foreign, str(repo_cwd))
    assert reason is not None and needle in reason and "(issue 29)" in reason, reason
    assert bindings_path(repo_cwd, TRAIN).read_bytes() == before


def test_gate_is_off_outside_a_train(repo_cwd: Path, unit: Path) -> None:
    (repo_cwd / ".claude" / "daedalus" / "train.active").unlink()
    _ok(repo_cwd, unit)


def test_resume_gate_is_off_outside_a_train(repo_cwd: Path, unit: Path) -> None:
    # 0086: no train, no binding file; a resume naming a worktree binds nothing.
    (repo_cwd / ".claude" / "daedalus" / "train.active").unlink()
    message = {"to": "c1", "message": f"Worktree: {unit}"}
    assert dispatch_binding._resume_reason(message, str(repo_cwd)) is None
    assert not bindings_path(repo_cwd, TRAIN).exists()


def test_resume_gate_reads_every_text_of_a_structured_message(repo_cwd: Path, unit: Path) -> None:
    # 0086: a Worktree: line inside a structured message still meets the gate.
    seed_plan(repo_cwd, TRAIN)
    for message in ({"body": [f"Worktree: {unit}"]}, [f"x\nWorktree: {unit}"]):
        reason = dispatch_binding._resume_reason({"to": "c1", "message": message}, str(repo_cwd))
        assert reason is not None and "coder c1 holds no unit" in reason, message
    plain = {"to": "c1", "message": {"body": "RESUME. Research payload: x"}}
    assert dispatch_binding._resume_reason(plain, str(repo_cwd)) is None


def test_a_plan_recorded_in_another_trains_state_is_refused(repo_cwd: Path, unit: Path) -> None:
    train_state.save(repo_cwd, OTHER, {"train_id": OTHER})
    seed_plan(repo_cwd, OTHER)
    _refused(repo_cwd, unit, "records no plan")


def test_a_plan_file_under_another_train_id_is_refused(repo_cwd: Path, unit: Path) -> None:
    other = plan_file(repo_cwd, OTHER)
    record_plan(repo_cwd, TRAIN, str(other), _sha(other))
    _refused(repo_cwd, unit, f"train {OTHER}")
    relative = f"docs/.tmp/daedalus/{OTHER}/plan.md"
    record_plan(repo_cwd, TRAIN, relative, _sha(other))
    _refused(repo_cwd, unit, f"train {OTHER}")
    dotted = repo_cwd / "docs" / ".tmp" / "daedalus" / TRAIN / ".." / OTHER / "plan.md"
    record_plan(repo_cwd, TRAIN, str(dotted), _sha(other))
    _refused(repo_cwd, unit, f"train {OTHER}")


def test_a_link_to_another_trains_plan_is_refused(repo_cwd: Path, unit: Path) -> None:
    other = plan_file(repo_cwd, OTHER)
    link = repo_cwd / "docs" / ".tmp" / "daedalus" / TRAIN / "plan.md"
    link.parent.mkdir(parents=True)
    link.symlink_to(other)
    record_plan(repo_cwd, TRAIN, str(link), _sha(other))
    _refused(repo_cwd, unit, f"train {OTHER}")


def test_a_missing_plan_file_is_refused(repo_cwd: Path, unit: Path) -> None:
    gone = repo_cwd / "docs" / ".tmp" / "daedalus" / TRAIN / "plan.md"
    record_plan(repo_cwd, TRAIN, str(gone), "0" * 64)
    _refused(repo_cwd, unit, "could not be read")


@pytest.mark.parametrize(
    "record",
    [
        "docs/.tmp/daedalus/plan.md",
        {"path": "docs/plan.md"},
        {"sha256": "0" * 64},
        {"path": 7, "sha256": "0" * 64},
        {"path": "", "sha256": "0" * 64},
        {"path": "docs/plan.md", "sha256": "abc"},
        {"path": "docs/plan.md", "sha256": "A" * 64},
        {"path": "docs/plan.md", "sha256": 0},
    ],
)
def test_a_malformed_plan_record_is_refused(repo_cwd: Path, unit: Path, record: object) -> None:
    train_state.update(repo_cwd, TRAIN, plan=record)
    _refused(repo_cwd, unit, "plan")


def test_a_relative_plan_path_resolves_from_the_repo(repo_cwd: Path, unit: Path) -> None:
    path = plan_file(repo_cwd, TRAIN)
    record_plan(repo_cwd, TRAIN, f"docs/.tmp/daedalus/{TRAIN}/plan.md", _sha(path))
    _ok(repo_cwd, unit)


def test_the_hook_chain_enforces_the_plan_gate(
    repo_cwd: Path, unit: Path, run_script: Callable[[str, dict[str, Any]], Any]
) -> None:
    # Main never prompted (amends 0106): the operator's own dispatch without a plan is warned.
    warned = run_script("enforce_agent_jail.py", _dispatch(repo_cwd, unit))
    assert warned.returncode == 0, warned.stderr
    assert NEXT in main_warning(warned.stdout)
    # 0106: a subagent claiming main stays refused, by the identity rule ahead of the plan gate.
    claimed = {**_dispatch(repo_cwd, unit), "agent_id": "sub1"}
    refused = run_script("enforce_agent_jail.py", claimed)
    assert refused.returncode == 2 and refused.stdout == "", refused.stdout
    assert "a subagent may not run as main. Next:" in refused.stderr, refused.stderr
    seed_plan(repo_cwd, TRAIN)
    allowed = run_script("enforce_agent_jail.py", _dispatch(repo_cwd, unit))
    assert allowed.returncode == 0, allowed.stderr


def _audit_tree(repo: Path, flagged: bool) -> Path:
    # spec 4: create flags the audit unit; a state written before D2 carries only its name.
    tree = create(repo, f"{TRAIN}-audit", f"daedalus/{TRAIN}")
    if not flagged:

        def strip(state: dict[str, object]) -> None:
            state["units"] = [
                {k: v for k, v in u.items() if k != "audit"} for u in train_state.units(state)
            ]

        train_state.change(repo, TRAIN, strip)
    jail._registered_worktrees.cache_clear()
    return tree


@pytest.mark.parametrize("flagged", [True, False])
def test_a_coder_dispatch_naming_the_audit_worktree_is_refused(
    repo_cwd: Path, unit: Path, flagged: bool
) -> None:
    seed_plan(repo_cwd, TRAIN)
    tree = _audit_tree(repo_cwd, flagged)
    want = dispatch_binding.R_AUDIT_UNIT.format(path=tree, train=TRAIN)
    tool_input = _dispatch(repo_cwd, tree)["tool_input"]
    assert dispatch_binding._dispatch_reason(tool_input, str(repo_cwd)) == want
    d = decide(_dispatch(repo_cwd, tree), Config())
    assert not d.allow and want in str(d.reason)
    assert f"{tree} is the audit worktree" in want and "Next: name the coder's own unit" in want
    assert not bindings_path(repo_cwd, TRAIN).exists(), "a refused dispatch is never recorded"
    _ok(repo_cwd, unit)


def test_a_resume_moving_a_coder_onto_the_audit_worktree_is_refused(
    repo_cwd: Path, unit: Path
) -> None:
    # spec 4: a rebind onto the audit worktree meets the same refusal as a cold dispatch.
    seed_plan(repo_cwd, TRAIN)
    tree = _audit_tree(repo_cwd, flagged=True)
    _ok(repo_cwd, unit)
    assert claim(repo_cwd, TRAIN, "c1", "u1") is None
    before = bindings_path(repo_cwd, TRAIN).read_bytes()
    message = {"to": "c1", "message": f"FIX.\nWorktree: {tree}"}
    reason = dispatch_binding._resume_reason(message, str(repo_cwd))
    assert reason == dispatch_binding.R_AUDIT_UNIT.format(path=tree, train=TRAIN)
    assert bindings_path(repo_cwd, TRAIN).read_bytes() == before

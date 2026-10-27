# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0132, 0134: the docs writer's worktree binding and write scope, and the terraform class.
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from lib import dispatch_binding, jail, train_state
from lib.agent_files import Hook, load
from lib.config import Config
from lib.unit_binding import bindings_path, claim
from lib.workspace import create, mark_train

from tests.conftest import REPO_ROOT
from tests.conftest import git as _git
from tests.hook_chain import evaluate, first_deny
from tests.hook_chain import judge as decide
from tests.test_dispatch_binding import TRAIN, seed_plan

DOCS = f"{TRAIN}-docstage"
WRITER = "daedalus:docs-writer"
AGENTS = REPO_ROOT / "agents"
ALLOW = ("--allow", "terraform,inspect")


@pytest.fixture
def trees(repo_cwd: Path, project_data: Path) -> tuple[Path, Path]:
    ident = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    _git(repo_cwd, *ident, "commit", "-q", "--allow-empty", "-m", "base")
    _git(repo_cwd, "branch", f"daedalus/{TRAIN}")
    train_state.save(repo_cwd, TRAIN, {"train_id": TRAIN})
    mark_train(repo_cwd, TRAIN)
    unit = create(repo_cwd, "u1", f"daedalus/{TRAIN}")
    docs = create(repo_cwd, DOCS, f"daedalus/{TRAIN}")
    jail._registered_worktrees.cache_clear()
    return unit, docs


def _dispatch(repo: Path, prompt: str, subagent: str = WRITER) -> dict[str, Any]:
    tool_input = {"description": "docs", "prompt": prompt, "subagent_type": subagent}
    return {
        "agent_type": "daedalus:orchestrator",
        "agent_id": "orch-1",
        "tool_name": "Agent",
        "tool_input": tool_input,
        "cwd": str(repo),
        "session_id": "s",
    }


def _writer(repo: Path, tool: str, **tool_input: str) -> dict[str, Any]:
    return {
        "agent_type": WRITER,
        "agent_id": "dw-1",
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": str(repo),
        "session_id": "s",
    }


def _bound_writer(repo: Path) -> None:
    assert (
        dispatch_binding._docs_dispatch_reason(
            {"prompt": f"Worktree: {repo}/.claude/worktrees/{DOCS}"}, str(repo), WRITER
        )
        is None
    )


# Requirement 1: the docs-writer dispatch binds the <train-id>-docstage worktree alone.


def test_docs_writer_dispatch_binds_the_docs_worktree(
    repo_cwd: Path, trees: tuple[Path, Path]
) -> None:
    d = decide(_dispatch(repo_cwd, f"Write the docs.\nWorktree: {trees[1]}\n"), Config())
    assert d.allow, d.reason
    units = json.loads(bindings_path(repo_cwd, TRAIN).read_text(encoding="utf-8"))["units"]
    assert units == {DOCS: {"agent_id": None}}


@pytest.mark.parametrize("which", ["unit", "none", "two"])
def test_docs_writer_dispatch_naming_another_worktree_is_refused(
    repo_cwd: Path, trees: tuple[Path, Path], which: str
) -> None:
    unit, docs = trees
    prompt = {
        "unit": f"Worktree: {unit}",
        "none": "Write the docs.",
        "two": f"Worktree: {docs}\nWorktree: {unit}",
    }[which]
    d = decide(_dispatch(repo_cwd, prompt), Config())
    assert not d.allow and "(0134)" in str(d.reason) and f"Worktree: {docs}" in str(d.reason)
    assert not bindings_path(repo_cwd, TRAIN).exists(), "a refused dispatch is never recorded"


def test_a_resume_never_moves_a_coder_onto_the_docs_worktree(
    repo_cwd: Path, trees: tuple[Path, Path]
) -> None:
    unit, docs = trees
    seed_plan(repo_cwd, TRAIN)
    assert dispatch_binding.record_dispatch(repo_cwd, TRAIN, "u1") is None
    assert claim(repo_cwd, TRAIN, "coder-1", "u1") is None
    move = {**_dispatch(repo_cwd, ""), "tool_name": "SendMessage"}
    move["tool_input"] = {"to": "coder-1", "message": f"Next unit.\nWorktree: {docs}"}
    d = decide(move, Config())
    assert not d.allow and str(d.reason).startswith(f"the docs worktree {DOCS} takes only")
    stay = {**move, "tool_input": {"to": "coder-1", "message": f"Again.\nWorktree: {unit}"}}
    assert decide(stay, Config()).allow


# Requirement 2: --docs lets the docs-writer write only the four public docs.


@pytest.mark.parametrize("doc", dispatch_binding.PUBLIC_DOCS)
def test_docs_writer_writes_each_public_doc(
    repo_cwd: Path, trees: tuple[Path, Path], doc: str
) -> None:
    _bound_writer(repo_cwd)
    payload = _writer(repo_cwd, "Write", file_path=f"{trees[1]}/{doc}", content="x")
    assert evaluate("unit_writes", payload, "--docs") is None


@pytest.mark.parametrize(
    "rel", ["scripts/a.py", "docs/other.md", "readme.md", "docs/howto/README.md.bak"]
)
def test_docs_writer_refuses_any_other_path_in_the_docs_worktree(
    repo_cwd: Path, trees: tuple[Path, Path], rel: str
) -> None:
    _bound_writer(repo_cwd)
    payload = _writer(repo_cwd, "Write", file_path=f"{trees[1]}/{rel}", content="x")
    reason = evaluate("unit_writes", payload, "--docs")
    assert reason is not None and reason.startswith("the docs-writer writes only"), reason


def test_docs_writer_refuses_a_public_doc_in_a_coder_unit(
    repo_cwd: Path, trees: tuple[Path, Path]
) -> None:
    payload = _writer(repo_cwd, "Edit", file_path=f"{trees[0]}/README.md")
    reason = evaluate("unit_writes", payload, "--docs")
    assert reason is not None and f"docs worktree {DOCS}" in reason, reason
    # 0054: without --docs the same write is a coder's ordinary unit write.
    assert "docs-writer" not in str(evaluate("unit_writes", payload))


@pytest.mark.parametrize(
    ("command", "allowed"),
    [
        ("git -C {docs} add README.md docs/guardrails.md", True),
        ("git -C {docs} commit -m 'Describe the docs stage'", True),
        ("tee {docs}/docs/howto/README.md", True),
        ("git -C {docs} add -A", False),
        ("git -C {docs} add scripts/a.py", False),
        ("git -C {docs} restore README.md", False),
        ("git -C {docs} stash", False),
        ("cp {docs}/README.md {docs}/scripts/a.py", False),
        ("touch {unit}/README.md", False),
        ("git -C {unit} add README.md", False),
    ],
)
def test_docs_writer_bash_writes_stay_on_the_public_docs(
    repo_cwd: Path, trees: tuple[Path, Path], command: str, allowed: bool
) -> None:
    _bound_writer(repo_cwd)
    text = command.format(unit=trees[0], docs=trees[1])
    reason = evaluate("unit_writes", _writer(repo_cwd, "Bash", command=text), "--docs")
    assert (reason is None) is allowed, reason
    if not allowed:
        assert "(0134)" in str(reason), reason


# Requirement 3: the terraform class admits fmt -check and validate only.


def _tf(repo: Path, command: str) -> dict[str, Any]:
    return {
        "agent_type": "daedalus:terraform-reviewer",
        "agent_id": "tf-1",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": str(repo),
        "session_id": "s",
    }


@pytest.mark.parametrize(
    "command",
    [
        "terraform fmt -check",
        "terraform validate",
        "terraform -chdir={repo}/infra fmt -check",
        "terraform -chdir={repo}/infra validate",
        "find /usr/local/bin /usr/bin -maxdepth 1 -name terraform",
    ],
)
def test_terraform_class_admits_the_two_checks(repo_cwd: Path, command: str) -> None:
    # 0158: validate needs its own switch on.
    manifest = repo_cwd / "service-manifest.json"
    manifest.write_text(json.dumps({"features": {"terraform_validate": True}}), encoding="utf-8")
    payload = _tf(repo_cwd, command.format(repo=repo_cwd))
    assert evaluate("command_allowlist", payload, *ALLOW) is None
    assert first_deny(payload, Config()) is None


@pytest.mark.parametrize(
    "command",
    [
        "terraform apply -auto-approve",
        "terraform init",
        "terraform plan",
        "terraform fmt",
        "terraform fmt -check -recursive",
        "terraform validate -json",
        "terraform -chdir=/etc validate",
        "terraform -chdir=infra validate",
        "terraform -chdir={repo}/../x validate",
        "/tmp/terraform fmt -check",
    ],
)
def test_terraform_class_refuses_every_other_form(repo_cwd: Path, command: str) -> None:
    reason = evaluate("command_allowlist", _tf(repo_cwd, command.format(repo=repo_cwd)), *ALLOW)
    assert reason is not None, command
    # 0132: a path to a binary is no terraform segment, so the class list refuses it.
    assert "(0132)" in reason if command.startswith("terraform") else "Next:" in reason, reason


def test_terraform_class_refuses_both_checks_when_the_switch_is_off(repo_cwd: Path) -> None:
    manifest = repo_cwd / "service-manifest.json"
    manifest.write_text(json.dumps({"features": {"terraform_tools": False}}), encoding="utf-8")
    for command in ("terraform fmt -check", "terraform validate"):
        reason = evaluate("command_allowlist", _tf(repo_cwd, command), *ALLOW)
        assert reason is not None and reason.startswith("features.terraform_tools is false")
    on = {"terraform_tools": True, "terraform_validate": True}
    manifest.write_text(json.dumps({"features": on}), encoding="utf-8")
    assert evaluate("command_allowlist", _tf(repo_cwd, "terraform validate"), *ALLOW) is None


def test_terraform_class_fails_closed_on_an_unreadable_manifest(repo_cwd: Path) -> None:
    (repo_cwd / "service-manifest.json").write_text("{not json", encoding="utf-8")
    reason = evaluate("command_allowlist", _tf(repo_cwd, "terraform validate"), *ALLOW)
    assert reason is not None and reason.startswith("the service manifest could not be read")


def test_terraform_needs_its_class(repo_cwd: Path) -> None:
    payload = _tf(repo_cwd, "terraform validate")
    assert evaluate("command_allowlist", payload, "--allow", "inspect") is not None


# Requirement 4: the agent files name the class and the narrowed write check.


def test_agent_files_name_the_new_class_and_the_narrowed_check() -> None:
    reviewer = load(AGENTS / "terraform-reviewer.md")
    assert Hook("command_allowlist", ALLOW) in reviewer.hooks
    assert "read_only_bash" not in {h.script for h in reviewer.hooks}
    writer = load(AGENTS / "docs-writer.md")
    assert Hook("unit_writes", ("--docs",)) in writer.hooks
    coder = load(AGENTS / "repo-coder.md")
    assert Hook("unit_writes", ()) in coder.hooks

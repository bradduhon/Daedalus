# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0132, 0134, 0186: the docs writer's binding and write scope, and the auditor's terraform class.
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from lib import dispatch_binding, jail, train_state, writer_mode
from lib.agent_files import Hook, load
from lib.config import Config
from lib.unit_binding import bindings_path, claim
from lib.workspace import create, mark_train

from tests.conftest import REPO_ROOT
from tests.conftest import git as _git
from tests.hook_chain import evaluate, first_deny
from tests.hook_chain import judge as decide
from tests.hook_chain import load as load_hook
from tests.test_dispatch_binding import TRAIN, seed_plan

DOCS = f"{TRAIN}-docstage"
WRITER = "daedalus:writer"
AGENTS = REPO_ROOT / "agents"
ALLOW = ("--git", "read-only", "--test-runner", "audit", "--terraform")
READS = "read_only_bash"


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
        dispatch_binding._writer_dispatch_reason(
            {"prompt": f"Worktree: {repo}/.claude/worktrees/{DOCS}"}, str(repo), WRITER, None, False
        )
        is None
    )


# Requirement 1: the writer dispatch binds the <train-id>-docstage worktree alone.


def test_public_docs_writer_dispatch_binds_the_docs_worktree(
    repo_cwd: Path, trees: tuple[Path, Path]
) -> None:
    d = decide(_dispatch(repo_cwd, f"Write the docs.\nWorktree: {trees[1]}\n"), Config())
    assert d.allow, d.reason
    units = json.loads(bindings_path(repo_cwd, TRAIN).read_text(encoding="utf-8"))["units"]
    assert units == {DOCS: {"agent_id": None}}


@pytest.mark.parametrize("which", ["unit", "two"])
def test_public_docs_writer_dispatch_naming_another_worktree_is_refused(
    repo_cwd: Path, trees: tuple[Path, Path], which: str
) -> None:
    unit, docs = trees
    prompt = {"unit": f"Worktree: {unit}", "two": f"Worktree: {docs}\nWorktree: {unit}"}[which]
    d = decide(_dispatch(repo_cwd, prompt), Config())
    assert not d.allow and "(0134)" in str(d.reason) and f"Worktree: {docs}" in str(d.reason)
    assert not bindings_path(repo_cwd, TRAIN).exists(), "a refused dispatch is never recorded"


def test_a_writer_dispatch_with_no_worktree_line_needs_frozen_sources(
    repo_cwd: Path, trees: tuple[Path, Path]
) -> None:
    # 0190: no Worktree: line is the derived kind; a build run has no frozen sources file.
    d = decide(_dispatch(repo_cwd, "Write the docs."), Config())
    assert not d.allow and "frozen sources file" in str(d.reason) and "(0190" in str(d.reason)
    assert not bindings_path(repo_cwd, TRAIN).exists(), "a refused dispatch is never recorded"
    assert not writer_mode.records_path(repo_cwd, TRAIN).exists()


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


# Requirement 2: --docs lets the writer write only the four public docs.


@pytest.mark.parametrize("doc", dispatch_binding.PUBLIC_DOCS)
def test_public_docs_writer_writes_each_public_doc(
    repo_cwd: Path, trees: tuple[Path, Path], doc: str
) -> None:
    _bound_writer(repo_cwd)
    payload = _writer(repo_cwd, "Write", file_path=f"{trees[1]}/{doc}", content="x")
    assert evaluate("unit_writes", payload, "--docs") is None


@pytest.mark.parametrize(
    "rel", ["scripts/a.py", "docs/other.md", "readme.md", "docs/howto/README.md.bak"]
)
def test_public_docs_writer_refuses_any_other_path_in_the_docs_worktree(
    repo_cwd: Path, trees: tuple[Path, Path], rel: str
) -> None:
    _bound_writer(repo_cwd)
    payload = _writer(repo_cwd, "Write", file_path=f"{trees[1]}/{rel}", content="x")
    reason = evaluate("unit_writes", payload, "--docs")
    assert reason is not None and reason.startswith("the writer writes only"), reason


def test_public_docs_writer_refuses_a_public_doc_in_a_coder_unit(
    repo_cwd: Path, trees: tuple[Path, Path]
) -> None:
    payload = _writer(repo_cwd, "Edit", file_path=f"{trees[0]}/README.md")
    reason = evaluate("unit_writes", payload, "--docs")
    assert reason is not None and f"docs worktree {DOCS}" in reason, reason
    # 0054: without --docs the same write is a coder's ordinary unit write.
    # issue 306: the coder refusal names the repository, whose temp path holds this test's name.
    assert "writer" not in str(evaluate("unit_writes", payload)).replace(str(repo_cwd), "")


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
def test_public_docs_writer_bash_writes_stay_on_the_public_docs(
    repo_cwd: Path, trees: tuple[Path, Path], command: str, allowed: bool
) -> None:
    _bound_writer(repo_cwd)
    text = command.format(unit=trees[0], docs=trees[1])
    reason = evaluate("unit_writes", _writer(repo_cwd, "Bash", command=text), "--docs")
    assert (reason is None) is allowed, reason
    if not allowed:
        # 228 S3b: restore and stash off the coder grammar are refused by name first.
        assert "(0134)" in str(reason) or "Refused: git " in str(reason), reason


# Requirement 3: the auditor's terraform class admits fmt -check and validate only.


def _tf(repo: Path, command: str) -> dict[str, Any]:
    return {
        "agent_type": "daedalus:auditor",
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
        "terraform -chdir={repo}/infra fmt -check",
        "find /usr/local/bin /usr/bin -maxdepth 1 -name terraform",
    ],
)
def test_terraform_class_admits_the_format_check(repo_cwd: Path, command: str) -> None:
    # 0158, 0265: the format check only; the run validates outside the wrapper.
    manifest = repo_cwd / "service-manifest.json"
    manifest.write_text(json.dumps({"checks": {"terraform_validate": True}}), encoding="utf-8")
    payload = _tf(repo_cwd, command.format(repo=repo_cwd))
    assert evaluate(READS, payload, *ALLOW) is None
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
        "terraform validate",
        "terraform -chdir={repo}/infra validate",
        "/tmp/terraform fmt -check",
    ],
)
def test_terraform_class_refuses_every_other_form(repo_cwd: Path, command: str) -> None:
    reason = evaluate(READS, _tf(repo_cwd, command.format(repo=repo_cwd)), *ALLOW)
    assert reason is not None, command
    run_validates = load_hook("command_allowlist").R_TERRAFORM_RUN_VALIDATES
    if command.startswith("terraform") and command.split()[-1] == "validate":
        # 0265: every validate the class's parser admits meets the run's-validate refusal.
        assert reason.startswith(run_validates), command
        return
    # 0132: a path to a binary is no terraform segment, so the read check refuses it.
    assert "(0132)" in reason if command.startswith("terraform") else "Next:" in reason, reason


def test_terraform_class_refuses_validate_whatever_the_switch(repo_cwd: Path) -> None:
    manifest = repo_cwd / "service-manifest.json"
    manifest.write_text(json.dumps({"checks": {"terraform_format": False}}), encoding="utf-8")
    reason = evaluate(READS, _tf(repo_cwd, "terraform fmt -check"), *ALLOW)
    assert reason is not None and reason.startswith("checks.terraform_format is false")
    run_validates = load_hook("command_allowlist").R_TERRAFORM_RUN_VALIDATES
    for block in ({"terraform_format": False}, {"terraform_validate": True}):
        manifest.write_text(json.dumps({"checks": block}), encoding="utf-8")
        got = evaluate(READS, _tf(repo_cwd, "terraform validate"), *ALLOW)
        assert got is not None and got.startswith(run_validates)


def test_terraform_class_fails_closed_on_an_unreadable_manifest(repo_cwd: Path) -> None:
    (repo_cwd / "service-manifest.json").write_text("{not json", encoding="utf-8")
    reason = evaluate(READS, _tf(repo_cwd, "terraform fmt -check"), *ALLOW)
    assert reason is not None and reason.startswith("the service manifest could not be read")


def test_terraform_needs_its_class(repo_cwd: Path) -> None:
    # 0186, 0188: the verifier's read check carries no --terraform, so it refuses both forms.
    payload = {**_tf(repo_cwd, "terraform fmt -check"), "agent_type": "daedalus:verifier"}
    assert evaluate(READS, payload, "--git", "read-only", "--test-runner", "unit") is not None
    assert first_deny(payload, Config()) is not None


@pytest.mark.parametrize(
    "command",
    [
        "cd {repo} && terraform fmt -check",
        "cd /etc && terraform validate",
        "cd {repo}/infra && terraform -chdir={repo}/infra fmt -check",
    ],
)
def test_terraform_after_a_cd_is_refused(repo_cwd: Path, command: str) -> None:
    # 0188: the terraform folder is judged against the hook cwd, so no cd may move it first.
    manifest = repo_cwd / "service-manifest.json"
    manifest.write_text(json.dumps({"checks": {"terraform_validate": True}}), encoding="utf-8")
    (repo_cwd / "infra").mkdir(exist_ok=True)
    reason = evaluate(READS, _tf(repo_cwd, command.format(repo=repo_cwd)), *ALLOW)
    assert reason is not None and "terraform check follows it" in reason, reason


# Requirement 4: the agent files name the class and the narrowed write check.


def test_agent_files_name_the_new_class_and_the_narrowed_check() -> None:
    auditor = load(AGENTS / "auditor.md")
    assert Hook(READS, ALLOW) in auditor.hooks
    assert "command_allowlist" not in {h.script for h in auditor.hooks}
    writer = load(AGENTS / "writer.md")
    assert Hook("unit_writes", ("--docs",)) in writer.chains()["public-docs"]
    coder = load(AGENTS / "coder.md")
    assert Hook("unit_writes", ()) in coder.hooks

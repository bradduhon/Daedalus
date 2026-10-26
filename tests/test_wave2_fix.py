# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0131, 0134: the WAVE2-FIX follow-ups, one allowed and one refused case per requirement.
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from lib import (
    audit_proof,
    dispatch_binding,
    plan_record,
    train_runner,
    train_state,
    train_summary,
)
from lib.audit_proof import PUBLIC_DOCS, ProofError, push_proof
from lib.config import Config
from lib.manifest import ManifestError
from lib.manifest import load as load_manifest

from tests import test_train_runner as runner_tests
from tests.conftest import REPO_ROOT
from tests.conftest import git as _git
from tests.hook_chain import evaluate
from tests.hook_chain import judge as decide
from tests.test_dispatch_binding import TRAIN, VALID, seed_plan
from tests.test_docs_stage import (
    CLAIM,
    ID,
    _claims,
    _commit,
    _exempted_security,
    _train,
)
from tests.test_persona_jails import _bound_writer, _dispatch, _writer, trees
from tests.test_train_runner import _config, _integration
from tests.test_train_state_print import RECORDS, _section, _stop, _text

# 0131: the runner tests' fixtures, a temp HOME, a plugin root and a one-commit repository.
_isolated_env = runner_tests._isolated_env
plugin = runner_tests.plugin
repo = runner_tests.repo
__all__ = ["trees"]

CODER = "daedalus:repo-coder"
LEDGER = "docs/decisions.md"
LEDGER_DECL = {
    "path": LEDGER,
    "format": "markdown-table-row",
    "id_scheme": "{seq:04d}-{repo}-{type}",
    "sequence_source": "last-row-id",
}


def _flat(rel: str) -> str:
    return " ".join((REPO_ROOT / rel).read_text(encoding="utf-8").split())


# Requirement 1: the docs stage worktree is <train-id>-docstage everywhere.


def test_the_docs_stage_worktree_is_named_docstage() -> None:
    assert dispatch_binding.docs_unit(TRAIN) == f"{TRAIN}-docstage"
    assert train_state.DOCS_SUFFIX == dispatch_binding.DOCS_SUFFIX == "-docstage"
    for rel in ("agents/orchestrator.md", "skills/catalog/SKILL.md", "agents/docs-writer.md"):
        text = _flat(rel)
        assert "<train-id>-docstage" in text, rel
        assert "<train-id>-docs`" not in text and "<train-id>-docs " not in text, rel


def test_a_verified_docs_verdict_reads_the_docstage_worktree(repo: Path, plugin: Path) -> None:
    runner_tests._audit_train(repo, plugin)
    train = _train(repo)
    old = repo.parent / f"{train}-docs"
    train_state.add_unit(repo, train, f"{train}-docs", f"daedalus-unit/{train}-docs", old)
    refused = train_runner.record_docs_verdict(repo, "verified")
    assert refused.code == 1 and f"records no docs worktree {train}-docstage" in refused.lines[0]


# Requirement 2: no coder takes the docstage worktree by dispatch or resume.


def test_a_coder_dispatch_onto_the_docstage_worktree_is_refused(
    repo_cwd: Path, trees: tuple[Path, Path]
) -> None:
    unit, docs = trees
    seed_plan(repo_cwd, TRAIN)
    onto_docs = decide(_dispatch(repo_cwd, f"Build.\nWorktree: {docs}", CODER), Config())
    assert not onto_docs.allow
    assert str(onto_docs.reason).startswith(f"the docs worktree {TRAIN}-docstage takes only")
    onto_unit = decide(_dispatch(repo_cwd, f"Build.\nWorktree: {unit}", CODER), Config())
    assert onto_unit.allow, onto_unit.reason


def test_a_bound_coder_resume_onto_the_docstage_worktree_is_refused(
    repo_cwd: Path, trees: tuple[Path, Path]
) -> None:
    # 0134: even a coder the bindings already name never resumes onto the docs stage.
    unit, docs = trees
    seed_plan(repo_cwd, TRAIN)
    assert dispatch_binding.record_dispatch(repo_cwd, TRAIN, f"{TRAIN}-docstage") is None
    assert dispatch_binding.claim(repo_cwd, TRAIN, "coder-1", f"{TRAIN}-docstage") is None
    move = {**_dispatch(repo_cwd, ""), "tool_name": "SendMessage"}
    move["tool_input"] = {"to": "coder-1", "message": f"Again.\nWorktree: {docs}"}
    refused = decide(move, Config())
    assert not refused.allow and "takes only the docs-writer" in str(refused.reason)
    assert dispatch_binding.record_dispatch(repo_cwd, TRAIN, "u1") is None
    assert dispatch_binding.claim(repo_cwd, TRAIN, "coder-2", "u1") is None
    stay = {**move, "tool_input": {"to": "coder-2", "message": f"Again.\nWorktree: {unit}"}}
    assert decide(stay, Config()).allow


@pytest.mark.parametrize(("unit_id", "reserved"), [("DOCS", False), ("DocStage", True)])
def test_plan_validation_reserves_the_docstage_slug(
    tmp_path: Path, unit_id: str, reserved: bool
) -> None:
    # 0134: a unit whose slug would be docstage is a plan defect, so no unit takes that worktree.
    text = (VALID).read_text(encoding="utf-8").replace("U3", unit_id)
    path = tmp_path / "plan.md"
    path.write_text(text, encoding="utf-8")
    defects = plan_record.validate(plan_record.load(path), 5)
    want = (
        f"unit {unit_id} takes the slug of the reserved docs stage worktree "
        "<train-id>-docstage. Next: give that unit another id in the plan."
    )
    assert (want in defects) is reserved, defects
    if not reserved:
        assert defects == plan_record.validate(plan_record.load(VALID), 5)


# Requirement 3: the docs writer commits only with -m <message>.


@pytest.mark.parametrize(
    ("command", "allowed"),
    [
        ("git -C {docs} commit -m 'Describe the docs stage'", True),
        ("git -C {docs} commit -a -m 'Describe the docs stage'", False),
        ("git -C {docs} commit --all -m 'Describe the docs stage'", False),
        ("git -C {docs} commit -m 'Describe it' README.md", False),
        ("git -C {docs} commit -m 'Describe it' -- docs/guardrails.md", False),
        ("git -C {docs} commit --amend -m 'Describe it'", False),
    ],
)
def test_docs_writer_commit_takes_only_a_message(
    repo_cwd: Path, trees: tuple[Path, Path], command: str, allowed: bool
) -> None:
    _bound_writer(repo_cwd)
    text = command.format(docs=trees[1])
    reason = evaluate("unit_writes", _writer(repo_cwd, "Bash", command=text), "--docs")
    assert (reason is None) is allowed, reason
    if not allowed:
        assert str(reason).startswith("the docs-writer commits only what it staged"), reason


# Requirement 4: a docs-only commit keeps each doc a regular non-executable file.


def _verified_at(repo: Path, tip: str) -> None:
    train_state.update(repo, _train(repo), docs_verdict={"status": "verified", "tip": tip})


@pytest.mark.parametrize("change", ["executable", "symlink", "gitlink"])
def test_a_docs_path_type_or_mode_change_is_refused(repo: Path, plugin: Path, change: str) -> None:
    judged = _exempted_security(repo, plugin)
    train = _train(repo)
    plain = _commit(repo, "README.md")
    _verified_at(repo, plain)
    assert push_proof(repo, train).endswith(f"docs verified on tip {plain[:12]}")
    if change == "executable":
        _commit(repo, "docs/howto/README.md")
        _git(repo, "update-index", "--chmod=+x", "docs/howto/README.md")
    elif change == "symlink":
        os.symlink("../README.md", repo / "docs" / "guardrails.md")
        _git(repo, "add", "docs/guardrails.md")
    else:
        gitlink = f"160000,{judged},docs/project-requirements.md"
        _git(repo, "update-index", "--add", "--cacheinfo", gitlink)
    _git(repo, "commit", "-q", "-m", f"{change} doc")
    moved = _integration(repo)
    _verified_at(repo, moved)
    with pytest.raises(ProofError) as info:
        push_proof(repo, train)
    assert "changes the type or mode of a public doc" in str(info.value)


# Requirement 5: one ledger commit after the docs-only commits is admitted, no more.


def _ledger(repo: Path, *extra: str) -> str:
    _config(repo, {"ledger": LEDGER_DECL})
    return _commit(repo, LEDGER, *extra)


def test_one_ledger_commit_after_the_docs_commits_passes(repo: Path, plugin: Path) -> None:
    _exempted_security(repo, plugin)
    train = _train(repo)
    docs_tip = _commit(repo, "README.md")
    _verified_at(repo, docs_tip)
    ledger_tip = _ledger(repo)
    assert push_proof(repo, train).endswith(
        f"integration tip {ledger_tip[:12]}, docs verified on tip {docs_tip[:12]}"
    )
    _ledger(repo)
    with pytest.raises(ProofError) as info:
        push_proof(repo, train)
    assert "changes more than the four public docs" in str(info.value)


def test_a_ledger_commit_mixed_with_another_path_is_refused(repo: Path, plugin: Path) -> None:
    _exempted_security(repo, plugin)
    train = _train(repo)
    _verified_at(repo, _commit(repo, "README.md"))
    mixed = _ledger(repo, "docs/guardrails.md")
    with pytest.raises(ProofError) as info:
        push_proof(repo, train)
    assert f"the commit {mixed[:12]}" in str(info.value)
    assert "changes more than the four public docs" in str(info.value)


def test_a_ledger_commit_without_a_docs_record_keeps_todays_refusal(
    repo: Path, plugin: Path
) -> None:
    judged = _exempted_security(repo, plugin)
    train = _train(repo)
    _commit(repo, "README.md")
    current = _ledger(repo)
    with pytest.raises(ProofError) as info:
        push_proof(repo, train)
    assert f"the tip {current[:12]} moved past the judged tip {judged[:12]}" in str(info.value)


def test_a_docs_exemption_lands_after_the_ruling_ledger_commit(repo: Path, plugin: Path) -> None:
    _exempted_security(repo, plugin)
    train = _train(repo)
    docs_tip = _commit(repo, "README.md")
    train_runner.record_docs_verdict(repo, "refuted", findings=_claims(repo, CLAIM))
    _ledger(repo)
    outcome = train_runner.record_exception(repo, ID, CLAIM, "issue")
    assert outcome.code == 0, outcome.lines
    assert push_proof(repo, train).endswith(
        f"docs refuted with every claim exempted on tip {docs_tip[:12]}"
    )
    _ledger(repo)
    with pytest.raises(ProofError):
        push_proof(repo, train)


# Requirement 6: one list of the four public docs.


def test_dispatch_binding_imports_the_one_docs_list() -> None:
    assert dispatch_binding.PUBLIC_DOCS is audit_proof.PUBLIC_DOCS
    assert PUBLIC_DOCS[0] == "README.md" and len(PUBLIC_DOCS) == 4
    source = (REPO_ROOT / "scripts" / "lib" / "dispatch_binding.py").read_text(encoding="utf-8")
    assert "PUBLIC_DOCS = (" not in source


# Requirement 8: a priorities rule yield goes to the operator.


def test_a_priorities_yield_names_the_operator_as_its_answerer(tmp_path: Path) -> None:
    question = "priorities rule 2: keep the cheaper default or the secure one?"
    records = list(RECORDS)
    records[2] = _stop(3, "repo-coder", f"[STATUS: YIELD_STANDARDS] {question}", "c2")
    assert _section(_text(tmp_path, records=records), "Yields") == [
        f"- u2: YIELD_STANDARDS {question} (answered by operator)"
    ]
    assert train_summary._ANSWERERS[train_summary.PRIORITIES_YIELD] == ("operator",)
    # 0129: the other standards questions still go to the specialist.
    assert "(answered by standards-rules-specialist)" in _section(_text(tmp_path), "Yields")[0]


def test_the_yield_table_routes_priorities_rule_yields_to_the_operator() -> None:
    recipe = (REPO_ROOT / "agents" / "orchestrator.md").read_text(encoding="utf-8")
    row = next(ln for ln in recipe.splitlines() if ln.startswith("| `[STATUS: YIELD_STANDARDS]"))
    assert "A question that starts `priorities rule <n>:` is a surfaced default" in row
    assert "goes to the operator as the Priorities rule says" in row
    assert "never to the standards specialist" in row


# Requirement 9: "priorities": null reads as no block declared.


def test_a_null_priorities_block_is_none_declared(tmp_path: Path) -> None:
    (tmp_path / "service-manifest.json").write_text(json.dumps({"priorities": None}))
    loaded = load_manifest(tmp_path)
    assert loaded is not None and loaded.priorities is None
    (tmp_path / "service-manifest.json").write_text(json.dumps({"priorities": "security"}))
    with pytest.raises(ManifestError):
        load_manifest(tmp_path)


# Requirements 10 to 13: the verifier follow-ups.


def test_the_orchestrator_bash_rules_name_the_new_train_scripts() -> None:
    recipe = (REPO_ROOT / "agents" / "orchestrator.md").read_text(encoding="utf-8")
    rule = next(ln for ln in recipe.splitlines() if ln.startswith("- Your Bash runs only"))
    for part in (
        "daedalus_doctor.py --print-cache-dir and --check-tools",
        "daedalus_map.py --repo",
        "freeze_sources.py in both its forms, --train and --verify",
    ):
        assert part in rule, part
    assert "daedalus_doctor.py --print-cache-dir, audit_report.py and validate_plan.py," not in rule


def test_setup_step_two_covers_the_literacy_line() -> None:
    step = _flat("skills/setup/SKILL.md").split(" 2. ", 1)[1].split(" 3. ", 1)[0]
    assert "Each line names one file" in step
    assert "`docs.literacy: null; examples: <examples>`" in step


def test_the_verified_line_comment_points_at_the_verifier_contract() -> None:
    verifier = (REPO_ROOT / "agents" / "verifier.md").read_text(encoding="utf-8").splitlines()
    line = next(i for i, ln in enumerate(verifier, 1) if ln.startswith("- `[VERDICT: VERIFIED]"))
    workspace = (REPO_ROOT / "scripts" / "lib" / "workspace.py").read_text(encoding="utf-8")
    assert f"agents/verifier.md:{line}:" in workspace
    assert "agents/verifier.md:67:" not in workspace


def test_doc_outputs_is_named_by_agent_files_alone() -> None:
    from tests.test_agent_hooks import LOADED

    named = {hook.script for agent in LOADED.values() for hook in agent.hooks}
    assert "doc_outputs" in named
    source = (REPO_ROOT / "tests" / "test_agent_hooks.py").read_text(encoding="utf-8")
    assert '{"doc_outputs"}' not in source

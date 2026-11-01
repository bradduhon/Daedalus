# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, 0053: the root_writes hook; cases copied from tests/test_jail.py run each agent's chain.
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from lib import jail
from lib.config import Config, LedgerDecl

from tests.conftest import CFG, CWD, write_folder_run, write_train_marker
from tests.hook_chain import (
    decide,
    evaluate,
    internal_error_denies,
    payload,
    run_script,
)
from tests.jail_cases import _MANIFEST_LEDGER, _git_init
from tests.payloads import _b, _w, _wr

pytestmark = pytest.mark.usefixtures("jail_fakes")
HOOK = "root_writes"


class TestContractSpec:
    def test_writes_contracts_or_charter_specs_only(self) -> None:
        assert decide(_w("contract-spec", f"{CWD}/contracts/openapi.yaml"), CFG).allow
        assert decide(_w("contract-spec", "/work/Charter/specs/x.md"), CFG).allow
        assert not decide(_w("contract-spec", f"{CWD}/src/a.py"), CFG).allow
        assert not decide(_w("contract-spec", "/work/Charter/decision-log.md"), CFG).allow

    def test_without_charter_root_only_contracts(self) -> None:
        assert not decide(_w("contract-spec", "/work/Charter/specs/x.md"), Config()).allow


class TestCharterDocs:
    def test_ledger_file_is_never_written_directly(self) -> None:
        d = decide(_w("charter-docs", "/work/Charter/decision-log.md"), CFG)
        assert not d.allow and "append_ledger.py" in d.reason

    def test_writes_charter_or_docs(self) -> None:
        assert decide(_w("charter-docs", "/work/Charter/audit/s.md"), CFG).allow
        assert decide(_w("charter-docs", f"{CWD}/docs/x.md"), CFG).allow
        assert not decide(_w("charter-docs", f"{CWD}/src/a.py"), CFG).allow


class TestFixWaveLedgerResolution:
    @pytest.mark.parametrize("tool", ["Write", "Edit"])
    def test_manifest_ledger_blocked(self, tmp_path: Path, tool: str) -> None:
        repo = _git_init(tmp_path / "repo")
        manifest = {"ledger": _MANIFEST_LEDGER}
        (repo / "service-manifest.json").write_text(json.dumps(manifest))
        d = decide(_wr(repo, repo / "docs" / "adr.md", tool), Config())
        assert not d.allow and d.reason is not None and "append_ledger.py" in d.reason
        assert decide(_wr(repo, repo / "docs" / "notes.md", tool), Config()).allow

    @pytest.mark.parametrize("tool", ["Write", "Edit"])
    def test_probed_ledger_blocked(self, tmp_path: Path, tool: str) -> None:
        repo = _git_init(tmp_path / "repo")
        (repo / "docs").mkdir()
        (repo / "docs" / "decisions.md").write_text("| Id | Date |\n|---|---|\n")
        d = decide(_wr(repo, repo / "docs" / "decisions.md", tool), Config())
        assert not d.allow and d.reason is not None and "append_ledger.py" in d.reason

    def test_default_ledger_protected_beside_a_declared_one(self, tmp_path: Path) -> None:
        repo = _git_init(tmp_path / "repo")
        (repo / "docs").mkdir()
        (repo / "docs" / "decisions.md").write_text("| Id | Date |\n|---|---|\n")
        cfg = Config(ledger=LedgerDecl(repo / "LEDGER.md", "heading-entry", "{seq}", "last-row-id"))
        assert not decide(_wr(repo, repo / "docs" / "decisions.md"), cfg).allow
        assert not decide(_wr(repo, repo / "LEDGER.md"), cfg).allow

    def test_config_ledger_still_blocked(self, tmp_path: Path) -> None:
        repo = _git_init(tmp_path / "repo")
        decl = LedgerDecl(repo / "docs" / "log.md", "markdown-table-row", "{seq}", "last-row-id")
        assert not decide(_wr(repo, repo / "docs" / "log.md"), Config(ledger=decl)).allow

    def test_no_ledger_nothing_protected(self, tmp_path: Path) -> None:
        repo = _git_init(tmp_path / "repo")
        assert decide(_wr(repo, repo / "docs" / "decisions.md"), Config()).allow

    @staticmethod
    def _probed(tmp_path: Path) -> Path:
        repo = _git_init(tmp_path / "repo")
        (repo / "docs" / ".tmp").mkdir(parents=True)
        (repo / "docs" / "decisions.md").write_text("| Id | Date |\n|---|---|\n")
        return repo

    def test_case_variant_spelling_blocked(self, tmp_path: Path) -> None:
        # FW-I1: casefold branch; Decisions.md does not exist as a separate file.
        repo = self._probed(tmp_path)
        target = repo / "docs" / "Decisions.md"
        if not target.exists():
            assert not decide(_wr(repo, target), Config()).allow
        else:
            assert os.path.samefile(target, repo / "docs" / "decisions.md")
            assert not decide(_wr(repo, target, "Edit"), Config()).allow

    def test_hardlink_to_ledger_blocked(self, tmp_path: Path) -> None:
        # FW-I1: samefile branch; an existing name that is the ledger's inode.
        repo = self._probed(tmp_path)
        alias = repo / "docs" / "alias.md"
        os.link(repo / "docs" / "decisions.md", alias)
        assert not decide(_wr(repo, alias, "Edit"), Config()).allow

    def test_symlink_to_ledger_blocked(self, tmp_path: Path) -> None:
        repo = self._probed(tmp_path)
        link = repo / "docs" / "link.md"
        link.symlink_to(repo / "docs" / "decisions.md")
        assert not decide(_wr(repo, link), Config()).allow

    def test_dotdot_path_to_ledger_blocked(self, tmp_path: Path) -> None:
        repo = self._probed(tmp_path)
        d = decide(_wr(repo, Path(f"{repo}/docs/.tmp/../decisions.md")), Config())
        assert not d.allow

    def test_other_doc_allowed_beside_ledger(self, tmp_path: Path) -> None:
        repo = self._probed(tmp_path)
        assert decide(_wr(repo, repo / "docs" / "other.md"), Config()).allow
        (repo / "docs" / "other.md").write_text("x")
        assert decide(_wr(repo, repo / "docs" / "other.md", "Edit"), Config()).allow

    def test_malformed_manifest_fails_closed_with_next(self, tmp_path: Path) -> None:
        repo = _git_init(tmp_path / "repo")
        (repo / "service-manifest.json").write_text("{not json")
        d = decide(_wr(repo, repo / "docs" / "notes.md"), Config())
        assert not d.allow and d.reason is not None
        assert "fail closed" in d.reason and "Next: fix the manifest syntax." in d.reason


def test_root_writes_judges_the_hook_alone() -> None:
    spec = ("--touch", "contracts,charter-specs")
    assert evaluate(HOOK, _w("x", f"{CWD}/contracts/a.yaml"), *spec) is None
    reason = evaluate(HOOK, _w("x", f"{CWD}/docs/a.md"), *spec)
    assert reason == jail.R_CONTRACT_SPEC_WRITE
    docs = ("--touch", "charter,docs")
    assert evaluate(HOOK, _w("x", f"{CWD}/src/a.py"), *docs) == jail.R_CHARTER_DOCS_WRITE
    reason = evaluate(HOOK, _w("x", f"{CWD}/src/a.py"), "--touch", "docs")
    assert reason == f"writes are limited to docs: {CWD}/src/a.py. Next: write there."
    assert evaluate(HOOK, _b("x", f"tee {CWD}/docs/a.md"), "--touch", "docs") is None
    assert evaluate(HOOK, _b("x", f"tee {CWD}/src/a.md"), "--touch", "docs") is not None
    assert evaluate(HOOK, _w("x", f"{CWD}/docs/a.md")) is not None


def test_root_writes_name_narrows_to_one_file_in_a_class_root() -> None:
    flags = ("--touch", "docs", "--name", "notes.md")
    assert evaluate(HOOK, _w("x", f"{CWD}/docs/notes.md"), *flags) is None
    assert evaluate(HOOK, _w("x", f"{CWD}/docs/other.md"), *flags) is not None
    assert evaluate(HOOK, _w("x", f"{CWD}/docs/sub/notes.md"), *flags) is not None
    bad = evaluate(HOOK, _w("x", f"{CWD}/docs/notes.md"), "--touch", "docs", "--name", "../x")
    assert bad is not None and bad.startswith("hook root_writes failed closed")


def test_root_writes_scratch_class_follows_the_train(tmp_path: Path) -> None:
    # 0053: in a train the scratch root is docs/.tmp/daedalus/<train-id>/; without one it is
    # docs/.tmp/daedalus/ itself (spec 3.1, the planner outside a train).
    repo = _git_init(tmp_path / "repo")
    target = f"{repo}/docs/.tmp/daedalus/20261017-120000/brief.md"
    hook_input = {**_w("x", target), "cwd": str(repo)}
    assert evaluate(HOOK, hook_input, "--touch", "scratch") is None
    outside = {**_w("x", f"{repo}/docs/notes.md"), "cwd": str(repo)}
    assert evaluate(HOOK, outside, "--touch", "scratch") is not None
    (repo / ".claude" / "daedalus").mkdir(parents=True)
    write_train_marker(repo)
    assert evaluate(HOOK, hook_input, "--touch", "scratch") is None
    other = {**_w("x", f"{repo}/docs/.tmp/daedalus/20261017-999999/b.md"), "cwd": str(repo)}
    assert evaluate(HOOK, other, "--touch", "scratch") is not None


def test_root_writes_scratch_class_refuses_the_trains_summary_file(tmp_path: Path) -> None:
    # W3.2: the summary command writes the summary; the scratch class admits only the folder.
    repo = _git_init(tmp_path / "repo")
    scratch = f"{repo}/docs/.tmp/daedalus"

    def judged(path: str, *flags: str) -> str | None:
        return evaluate(HOOK, {**_w("x", path), "cwd": str(repo)}, "--touch", "scratch", *flags)

    summary = f"{scratch}/20261017-120000-summary.md"
    (repo / ".claude" / "daedalus").mkdir(parents=True)
    write_train_marker(repo)
    assert judged(f"{scratch}/20261017-120000/summary-notes.md") is None
    for path in (
        summary,
        f"{scratch}/20261017-999999-summary.md",
        f"{scratch}/20261017-120000-charter-pr.md",
        f"{scratch}/other.md",
        f"{repo}/docs/howto/README.md",
        f"{repo}/docs/private/specs/x.md",
    ):
        assert judged(path) is not None, path
    # spec 3.1: --name keeps the planner to its own file; the summary never passes it.
    assert judged(summary, "--name", "plan*.md") is not None


def test_root_writes_name_takes_a_glob() -> None:
    flags = ("--touch", "docs", "--name", "plan*.md")
    assert evaluate(HOOK, _w("x", f"{CWD}/docs/plan.md"), *flags) is None
    assert evaluate(HOOK, _w("x", f"{CWD}/docs/plan-2026-10-19.md"), *flags) is None
    assert evaluate(HOOK, _w("x", f"{CWD}/docs/other.md"), *flags) is not None
    assert evaluate(HOOK, _w("x", f"{CWD}/docs/plan.txt"), *flags) is not None
    assert evaluate(HOOK, _w("x", f"{CWD}/docs/sub/plan.md"), *flags) is not None
    for bad in ("plan/*.md", "../plan*.md", "plan?.md", "[p]lan.md"):
        reason = evaluate(HOOK, _w("x", f"{CWD}/docs/plan.md"), "--touch", "docs", "--name", bad)
        assert reason is not None and reason.startswith("hook root_writes failed closed"), bad


def _sub_judged(repo: Path, path: str, *flags: str) -> str | None:
    hook_input = {**_w("x", path), "cwd": str(repo)}
    return evaluate(HOOK, hook_input, "--touch", "scratch", *flags)


def test_root_writes_sub_admits_one_folder_level(tmp_path: Path) -> None:
    # 0152: brainstorm spec 4.3, the planner's draft one folder below scratch.
    repo = _git_init(tmp_path / "repo")
    scratch = repo / "docs" / ".tmp" / "daedalus"
    (scratch / "brainstorm-a").mkdir(parents=True)
    flags = ("--sub", "brainstorm-*/spec.md")
    assert _sub_judged(repo, f"{scratch}/brainstorm-a/spec.md", *flags) is None
    assert _sub_judged(repo, f"{scratch}/brainstorm-new/spec.md", *flags) is None
    for path in (
        f"{scratch}/brainstorm-a/b/spec.md",
        f"{scratch}/x/brainstorm-a/spec.md",
        f"{scratch}/brainstorm-a/../spec.md",
        f"{scratch}/brainstorm-a/../../spec.md",
        f"{scratch}/../brainstorm-a/spec.md",
        f"{scratch}/brainstorm-a/../other/spec.md",
        f"{scratch}/brainstorm-a/plan.md",
        f"{scratch}/brainstorm-a/spec.md.bak",
        f"{scratch}/spec.md",
        f"{scratch}/other/spec.md",
        f"{repo}/docs/brainstorm-a/spec.md",
    ):
        assert _sub_judged(repo, path, *flags) is not None, path


def test_root_writes_sub_refuses_symlinks_out_of_scratch(tmp_path: Path) -> None:
    repo = _git_init(tmp_path / "repo")
    scratch = repo / "docs" / ".tmp" / "daedalus"
    scratch.mkdir(parents=True)
    outside = tmp_path / "outside"
    (outside / "brainstorm-x").mkdir(parents=True)
    os.symlink(outside / "brainstorm-x", scratch / "brainstorm-link")
    (scratch / "brainstorm-f").mkdir()
    os.symlink(outside / "spec.md", scratch / "brainstorm-f" / "spec.md")
    flags = ("--sub", "brainstorm-*/spec.md")
    assert _sub_judged(repo, f"{scratch}/brainstorm-link/spec.md", *flags) is not None
    assert _sub_judged(repo, f"{scratch}/brainstorm-f/spec.md", *flags) is not None


def test_root_writes_sub_judges_the_folder_and_the_file_realpath(tmp_path: Path) -> None:
    repo = _git_init(tmp_path / "repo")
    scratch = repo / "docs" / ".tmp" / "daedalus"
    for folder in ("brainstorm-a", "brainstorm-b", "brainstorm-y"):
        (scratch / folder).mkdir(parents=True)
    outside = tmp_path / "outside" / "brainstorm-x"
    outside.mkdir(parents=True)
    # 0152: folder out of scratch whose spec.md links back in; the folder's realpath refuses it.
    os.symlink(outside, scratch / "brainstorm-link")
    os.symlink(scratch / "brainstorm-y" / "spec.md", outside / "spec.md")
    # 0152: a spec.md that resolves to another name, and another name that resolves to spec.md.
    os.symlink(scratch / "brainstorm-b" / "notes.md", scratch / "brainstorm-a" / "spec.md")
    os.symlink(scratch / "brainstorm-y" / "spec.md", scratch / "brainstorm-b" / "alias")
    flags = ("--sub", "brainstorm-*/spec.md")
    assert _sub_judged(repo, f"{scratch}/brainstorm-y/spec.md", *flags) is None
    for path in (
        f"{scratch}/brainstorm-link/spec.md",
        f"{scratch}/brainstorm-a/spec.md",
        f"{scratch}/brainstorm-b/alias",
    ):
        assert _sub_judged(repo, path, *flags) is not None, path


def test_root_writes_sub_and_name_admit_either(tmp_path: Path) -> None:
    repo = _git_init(tmp_path / "repo")
    scratch = repo / "docs" / ".tmp" / "daedalus"
    flags = ("--name", "plan*.md", "--sub", "brainstorm-*/spec.md")
    assert _sub_judged(repo, f"{scratch}/plan-2026-10-26.md", *flags) is None
    assert _sub_judged(repo, f"{scratch}/brainstorm-a/spec.md", *flags) is None
    assert _sub_judged(repo, f"{scratch}/brainstorm-a/plan.md", *flags) is not None
    assert _sub_judged(repo, f"{scratch}/spec.md", *flags) is not None
    assert _sub_judged(repo, f"{scratch}/other.md", *flags) is not None
    bash = {**_b("x", f"touch {scratch}/brainstorm-a/spec.md"), "cwd": str(repo)}
    assert evaluate(HOOK, bash, "--touch", "scratch", *flags) is None
    bash = {**_b("x", f"touch {scratch}/brainstorm-a/b/spec.md"), "cwd": str(repo)}
    assert evaluate(HOOK, bash, "--touch", "scratch", *flags) is not None


@pytest.mark.parametrize(
    "bad",
    [
        "brainstorm-*/spe*.md",
        "brainstorm-*/spec?.md",
        "brainstorm-*/[s]pec.md",
        "brainstorm-*/a/spec.md",
        "brainstorm-*/../spec.md",
        "../spec.md",
        "brainstorm-*/",
        "spec.md",
        "/spec.md",
        "brainstorm-?/spec.md",
    ],
)
def test_root_writes_sub_flag_value_fails_closed(bad: str) -> None:
    reason = evaluate(HOOK, _w("x", f"{CWD}/docs/b/spec.md"), "--touch", "docs", "--sub", bad)
    assert reason is not None and reason.startswith("hook root_writes failed closed"), bad


def _planner(repo: Path, path: str) -> tuple[bool, str | None, str]:
    # spec 3.1: the planner's own agent-file hooks, run as the router runs them.
    from lib import router

    from tests.conftest import REPO_ROOT

    payload = {**_w("daedalus:planner", path), "cwd": str(repo)}
    return router.route(payload, REPO_ROOT)


def test_planner_writes_its_plan_outside_a_train(tmp_path: Path) -> None:
    repo = _git_init(tmp_path / "repo")
    scratch = repo / "docs" / ".tmp" / "daedalus"
    assert _planner(repo, f"{scratch}/plan-2026-10-19.md") == (True, None, "")
    for path in (f"{scratch}/other.md", f"{repo}/docs/plan.md", f"{scratch}/t/plan.md"):
        allow, _, hook = _planner(repo, path)
        assert not allow and hook == "root_writes", path


def test_planner_writes_its_plan_inside_a_train(tmp_path: Path) -> None:
    repo = _git_init(tmp_path / "repo")
    (repo / ".claude" / "daedalus").mkdir(parents=True)
    write_train_marker(repo)
    scratch = repo / "docs" / ".tmp" / "daedalus"
    assert _planner(repo, f"{scratch}/20261017-120000/plan.md") == (True, None, "")
    for path in (
        f"{scratch}/20261017-120000/other.md",
        f"{scratch}/plan-2026-10-19.md",
        f"{repo}/src/plan.md",
    ):
        allow, _, hook = _planner(repo, path)
        assert not allow and hook == "root_writes", path


def test_root_writes_repeated_flag_denies() -> None:
    reason = evaluate(HOOK, _w("x", f"{CWD}/docs/a.md"), "--touch", "scratch", "--touch", "docs")
    assert reason == "hook root_writes failed closed (flag --touch is given twice)"


def test_root_writes_fixture_decisions() -> None:
    ok = payload("Write", agent="contract-spec", file_path=f"{CWD}/contracts/a.yaml")
    spec = ("--touch", "contracts,charter-specs")
    assert run_script(HOOK, ok, *spec) == {"decision": "allow", "reason": ""}
    bad = payload("Write", agent="contract-spec", file_path=f"{CWD}/src/a.py")
    assert run_script(HOOK, bad, *spec) == {
        "decision": "deny",
        "reason": jail.R_CONTRACT_SPEC_WRITE,
    }
    wrong = run_script(HOOK, ok, "--touch", "unit-src-tests")
    assert wrong["decision"] == "deny" and wrong["reason"].startswith("hook root_writes failed")


def test_root_writes_internal_error_denies_and_names_the_hook() -> None:
    inside = payload("Write", file_path=f"{CWD}/docs/a.md")
    internal_error_denies(HOOK, inside, "--touch", "docs")


TRAIN = "20261017-120000"


def _audit_judged(repo: Path, path: str, tool: str = "Write") -> str | None:
    return evaluate(HOOK, {**_w("x", path, tool), "cwd": str(repo)}, "--touch", "audit")


def test_root_writes_audit_class_admits_only_the_trains_audit_folder(tmp_path: Path) -> None:
    # 0109, spec 3.1: docs/.tmp/daedalus/<train-id>/audit/ in a train; nothing outside a train.
    repo = _git_init(tmp_path / "repo")
    scratch = f"{repo}/docs/.tmp/daedalus"
    inside = f"{scratch}/{TRAIN}/audit/round1/test_scope_x.py"
    findings = f"{scratch}/{TRAIN}/audit/round1/findings.txt"
    assert _audit_judged(repo, inside) is not None
    (repo / ".claude" / "daedalus").mkdir(parents=True)
    write_train_marker(repo, TRAIN)
    for path in (inside, findings):
        for tool in ("Write", "Edit"):
            assert _audit_judged(repo, path, tool) is None, (path, tool)
    for path in (
        f"{scratch}/{TRAIN}-summary.md",
        f"{scratch}/{TRAIN}/briefs/c1.md",
        f"{scratch}/{TRAIN}/plan.md",
        f"{scratch}/{TRAIN}/audit/../briefs/c1.md",
        f"{scratch}/20261017-999999/audit/round1/test_x.py",
        f"{repo}/scripts/checks/root_writes.py",
        f"{repo}/.claude/worktrees/{TRAIN}-audit/tests/adversarial/test_x.py",
    ):
        reason = _audit_judged(repo, path)
        assert reason == f"writes are limited to audit: {path}. Next: write there.", path


def test_root_writes_audit_class_refuses_a_symlink_out_of_the_folder(tmp_path: Path) -> None:
    repo = _git_init(tmp_path / "repo")
    (repo / ".claude" / "daedalus").mkdir(parents=True)
    write_train_marker(repo, TRAIN)
    audit = repo / "docs" / ".tmp" / "daedalus" / TRAIN / "audit"
    audit.mkdir(parents=True)
    (repo / "src").mkdir()
    (audit / "link").symlink_to(repo / "src")
    assert _audit_judged(repo, f"{audit}/link/a.py") is not None


def test_auditor_chain_writes_its_audit_folder_only(tmp_path: Path) -> None:
    # 0109: the auditor's own agent-file hooks, run as the router runs them.
    from lib import router

    from tests.conftest import REPO_ROOT

    repo = _git_init(tmp_path / "repo")
    (repo / ".claude" / "daedalus").mkdir(parents=True)
    write_train_marker(repo, TRAIN)
    scratch = f"{repo}/docs/.tmp/daedalus/{TRAIN}"

    def route(path: str) -> tuple[bool, str | None, str]:
        return router.route({**_w("daedalus:auditor", path), "cwd": str(repo)}, REPO_ROOT)

    assert route(f"{scratch}/audit/round1/test_scope_x.py") == (True, None, "")
    for path in (f"{scratch}/briefs/c1.md", f"{repo}/src/a.py"):
        allow, _, hook = route(path)
        assert not allow and hook == "root_writes", path
    verifier = {**_w("daedalus:verifier", f"{scratch}/audit/round1/x.py"), "cwd": str(repo)}
    allow, _, hook = router.route(verifier, REPO_ROOT)
    assert not allow and hook == "tool_bound"


def test_planner_writes_its_shapes_into_a_folder_runs_output_folder(tmp_path: Path) -> None:
    # issue 48: a folder run's recorded output_dir takes the planner's scratch shapes, nothing more.
    root, out = tmp_path.resolve() / "plain", tmp_path.resolve() / "out"
    root.mkdir()
    (out / "brainstorm-a").mkdir(parents=True)
    plan, spec = f"{out}/plan-20261027.md", f"{out}/brainstorm-a/spec.md"
    write_folder_run(root, out)
    assert _planner(root, plan) == (True, None, "")
    assert _planner(root, spec) == (True, None, "")
    # (c) off the shapes or outside output_dir.
    for path in (f"{out}/notes.md", f"{out}/x/plan.md", f"{tmp_path}/plan-1.md", f"{out}/../p.md"):
        allow, _, hook = _planner(root, path)
        assert not allow and hook == "root_writes", path
    # (d) a file or folder link under output_dir that resolves outside it.
    outside = tmp_path.resolve() / "outside"
    (outside / "brainstorm-x").mkdir(parents=True)
    os.symlink(outside / "f.md", out / "plan-link.md")
    os.symlink(outside / "brainstorm-x", out / "brainstorm-link")
    for path in (f"{out}/plan-link.md", f"{out}/brainstorm-link/spec.md"):
        allow, _, hook = _planner(root, path)
        assert not allow and hook == "root_writes", path
    # (e) another agent's root_writes flags, the orchestrator's bare scratch class, get nothing.
    hook_input = {**_w("x", plan), "cwd": str(root)}
    assert evaluate(HOOK, hook_input, "--touch", "scratch", "--ledger-guard") is not None
    # (a) a repository run and (b) a folder run with no output_dir are refused as before.
    for scope, recorded in (("repository", out), ("folder", None)):
        write_folder_run(root, recorded, scope)
        allow, _, hook = _planner(root, plan)
        assert not allow and hook == "root_writes", scope
    # issue 48: a recorded output_dir that is itself a link loses the grant.
    os.symlink(out, tmp_path.resolve() / "out-link")
    write_folder_run(root, tmp_path.resolve() / "out-link")
    allow, _, hook = _planner(root, f"{tmp_path.resolve()}/out-link/plan-20261027.md")
    assert not allow and hook == "root_writes"

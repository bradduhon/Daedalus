# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, 0054: the unit_writes hook; cases copied from tests/test_jail.py run each agent's chain.
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from lib import jail
from lib.config import Config, LedgerDecl

from tests.conftest import CFG, CWD, WT
from tests.hook_chain import (
    decide,
    evaluate,
    internal_error_denies,
    malformed_input_denies,
    outside_tools_allow,
    payload,
    run_script,
    unknown_flag_denies,
)
from tests.test_jail import BUILTIN_REL, NARROWING, _b, _cwd, _narrowed_repo, _unit_repo, _w

pytestmark = pytest.mark.usefixtures("jail_fakes")
HOOK = "unit_writes"


class TestRepoCoder:
    def test_main_checkout_writes_refused(self) -> None:
        # 0022, 0054: the main checkout is never a coder write target; see the unit worktree tests.
        assert not decide(_w("repo-coder", f"{CWD}/src/a.py"), CFG).allow
        assert not decide(_w("repo-coder", f"{CWD}/tests/test_a.py", "Edit"), CFG).allow
        assert not decide(_w("repo-coder", f"{CWD}/service-manifest.json"), CFG).allow
        assert not decide(_w("repo-coder", f"{CWD}/src/../infra/a.tf"), CFG).allow
        assert not decide(_w("repo-coder", "/other/repo/src/a.py"), CFG).allow

    def test_local_work_allowed(self) -> None:
        for command in (
            "pytest -q",
            "npm run test:unit",
            f"git -C {WT} add -A && git -C {WT} commit -m 'WIP: yield'",
            "git diff",
        ):
            assert decide(_b("repo-coder", command), CFG).allow, command


class TestRegressionRepoCoder:
    def test_relative_paths_resolve_against_cwd(self) -> None:
        assert not decide(_w("repo-coder", "src/a.py"), CFG).allow
        assert decide(_w("repo-coder", ".claude/worktrees/u1/src/a.py"), CFG).allow
        assert not decide(_w("repo-coder", "infra/a.tf"), CFG).allow

    def test_notebook_path(self) -> None:
        def nb(path: str) -> dict[str, Any]:
            return {
                "tool_name": "NotebookEdit",
                "tool_input": {"notebook_path": path},
                "cwd": CWD,
                "agent_type": "repo-coder",
            }

        assert evaluate(HOOK, nb(f"{CWD}/.claude/worktrees/u1/src/n.ipynb")) is None
        # open item 4: repo-coder lists no NotebookEdit tool, so tool_bound refuses the chain.
        assert decide(nb(f"{CWD}/.claude/worktrees/u1/src/n.ipynb"), CFG).reason == jail.R_TOOL
        assert not decide(nb(f"{CWD}/src/n.ipynb"), CFG).allow
        assert not decide(nb(f"{CWD}/docs/n.ipynb"), CFG).allow
        assert evaluate(HOOK, nb(f"{CWD}/src/n.ipynb")) is not None


class TestRound3SortPytestGitleaks:
    @pytest.mark.parametrize(
        "command",
        [
            "pytest --basetemp=/tmp/x",
            "pytest --basetemp /tmp/x",
            "python -m pytest --basetemp x",
            "uv run pytest --basetemp=x",
        ],
    )
    def test_basetemp_denied(self, command: str) -> None:
        assert not decide(_b("repo-coder", command), CFG).allow, command


class TestFinalCoderWriteTargets:
    @pytest.mark.parametrize(
        "command",
        [
            "cp src/a.py docs/project-requirements.md",
            "sed -i s/a/b/ contracts/openapi.yaml",
            "tee service-manifest.json",
            "mv src/a.py /tmp/a.py",
            "ln -s /etc/passwd src/p",
            "install -m 644 src/a.py /usr/local/bin/a",
            "truncate -s 0 service-manifest.json",
            "dd of=contracts/x.yaml",
            "rsync -a src/ ../other/",
            "cp --target-directory=docs/x src/a.py",
            "sed -i.bak -e s/a/b/ docs/x.md",
            "cp src/../infra/a.tf src/a.tf",
        ],
    )
    def test_blocked(self, command: str) -> None:
        d = decide(_b("repo-coder", command), CFG)
        assert not d.allow and d.reason.startswith("Bash write outside your unit worktree:"), (
            command
        )
        assert "Next:" in d.reason

    @pytest.mark.parametrize(
        "command",
        [
            "cp .claude/worktrees/u1/src/a.py .claude/worktrees/u1/src/b.py",
            "sed -i s/a/b/ .claude/worktrees/u1/src/a.py",
            "tee .claude/worktrees/u1/tests/out.txt",
            "mv .claude/worktrees/u1/src/a.py .claude/worktrees/u1/tests/a.py",
            "install -m 644 .claude/worktrees/u1/src/a.py .claude/worktrees/u1/src/b.py",
            "truncate -s 0 .claude/worktrees/u1/tests/out.txt",
            "sed -n 1p docs/x.md",
            "sed --in-place=.bak s/a/b/ .claude/worktrees/u1/src/a.py",
        ],
    )
    def test_allowed(self, command: str) -> None:
        assert decide(_b("repo-coder", command), CFG).allow, command

    @pytest.mark.parametrize(
        "command",
        [
            "cp src/a.py src/b.py",
            "sed -i s/a/b/ src/a.py",
            "tee tests/out.txt",
            "mv .claude/worktrees/u1/src/a.py tests/a.py",
            "install -m 644 src/a.py src/b.py",
            "truncate -s 0 tests/out.txt",
            "sed --in-place=.bak s/a/b/ src/a.py",
        ],
    )
    def test_main_checkout_blocked(self, command: str) -> None:
        # 0022: the same grammar aimed at the main checkout is refused.
        d = decide(_b("repo-coder", command), CFG)
        assert not d.allow and d.reason.startswith("Bash write outside your unit worktree:"), (
            command
        )


class TestProjectDataDir:
    @pytest.mark.parametrize(
        "command",
        [
            "git add -A",
            "git add src/a.py",
            'git commit -m "keep .claude/daedalus out of git"',
            "git status --porcelain",
        ],
    )
    def test_ordinary_git_add_commit_allowed(self, command: str) -> None:
        # 0022: the coder runs the same command inside its unit worktree.
        assert decide(_b("repo-coder", f"git -C {WT} {command[4:]}"), CFG).allow, command


def test_coder_writes_inside_a_unit_worktree() -> None:
    # 0022: the coder's cwd is the main checkout; its code dirs live in the unit worktree.
    assert decide(_w("repo-coder", f"{WT}/src/a.py"), CFG).allow
    assert decide(_w("repo-coder", f"{WT}/tests/test_a.py", "Edit"), CFG).allow
    assert decide(_b("repo-coder", f"cp {WT}/src/a.py {WT}/src/b.py"), CFG).allow


@pytest.mark.parametrize(
    "path",
    [
        f"{CWD}/.claude/worktrees/src/a.py",
        f"{CWD}/.claude/worktrees/x/../../daedalus/src/a.py",
        "/other/repo/.claude/worktrees/u1/src/a.py",
    ],
)
def test_coder_write_outside_a_unit_worktree_is_refused(path: str) -> None:
    d = decide(_w("repo-coder", path), CFG)
    assert not d.allow and "Next:" in str(d.reason), path


def test_coder_write_outside_reason() -> None:
    d = decide(_w("repo-coder", f"{CWD}/infra/a.tf"), CFG)
    want = f"write outside your unit worktree: {CWD}/infra/a.tf. Next: ask the orchestrating"
    assert not d.allow and str(d.reason).startswith(want)


@pytest.mark.parametrize(
    "rel", ["scripts/x.py", "scripts/lib/y.py", "infra/a.tf", "README.md", "docs/x.md"]
)
def test_coder_writes_anywhere_unprotected_in_its_worktree(rel: str) -> None:
    # 0054: the boundary is the unit worktree minus protected paths.
    assert decide(_w("repo-coder", f"{WT}/{rel}"), CFG).allow, rel
    assert decide(_w("repo-coder", f"{WT}/{rel}", "Edit"), CFG).allow, rel
    assert decide(_b("repo-coder", f"tee {WT}/{rel}"), CFG).allow, rel


@pytest.mark.parametrize("rel", BUILTIN_REL)
def test_coder_builtin_protected_paths_are_refused(rel: str) -> None:
    target = f"{WT}/{rel}"
    want = f"protected path (built in): {target}. Next: ask the orchestrating session"
    for hook_input in (_w("repo-coder", target), _w("repo-coder", target, "Edit")):
        d = decide(hook_input, CFG)
        assert not d.allow and str(d.reason).startswith(want), (rel, d.reason)
        assert "contract-spec or charter-docs" in str(d.reason)
    d = decide(_b("repo-coder", f"tee {target}"), CFG)
    assert not d.allow and str(d.reason).startswith(want), (rel, d.reason)


@pytest.mark.parametrize(
    "command",
    [
        f"cp {WT}/src/a.py {WT}/contracts/openapi.yaml",
        f"sed -i s/a/b/ {WT}/.github/workflows/ci.yml",
        f"rm -r {WT}/.github",
        f"cp {WT}/src/a {WT}/.github/CODEOWNERS",
        f"mv {WT}/contracts {WT}/c2",
        f"truncate -s 0 {WT}/service-manifest.json",
        f"tee {WT}/.git",
        f"git -C {WT} restore -- contracts/openapi.yaml",
        f"git restore -- {WT}/.claude/settings.json",
    ],
)
def test_coder_bash_writes_to_builtin_protected_paths_are_refused(command: str) -> None:
    d = decide(_b("repo-coder", command), CFG)
    assert not d.allow and str(d.reason).startswith("protected path (built in):"), command


def test_coder_repo_local_ledger_in_worktree_is_refused() -> None:
    # 0054: the ledger begin resolves, mapped into the worktree, is a built-in protected path.
    decl = LedgerDecl(Path("docs/decisions.md"), "markdown-table-row", "{seq:04d}", "last-row-id")
    cfg = Config(ledger=decl)
    target = f"{WT}/docs/decisions.md"
    d = decide(_w("repo-coder", target), cfg)
    assert not d.allow and str(d.reason).startswith(f"protected path (built in): {target}.")
    d = decide(_b("repo-coder", f"rm -r {WT}/docs"), cfg)
    assert not d.allow and str(d.reason).startswith("protected path (built in):")
    assert decide(_w("repo-coder", f"{WT}/docs/other.md"), cfg).allow
    # 0054: a ledger outside the repo has no worktree copy to protect.
    assert decide(_w("repo-coder", f"{WT}/docs/decisions.md"), CFG).allow


def test_coder_restores_paths_inside_its_unit_worktree() -> None:
    assert decide(_b("repo-coder", f"git restore -- {WT}/src/a.py"), CFG).allow


def test_coder_cannot_write_the_main_checkout() -> None:
    # 0022: coders own a unit worktree; the main checkout is never their write target.
    assert not decide(_w("repo-coder", f"{CWD}/src/a.py"), CFG).allow
    assert not decide(_w("repo-coder", f"{CWD}/tests/test_a.py", "Edit"), CFG).allow
    assert not decide(_b("repo-coder", f"cp a {CWD}/src/b.py"), CFG).allow
    assert not decide(_b("repo-coder", f"git restore -- {CWD}/src/a.py"), CFG).allow


def test_coder_unit_worktree_through_a_symlinked_root(tmp_path: Path) -> None:
    # 0022: a symlinked path to the repo and the real path resolve to one worktree base.
    repo, _ = _unit_repo(tmp_path / "real")
    link = tmp_path / "link"
    link.symlink_to(repo)
    for cwd, root in ((link, repo), (repo, link), (link, link)):
        hook_input = _w("repo-coder", f"{root}/.claude/worktrees/u1/src/a.py")
        hook_input["cwd"] = str(cwd)
        hook_input["session_id"] = "s"
        assert decide(hook_input, CFG).allow, (cwd, root)
        hook_input = _w("repo-coder", f"{root}/src/a.py")
        hook_input["cwd"] = str(cwd)
        assert not decide(hook_input, CFG).allow, (cwd, root)


def test_coder_plain_unit_worktree_bash_write_still_allowed() -> None:
    assert decide(_b("repo-coder", f"tee {WT}/src/a.py"), CFG).allow
    assert decide(_b("repo-coder", "set -e"), CFG).allow


def test_coder_unregistered_worktree_dir_is_refused(tmp_path: Path) -> None:
    # 0022: only a git-registered worktree under .claude/worktrees is a unit worktree.
    repo, wt = _unit_repo(tmp_path / "repo")
    evil = repo / ".claude" / "worktrees" / "evil"
    (evil / "src").mkdir(parents=True)
    assert decide(_cwd(_w("repo-coder", f"{wt}/src/a.py"), repo), CFG).allow
    assert not decide(_cwd(_w("repo-coder", f"{evil}/src/a.py"), repo), CFG).allow
    assert not decide(_cwd(_b("repo-coder", f"tee {evil}/src/a.py"), repo), CFG).allow
    assert not decide(_w("repo-coder", f"{CWD}/.claude/worktrees/u2/src/a.py"), CFG).allow


@pytest.mark.parametrize(
    "command",
    [
        f"mkdir -p {CWD}/.claude/worktrees/evil/src",
        "mkdir -p .claude/worktrees/evil/src",
        "touch infra/a.tf",
        f"rm {CWD}/infra/a.tf",
        f"rmdir {CWD}/infra/x",
        f"unlink {CWD}/src/a.py",
        f"chmod 755 {CWD}/scripts/a.sh",
    ],
)
def test_coder_file_mutators_outside_unit_worktree_are_refused(command: str) -> None:
    assert not decide(_b("repo-coder", command), CFG).allow, command


@pytest.mark.parametrize(
    "command",
    [
        f"mkdir -p {WT}/src/pkg",
        f"touch {WT}/tests/__init__.py",
        f"rm {WT}/src/old.py",
        f"chmod 755 {WT}/src/run.py",
    ],
)
def test_coder_file_mutators_inside_unit_worktree_are_allowed(command: str) -> None:
    assert decide(_b("repo-coder", command), CFG).allow, command


@pytest.mark.parametrize(
    "command",
    [
        f"cd {CWD}/infra && tee .claude/worktrees/u1/src/a.py",
        "pushd /tmp && tee .claude/worktrees/u1/src/a.py",
        "cd /tmp && git restore -- .claude/worktrees/u1/src/a.py",
        "cd /tmp && git -C .claude/worktrees/u1 restore -- src/a.py",
        "cd /tmp; cp .claude/worktrees/u1/src/a.py .claude/worktrees/u1/src/b.py",
    ],
)
def test_coder_relative_write_after_cd_is_refused(command: str) -> None:
    # 0022: relative operands after cd resolve against the hook cwd, not the cd target.
    d = decide(_b("repo-coder", command), CFG)
    assert not d.allow and "absolute" in str(d.reason), command


@pytest.mark.parametrize(
    "command",
    [
        f"cd {WT} && tee {WT}/src/a.py",
        f"cd /tmp && git -C {WT} restore -- src/a.py",
        f"cd {WT} && python3 -m pytest -q",
    ],
)
def test_coder_absolute_write_after_cd_is_allowed(command: str) -> None:
    assert decide(_b("repo-coder", command), CFG).allow, command


def test_coder_cwd_inside_a_real_unit_worktree(tmp_path: Path) -> None:
    # 0022: a hook cwd of the worktree or its src/ still binds writes to that worktree.
    repo, wt = _unit_repo(tmp_path / "repo")
    (wt / "src").mkdir()
    for cwd in (wt, wt / "src"):
        assert decide(_cwd(_w("repo-coder", f"{wt}/src/a.py"), cwd), CFG).allow, cwd
        assert decide(_cwd(_w("repo-coder", f"{wt}/tests/t.py"), cwd), CFG).allow, cwd
        assert not decide(_cwd(_w("repo-coder", f"{repo}/src/a.py"), cwd), CFG).allow, cwd
        assert decide(_cwd(_w("repo-coder", f"{wt}/README.md"), cwd), CFG).allow, cwd
        hook_input = _cwd(_w("repo-coder", f"{wt}/.claude/settings.json"), cwd)
        assert not decide(hook_input, CFG).allow, cwd
    assert decide(_cwd(_w("repo-coder", "src/a.py"), wt), CFG).allow


@pytest.mark.parametrize("rel", ["infra/main.tf", "infra", "Makefile", "INFRA/x.tf"])
def test_coder_manifest_forbidden_path_is_refused(tmp_path: Path, rel: str) -> None:
    repo, wt = _narrowed_repo(tmp_path, json.dumps(NARROWING))
    target = f"{wt}/{rel}"
    want = f"protected path (service-manifest.json jail_narrowing): {target}. Next:"
    d = decide(_cwd(_w("repo-coder", target), repo), CFG)
    assert not d.allow and str(d.reason).startswith(want), d.reason
    d = decide(_cwd(_b("repo-coder", f"tee {target}"), repo), CFG)
    assert not d.allow and str(d.reason).startswith(want), d.reason
    assert decide(_cwd(_w("repo-coder", f"{wt}/infra2/x.tf"), repo), CFG).allow
    assert decide(_cwd(_w("repo-coder", f"{wt}/Makefile.d/x"), repo), CFG).allow


def test_coder_manifest_forbidden_extension_is_refused(tmp_path: Path) -> None:
    repo, wt = _narrowed_repo(tmp_path, json.dumps(NARROWING))
    for rel in ("keys/server.pem", "a.PEM"):
        target = f"{wt}/{rel}"
        want = f"protected extension (service-manifest.json jail_narrowing): {target}. Next:"
        d = decide(_cwd(_w("repo-coder", target), repo), CFG)
        assert not d.allow and str(d.reason).startswith(want), d.reason
        d = decide(_cwd(_b("repo-coder", f"cp {wt}/src/a {target}"), repo), CFG)
        assert not d.allow and str(d.reason).startswith(want), d.reason
    assert decide(_cwd(_w("repo-coder", f"{wt}/src/pem.py"), repo), CFG).allow


@pytest.mark.parametrize(
    "manifest",
    [
        "{ not json",
        "[]",
        '{"jail_narrowing": []}',
        '{"jail_narrowing": {"forbidden_paths": ["../x"]}}',
    ],
)
def test_coder_manifest_error_fails_closed(tmp_path: Path, manifest: str) -> None:
    repo, wt = _narrowed_repo(tmp_path, manifest)
    for hook_input in (
        _w("repo-coder", f"{wt}/src/a.py"),
        _b("repo-coder", f"tee {wt}/src/a.py"),
    ):
        d = decide(_cwd(hook_input, repo), CFG)
        reason = str(d.reason)
        assert not d.allow and "coder writes fail closed" in reason and "Next:" in reason
    assert decide(_cwd(_b("repo-coder", "pytest -q"), repo), CFG).allow


@pytest.mark.parametrize(
    "command",
    [
        "mkdir newdir",
        "touch NEWFILE",
        "mkdir -m 700 infra2",
        f"chown x {CWD}/infra/a.tf",
        f"chgrp x {CWD}/infra/a.tf",
        f"chown x:y {WT}/src/a.py {CWD}/infra/a.tf",
        f"install --mode=644 {WT}/src/a.py {CWD}/bin/a",
        f"find {CWD}/infra -delete",
        f"find {WT}/src -exec rm {{}} +",
        f"find {WT}/src -fprint {CWD}/x",
    ],
)
def test_coder_bare_and_owner_operands_are_paths(command: str) -> None:
    # 0022: every non-option operand of a coder write command is a path, no heuristic.
    assert not decide(_b("repo-coder", command), CFG).allow, command


@pytest.mark.parametrize(
    "command",
    [
        f"mkdir {WT}/src/pkg",
        f"mkdir -m 700 {WT}/src/pkg",
        f"touch {WT}/tests/__init__.py",
        f"chown x {WT}/src/a.py",
        f"chmod 755 {WT}/src/a.py",
        f"install -m 644 -o x {WT}/src/a.py {WT}/src/b.py",
        f"install --mode=644 {WT}/src/a.py {WT}/src/b.py",
        f"truncate -s 0 {WT}/tests/out.txt",
        f"find {WT}/src -name '*.py'",
    ],
)
def test_coder_unit_worktree_operands_allowed(command: str) -> None:
    assert decide(_b("repo-coder", command), CFG).allow, command


@pytest.mark.parametrize(
    "command",
    [
        "git add -A",
        "git add .",
        "git add -- src/a.py",
        "git commit -m x",
        "git commit -a -m x",
        f"git -C {CWD} add -A",
        f"git -C {CWD}/.claude/worktrees/evil commit -m x",
        f"cd {CWD}/.claude/worktrees/u1 && git commit -a -m x",
    ],
)
def test_coder_add_and_commit_outside_unit_worktree_refused(command: str) -> None:
    # 0022: staging or committing in the main checkout lands on the main branch.
    assert not decide(_b("repo-coder", command), CFG).allow, command


@pytest.mark.parametrize(
    "command",
    [
        f"git -C {WT} add -A",
        f"git -C {WT} add -- {WT}/src/a.py",
        f"git -C {WT} commit -m 'WIP: yield'",
        f"git -C {WT}/src commit -m x",
    ],
)
def test_coder_add_and_commit_in_unit_worktree_allowed(command: str) -> None:
    assert decide(_b("repo-coder", command), CFG).allow, command


def test_coder_add_and_commit_with_cwd_in_real_unit_worktree(tmp_path: Path) -> None:
    repo, wt = _unit_repo(tmp_path / "repo")
    assert decide(_cwd(_b("repo-coder", "git add -A"), wt), CFG).allow
    assert decide(_cwd(_b("repo-coder", "git commit -m x"), wt), CFG).allow
    assert not decide(_cwd(_b("repo-coder", "git add -A"), repo), CFG).allow


@pytest.mark.parametrize(
    "command",
    [
        f"cp -t{CWD}/infra {WT}/src/a.py",
        f"mv -t{CWD}/infra {WT}/src/a.py",
        f"cp -rt{CWD}/infra {WT}/src/a.py",
        f"install -t {CWD}/infra {WT}/src/a.py",
        f"ln -st{CWD}/infra {WT}/src/a.py",
        f"touch -r{CWD}/infra/a.tf {WT}/src/a.py",
        f"rsync {WT}/src/a.py evilhost:x",
        f"rsync -e touch {WT}/src/a.py evilhost:x",
        f"rsync -avze ssh {WT}/src/ {WT}/src/pkg/",
        f"rsync --rsh=ssh {WT}/src/ {WT}/src/pkg/",
        f"rsync {WT}/src/a.py rsync://host/x",
        f"rsync --exclude x {CWD}/infra/ {WT}/src/pkg/",
    ],
)
def test_coder_attached_targets_and_remote_rsync_refused(command: str) -> None:
    # 0022: an attached -t<dir> is a write target; host:path is a remote rsync operand.
    assert not decide(_b("repo-coder", command), CFG).allow, command


@pytest.mark.parametrize(
    "command",
    [
        f"cp -t {WT}/src/pkg {WT}/src/a.py",
        f"cp -t{WT}/src/pkg {WT}/src/a.py",
        f"cp --target-directory={WT}/src/pkg {WT}/src/a.py",
        f"cp --preserve=mode {WT}/src/a.py {WT}/src/b.py",
        f"rsync -a {WT}/src/ {WT}/src/pkg/",
        f"rsync -a --exclude '*.pyc' {WT}/src/ {WT}/src/pkg/",
        f"rsync -a --filter '- *.pyc' --chmod u+w {WT}/src/ {WT}/src/pkg/",
        f"mkdir -pm 700 {WT}/src/pkg",
        f"mkdir -m700 {WT}/src/pkg",
        f"install --mode 644 {WT}/src/a.py {WT}/src/b.py",
        f"touch --date 2026-01-01 {WT}/src/a.py",
    ],
)
def test_coder_value_options_skipped_as_non_paths(command: str) -> None:
    assert decide(_b("repo-coder", command), CFG).allow, command


@pytest.mark.parametrize(
    "command",
    [
        f"rsync -aT/opt/x {WT}/src/a.py {WT}/src/b.py",
        f"rsync -a -T {CWD}/infra {WT}/src/a.py {WT}/src/b.py",
        f"cp -b --suffix=/../../../infra/x {WT}/src/a.py {WT}/src/b.py",
        f"cp -b -S /../../infra/x {WT}/src/a.py {WT}/src/b.py",
        f"mv --backup --suffix ../x {WT}/src/a.py {WT}/src/b.py",
    ],
)
def test_issue30_coder_temp_dir_and_backup_suffix_are_write_targets(command: str) -> None:
    assert not decide(_b("repo-coder", command), CFG).allow, command


def test_issue30_coder_plain_backup_suffix_passes() -> None:
    command = f"cp -b --suffix=.orig {WT}/src/a.py {WT}/src/b.py"
    assert decide(_b("repo-coder", command), CFG).allow


def test_unit_writes_judges_the_hook_alone() -> None:
    # 0054: the worktree minus protected paths; there is no src/tests allow-list.
    assert evaluate(HOOK, _w("repo-coder", f"{WT}/infra/main.tf")) is None
    outside = evaluate(HOOK, _w("repo-coder", f"{CWD}/src/a.py"))
    assert outside == jail.R_UNIT_OUTSIDE.format(f"{CWD}/src/a.py")
    protected = evaluate(HOOK, _w("repo-coder", f"{WT}/contracts/x.yaml"))
    assert protected == jail.R_PROTECTED_BUILTIN.format(f"{WT}/contracts/x.yaml")
    assert evaluate(HOOK, _b("repo-coder", "pytest --basetemp=x")) == jail.R_BASETEMP
    assert evaluate(HOOK, _b("repo-coder", "git commit -m x")) == jail.R_CODER_UNIT_GIT
    assert evaluate(HOOK, _b("repo-coder", "git push origin x")) is None


def test_unit_writes_fixture_decisions(tmp_path: Path) -> None:
    repo, wt = _unit_repo(tmp_path / "repo")
    write = payload("Write", cwd=str(repo), file_path=f"{repo}/src/a.py")
    want = {"decision": "deny", "reason": jail.R_UNIT_OUTSIDE.format(f"{repo}/src/a.py")}
    assert run_script(HOOK, write) == want
    rel = payload("Write", cwd=str(repo), file_path=f"{wt}/.github/x.yml")
    want = {"decision": "deny", "reason": jail.R_PROTECTED_BUILTIN.format(f"{wt}/.github/x.yml")}
    assert run_script(HOOK, rel) == want
    test = payload("Bash", cwd=str(repo), command="pytest -q")
    assert run_script(HOOK, test) == {"decision": "allow", "reason": ""}


def test_unit_writes_allows_tools_outside_its_tools() -> None:
    outside_tools_allow(HOOK, "Read")


def test_unit_writes_unknown_flag_denies() -> None:
    unknown_flag_denies(HOOK, payload("Bash", command="ls"))


def test_unit_writes_malformed_input_denies() -> None:
    malformed_input_denies(HOOK)


def test_unit_writes_internal_error_denies_and_names_the_hook() -> None:
    internal_error_denies(HOOK, payload("Bash", command="ls"))

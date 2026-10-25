# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# W1.4: the agent lists, case tables and repo builders the jail test modules share.
from __future__ import annotations

import json
from pathlib import Path

from lib import train_state
from lib.unit_binding import record_dispatch
from lib.workspace import mark_train

from tests.conftest import git, write_train_marker

UNIT_TRAIN = "20261015-120000"
BASH_AGENTS = [
    "repo-coder",
    "charter-docs",
    "security-auditor",
    "nist-specialist",
    "cis-specialist",
    "pr-train-conductor",
]
PIPE_ALLOWED = {"security-auditor", "nist-specialist", "cis-specialist"}
SEPARATORS = [
    "git diff & git diff",
    "git diff\ngit diff",
    "git diff\rgit diff",
    "git diff || git diff",
    "git diff $(git diff)",
    "git diff `git diff`",
    "git diff > f",
    "git diff >> f",
    "git diff 2> f",
    "git diff &> f",
    "git diff < f",
    "git diff |& head",
    "git diff <(git diff)",
    "git diff >(cat)",
]
WORKERS_WITH_SHELL = [a for a in BASH_AGENTS]
DATA = "/tmp/daedalus-test-data/daedalus-inline"
_MANIFEST_LEDGER = {
    "path": "docs/adr.md",
    "format": "markdown-table-row",
    "id_scheme": "{seq:04d}",
    "sequence_source": "last-row-id",
}
BUILTIN_REL = [
    "contracts/openapi.yaml",
    "contracts/events/x.schema.json",
    "contracts",
    ".github/workflows/ci.yml",
    ".github/CODEOWNERS",
    ".github",
    ".claude/settings.json",
    ".claude/agents/x.md",
    "service-manifest.json",
    "Service-Manifest.JSON",
    "CONTRACTS/openapi.yaml",
]
NARROWING = {
    "jail_narrowing": {"forbidden_paths": ["infra/", "Makefile"], "forbidden_extensions": [".pem"]}
}
# issue 2: conductor commits that reach past the index; each draws R_CONDUCTOR_COMMIT_ALL.
CONDUCTOR_COMMIT_ALL = [
    "git commit -a",
    "git commit -a -m x",
    "git commit -m x -a",
    "git commit -q -a -m x",
    "git commit --all",
    "git commit --all -m x",
    "git commit -m x --all",
    "git commit --al -m x",
    "git commit --a -m x",
    "git commit --all=yes -m x",
    "git commit -am x",
    "git commit -qam x",
    "git commit -aqm x",
    "git commit -qa -m x",
    "git commit -vam x",
    "git commit -ma",
    "git commit -mall",
    "git commit -a=1 -m x",
    "git commit -m -a",
    "git commit -m --all",
    "git commit -m x -- .",
    "git commit -m x -- src/a.py",
    "git commit -m x src/a.py",
    "git --no-pager commit -am x",
    "git -C . commit -a -m x",
    "git -c core.editor=true commit -a -m x",
    "git -c commit.verbose=true commit --all -m x",
]
# issue 2: the conductor's admitted commit forms, message words holding an a included.
CONDUCTOR_COMMIT_ADMITTED = [
    "git commit -m x",
    "git commit -q -m x",
    "git commit --quiet -m x",
    "git commit -m 'stage a file'",
    "git commit -m 'Commit Build Train result for train 20261015-120000'",
    "git commit -F docs/.tmp/message.md",
    "git --no-pager commit -m x",
]
CREDENTIAL_PATHS = [
    ".ssh/id_ed25519",
    ".aws/credentials",
    ".aws/config",
    ".gnupg/pubring.kbx",
    ".config/gh/hosts.yml",
    ".claude/.credentials.json",
]


def _git_init(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q", "-b", "main")
    return path.resolve()


def _unit_repo(path: Path) -> tuple[Path, Path]:
    repo = _git_init(path)
    git(repo, "commit", "-q", "--allow-empty", "-m", "init")
    wt = repo / ".claude" / "worktrees" / "u1"
    git(repo, "worktree", "add", "-q", "-b", "daedalus-unit/u1", str(wt))
    # issue 29: coder writes need a train with the unit recorded and dispatched.
    (repo / ".claude" / "daedalus").mkdir(exist_ok=True)
    unit = {"name": "u1", "branch": "daedalus-unit/u1", "path": str(wt)}
    train_state.save(repo, UNIT_TRAIN, {"train_id": UNIT_TRAIN, "units": [unit]})
    mark_train(repo, UNIT_TRAIN)
    assert record_dispatch(repo, UNIT_TRAIN, "u1") is None
    return repo, wt.resolve()


def _narrowed_repo(tmp_path: Path, manifest: str) -> tuple[Path, Path]:
    repo, wt = _unit_repo(tmp_path / "repo")
    (repo / "service-manifest.json").write_text(manifest, encoding="utf-8")
    return repo, wt


def _refusal(path: str) -> str:
    return (
        f"{path} is a credential path. "
        "Next: Daedalus never reads credentials; use the tool that needs them from your own shell"
    )


def _train(root: Path) -> None:
    # 0035: main and foreign agents meet the Bash credential model only while a train runs.
    write_train_marker(root, UNIT_TRAIN)


GATE_TRAIN = "20261019-120000"
GATE_BRANCH = f"daedalus/{GATE_TRAIN}"
GATE_NEXT = "Next: audit the exact tip, or record the operator's exception."
LEDGER = "docs/decisions.md"


def seed_train(repo: Path, state: bool = True, train: str = GATE_TRAIN) -> str:
    # spec 4.2: a real repo with the train branch, its marker and its state; returns the tip.
    git(repo, "commit", "-q", "--allow-empty", "-m", "base")
    git(repo, "switch", "-q", "-c", f"daedalus/{train}")
    write_train_marker(repo, train)
    if state:
        train_state.save(repo, train, {"train_id": train})
    return git(repo, "rev-parse", f"daedalus/{train}").stdout.strip()


def move_tip(repo: Path) -> str:
    git(repo, "commit", "-q", "--allow-empty", "-m", "after the verdict")
    return git(repo, "rev-parse", GATE_BRANCH).stdout.strip()


def approve(repo: Path, tip: str, train: str = GATE_TRAIN) -> None:
    verdict = {"status": "approved", "tip": tip, "round": 1, "seq": 7}
    train_state.update(repo, train, verdict=verdict)


def audited_train(repo: Path, train: str) -> None:
    # spec 4.2: a train whose integration tip carries an approved verdict.
    approve(repo, seed_train(repo, train=train), train)


def _ledger_commit(repo: Path, *paths: str) -> str:
    # spec 3.5: a repo-local ledger declared in config, then one commit touching the paths.
    decl = {
        "path": LEDGER,
        "format": "markdown-table-row",
        "id_scheme": "{seq:04d}-{repo}-{type}",
        "sequence_source": "last-row-id",
    }
    config = repo / ".claude" / "daedalus" / "config.json"
    config.write_text(json.dumps({"ledger": decl}), encoding="utf-8")
    for name in paths:
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"{name} row\n", encoding="utf-8")
        git(repo, "add", name)
    git(repo, "commit", "-q", "-m", "ledger")
    return git(repo, "rev-parse", GATE_BRANCH).stdout.strip()

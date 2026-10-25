# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# W1.4: the agent lists, case tables and repo builders the jail test modules share.
from __future__ import annotations

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

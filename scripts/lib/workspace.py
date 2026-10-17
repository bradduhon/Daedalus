# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from lib import train_state
from lib.audit import cache_dir_or_probe
from lib.audit_proof import SUMMARY_DIR, ProofError, live_log
from lib.config import Config, ConfigError, load_config
from lib.ledger import LedgerError, read_sequence, resolve_ledger
from lib.sandbox_state import SettingsError, sandbox_state
from lib.train_state import TRAIN_ID as _TRAIN_ID
from lib.train_state import TRAIN_MARKER

# 0022: pipeline-neutral; every caller names its own base ref.
WORKTREES_DIR = Path(".claude") / "worktrees"
BRANCH_PREFIX = "daedalus-unit/"
_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
_GIT_TIMEOUT_S = 120


class WorkspaceError(RuntimeError):
    pass


def _check_name(name: str) -> None:
    if not _NAME.fullmatch(name):
        raise WorkspaceError(
            f"workspace name {name!r} must be lowercase letters, digits and hyphens. "
            "Next: pass a name such as 20261015-120000-u1."
        )


def worktree_path(repo: Path, name: str) -> Path:
    _check_name(name)
    return repo / WORKTREES_DIR / name


def branch_name(name: str) -> str:
    _check_name(name)
    return BRANCH_PREFIX + name


def _confined(repo: Path, name: str) -> Path:
    # spec 7: never act on a path that resolves outside <repo>/.claude/worktrees/.
    path = worktree_path(repo, name)
    root = repo.resolve() / WORKTREES_DIR
    if path.resolve().parent != root:
        raise WorkspaceError(
            f"{path} resolves outside {root}. "
            f"Next: replace any symlink at {root} with a plain directory, then rerun."
        )
    return path


def _run(repo: Path, *args: str, path: Path | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        # spec 7: a killed worktree add can leave a lock that a single --force will not clear.
        target = path or repo / WORKTREES_DIR / "<name>"
        raise WorkspaceError(
            f"git {args[0]} {args[1]} timed out after {_GIT_TIMEOUT_S} s. "
            f"Next: run git -C {repo} worktree unlock {target} (or worktree remove -f -f "
            f"{target}), then run daedalus_workspace.py remove and rerun."
        ) from exc
    except OSError as exc:
        raise WorkspaceError(
            f"git {args[0]} {args[1]} did not run ({exc}). Next: check git is on PATH, then rerun."
        ) from exc


def _git(repo: Path, *args: str, path: Path | None = None) -> None:
    result = _run(repo, *args, path=path)
    if result.returncode != 0:
        detail = " ".join(result.stderr.split()) or "no stderr"
        raise WorkspaceError(
            f"git {args[0]} {args[1]} failed ({detail}). Next: fix the cause git names, then rerun."
        )


def _ensure_marker(repo: Path) -> None:
    # 0022: a single * keeps every worktree here out of the main checkout's status.
    marker = repo / WORKTREES_DIR / ".gitignore"
    if marker.exists():
        return
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("*\n", encoding="utf-8")
    except OSError as exc:
        raise WorkspaceError(
            f"cannot write {marker} ({exc}). Next: make {marker.parent} a writable directory."
        ) from exc


def create(repo: Path, name: str, base_ref: str) -> Path:
    # spec 7: git reads paths relative to -C <repo>, so work from the absolute repo.
    repo = repo.resolve()
    path = _confined(repo, name)
    branch = branch_name(name)
    remedy = (
        f"Next: if a crashed run left it behind, run daedalus_workspace.py remove "
        f"--repo {repo} --name {name}, delete the branch with git branch -D {branch} "
        "once nothing needs it, then rerun; otherwise pick a new name."
    )
    if path.exists() or path.is_symlink():
        raise WorkspaceError(f"worktree path {path} already exists. {remedy}")
    if _run(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}").returncode == 0:
        raise WorkspaceError(f"branch {branch} already exists. {remedy}")
    _ensure_marker(repo)
    # spec 7: documented option order, branch before path before base.
    _git(repo, "worktree", "add", "-q", "-b", branch, str(path), base_ref, path=path)
    # 0024: inside a train, record the unit so stop and finish tear down only train worktrees.
    train = train_state.active_train(repo)
    if train is not None and train_state.state_path(repo, train).is_file():
        try:
            train_state.add_unit(repo, train, name, branch, path)
        except train_state.TrainStateError as exc:
            raise WorkspaceError(str(exc)) from exc
    return path


def remove(repo: Path, name: str) -> None:
    repo = repo.resolve()
    path = _confined(repo, name)
    # spec 7: an already-gone worktree only needs its admin entry pruned.
    if path.exists():
        _git(repo, "worktree", "remove", "--force", str(path), path=path)
    _git(repo, "worktree", "prune")


UNMARK_NEXT = (
    "Next: if no Daedalus train is running, run python3 ${{CLAUDE_PLUGIN_ROOT}}"
    "/scripts/daedalus_workspace.py unmark --repo {repo} and retry."
)


def train_marker(repo: Path) -> Path:
    return repo.resolve() / TRAIN_MARKER


def mark_train(repo: Path, train_id: str) -> Path:
    # 0023: the jail writes .claude/daedalus off-limits to tools, so the trains mark through here.
    if not _TRAIN_ID.fullmatch(train_id):
        raise WorkspaceError(
            f"train id {train_id!r} is not YYYYMMDD-HHMMSS. Next: pass the train's own id."
        )
    marker = train_marker(repo)
    if not marker.parent.is_dir():
        raise WorkspaceError(
            f"{marker.parent} is missing, so the audit hooks have not run here. "
            "Next: run /daedalus:doctor."
        )
    if marker.is_symlink():
        raise WorkspaceError(
            f"{marker} is a symlink. Next: delete it from your own shell, then rerun."
        )
    # 0023: temp file plus os.replace, so a reader never sees a partial id.
    tmp: Path | None = None
    try:
        fd, name = tempfile.mkstemp(prefix=f".{marker.name}.", dir=marker.parent)
        tmp = Path(name)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(f"{train_id}\n")
        os.replace(tmp, marker)
    except OSError as exc:
        if tmp is not None:
            tmp.unlink(missing_ok=True)
        raise WorkspaceError(f"cannot write {marker} ({exc}). Next: run /daedalus:doctor.") from exc
    return marker


def clear_train(repo: Path) -> Path:
    marker = train_marker(repo)
    try:
        marker.unlink(missing_ok=True)
    except OSError as exc:
        raise WorkspaceError(
            f"cannot remove {marker} ({exc}). Next: delete it from your own shell."
        ) from exc
    return marker


BEGIN_NEEDLE = "daedalus_workspace.py begin"
DIRTY_LIMIT = 10
RERUN = "run /daedalus:build-train again."
CLEAN_NEXT = f"Next: commit or stash your changes from your own shell, then {RERUN}"
LEDGER_NONE = "ledger: none declared and none found."
LEDGER_QUESTION = (
    "This repo has no decision ledger. Options: name an existing file, or let Daedalus "
    "create docs/decisions.md as a table. Which?"
)
LEDGER_TABLE = "| Id | Date | Ruling | Supersedes | Follow-ups |\n|---|---|---|---|---|"


class LedgerQuestion(WorkspaceError):
    pass


def _out(repo: Path, *args: str) -> str:
    result = _run(repo, *args)
    if result.returncode != 0:
        detail = " ".join(result.stderr.split()) or "no stderr"
        raise WorkspaceError(
            f"git {args[0]} {args[1]} failed in {repo} ({detail}). "
            "Next: fix the cause git names, then rerun."
        )
    return result.stdout


def _dirty(repo: Path, *pathspec: str) -> list[str]:
    # 0007: name the dirty paths so nobody reruns git status to find them.
    out = _out(repo, "status", "--porcelain", "--untracked-files=all", *pathspec)
    return [line[3:].split(" -> ")[-1] for line in out.splitlines() if line.strip()]


def _shown(paths: list[str]) -> str:
    shown = ", ".join(paths[:DIRTY_LIMIT])
    if len(paths) > DIRTY_LIMIT:
        shown += f" +{len(paths) - DIRTY_LIMIT} more"
    return shown


def _branch(repo: Path) -> str:
    head = _out(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
    if head == "HEAD":
        raise WorkspaceError(
            f"{repo} is on a detached HEAD, so a stop has no branch to return to. "
            f"Next: switch to a branch from your own shell, then {RERUN}"
        )
    return head


def repo_root(cwd: Path) -> Path:
    inside = _run(cwd, "rev-parse", "--is-inside-work-tree")
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        raise WorkspaceError(
            f"{cwd} is not inside a git work tree. "
            f"Next: start the session inside the target repository, then {RERUN}"
        )
    # 0010: the common dir's parent is the main working tree every worktree shares.
    common = _out(cwd, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    return Path(common).parent


def _ledger_line(repo: Path, config: Config) -> str:
    try:
        ledger = resolve_ledger(str(repo), config)
        if ledger is None:
            raise LedgerQuestion(f"{LEDGER_NONE}\n{LEDGER_QUESTION}\n{LEDGER_TABLE}")
        seq = read_sequence(ledger)
    except LedgerError as exc:
        raise WorkspaceError(str(exc)) from exc
    return f"ledger: {ledger.path} ({ledger.origin}, {ledger.format}, seq={seq})"


def _scratch(repo: Path) -> None:
    scratch = repo / SUMMARY_DIR
    marker = scratch / ".gitignore"
    try:
        scratch.mkdir(parents=True, exist_ok=True)
        if not marker.exists():
            marker.write_text("*\n", encoding="utf-8")
    except OSError as exc:
        raise WorkspaceError(
            f"cannot write {marker} ({exc}). Next: make {scratch} a writable directory."
        ) from exc


def _charter_branch(charter: Path, train_id: str) -> str:
    dirty = _dirty(charter)
    if dirty:
        raise WorkspaceError(
            f"uncommitted changes in {charter}: {_shown(dirty)}. Next: commit or stash the "
            f"changes in {charter} from your own shell, then {RERUN}"
        )
    base = _branch(charter)
    _git(charter, "switch", "-q", "-c", f"daedalus/{train_id}")
    return base


def _undo_charter(charter: Path, base: str, exc: Exception) -> WorkspaceError:
    switched = _run(charter, "switch", "-q", base)
    if switched.returncode == 0:
        return WorkspaceError(str(exc))
    return WorkspaceError(
        f"{exc} The Charter switch-back failed too. "
        f"Next: run git -C {charter} switch {base} from your own shell, then {RERUN}"
    )


def begin(cwd: Path, needle: str = BEGIN_NEEDLE) -> list[str]:
    # 0024: build-train Preconditions 1 to 9, ordered so a failure leaves no train state behind.
    repo = repo_root(cwd.resolve())
    dirty = _dirty(repo)
    if dirty:
        raise WorkspaceError(f"uncommitted changes in {repo}: {_shown(dirty)}. {CLEAN_NEXT}")
    base = _branch(repo)
    base_sha = _out(repo, "rev-parse", "HEAD").strip()
    try:
        config = load_config(path=repo / ".claude" / "daedalus" / "config.json")
    except ConfigError as exc:
        raise WorkspaceError(str(exc)) from exc
    ledger_line = _ledger_line(repo, config)
    try:
        log, _ = live_log(repo, needle)
    except ProofError as exc:
        raise WorkspaceError(str(exc)) from exc
    train_id = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    if train_state.state_path(repo, train_id).exists():
        raise WorkspaceError(f"train {train_id} already exists. Next: wait a second, then {RERUN}")
    _scratch(repo)
    charter = (repo / config.charter_root).resolve() if config.charter_root else None
    charter_base = _charter_branch(charter, train_id) if charter else None
    try:
        sandbox = sandbox_state(repo)
        try:
            cache: str | None = str(cache_dir_or_probe() / "frameworks")
        except RuntimeError:
            cache = None
        state = {
            "train_id": train_id,
            "repo": str(repo),
            "base_branch": base,
            "base_sha": base_sha,
            "charter_root": str(charter) if charter else None,
            "charter_base": charter_base,
            "charter_branch_created": charter is not None,
            "audit_session": log.stem,
            "sandbox": sandbox,
            "ledger_line": ledger_line,
            "cache_dir": cache,
            "units": [],
            "merged": False,
        }
        train_state.save(repo, train_id, state)
        try:
            mark_train(repo, train_id)
        except WorkspaceError:
            train_state.state_path(repo, train_id).unlink(missing_ok=True)
            raise
    except (SettingsError, train_state.TrainStateError, WorkspaceError) as exc:
        if charter is not None and charter_base is not None:
            raise _undo_charter(charter, charter_base, exc) from exc
        raise WorkspaceError(str(exc)) from exc
    policy = f"{config.policy.engine} {config.policy.path}" if config.policy else "none declared"
    return [
        f"train: {train_id}  base: {base} @ {base_sha}  audit session: {log.stem}",
        ledger_line,
        f"charter_root: {charter or 'none'}  charter base: {charter_base or 'none'}",
        f"policy: {policy}  standards: {len(config.standards_sources)} sources",
        f"cache: {cache}" if cache else "cache: unresolved",
        f"sandbox: {sandbox}",
    ]


def _active(repo: Path) -> tuple[str, dict[str, Any]]:
    train_id = train_state.active_train(repo)
    if train_id is None:
        raise WorkspaceError(
            f"no Daedalus train is active in {repo}. Next: run /daedalus:build-train."
        )
    try:
        return train_id, train_state.load(repo, train_id)
    except train_state.TrainStateError as exc:
        raise WorkspaceError(str(exc)) from exc


def _record(repo: Path, train_id: str, **fields: Any) -> None:
    try:
        train_state.update(repo, train_id, **fields)
    except train_state.TrainStateError as exc:
        raise WorkspaceError(str(exc)) from exc


def _on_branch(repo: Path, branch: str, start: str | None = None) -> None:
    if _out(repo, "rev-parse", "--abbrev-ref", "HEAD").strip() == branch:
        return
    exists = _run(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}")
    if exists.returncode == 0:
        _git(repo, "switch", "-q", branch)
    elif start is not None:
        _git(repo, "switch", "-q", "-c", branch, start)
    else:
        raise WorkspaceError(f"branch {branch} is missing in {repo}. Next: {RERUN}")


def _contract_target(repo: Path, state: dict[str, Any], contract: str) -> tuple[Path, Path]:
    # 0011: contracts/<name>.md in this repo, or specs/<name>.md under the declared charter_root.
    path = (repo / contract).resolve()
    charter = Path(state["charter_root"]) if state.get("charter_root") else None
    root, folder = (
        (charter, "specs") if charter and path.is_relative_to(charter) else (repo, "contracts")
    )
    rel = path.relative_to(root) if path.is_relative_to(root) else None
    if (
        rel is None
        or len(rel.parts) != 2
        or rel.parts[0] != folder
        or rel.suffix != ".md"
        or not _NAME.fullmatch(rel.stem)
    ):
        raise WorkspaceError(
            f"contract path {contract} is not {folder}/<name>.md in {root}. "
            "Next: ask contract-spec to save the packet there, then rerun the lock."
        )
    return root, path


def lock(repo: Path, contract: str, version: int) -> list[str]:
    repo = repo.resolve()
    train_id, state = _active(repo)
    root, path = _contract_target(repo, state, contract)
    recorded = state.get("packet_version")
    if isinstance(recorded, int) and version <= recorded:
        raise WorkspaceError(
            f"packet_version {version} does not exceed {recorded}. "
            "Next: ask contract-spec for a higher packet_version."
        )
    if not path.is_file():
        raise WorkspaceError(
            f"contract-spec did not save the packet at {path}. Next: rerun /daedalus:build-train."
        )
    integration = f"daedalus/{train_id}"
    _on_branch(repo, integration, state["base_sha"])
    if root != repo:
        _on_branch(root, integration)
    rel = str(path.relative_to(root))
    _git(root, "add", "--", rel)
    unchanged = _run(root, "diff", "--cached", "--quiet", "--", rel)
    if unchanged.returncode not in (0, 1):
        raise WorkspaceError(
            f"git diff --cached failed in {root}. Next: fix the cause, then rerun."
        )
    verb = "Revise" if isinstance(recorded, int) else "Lock"
    if unchanged.returncode == 1:
        _git(root, "commit", "-q", "-m", f"{verb} contract {path.stem} v{version}", "--", rel)
    sha = _out(repo, "rev-parse", integration).strip()
    _record(
        repo,
        train_id,
        contract_path=str(path),
        contract_repo=str(root),
        packet_version=version,
        lock_sha=sha,
    )
    detail = (
        f"contract: {path} v{version}"
        if unchanged.returncode == 1
        else "contract unchanged, no commit"
    )
    return [f"lock: {sha}", detail]

# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import hashlib
import hmac
import os
import re
import shlex
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from lib import atomic, audit_proof, git, narrow, plan_record, scrub, train_state, unit_binding
from lib.audit import SESSION_ID, DataDirError, cache_dir_or_probe, ensure_project_data_dir
from lib.audit_proof import SUMMARY_DIR
from lib.config import Config, ConfigError, load_config
from lib.ledger import LedgerError, read_sequence, resolve_ledger
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
        return git.run(args, repo, _GIT_TIMEOUT_S)
    except git.GitTimeout as exc:
        took = f"git {args[0]} {args[1]} timed out after {_GIT_TIMEOUT_S} s."
        if path is None:
            raise WorkspaceError(
                f"{took} Next: run git -C {repo} {' '.join(args)} from your own shell "
                "to see why it hangs, then rerun."
            ) from exc
        # spec 7: a killed worktree add can leave a lock that a single --force will not clear.
        raise WorkspaceError(
            f"{took} Next: run git -C {repo} worktree unlock {path} (or worktree remove -f -f "
            f"{path}), then run daedalus_workspace.py remove and rerun."
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
            audit = name == audit_unit(train)
            train_state.add_unit(repo, train, name, branch, path, base_ref, audit=audit)
        except train_state.TrainStateError as exc:
            raise WorkspaceError(str(exc)) from exc
    return path


def _is_locked(repo: Path, path: Path) -> bool:
    # issue 24: the porcelain listing marks a locked worktree with a "locked" line in its block.
    listing = _out(repo, "worktree", "list", "--porcelain")
    current: Path | None = None
    for line in listing.splitlines():
        if line.startswith("worktree "):
            current = Path(line.removeprefix("worktree ")).resolve()
        elif current == path.resolve() and (line == "locked" or line.startswith("locked ")):
            return True
    return False


def remove(repo: Path, name: str) -> None:
    repo = repo.resolve()
    path = _confined(repo, name)
    # spec 7: an already-gone worktree only needs its admin entry pruned.
    if path.exists():
        # issue 24: a single --force leaves a locked worktree in place, so unlock it first.
        if _is_locked(repo, path):
            _git(repo, "worktree", "unlock", str(path), path=path)
        _git(repo, "worktree", "remove", "--force", str(path), path=path)
    _git(repo, "worktree", "prune")


AUDIT_SUFFIX = train_state.AUDIT_SUFFIX


def audit_unit(train_id: str) -> str:
    # pin C4 -> C1: the audit worktree is the train unit named <train-id>-audit.
    return f"{train_id}{AUDIT_SUFFIX}"


def _audit_readd(repo: Path, train_id: str, name: str, path: Path, integration: str) -> None:
    branch = branch_name(name)
    _ensure_marker(repo)
    _git(repo, "worktree", "prune")
    if _run(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}").returncode == 0:
        _git(repo, "worktree", "add", "-q", str(path), branch, path=path)
    else:
        _git(repo, "worktree", "add", "-q", "-b", branch, str(path), integration, path=path)
    try:
        found = [
            u for u in train_state.units(train_state.load(repo, train_id)) if u.get("name") == name
        ]
        if not found:
            train_state.add_unit(repo, train_id, name, branch, path, integration, audit=True)
        elif found[0].get(train_state.AUDIT) is not True:
            train_state.mark_audit(repo, train_id, name)
    except train_state.TrainStateError as exc:
        raise WorkspaceError(str(exc)) from exc


def refresh(repo: Path, name: str) -> Path:
    # 0112: fast-forward only; a diverged or dirty audit worktree is refused, never discarded.
    repo = repo.resolve()
    train_id, _state = _active(repo)
    if name != audit_unit(train_id):
        raise WorkspaceError(
            f"refresh moves only the audit worktree, {audit_unit(train_id)}, not {name}. "
            f"Next: rerun the refresh for the audit worktree with --name {audit_unit(train_id)}."
        )
    path = _confined(repo, name)
    branch = branch_name(name)
    integration = f"daedalus/{train_id}"
    if _run(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{integration}").returncode:
        raise WorkspaceError(
            f"branch {integration} is missing in {repo}. Next: lock the contract with "
            "daedalus_workspace.py lock, which creates it, then rerun the refresh."
        )
    if not path.exists() and not path.is_symlink():
        _audit_readd(repo, train_id, name, path, integration)
    inspect = f"Next: run git -C {path} status and settle it from your own shell, then rerun."
    if _unit_worktrees(repo).get(branch) != path:
        raise WorkspaceError(f"{path} is not the worktree of {branch}. {inspect}")
    dirty = _dirty(path)
    if dirty:
        raise WorkspaceError(f"the audit worktree {path} has changes: {_shown(dirty)}. {inspect}")
    if _run(path, "merge-base", "--is-ancestor", "HEAD", integration).returncode:
        raise WorkspaceError(
            f"{branch} has commits {integration} does not, so it cannot fast-forward. {inspect}"
        )
    merged = _run(path, "merge", "--ff-only", integration)
    if merged.returncode:
        detail = " ".join(merged.stderr.split()) or "no stderr"
        raise WorkspaceError(f"git merge --ff-only {integration} failed ({detail}). {inspect}")
    return path


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
            "Next: run the Daedalus health check (/daedalus:doctor)."
        )
    # 0023: temp file plus os.replace, so a reader never sees a partial id.
    try:
        atomic.write_atomic(marker, f"{train_id}\n", 0o600)
    except atomic.LinkRefused as exc:
        raise WorkspaceError(str(exc)) from exc
    except OSError as exc:
        # 0023: a directory or an unwritable file at the marker is the operator's to remove.
        raise WorkspaceError(
            f"cannot write {marker} ({exc}). Next: remove {marker} from your own shell, then rerun."
        ) from exc
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


DIRTY_LIMIT = 10
RERUN = "start the Build Train again (/daedalus:build-train)."
CLEAN_NEXT = f"Next: commit or stash your changes from your own shell, then {RERUN}"
LEDGER_NONE = "ledger: none declared and none found."
LEDGER_OFF = "ledger: off in the service manifest."
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


def _ledger_line(repo: Path, config: Config, ledger_feature: bool | None) -> str:
    # 0069: off resolves nothing; absent uses a found ledger and never asks; on asks when none.
    if ledger_feature is False:
        return LEDGER_OFF
    try:
        ledger = resolve_ledger(str(repo), config)
        if ledger is None and ledger_feature is None:
            return LEDGER_NONE
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


def _config(repo: Path) -> Config:
    try:
        return load_config(path=repo / ".claude" / "daedalus" / "config.json")
    except ConfigError as exc:
        raise WorkspaceError(str(exc)) from exc


def _new_train(repo: Path) -> str:
    try:
        # 0035: the first write of a train; outside one the audit layer never creates this folder.
        ensure_project_data_dir(str(repo))
    except DataDirError as exc:
        raise WorkspaceError(str(exc)) from exc
    train_id = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    if train_state.state_path(repo, train_id).exists():
        raise WorkspaceError(f"train {train_id} already exists. Next: wait a second, then {RERUN}")
    _scratch(repo)
    return train_id


def _cache() -> str | None:
    try:
        return str(cache_dir_or_probe() / "frameworks")
    except RuntimeError:
        return None


def _open_train(repo: Path, train_id: str, state: dict[str, object]) -> None:
    train_state.save(repo, train_id, state)
    try:
        mark_train(repo, train_id)
    except WorkspaceError:
        train_state.state_path(repo, train_id).unlink(missing_ok=True)
        raise


def _config_lines(config: Config, cache: str | None) -> list[str]:
    policy = f"{config.policy.engine} {config.policy.path}" if config.policy else "none declared"
    # 0019: a pack has no path in config.json; the standards specialist reads it from this line.
    packs = [f"{s.name} at {s.path}" for s in config.standards_sources if s.kind == "pack"]
    return [
        f"policy: {policy}  standards: {len(config.standards_sources)} sources",
        f"cache: {cache}" if cache else "cache: unresolved",
        f"standards packs: {', '.join(packs) or 'none declared'}",
    ]


def begin(cwd: Path, ledger_feature: bool | None = True) -> list[str]:
    # 0024: build-train Preconditions 1 to 9, ordered so a failure leaves no train state behind.
    repo = repo_root(cwd.resolve())
    dirty = _dirty(repo)
    if dirty:
        raise WorkspaceError(f"uncommitted changes in {repo}: {_shown(dirty)}. {CLEAN_NEXT}")
    base = _branch(repo)
    base_sha = _out(repo, "rev-parse", "HEAD").strip()
    config = _config(repo)
    ledger_line = _ledger_line(repo, config, ledger_feature)
    train_id = _new_train(repo)
    charter = (repo / config.charter_root).resolve() if config.charter_root else None
    charter_base = _charter_branch(charter, train_id) if charter else None
    try:
        cache = _cache()
        state: dict[str, object] = {
            "train_id": train_id,
            "repo": str(repo),
            "base_branch": base,
            "base_sha": base_sha,
            "charter_root": str(charter) if charter else None,
            "charter_base": charter_base,
            "charter_branch_created": charter is not None,
            "ledger_line": ledger_line,
            "cache_dir": cache,
            "units": [],
            "merged": False,
        }
        _open_train(repo, train_id, state)
    except (train_state.TrainStateError, WorkspaceError) as exc:
        if charter is not None and charter_base is not None:
            raise _undo_charter(charter, charter_base, exc) from exc
        raise WorkspaceError(str(exc)) from exc
    return [
        f"train: {train_id}  base: {base} @ {base_sha}  audit session: pending",
        ledger_line,
        f"charter_root: {charter or 'none'}  charter base: {charter_base or 'none'}",
        *_config_lines(config, cache),
    ]


def begin_folder(root: Path, ledger_feature: bool | None) -> list[str]:
    # 0069: folder scope opens a train with no git command: no clean-tree, branch or charter step.
    root = root.resolve()
    config = _config(root)
    ledger_line = _ledger_line(root, config, ledger_feature)
    train_id = _new_train(root)
    charter = (root / config.charter_root).resolve() if config.charter_root else None
    cache = _cache()
    state: dict[str, object] = {
        "train_id": train_id,
        "repo": str(root),
        "base_branch": None,
        "base_sha": None,
        "charter_root": str(charter) if charter else None,
        "charter_base": None,
        "charter_branch_created": False,
        "ledger_line": ledger_line,
        "cache_dir": cache,
        "units": [],
        "merged": False,
    }
    try:
        _open_train(root, train_id, state)
    except train_state.TrainStateError as exc:
        raise WorkspaceError(str(exc)) from exc
    return [
        f"train: {train_id}  folder: {root}  audit session: pending",
        ledger_line,
        f"charter_root: {charter or 'none'}  charter base: none",
        *_config_lines(config, cache),
    ]


def _active(repo: Path) -> tuple[str, dict[str, object]]:
    train_id = train_state.active_train(repo)
    if train_id is None:
        raise WorkspaceError(
            f"no Daedalus train is active in {repo}. "
            "Next: start a Build Train first (/daedalus:build-train)."
        )
    try:
        return train_id, train_state.load(repo, train_id)
    except train_state.TrainStateError as exc:
        raise WorkspaceError(str(exc)) from exc


def _record(repo: Path, train_id: str, **fields: object) -> None:
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


def _contract_target(repo: Path, state: dict[str, object], contract: str) -> tuple[Path, Path]:
    # 0011: contracts/<name>.md in this repo, or specs/<name>.md under the declared charter_root.
    path = (repo / contract).resolve()
    charter = Path(str(state["charter_root"])) if state.get("charter_root") else None
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


def lock(repo: Path, contract: str | None, version: int | None = None) -> list[str]:
    repo = repo.resolve()
    train_id, state = _active(repo)
    integration = f"daedalus/{train_id}"
    if contract is None:
        # 0156: a skipped contract locks the integration branch at the base and commits nothing.
        if state.get(train_state.CONTRACT_SKIP) is not True:
            raise WorkspaceError(
                f"train {train_id} records no contract skip, so lock --no-contract is refused. "
                f"Next: run daedalus_train.py contract --repo {repo}; when it prints contract: "
                "required, lock the contract contract-spec saves with --contract and --version."
            )
        if state.get("packet_version") is not None:
            raise WorkspaceError(
                f"train {train_id} already locked contract packet_version "
                f"{state['packet_version']}. Next: revise that contract with --contract and a "
                "higher --version instead of --no-contract."
            )
        base = str(state["base_sha"])
        _on_branch(repo, integration, base)
        _record(repo, train_id, lock_sha=base)
        return [f"lock: {base}"]
    if version is None:
        raise WorkspaceError(
            f"lock --contract {contract} names no --version. "
            "Next: rerun the lock with --version set to the packet_version contract-spec gave."
        )
    root, path = _contract_target(repo, state, contract)
    recorded = state.get("packet_version")
    if isinstance(recorded, int) and version <= recorded:
        raise WorkspaceError(
            f"packet_version {version} does not exceed {recorded}. "
            "Next: ask contract-spec for a higher packet_version."
        )
    if not path.is_file():
        raise WorkspaceError(f"contract-spec did not save the packet at {path}. Next: {RERUN}")
    _on_branch(repo, integration, str(state["base_sha"]))
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
    # 0150, issue 96: a revise keeps the lock at the train base, never the integration tip.
    kept = state.get("lock_sha") if isinstance(recorded, int) else None
    sha = kept if isinstance(kept, str) and kept else _out(repo, "rev-parse", integration).strip()
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


STOP_NEXT = "start the Build Train again (/daedalus:build-train)"


def _unit_worktrees(repo: Path) -> dict[str, Path]:
    listing = _out(repo, "worktree", "list", "--porcelain")
    found: dict[str, Path] = {}
    path: Path | None = None
    for line in listing.splitlines():
        if line.startswith("worktree "):
            path = Path(line.removeprefix("worktree "))
        elif line.startswith("branch refs/heads/") and path is not None:
            found[line.removeprefix("branch refs/heads/")] = path
    return found


def _teardown(
    repo: Path, units: list[dict[str, object]], lines: list[str], nexts: list[str]
) -> bool:
    # 0024: only the units this train recorded, never another worktree under .claude/worktrees/.
    listed = _unit_worktrees(repo)
    ok = True
    for unit in units:
        path = listed.get(str(unit.get("branch")))
        if path is None:
            continue
        lines.append(f"discarding {path}:")
        status = _run(path, "status", "--porcelain")
        lines.extend(f"  {entry}" for entry in status.stdout.splitlines() if entry.strip())
        try:
            remove(repo, str(unit["name"]))
        except WorkspaceError as exc:
            ok = False
            lines.append(f"remove failed for {path}: {exc}")
            # issue 24: a locked worktree needs the unlock before the remove.
            nexts.append(
                f"run git -C {repo} worktree unlock {path} if it is locked, then "
                f"git -C {repo} worktree remove --force {path} and git -C {repo} worktree prune "
                "from your own shell"
            )
            continue
        lines.append(f"removed {path}")
    return ok


def _switch(repo: Path, branch: str, lines: list[str], nexts: list[str]) -> bool:
    result = _run(repo, "switch", "-q", branch)
    if result.returncode == 0:
        lines.append(f"switched {repo} to {branch}")
        return True
    detail = " ".join(result.stderr.split()) or "no stderr"
    lines.append(f"switch to {branch} failed in {repo} ({detail})")
    nexts.append(f"run git -C {repo} switch {branch} from your own shell")
    return False


def _integration_back(
    repo: Path, state: dict[str, object], integration: str, lines: list[str], nexts: list[str]
) -> bool:
    if (
        state.get("merged")
        or _out(repo, "rev-parse", "--abbrev-ref", "HEAD").strip() != integration
    ):
        return True
    # 0024: a dirty main checkout or uncommitted contract stays on the integration branch.
    dirty = _dirty(repo)
    if state.get("charter_root"):
        charter = Path(str(state["charter_root"]))
        dirty += [f"{charter.name}/{p}" for p in _dirty(charter, "--", "specs/")]
    if dirty:
        lines.append(f"kept on {integration}: {_shown(dirty)}")
        nexts.append(
            f"commit or discard those files on {integration} from your own shell, "
            f"then run git switch {state['base_branch']}"
        )
        return True
    if not _switch(repo, str(state["base_branch"]), lines, nexts):
        return False
    return _drop_empty(repo, state, integration, str(state["base_sha"]), lines, nexts)


def _drop_empty(
    repo: Path,
    state: dict[str, object],
    integration: str,
    base: str,
    lines: list[str],
    nexts: list[str],
) -> bool:
    # issue 23: before Phase 2 a branch holding no commit beyond its base is deleted with -d.
    if (
        narrow.objects(state, "units")
        or _run(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{integration}").returncode
    ):
        return True
    if _run(repo, "merge-base", "--is-ancestor", integration, base).returncode:
        return True
    result = _run(repo, "branch", "-d", integration)
    if result.returncode == 0:
        lines.append(f"deleted the empty branch {integration} in {repo}")
        return True
    detail = " ".join(result.stderr.split()) or "no stderr"
    lines.append(f"deleting {integration} failed in {repo} ({detail})")
    nexts.append(f"run git -C {repo} branch -d {integration} from your own shell")
    return False


def _charter_back(
    state: dict[str, object], integration: str, lines: list[str], nexts: list[str]
) -> bool:
    if not state.get("charter_branch_created") or not state.get("charter_root"):
        return True
    charter, base = Path(str(state["charter_root"])), str(state["charter_base"])
    dirty = _dirty(charter)
    if dirty:
        lines.append(f"kept on {integration} in {charter.name}: {_shown(dirty)}")
        nexts.append(
            f"commit or discard those files on {integration} in {charter.name} from your own "
            f"shell, then run git -C {charter} switch {base}"
        )
        return True
    on_base = _out(charter, "rev-parse", "--abbrev-ref", "HEAD").strip() == base
    if not on_base and not _switch(charter, base, lines, nexts):
        return False
    return _drop_empty(charter, state, integration, base, lines, nexts)


def stop(repo: Path, reason: str, next_action: str | None) -> tuple[list[str], bool]:
    # 0024: every train stop runs these steps in order; the last line is always one Next.
    repo = repo.resolve()
    marker = train_marker(repo)
    train_id = train_state.active_train(repo)
    lines: list[str] = []
    nexts: list[str] = []
    ok = True
    if train_id is None and not marker.exists() and not marker.is_symlink():
        lines.append("nothing to stop")
    else:
        lines.append(f"Stopped train {train_id or 'unknown'}: {reason}")
        state_file = train_state.state_path(repo, train_id) if train_id else None
        if state_file is None or not state_file.is_file():
            lines.append("no train state recorded; unmarking only")
        else:
            try:
                state = train_state.load(repo, train_id or "")
                integration = f"daedalus/{train_id}"
                # 0069: a folder-scope train made no worktree or branch, so no git step runs.
                if state.get("scope_kind") == "folder":
                    lines.append("folder scope: no worktrees or branches to restore")
                else:
                    ok = _teardown(repo, narrow.objects(state, "units"), lines, nexts) and ok
                    ok = _integration_back(repo, state, integration, lines, nexts) and ok
                    ok = _charter_back(state, integration, lines, nexts) and ok
            except (WorkspaceError, train_state.TrainStateError) as exc:
                ok = False
                lines.append(f"stop could not finish: {exc}")
                nexts.append("finish the step it names from your own shell")
        try:
            lines.append(f"cleared {clear_train(repo)}")
        except WorkspaceError as exc:
            ok = False
            lines.append(str(exc))
            nexts.append(f"remove {marker} from your own shell")
    if nexts:
        final = "; ".join(nexts)
    else:
        final = next_action or STOP_NEXT
    lines.append(final if final.startswith("Next:") else f"Next: {final}")
    return lines, ok


def _unit_label(train_id: str, name: str) -> str:
    return name.removeprefix(f"{train_id}-")


def _merge(repo: Path, state: dict[str, object], train_id: str, unit: dict[str, object]) -> None:
    branch = str(unit["branch"])
    message = f"Merge {_unit_label(train_id, str(unit['name']))} for train {train_id}"
    merged = _run(repo, "merge", "-q", "--no-ff", branch, "-m", message)
    if merged.returncode == 0:
        return
    conflicts = _out(repo, "diff", "--name-only", "--diff-filter=U").split()
    # issue 95: abort only; the repository stays on the integration branch with earlier merges.
    _run(repo, "merge", "--abort")
    detail = _shown(conflicts) if conflicts else " ".join(merged.stderr.split()) or "no stderr"
    raise WorkspaceError(
        f"merging {branch} into daedalus/{train_id} failed: {detail}. "
        f"Next: the repository stays on daedalus/{train_id} with the completed merges in "
        f"place; merge {branch} there by hand and resolve the conflicting files named above, "
        "then rerun the merge step, which skips units already merged; or rerun the train with "
        "units that do not share files."
    )


def finish(repo: Path) -> list[str]:
    # 0024: Phase 3 step 4 merges, with the merge-base check moved here from the skill.
    repo = repo.resolve()
    train_id, state = _active(repo)
    integration = f"daedalus/{train_id}"
    dirty = _dirty(repo)
    if dirty:
        raise WorkspaceError(
            f"a coder changed the main checkout instead of its worktree: {_shown(dirty)}. "
            "Next: inspect and discard those changes from your own shell, run git switch "
            f"{state['base_branch']}, then rerun the train."
        )
    units = narrow.objects(state, "units")
    # pin C4 -> C5, spec 4: the audit unit is never merged; _teardown still removes its worktree.
    merging = [u for u in units if not train_state.is_audit_unit(u)]
    lock_sha = state.get("lock_sha")
    if not merging or not lock_sha:
        raise WorkspaceError(
            f"train {train_id} has no locked contract or no recorded units. Next: {RERUN}"
        )
    for unit in merging:
        if _run(repo, "merge-base", "--is-ancestor", str(lock_sha), str(unit["branch"])).returncode:
            raise WorkspaceError(
                f"Unit {unit['branch']} does not descend from the integration branch. "
                f"Next: a likely cause is a contract revise that moved the lock {lock_sha} off "
                f"the train base {state['base_sha']} (0150); set lock_sha in the train state "
                "back to the lock the unit was built on, then rerun the finish; otherwise "
                "rerun the train, and if it repeats, file an issue with the train summary."
            )
    _skip_scope(repo, state, merging, str(lock_sha), integration)
    _git(repo, "switch", "-q", integration)
    lines = _merge_all(repo, state, train_id, merging)
    _finished(repo, train_id, merging)
    _record(repo, train_id, merged=True)
    nexts: list[str] = []
    if not _teardown(repo, units, lines, nexts):
        raise WorkspaceError("\n".join([*lines, f"Next: {'; '.join(nexts)}"]))
    return lines


SKIP_NEXT = (
    "Next: stop the train and run it again with a plan the contract step "
    "(daedalus_train.py contract --repo {repo}) answers contract: required for, so "
    "contract-spec locks a contract before more than the plan's one file merges."
)


def _skip_scope(
    repo: Path,
    state: dict[str, object],
    merging: list[dict[str, object]],
    lock_sha: str,
    integration: str,
) -> None:
    # prepush-2026-10-27 finding 4, 0156: a skipped contract covers one unit and one file.
    if state.get(train_state.CONTRACT_SKIP) is not True or state.get("packet_version") is not None:
        return
    # 126: only unmerged units count; the integration branch is judged too, as the wave merge
    # never runs this check.
    pending = [
        unit
        for unit in merging
        if _run(repo, "merge-base", "--is-ancestor", str(unit["branch"]), integration).returncode
    ]
    files = [f for unit in _recorded_plan(state).units for f in unit.files]
    nxt = SKIP_NEXT.format(repo=repo)
    if len(pending) > 1 or len(files) != 1:
        raise WorkspaceError(
            f"this train skipped the contract for a one-file plan, yet {len(pending)} units "
            f"would merge against a plan naming {len(files)} files. {nxt}"
        )
    allowed = os.path.normpath(files[0])
    for ref in [integration, *(str(unit["branch"]) for unit in pending)]:
        raw = _out(repo, "diff", "--name-only", "--no-renames", "-z", f"{lock_sha}...{ref}")
        changed = sorted(name for name in raw.split("\0") if name)
        fits = changed in ([], [allowed]) if ref == integration else changed == [allowed]
        if not fits:
            raise WorkspaceError(
                f"this train skipped the contract for the one file {files[0]}, yet {ref} "
                f"changes {_shown(changed) if changed else 'no file'}. {nxt}"
            )


def _finished(repo: Path, train_id: str, units: list[dict[str, object]]) -> None:
    # spec 4, 0121: every merged unit reads done in the progress note and takes no later write.
    for unit in units:
        refused = unit_binding.mark_finished(repo, train_id, str(unit["name"]))
        if refused is not None:
            raise WorkspaceError(refused)


def _merge_all(
    repo: Path, state: dict[str, object], train_id: str, units: list[dict[str, object]]
) -> list[str]:
    # 0121: a unit already on the integration branch is skipped, so a later wave never re-merges.
    integration = f"daedalus/{train_id}"
    merged, skipped = 0, []
    for unit in units:
        branch = str(unit["branch"])
        if _run(repo, "merge-base", "--is-ancestor", branch, integration).returncode == 0:
            skipped.append(_unit_label(train_id, str(unit["name"])))
            continue
        _merge(repo, state, train_id, unit)
        merged += 1
    lines = [f"merged {merged} units into {integration}"]
    if skipped:
        lines.append(f"skipped {', '.join(skipped)}: already on {integration}")
    return lines


VERIFIED = "[VERDICT: VERIFIED] claims=<n>"
# 0121, agents/verifier.md:138: the verifier's closing line, after its corrected=<k> line.
VERIFIED_LINE = re.compile(r"\[VERDICT: VERIFIED\] claims=[0-9]+")
VERIFIER = "verifier"
_UNIT_LINE = "Unit worktree: "
_DISPATCH_TOOLS = ("Agent", "SendMessage")
# 101, agents/orchestrator.md:135: the relay's begin marker; a payload can forge the end marker.
PAYLOAD_BEGIN = "--- research payload begin"


def before_payload(text: str) -> str:
    # 101: reading stops at the first begin marker line, so no fetched line names a worktree.
    kept: list[str] = []
    for line in text.splitlines():
        if line.lstrip().startswith(PAYLOAD_BEGIN):
            break
        kept.append(line)
    return "\n".join(kept)


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def _worktree_lines(record: dict[str, object]) -> list[str]:
    # 0121: the Unit worktree lines of a PreToolUse Agent or SendMessage record, else none.
    if record.get("event") != "PreToolUse" or record.get("tool_name") not in _DISPATCH_TOOLS:
        return []
    text = before_payload("\n".join(_strings(record.get("tool_input"))))
    return [line for line in text.splitlines() if line.startswith(_UNIT_LINE)]


def unit_verified(records: list[dict[str, object]], worktree: Path) -> bool:
    # 0121: ordered match, one verifier at a time; the window runs from the newest dispatch
    # naming the worktree to the next dispatch naming any worktree.
    line = f"{_UNIT_LINE}{worktree}"
    anchors = [i for i, r in enumerate(records) if line in _worktree_lines(r)]
    if not anchors:
        return False
    window: list[dict[str, object]] = []
    for record in records[anchors[-1] + 1 :]:
        if _worktree_lines(record):
            break
        window.append(record)
    # 0121: a verifier's reply sits in its stop tail or its hand-back call; the newest
    # string reply decides, so a null-tail stop after a hand-back does not override it.
    replies: list[object] = []
    for r in window:
        agent = r.get("agent_type")
        if not isinstance(agent, str) or agent.rpartition(":")[2] != VERIFIER:
            continue
        if r.get("event") == "SubagentStop":
            replies.append(r.get("last_message_tail"))
        elif r.get("event") == "PostToolUse" and r.get("tool_name") == audit_proof.HANDBACK:
            replies.append(audit_proof.handback_message(r))
    texts = [reply for reply in replies if isinstance(reply, str)]
    if not texts:
        return False
    last = [text.strip() for text in texts[-1].splitlines() if text.strip()]
    return bool(last) and VERIFIED_LINE.fullmatch(last[-1]) is not None


def _audit_records(repo: Path, state: dict[str, object]) -> list[dict[str, object]]:
    session = train_state.audit_session(state)
    if session is None or not SESSION_ID.fullmatch(session):
        raise WorkspaceError(
            "the train records no audit session, so no verifier verdict can be read. "
            f"Next: {VERIFY_NEXT}"
        )
    try:
        return audit_proof.read_chain(repo / audit_proof.AUDIT_DIR / f"{session}.jsonl")
    except audit_proof.ProofError as exc:
        raise WorkspaceError(
            f"the audit log could not be read ({exc}). Next: {VERIFY_NEXT}"
        ) from exc


VERIFY_NEXT = (
    "run the verifier step on that unit worktree, as the orchestrator recipe describes, "
    "then rerun the merge."
)


def _plan_ids(state: dict[str, object]) -> set[str]:
    return {unit.id.casefold() for unit in _recorded_plan(state).units}


def _recorded_plan(state: dict[str, object]) -> plan_record.Plan:
    record = train_state.record(state, train_state.PLAN)
    path, digest = record.get("path"), record.get("sha256")
    rerun = "Next: record the plan with daedalus_train.py plan --path, then rerun the merge."
    if not isinstance(path, str) or not isinstance(digest, str):
        raise WorkspaceError(f"the train records no plan. {rerun}")
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise WorkspaceError(f"the plan {path} could not be read ({exc}). {rerun}") from exc
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), digest):
        raise WorkspaceError(f"the plan {path} changed after it was recorded. {rerun}")
    try:
        return plan_record.load(Path(path))
    except plan_record.PlanError as exc:
        raise WorkspaceError(f"{exc} {rerun}") from exc


def _wave(
    repo: Path, train_id: str, state: dict[str, object], ids: list[str]
) -> list[dict[str, object]]:
    named = _plan_ids(state)
    recorded = {
        _unit_label(train_id, str(u.get("name"))).casefold(): u
        for u in train_state.units(state)
        if not train_state.is_audit_unit(u)
    }
    records: list[dict[str, object]] | None = None
    wave: list[dict[str, object]] = []
    for uid in ids:
        if uid.casefold() not in named:
            raise WorkspaceError(
                f"the plan names no unit {uid}. Next: pass only unit ids the recorded plan names."
            )
        unit = recorded.get(uid.casefold())
        if unit is None:
            raise WorkspaceError(
                f"train {train_id} records no worktree for unit {uid}. "
                "Next: create the unit worktree with daedalus_workspace.py create first."
            )
        records = _audit_records(repo, state) if records is None else records
        if not unit_verified(records, Path(str(unit["path"]))):
            raise WorkspaceError(
                f"unit {uid} has no recorded verifier verdict {VERIFIED} for its worktree "
                f"{unit['path']}. Next: {VERIFY_NEXT}"
            )
        wave.append(unit)
    return wave


def merge(repo: Path, ids: list[str]) -> list[str]:
    # 0121, 0118: one wave into the integration branch; the train stays open for the next wave.
    repo = repo.resolve()
    train_id, state = _active(repo)
    integration = f"daedalus/{train_id}"
    if not ids or len(set(i.casefold() for i in ids)) != len(ids):
        raise WorkspaceError(
            "--units names no unit or one unit twice. "
            "Next: pass each unit id once, comma-separated."
        )
    wave = _wave(repo, train_id, state, ids)
    dirty = _dirty(repo)
    if dirty:
        raise WorkspaceError(
            f"the integration worktree {repo} has changes: {_shown(dirty)}. "
            "Next: commit or discard them from your own shell, then rerun the merge."
        )
    lock_sha = state.get("lock_sha")
    for unit in wave:
        if (
            not lock_sha
            or _run(
                repo, "merge-base", "--is-ancestor", str(lock_sha), str(unit["branch"])
            ).returncode
        ):
            raise WorkspaceError(
                f"Unit {unit['branch']} does not descend from the integration branch. "
                "Next: rerun the train; if it repeats, file an issue with the train summary."
            )
    _on_branch(repo, integration)
    lines = _merge_all(repo, state, train_id, wave)
    _finished(repo, train_id, wave)
    nexts: list[str] = []
    if not _teardown(repo, wave, lines, nexts):
        raise WorkspaceError("\n".join([*lines, f"Next: {'; '.join(nexts)}"]))
    return lines


def _resume_train(repo: Path) -> str:
    train_id = train_state.active_train(repo)
    if train_id is not None:
        return train_id
    # 0024: every stop clears the marker, so resume takes the newest recorded train.
    folder = repo / train_state.STATE_DIR
    ids = (
        sorted(p.stem for p in folder.glob("*.json") if train_state.TRAIN_ID.fullmatch(p.stem))
        if folder.is_dir()
        else []
    )
    if not ids:
        raise WorkspaceError(f"no Daedalus train is recorded in {repo}. Next: {RERUN}")
    return ids[-1]


VERSION_FILE = "VERSION"
_BARE_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
_SHA = re.compile(r"[0-9a-f]{7,40}")
CLASS_SHAPE = "Version class: <version> <X, Y or Z>: <one-line reason>"
MIGRATION_SHAPE = "Migration: <what an operator edits>"
_CLASS_LINE = re.compile(r"Version class: (\S+) ([XYZ]): (\S.*)")
_MIGRATION_LINE = re.compile(r"Migration: \S.*")
# 0068: GitHub's closing keywords, the ones that close an issue from a pull request body.
_CLOSES = re.compile(r"\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?) #([0-9]+)\b", re.IGNORECASE)
RELEASE_NOTES = "release-notes.md"


def _release_train(repo: Path, merge_sha: str) -> str:
    # 0068: the squash-merge subject names the train; otherwise the active or newest train.
    shown = (
        _run(repo, "log", "-1", "--format=%s", f"{merge_sha}^{{commit}}", "--")
        if _SHA.fullmatch(merge_sha)
        else None
    )
    subject = shown.stdout if shown is not None and shown.returncode == 0 else ""
    for found in train_state.TRAIN_ID.findall(subject):
        if train_state.state_path(repo, found).is_file():
            return str(found)
    return _resume_train(repo)


def _merge_commit(repo: Path, merge_sha: str, base: str) -> str:
    off = (
        f"merge sha {merge_sha} is not on the history of {base}, the branch the pull request "
        f"merged into. Next: fetch {base}, then rerun with the merge commit sha it shows."
    )
    if not _SHA.fullmatch(merge_sha):
        raise WorkspaceError(off)
    found = _run(repo, "rev-parse", "--verify", "--quiet", f"{merge_sha}^{{commit}}")
    if found.returncode != 0:
        raise WorkspaceError(off)
    sha = found.stdout.strip()
    for ref in (f"refs/heads/{base}", f"refs/remotes/origin/{base}"):
        known = _run(repo, "rev-parse", "--verify", "--quiet", ref).returncode == 0
        if known and _run(repo, "merge-base", "--is-ancestor", sha, ref).returncode == 0:
            return sha
    raise WorkspaceError(off)


def _version_at(repo: Path, sha: str) -> str | None:
    shown = _run(repo, "show", f"{sha}:{VERSION_FILE}")
    return shown.stdout.strip() if shown.returncode == 0 else None


def _merged_version(repo: Path, sha: str) -> str:
    # 0075: VERSION at the merge sha is the one version source; the working tree is never read.
    version = _version_at(repo, sha)
    form = "the bare version as three dot-separated numbers, with no v prefix"
    if version is None:
        raise WorkspaceError(
            f"{VERSION_FILE} is missing at merge sha {sha}. Next: add a {VERSION_FILE} file "
            f"at the project root holding {form}, merge it, then rerun."
        )
    if not _BARE_VERSION.fullmatch(version):
        raise WorkspaceError(
            f"{VERSION_FILE} at merge sha {sha} does not hold a bare version. "
            f"Next: make {VERSION_FILE} hold {form}, merge it, then rerun."
        )
    return version


def _moved(base: str | None, version: str) -> str | None:
    # 0071: the first digit that differs names the class; a new VERSION file has none.
    old = _BARE_VERSION.fullmatch(base or "")
    new = _BARE_VERSION.fullmatch(version)
    if old is None or new is None:
        return None
    for letter, before, after in zip("XYZ", old.groups(), new.groups(), strict=True):
        if before != after:
            return letter
    return None


def _class_line(summary: str, version: str, moved: str | None) -> tuple[str, str]:
    # 0071: the summary's class line names the version, the digit that moved and a reason.
    found = next(
        (m for line in summary.splitlines() if (m := _CLASS_LINE.fullmatch(line.strip()))), None
    )
    if found is None:
        raise WorkspaceError(
            f"the train summary has no version class line. Next: add the line {CLASS_SHAPE} "
            "to the summary, then rerun."
        )
    named, letter, reason = found.groups()
    if named != version:
        raise WorkspaceError(
            f"the class line names version {named} but {VERSION_FILE} holds {version}. "
            f"Next: correct the class line in the summary to {version}, then rerun."
        )
    if moved is not None and letter != moved:
        raise WorkspaceError(
            f"the class line names {letter} but the {moved} digit moved. "
            f"Next: correct the class line letter in the summary to {moved}, then rerun."
        )
    return letter, reason.strip()


def _section(summary: str, head: str) -> str:
    lines = summary.splitlines()
    if head not in lines:
        return "none"
    body: list[str] = []
    for line in lines[lines.index(head) + 1 :]:
        if line.startswith("## "):
            break
        body.append(line)
    return "\n".join(body).strip() or "none"


def _render_notes(summary: str, letter: str, reason: str) -> str:
    # 0065, 0068: notes carry no version literal; the tag and the release title carry it.
    lines = summary.splitlines()
    task = next((line.strip() for line in lines if line.startswith("Task: ")), "Task: none")
    migration = [line.strip() for line in lines if _MIGRATION_LINE.fullmatch(line.strip())]
    if letter == "X" and not migration:
        raise WorkspaceError(
            "the class line names X but the summary has no migration line. "
            f"Next: add the line {MIGRATION_SHAPE} to the summary, then rerun."
        )
    issues = list(dict.fromkeys(_CLOSES.findall(summary)))
    closed = ", ".join(f"#{n}" for n in issues) or "none"
    parts = [task, f"Class: {letter}, {reason}", *migration[:1], ""]
    for head in ("## Rulings", "## Units"):
        parts += [head, _section(summary, head), ""]
    parts += ["## Closed issues", closed]
    return "\n".join(parts) + "\n"


def _scrub_check(repo: Path, text: str) -> None:
    # 0069: release notes become a public GitHub Release; the refusal names a count, never a term.
    try:
        terms = scrub.declared_terms(repo)
    except scrub.ScrubError as exc:
        raise WorkspaceError(str(exc)) from exc
    hits = scrub.count_hits(text, terms) if terms else 0
    if hits:
        raise WorkspaceError(
            f"the release notes carry {hits} term(s) from the declared scrub file. "
            "Next: remove those terms from the train summary, then rerun."
        )


def _write_notes(repo: Path, train_id: str, text: str) -> Path:
    folder = repo / SUMMARY_DIR / train_id
    try:
        for part in (repo / "docs", repo / "docs" / ".tmp", repo / SUMMARY_DIR, folder):
            atomic.refuse_links(part)
    except atomic.LinkRefused as exc:
        raise WorkspaceError(str(exc)) from exc
    _scratch(repo)
    notes = folder / RELEASE_NOTES
    try:
        folder.mkdir(exist_ok=True)
        atomic.write_atomic(notes, text, 0o644)
    except OSError as exc:
        raise WorkspaceError(
            f"cannot write {notes} ({exc}). Next: remove anything in its place, then rerun."
        ) from exc
    return notes


def release(repo: Path, merge_sha: str) -> list[str]:
    # 0068: prints the tag and release commands for the main session and runs none of them.
    repo = repo.resolve()
    train_id = _release_train(repo, merge_sha)
    try:
        state = train_state.load(repo, train_id)
    except train_state.TrainStateError as exc:
        raise WorkspaceError(str(exc)) from exc
    base, base_sha = state.get("base_branch"), state.get("base_sha")
    if state.get("scope_kind") == "folder" or not isinstance(base, str) or not base_sha:
        raise WorkspaceError(
            f"train {train_id} did not run in repository scope, and a release needs a merged "
            "pull request. Next: run the release step only after a Push Train pull request merges."
        )
    sha = _merge_commit(repo, merge_sha, base)
    version = _merged_version(repo, sha)
    # issue 47: the squash commit's first parent is the pull request base, even when main moved.
    before = _version_at(repo, f"{sha}^1")
    if before == version:
        # issue 47: an unchanged VERSION is a skip recorded in state, never a refusal.
        _record(
            repo, train_id, release={"merge_sha": sha, "outcome": "skipped", "version": version}
        )
        return [f"release: skipped, {VERSION_FILE} is unchanged since the pull request base"]
    summary_path = repo / SUMMARY_DIR / f"{train_id}-summary.md"
    try:
        summary = summary_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise WorkspaceError(
            f"cannot read the train summary {summary_path} ({exc}). "
            "Next: restore the summary the Build Train wrote, then rerun."
        ) from exc
    letter, reason = _class_line(summary, version, _moved(before, version))
    text = _render_notes(summary, letter, reason)
    _scrub_check(repo, text)
    notes = _write_notes(repo, train_id, text)
    _record(
        repo,
        train_id,
        release={"merge_sha": sha, "outcome": "ready", "version": version, "notes": str(notes)},
    )
    tag, where = f"v{version}", shlex.quote(str(repo))
    return [
        f"release: {tag}, class {letter}, merge {sha}",
        f"notes: {notes}",
        "Run these three commands from the main session, in order; this script ran none of them:",
        f"git -C {where} tag -a {tag} -m {tag} {sha}",
        f"git -C {where} push origin {tag}",
        f"gh release create {tag} --verify-tag --title {tag} "
        f"--notes-file {shlex.quote(str(notes))}",
    ]


def _resume_target(repo: Path, branch: str, start: str | None = None) -> bool:
    # issue 23: a branch an early stop deleted is created again at start, when one is known.
    head = _out(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
    if head == branch:
        return False
    missing = _run(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}").returncode
    if missing and start is None:
        return False
    dirty = _dirty(repo)
    if dirty:
        raise WorkspaceError(
            f"cannot switch {repo} to {branch}: uncommitted changes {_shown(dirty)}. "
            "Next: commit or stash them from your own shell, then say continue."
        )
    return True


def resume(repo: Path) -> list[str]:
    repo = repo.resolve()
    train_id = _resume_train(repo)
    try:
        state = train_state.load(repo, train_id)
    except train_state.TrainStateError as exc:
        raise WorkspaceError(str(exc)) from exc
    integration = f"daedalus/{train_id}"
    charter = Path(str(state["charter_root"])) if state.get("charter_branch_created") else None
    charter_base = str(state.get("charter_base") or "") or None
    lock_sha = str(state.get("lock_sha") or "") or None
    switch_charter = charter is not None and _resume_target(charter, integration, charter_base)
    switch_repo = not state.get("merged") and _resume_target(repo, integration, lock_sha)
    mark_train(repo, train_id)
    lines = [f"resumed train {train_id}"]
    if switch_charter and charter is not None:
        _on_branch(charter, integration, charter_base)
        lines.append(f"switched {charter} to {integration}")
    if switch_repo:
        _on_branch(repo, integration, lock_sha)
        lines.append(f"switched {repo} to {integration}")
    return lines

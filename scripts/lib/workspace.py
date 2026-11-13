# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import re
import shlex
import stat
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from lib import (
    atomic,
    audit_proof,
    git,
    manifest,
    narrow,
    plan_record,
    scrub,
    train_state,
    unit_binding,
    writer_mode,
)
from lib.audit import SESSION_ID, DataDirError, cache_dir_or_probe, ensure_project_data_dir
from lib.audit_proof import REFUTED_PREFIX, SUMMARY_DIR
from lib.config import Config, ConfigError, load_config
from lib.ledger import LedgerError, probe_line, read_sequence, resolve_ledger
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
    train = train_state.active_train(repo)
    # 0190: a stop or an unmark leaves no writer dispatch waiting; an unreadable record stays,
    # and every writer meeting it is refused, so it never blocks the stop.
    if train is not None:
        with contextlib.suppress(train_state.TrainStateError):
            writer_mode.clear(repo, train)
    try:
        marker.unlink(missing_ok=True)
    except OSError as exc:
        raise WorkspaceError(
            f"cannot remove {marker} ({exc}). Next: delete it from your own shell."
        ) from exc
    return marker


DIRTY_LIMIT = 10
RERUN = "start the Build Train again (/daedalus:run)."
CLEAN_NEXT = f"Next: commit or stash your changes from your own shell, then {RERUN}"
# 0257: the settings files a run may start with uncommitted, named from the repository root.
SETTINGS_PATHS = (manifest.MANIFEST_NAME, ".claude/daedalus/config.json")
# 0257: changed in the work tree or untracked only; a staged change makes git merge abort.
SETTINGS_CODES = (" M", "??")
# 0247: with no decisions file named, a run records no decisions and asks nothing about it.
LEDGER_NONE = "decisions: none, no decisions file is named in the service manifest."


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


def _digest(repo: Path, rel: str) -> str | None:
    # 0257: a regular file inside the repository, no link on the way; anything else is not admitted.
    path = repo / rel
    below = (p for p in (path, *path.parents) if p != repo and p.is_relative_to(repo))
    if any(os.path.islink(p) for p in below):
        return None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            return None
        return hashlib.sha256(handle.read()).hexdigest()


def split_settings(repo: Path, porcelain: str) -> tuple[list[str], dict[str, str]]:
    # 0257: (every other uncommitted path, each admitted settings file with its digest).
    other: list[str] = []
    settings: dict[str, str] = {}
    for line in porcelain.splitlines():
        if not line.strip():
            continue
        code, rel = line[:2], line[3:]
        found = None
        if code in SETTINGS_CODES and rel in SETTINGS_PATHS:
            found = _digest(repo, rel)
        if found is None:
            other.append(rel.split(" -> ")[-1])
        else:
            settings[rel] = found
    return other, settings


def _admitted(state: dict[str, object]) -> dict[str, str]:
    held = state.get("settings_uncommitted")
    if not isinstance(held, dict):
        return {}
    return {str(k): v for k, v in held.items() if isinstance(v, str)}


def _uncommitted(repo: Path, admitted: dict[str, str] | None = None) -> list[str]:
    # 0257: the dirty paths, less each settings file still holding the bytes it held at begin.
    out = _out(repo, "status", "--porcelain", "--untracked-files=all")
    other, settings = split_settings(repo, out)
    held = admitted or {}
    return other + [rel for rel, digest in settings.items() if held.get(rel) != digest]


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
    # 0247: a named decisions file or none; nothing is searched for and nothing is asked.
    if ledger_feature is False:
        return LEDGER_NONE
    try:
        ledger = resolve_ledger(str(repo), config)
        if ledger is None:
            return LEDGER_NONE
        seq = read_sequence(ledger)
    except LedgerError as exc:
        raise WorkspaceError(str(exc)) from exc
    return probe_line(ledger, seq)


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
    # 0019, 0245: a coding_rules builtin has no path in config.json, unlike a folder or file
    # entry; the standards skill reads its path from this line.
    packs = [f"{s.name} at {s.path}" for s in config.standards_sources if s.kind == "pack"]
    return [
        f"policy: {policy}  standards: {len(config.standards_sources)} sources",
        f"cache: {cache}" if cache else "cache: unresolved",
        f"standards packs: {', '.join(packs) or 'none declared'}",
    ]


def begin(cwd: Path, ledger_feature: bool | None = True) -> list[str]:
    # 0024: build-train Preconditions 1 to 9, ordered so a failure leaves no train state behind.
    repo = repo_root(cwd.resolve())
    # 0257: the settings files alone may stay uncommitted; their bytes are held for later checks.
    dirty, settings = split_settings(
        repo, _out(repo, "status", "--porcelain", "--untracked-files=all")
    )
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
            "settings_uncommitted": settings,
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


TMP_ROOT = Path("/tmp")


def output_target(root: Path, output: str) -> Path:
    # issue 48: a folder run's output path, absolute or relative to the project root.
    return Path(output) if Path(output).is_absolute() else root / output


def make_output(target: Path, rerun: str) -> Path:
    # issue 48: the one creation of a folder run's output folder, for start and the folder begin.
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise WorkspaceError(
            f"cannot create the output folder {target} ({exc}). "
            f"Next: pick a writable folder and rerun {rerun}."
        ) from exc
    return target.resolve()


def _folder_out(root: Path, output: str, rerun: str = "begin") -> Path | None:
    # issue 48, 0069: an existing writable folder as is; None admits <root>/docs or new under /tmp.
    target = output_target(root, output)
    real = Path(os.path.realpath(target))
    home = Path(os.path.realpath(Path.home()))
    # issue 48: never the root, its parents, home, / or anything under <root>/.claude.
    barred = (
        Path(os.path.realpath(root)).is_relative_to(real)
        or real == home
        or real.is_relative_to(Path(os.path.realpath(root / ".claude")))
    )
    if not barred and real.is_dir() and os.access(real, os.W_OK | os.X_OK):
        return real
    docs = Path(os.path.realpath(root / "docs"))
    tmp = Path(os.path.realpath(TMP_ROOT))
    if not barred and not os.path.lexists(target) and (real == docs or real.is_relative_to(tmp)):
        return None
    raise WorkspaceError(
        f"--out {output} is not an existing writable folder outside the project root, its "
        f"parents, the home folder and {root / '.claude'}, nor {root / 'docs'}, nor a new folder "
        "under /tmp. Next: pass --out one of those three, or create the folder from your own "
        f"shell, then rerun {rerun}."
    )


def checked_output(root: Path, output: str, rerun: str) -> Path:
    # issue 48: start and the folder begin record only an output folder _folder_out passed.
    return _folder_out(root, output, rerun) or make_output(output_target(root, output), rerun)


def begin_folder_run(root: Path, output: str) -> list[str]:
    # issue 48, 0178: the run entry's folder start; the runner's start shares both helpers.
    root = root.resolve()
    try:
        features = manifest.features(root)
    except manifest.ManifestError as exc:
        raise WorkspaceError(str(exc)) from exc
    kind = manifest.scope_kind(root, features)
    if kind != "folder":
        raise WorkspaceError(
            f"{root} is {kind} scope, so a run here starts with the repository begin. "
            f"Next: run begin --repo {root} without --scope, then rerun."
        )
    found = _folder_out(root, output)
    out = found or make_output(output_target(root, output), "begin")
    try:
        lines = begin_folder(root, features.ledger)
    except WorkspaceError:
        if found is None:
            # issue 48: a refused begin leaves behind no output folder it made.
            out.rmdir()
        raise
    train_id = train_state.active_train(root)
    if train_id is None:
        raise WorkspaceError(f"begin left no run marker in {root}. Next: {RERUN}")
    _record(root, train_id, scope_kind="folder", output_dir=str(out))
    return [*lines, f"scope: folder  out: {out}"]


def _active(repo: Path) -> tuple[str, dict[str, object]]:
    train_id = train_state.active_train(repo)
    if train_id is None:
        raise WorkspaceError(
            f"no Daedalus train is active in {repo}. "
            "Next: start a Build Train first (/daedalus:run)."
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
    # 0261: a revise, or a first lock after a skip, reads every open brief before it commits.
    later = isinstance(recorded, int) or state.get(train_state.CONTRACT_SKIP) is True
    refresh = _brief_refresh(repo, train_id, state, str(path)) if later else None
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
    # issue 325: the new hash rides the line, so the build skill's yield row needs no sha256sum.
    detail = (
        f"contract: {path} v{version} sha256={hashlib.sha256(path.read_bytes()).hexdigest()}"
        if unchanged.returncode == 1
        else "contract unchanged, no commit"
    )
    lines = [f"lock: {sha}", detail]
    if refresh is not None:
        from lib import train_runner  # 0261: the brief writer owns the Contract line format.

        # 0261: the version records only after every brief is written, so a rerun finishes them.
        try:
            lines += train_runner.write_refresh(repo, train_id, *refresh)
        except train_runner.RunnerError as exc:
            raise WorkspaceError(str(exc)) from exc
    _record(
        repo,
        train_id,
        contract_path=str(path),
        contract_repo=str(root),
        packet_version=version,
        lock_sha=sha,
    )
    return lines


def _brief_refresh(
    repo: Path, train_id: str, state: dict[str, object], contract: str
) -> tuple[str, list[tuple[Path, str]]]:
    from lib import train_runner  # 0261: train_runner imports this module, so it loads here.

    try:
        return train_runner.contract_refresh(repo, train_id, state, contract)
    except train_runner.RunnerError as exc:
        raise WorkspaceError(str(exc)) from exc


STOP_NEXT = "start the Build Train again (/daedalus:run)"


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
    dirty = _uncommitted(repo, _admitted(state))
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
    dirty = _uncommitted(repo, _admitted(state))
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
    # 234: every unit finish would merge passes the merge step's verdict gate before any merge.
    pending = [
        unit
        for unit in merging
        if _run(repo, "merge-base", "--is-ancestor", str(unit["branch"]), integration).returncode
    ]
    records = _audit_records(repo, state) if pending else []
    for unit in pending:
        require_verified(repo, train_id, records, unit, _unit_label(train_id, str(unit["name"])))
        require_contract(train_id, state, records, unit, _unit_label(train_id, str(unit["name"])))
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
    "contract-spec locks a contract before a file outside the plan's files merges."
)


def _skip_scope(
    repo: Path,
    state: dict[str, object],
    merging: list[dict[str, object]],
    lock_sha: str,
    integration: str,
) -> None:
    # prepush-2026-10-27 finding 4, 0182: a skipped contract covers one unit and its plan files.
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
    if len(pending) > 1 or not 1 <= len(files) <= plan_record.CONTRACT_SKIP_FILES:
        raise WorkspaceError(
            f"this train skipped the contract for a one-unit plan of at most "
            f"{plan_record.CONTRACT_SKIP_FILES} files, yet {len(pending)} units "
            f"would merge against a plan naming {len(files)} files. {nxt}"
        )
    allowed = sorted({os.path.normpath(f) for f in files})
    for ref in [integration, *(str(unit["branch"]) for unit in pending)]:
        raw = _out(repo, "diff", "--name-only", "--no-renames", "-z", f"{lock_sha}...{ref}")
        changed = sorted(name for name in raw.split("\0") if name)
        # 0182: the unit changes a non-empty subset of the plan files; integration may change none.
        fits = set(changed) <= set(allowed) and (bool(changed) or ref == integration)
        if not fits:
            raise WorkspaceError(
                f"this train skipped the contract for the files {_shown(allowed)}, yet {ref} "
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
# 0121, agents/verifier.md:167: the verifier's closing line, after its corrected=<k> line.
VERIFIED_LINE = re.compile(r"\[VERDICT: VERIFIED\] claims=[0-9]+")
VERIFIER = "verifier"
_VERDICT_OPEN = "[VERDICT: "
_UNIT_LINE = "Unit worktree: "
_DISPATCH_TOOLS = ("Agent", "SendMessage")
# 101, skills/build/SKILL.md:32: the relay's begin marker; a payload can forge the end marker.
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


def _anchors(records: list[dict[str, object]], worktree: Path) -> list[int]:
    line = f"{_UNIT_LINE}{worktree}"
    return [i for i, r in enumerate(records) if line in _worktree_lines(r)]


def unit_verified(
    records: list[dict[str, object]],
    worktree: Path,
    exemptions: dict[str, object] | None = None,
    tip: str | None = None,
    run: str | None = None,
) -> bool:
    # 0231: the unit's own newest reply, selected by its key line, never by window position.
    reply = newest_verdict(records, worktree)
    if reply is None:
        return False
    seq, last = reply
    if VERIFIED_LINE.fullmatch(last) is not None:
        return True
    # 229, 0161: a REFUTED reply passes once every row carries an exemption keyed to that reply.
    rows = refuted_rows(last)
    if not rows or tip is None or not isinstance(seq, int) or isinstance(seq, bool):
        return False
    granted = train_state.record(exemptions or {}, str(seq))
    return all(audit_proof._exempt(granted.get(str(n)), tip, run) for n in range(1, len(rows) + 1))


def unit_refutations(records: list[dict[str, object]], worktree: Path) -> int:
    # 0187, 0231: one refutation per dispatch naming the worktree whose keyed reply is REFUTED.
    anchors = _anchors(records, worktree)
    count = 0
    for start, stop in zip(anchors, [*anchors[1:], len(records)], strict=False):
        reply = _pick(_keyed_replies(records, worktree, start, stop))
        if reply is not None and reply[1] is not None and reply[1].startswith(REFUTED_PREFIX):
            count += 1
    return count


def refuted_rows(line: str) -> list[str] | None:
    # 229, agents/verifier.md:165: rows joined by "; "; a bare ";" leaves the row count unknown.
    if not line.startswith(REFUTED_PREFIX):
        return None
    body = line.removeprefix(REFUTED_PREFIX).strip()
    rows = [row.strip() for row in body.split("; ")] if body else []
    if any(not row or ";" in row for row in rows):
        return None
    return rows


def newest_verdict(records: list[dict[str, object]], worktree: Path) -> tuple[object, str] | None:
    # 229: the audit seq and verdict line of the unit's newest keyed reply.
    reply = newest_reply(records, worktree)
    if reply is None or reply[1] is None:
        return None
    return reply[0], reply[1]


def newest_reply(
    records: list[dict[str, object]], worktree: Path
) -> tuple[object, str | None, str] | None:
    # 0231: the newest verifier reply whose second line names the worktree, after the newest
    # dispatch naming it; a reply keyed to any other path is never a candidate.
    anchors = _anchors(records, worktree)
    if not anchors:
        return None
    return _pick(_keyed_replies(records, worktree, anchors[-1], len(records)))


def _reply_key(text: str) -> str | None:
    # 0231, agents/verifier.md:155: the key is the line directly after the opening line.
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[1] if len(lines) > 1 else None


def _keyed_replies(
    records: list[dict[str, object]], worktree: Path, start: int, stop: int
) -> list[tuple[object, object, object, str]]:
    # 0121: a verifier's reply sits in its stop tail or its hand-back call.
    key = f"{_UNIT_LINE}{worktree}"
    texts: list[tuple[object, object, object, str]] = []
    for r in records[start + 1 : stop]:
        agent = r.get("agent_type")
        if not isinstance(agent, str) or agent.rpartition(":")[2] != VERIFIER:
            continue
        reply: object = None
        if r.get("event") == "SubagentStop":
            reply = r.get("last_message_tail")
        elif r.get("event") == "PostToolUse" and r.get("tool_name") == audit_proof.HANDBACK:
            reply = audit_proof.handback_message(r)
        if isinstance(reply, str) and _reply_key(reply) == key:
            texts.append((r.get("seq"), r.get("event"), r.get("agent_id"), reply))
    return texts


def _pick(
    texts: list[tuple[object, object, object, str]],
) -> tuple[object, str | None, str] | None:
    # 235: seq, verdict line (None when malformed) and text of the newest keyed reply.
    if not texts:
        return None
    seq, event, agent_id, text = texts[-1]
    # 235, 187: the hand-back is the reply; the same verifier's later stop tail is a digest.
    if event == "SubagentStop" and len(texts) > 1:
        prior = texts[-2]
        if prior[1] == "PostToolUse" and isinstance(agent_id, str) and prior[2] == agent_id:
            seq, text = prior[0], prior[3]
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    # 222, agents/verifier.md:154: the first and last lines are one verdict line, else none.
    if len(lines) < 2 or lines[0] != lines[-1] or not lines[-1].startswith(_VERDICT_OPEN):
        return seq, None, text
    return seq, lines[-1], text


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


# 229: unit record {"exemptions": {"<reply seq>": {"<row>": {ledger_id, tip, tracking[, other]}}}}.
# 0249: with no decisions file, finding, reason and run_id stand in place of ledger_id.
UNIT_EXEMPTIONS = "exemptions"


def unit_tip(repo: Path, unit: dict[str, object]) -> str:
    # 229: an exemption binds to the unit branch tip, so a later commit on the unit voids it.
    return _out(repo, "rev-parse", "--verify", f"refs/heads/{unit['branch']}").strip()


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
        require_verified(repo, train_id, records, unit, uid)
        require_contract(train_id, state, records, unit, uid)
        wave.append(unit)
    return wave


def require_verified(
    repo: Path,
    train_id: str,
    records: list[dict[str, object]],
    unit: dict[str, object],
    uid: str,
) -> None:
    # 234: the one verdict gate merge and finish share; an exemption binds to the unit tip.
    exempt = train_state.record(unit, UNIT_EXEMPTIONS)
    tip = unit_tip(repo, unit) if exempt else None
    run = audit_proof.accepting_run(repo, train_id) if exempt else None
    if not unit_verified(records, Path(str(unit["path"])), exempt, tip, run):
        raise WorkspaceError(
            f"unit {uid} has no recorded verifier verdict {VERIFIED} for its worktree "
            f"{unit['path']}. Next: {VERIFY_NEXT}"
        )


def require_contract(
    train_id: str,
    state: dict[str, object],
    records: list[dict[str, object]],
    unit: dict[str, object],
    uid: str,
) -> None:
    # 0271: a locked contract only; a skipped one keeps the _skip_scope rule.
    contract = state.get("contract_path")
    if not isinstance(contract, str) or not contract:
        return
    # 0271, 0134: by recorded name or flag, the docs and audit units have no coder to compare.
    if (
        train_state.is_audit_unit(unit)
        or unit.get("name") == f"{train_id}{train_state.DOCS_SUFFIX}"
    ):
        return
    from lib import train_runner  # 0271: train_runner imports this module, so it loads here.

    refusal = train_runner.completion_contract_refusal(contract, records, str(unit["branch"]), uid)
    if refusal is not None:
        raise WorkspaceError(refusal)


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
    dirty = _uncommitted(repo, _admitted(state))
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
# Work-order line 24: a `Refs #N` or `partial #N` reference marks the issue as partly done.
_REFS = re.compile(r"\b(?:refs?|partial(?:ly)?|part of) #([0-9]+)\b", re.IGNORECASE)
# 220: a range needs `#` or `issue(s) ` before it; a reversed or over-50 span is ignored.
MAX_ISSUE_RANGE = 50
_TASK_ISSUES = re.compile(
    r"(?:#|\bissues? )([0-9]+)\s*(?:to|through|-)\s*#?([0-9]+)\b"
    r"|#([0-9]+)\b|\bissues? ((?:[0-9]+(?:, and |, | and ))*[0-9]+)\b",
    re.IGNORECASE,
)
RELEASE_NOTES = "release-notes.md"
PR_BODY = "pr-body.md"
RELEASES_DIR = "releases"


@dataclass(frozen=True)
class _Source:
    name: str
    short: str


_SUMMARY = _Source("the train summary", "the summary")


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
    try:
        return _resume_train(repo)
    except WorkspaceError as exc:
        # 130: a plain-branch merge has no train; its pull request body is the notes source.
        raise WorkspaceError(
            f"no Daedalus train is recorded in {repo}, and no notes file was named. "
            "Next: save the pull request body to a file, then rerun with --notes-file <path>."
        ) from exc


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


def _class_line(
    summary: str, version: str, moved: str | None, source: _Source = _SUMMARY
) -> tuple[str, str]:
    # 0071: the summary's class line names the version, the digit that moved and a reason.
    found = next(
        (m for line in summary.splitlines() if (m := _CLASS_LINE.fullmatch(line.strip()))), None
    )
    if found is None:
        raise WorkspaceError(
            f"{source.name} has no version class line. Next: add the line {CLASS_SHAPE} "
            f"to {source.short}, then rerun."
        )
    named, letter, reason = found.groups()
    if named != version:
        raise WorkspaceError(
            f"the class line names version {named} but {VERSION_FILE} holds {version}. "
            f"Next: correct the class line in {source.short} to {version}, then rerun."
        )
    if moved is not None and letter != moved:
        raise WorkspaceError(
            f"the class line names {letter} but the {moved} digit moved. "
            f"Next: correct the class line letter in {source.short} to {moved}, then rerun."
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


def _render_notes(
    summary: str, letter: str, reason: str, source: _Source = _SUMMARY, task: str = "Task: none"
) -> str:
    # 0065, 0068: notes carry no version literal; the tag and the release title carry it.
    lines = summary.splitlines()
    task = next((line.strip() for line in lines if line.startswith("Task: ")), task)
    migration = [line.strip() for line in lines if _MIGRATION_LINE.fullmatch(line.strip())]
    if letter == "X" and not migration:
        raise WorkspaceError(
            f"the class line names X but {source.short} has no migration line. "
            f"Next: add the line {MIGRATION_SHAPE} to {source.short}, then rerun."
        )
    issues = list(dict.fromkeys(_CLOSES.findall(summary)))
    closed = ", ".join(f"#{n}" for n in issues) or "none"
    parts = [task, f"Class: {letter}, {reason}", *migration[:1], ""]
    for head in ("## Rulings", "## Units"):
        parts += [head, _section(summary, head), ""]
    parts += ["## Closed issues", closed]
    return "\n".join(parts) + "\n"


def _scrub_check(repo: Path, text: str, source: _Source = _SUMMARY) -> None:
    # 0069: release notes become a public GitHub Release; the refusal names a count, never a term.
    try:
        terms = scrub.declared_terms(repo)
    except scrub.ScrubError as exc:
        raise WorkspaceError(str(exc)) from exc
    hits = scrub.count_hits(text, terms) if terms else 0
    if hits:
        raise WorkspaceError(
            f"the release notes carry {hits} term(s) from the declared scrub file. "
            f"Next: remove those terms from {source.name}, then rerun."
        )


def _write_scratch(repo: Path, folders: tuple[str, ...], name: str, text: str) -> Path:
    chain = [repo / "docs", repo / "docs" / ".tmp", repo / SUMMARY_DIR]
    for folder in folders:
        chain.append(chain[-1] / folder)
    try:
        for link in chain:
            atomic.refuse_links(link)
    except atomic.LinkRefused as exc:
        raise WorkspaceError(str(exc)) from exc
    _scratch(repo)
    target = chain[-1] / name
    try:
        for link in chain[3:]:
            link.mkdir(exist_ok=True)
        atomic.write_atomic(target, text, 0o644)
    except OSError as exc:
        raise WorkspaceError(
            f"cannot write {target} ({exc}). Next: remove anything in its place, then rerun."
        ) from exc
    return target


def _write_notes(repo: Path, train_id: str, text: str) -> Path:
    return _write_scratch(repo, (train_id,), RELEASE_NOTES, text)


def _release_lines(repo: Path, version: str, letter: str, sha: str, notes: Path) -> list[str]:
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


def _plain_release(repo: Path, merge_sha: str, notes_file: Path, base: str) -> list[str]:
    # 130, 0163: a plain-branch merge has no train; the pull request body file is the notes source.
    sha = _merge_commit(repo, merge_sha, base)
    version = _merged_version(repo, sha)
    before = _version_at(repo, f"{sha}^1")
    if before == version:
        return [f"release: skipped, {VERSION_FILE} is unchanged since the pull request base"]
    try:
        body = notes_file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise WorkspaceError(
            f"cannot read the notes file {notes_file} ({exc}). "
            "Next: save the pull request body to that file, then rerun."
        ) from exc
    source = _Source(f"the notes file {notes_file}", "the notes file")
    letter, reason = _class_line(body, version, _moved(before, version), source)
    subject = _out(repo, "log", "-1", "--format=%s", sha, "--").strip()
    text = _render_notes(body, letter, reason, source, f"Task: {subject}")
    _scrub_check(repo, text, source)
    notes = _write_scratch(repo, (RELEASES_DIR, f"v{version}"), RELEASE_NOTES, text)
    return _release_lines(repo, version, letter, sha, notes)


def release(
    repo: Path, merge_sha: str, notes_file: Path | None = None, base: str = "main"
) -> list[str]:
    # 0068: prints the tag and release commands for the main session and runs none of them.
    repo = repo.resolve()
    if notes_file is not None:
        return _plain_release(repo, merge_sha, notes_file, base)
    train_id = _release_train(repo, merge_sha)
    try:
        state = train_state.load(repo, train_id)
    except train_state.TrainStateError as exc:
        raise WorkspaceError(str(exc)) from exc
    state_base, base_sha = state.get("base_branch"), state.get("base_sha")
    if state.get("scope_kind") == "folder" or not isinstance(state_base, str) or not base_sha:
        raise WorkspaceError(
            f"train {train_id} did not run in repository scope, and a release needs a merged "
            "pull request. Next: run the release step only after a Push Train pull request merges."
        )
    sha = _merge_commit(repo, merge_sha, state_base)
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
    return _release_lines(repo, version, letter, sha, notes)


def _task_issues(summary: str) -> list[str]:
    task = next((ln.strip() for ln in summary.splitlines() if ln.startswith("Task: ")), "")
    found: list[str] = []
    for low, high, hashed, words in _TASK_ISSUES.findall(task):
        if low:
            first, last = int(low), int(high)
            if first <= last < first + MAX_ISSUE_RANGE:
                found += [str(n) for n in range(first, last + 1)]
        else:
            found += [hashed] if hashed else re.findall(r"[0-9]+", words)
    return found


def issue_lines(summary: str) -> list[str]:
    # Work-order line 24: Closes only from a closing keyword; any other mention, partial too, Refs.
    partial = _REFS.findall(summary)
    closed = [n for n in dict.fromkeys(_CLOSES.findall(summary)) if n not in partial]
    mentioned = dict.fromkeys([*_task_issues(summary), *partial])
    return [f"Closes #{n}" for n in closed] + [f"Refs #{n}" for n in mentioned if n not in closed]


def pr_body(repo: Path, train_id: str) -> list[str]:
    # Work-order line 24: the pull request body is the summary plus one Closes or Refs line each.
    repo = repo.resolve()
    if not train_state.TRAIN_ID.fullmatch(train_id):
        raise WorkspaceError(
            f"{train_id!r} is not a run id (YYYYMMDD-HHMMSS). "
            "Next: pass the run id from the summary file name."
        )
    summary_path = repo / SUMMARY_DIR / f"{train_id}-summary.md"
    try:
        summary = summary_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise WorkspaceError(
            f"cannot read the train summary {summary_path} ({exc}). "
            "Next: restore the summary the Build Train wrote, then rerun."
        ) from exc
    lines = issue_lines(summary)
    text = summary.rstrip("\n") + "\n" + ("\n" + "\n".join(lines) + "\n" if lines else "")
    body = _write_scratch(repo, (train_id,), PR_BODY, text)
    return [f"body: {body}", f"issues: {', '.join(lines) or 'none'}"]


def _resume_target(
    repo: Path, branch: str, start: str | None = None, admitted: dict[str, str] | None = None
) -> bool:
    # issue 23: a branch an early stop deleted is created again at start, when one is known.
    head = _out(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
    if head == branch:
        return False
    missing = _run(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}").returncode
    if missing and start is None:
        return False
    dirty = _uncommitted(repo, admitted)
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
    switch_repo = not state.get("merged") and _resume_target(
        repo, integration, lock_sha, _admitted(state)
    )
    mark_train(repo, train_id)
    lines = [f"resumed train {train_id}"]
    if switch_charter and charter is not None:
        _on_branch(charter, integration, charter_base)
        lines.append(f"switched {charter} to {integration}")
    if switch_repo:
        _on_branch(repo, integration, lock_sha)
        lines.append(f"switched {repo} to {integration}")
    return lines

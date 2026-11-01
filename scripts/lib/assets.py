# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0192: the manifest assets block as a git pathspec tail the judges and the secret scan copy.
# 0128: a file with a source ending is never excluded, by root, by ending or by size.
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from lib import git
from lib.manifest import Assets, is_source, pathspec_safe

MAX_SOURCE_LINES = 10


class AssetsError(RuntimeError):
    pass


@dataclass(frozen=True)
class Exclusion:
    # 0192: whole roots, asset endings and single files a mixed root needs; plus what stays in.
    roots: tuple[str, ...] = ()
    extensions: tuple[str, ...] = ()
    names: tuple[str, ...] = ()
    over: tuple[tuple[str, int], ...] = ()
    root_sources: tuple[str, ...] = ()
    kept: tuple[str, ...] = ()


def declared(assets: Assets) -> bool:
    return bool(assets.roots or assets.extensions or assets.max_bytes is not None)


def _root_of(assets: Assets, path: str) -> str | None:
    for root in assets.roots:
        bare = root.rstrip("/")
        if path == bare or path.startswith(f"{bare}/"):
            return root
    return None


def excluded(assets: Assets, path: str) -> bool:
    # 0192: under an asset root or carrying an asset ending, and never a source ending.
    if is_source(path):
        return False
    return _root_of(assets, path) is not None or path.endswith(assets.extensions)


def _words(found: Exclusion) -> list[str]:
    return [
        *(f":(exclude){root}" for root in found.roots),
        *(f":(exclude)*{ext}" for ext in found.extensions),
        *(f":(exclude){name}" for name in found.names),
    ]


def diff_tail(found: Exclusion) -> str:
    # 0192: the shell form a git diff or git log line ends with; empty when nothing is excluded.
    words = _words(found)
    return " ".join(["--", ".", *(f"'{word}'" for word in words)]) if words else ""


def log_opts_tail(found: Exclusion) -> str:
    # 0192: gitleaks splits --log-opts on spaces and keeps quotes, so each word goes unquoted.
    words = _words(found)
    return " ".join(["--", ".", *words]) if words else ""


def _names(repo: Path, args: list[str]) -> set[str]:
    done = git.run(args, repo)
    if done.returncode != 0:
        raise AssetsError(
            f"git {' '.join(args)} failed: {done.stderr.strip()}. Next: pass the recorded base "
            "sha and the branch the judges read, both held by this repository."
        )
    return {name.strip("\n") for name in done.stdout.split("\0") if name.strip("\n")}


def _sizes(repo: Path, tip: str, wanted: set[str]) -> dict[str, int]:
    tree = git.run(["ls-tree", "-r", "-l", "-z", tip], repo)
    if tree.returncode != 0:
        raise AssetsError(
            f"git ls-tree {tip} failed: {tree.stderr.strip()}. Next: pass a tip this repository "
            "holds, the branch or commit the judges read."
        )
    sizes: dict[str, int] = {}
    for entry in tree.stdout.split("\0"):
        meta, _, path = entry.partition("\t")
        parts = meta.split()
        if path in wanted and len(parts) == 4 and parts[3].isdigit():
            sizes[path] = int(parts[3])
    return sizes


def touched(repo: Path, base: str, tip: str) -> set[str]:
    # 0192: every path any commit of the range touches, so the secret scan's log is covered too.
    for ref in (base, tip):
        if not ref or ref.startswith("-"):
            raise AssetsError(
                f"{ref!r} is not a commit name. Next: pass the recorded base sha and the branch "
                "the judges read."
            )
    # 0192: --no-renames, so a source file renamed to an asset name still counts as touched.
    log = ["log", "-m", "--no-renames", "--name-only", "-z", "--format=", f"{base}..{tip}"]
    diff = ["diff", "--no-renames", "--name-only", "-z", f"{base}...{tip}"]
    return _names(repo, log) | _names(repo, diff)


def exclusion(repo: Path, base: str, tip: str, assets: Assets) -> Exclusion:
    # 0192: a root is dropped whole only when the range touches no source file under it.
    if not declared(assets):
        return Exclusion()
    paths = touched(repo, base, tip)
    sources = sorted(p for p in paths if is_source(p) and _root_of(assets, p) is not None)
    mixed = {_root_of(assets, p) for p in sources}
    names: list[str] = []
    kept: list[str] = []
    for path in sorted(paths):
        if _root_of(assets, path) not in mixed or not excluded(assets, path):
            continue
        if not path.endswith(assets.extensions):
            (names if pathspec_safe(path) else kept).append(path)
    over: tuple[tuple[str, int], ...] = ()
    if assets.max_bytes is not None:
        dropped = {p for p in paths if excluded(assets, p) and p not in kept}
        sizes = _sizes(repo, tip, dropped)
        over = tuple(sorted((p, n) for p, n in sizes.items() if n > assets.max_bytes))
    roots = tuple(r for r in assets.roots if r not in mixed)
    return Exclusion(roots, assets.extensions, tuple(names), over, tuple(sources), tuple(kept))


def lines(found: Exclusion) -> list[str]:
    # 0192: what the assets subcommand prints; agents copy the tails, never compose them.
    tail = diff_tail(found)
    out = [f"Assets: {tail}", f"Assets log-opts: {log_opts_tail(found)}"] if tail else []
    out = out or ["Assets: none"]
    out += [f"Over size: {path} ({size} bytes)" for path, size in found.over]
    out += [f"Asset root source: {path}" for path in found.root_sources]
    out += [f"Kept in the diff: {path} (no exclusion can carry its name)" for path in found.kept]
    return out


def sources_in_roots(root: Path, assets: Assets) -> list[str]:
    # 0192: project-relative source files under an asset root, for the doctor's warning lines.
    found: list[str] = []
    for entry in assets.roots:
        folder = root / entry.rstrip("/")
        if not folder.is_dir() or folder.is_symlink():
            continue
        for path in sorted(folder.rglob("*")):
            rel = path.relative_to(root).as_posix()
            if path.is_file() and is_source(rel):
                found.append(rel)
    return found

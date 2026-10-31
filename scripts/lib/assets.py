# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0192: the manifest assets block as a git pathspec tail the judges and the secret scan copy.
# The tail drops asset roots, asset endings and changed files over max_bytes from a content diff.
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from lib import git
from lib.manifest import Assets, pathspec_safe

# 0192: endings the doctor treats as source; a source file under an asset root is a design error.
SOURCE_EXTENSIONS = (".py", ".ts", ".tsx", ".js", ".tf", ".json", ".yaml", ".yml", ".md")
MAX_SOURCE_LINES = 10


class AssetsError(RuntimeError):
    pass


@dataclass(frozen=True)
class Oversized:
    path: str
    size: int
    excluded: bool


def declared(assets: Assets) -> bool:
    return bool(assets.roots or assets.extensions or assets.max_bytes is not None)


def matches(assets: Assets, path: str) -> bool:
    # 0192: the same test the pathspec makes; a root prefix or an ending, case as written.
    under = any(path == r.rstrip("/") or path.startswith(f"{r.rstrip('/')}/") for r in assets.roots)
    return under or any(path.endswith(ext) for ext in assets.extensions)


def _words(assets: Assets, extra: tuple[str, ...]) -> list[str]:
    roots = [f":(exclude){root}" for root in assets.roots]
    endings = [f":(exclude)*{ext}" for ext in assets.extensions]
    return [*roots, *endings, *(f":(exclude){path}" for path in extra)]


def diff_tail(assets: Assets, extra: tuple[str, ...] = ()) -> str:
    # 0192: the shell form a git diff or git log line ends with; empty when nothing is excluded.
    words = _words(assets, extra)
    return " ".join(["--", ".", *(f"'{word}'" for word in words)]) if words else ""


def log_opts_tail(assets: Assets, extra: tuple[str, ...] = ()) -> str:
    # 0192: gitleaks splits --log-opts on spaces and keeps quotes, so each word goes unquoted.
    words = _words(assets, extra)
    return " ".join(["--", ".", *words]) if words else ""


def oversized(repo: Path, base: str, tip: str, assets: Assets) -> list[Oversized]:
    # 0192: changed files at tip over max_bytes, by name only; a name no pathspec carries stays in.
    if assets.max_bytes is None:
        return []
    for ref in (base, tip):
        if not ref or ref.startswith("-"):
            raise AssetsError(
                f"{ref!r} is not a commit name. Next: pass the recorded base sha and the branch "
                "the judges read."
            )
    names = git.run(["diff", "--name-only", "-z", "--diff-filter=d", f"{base}...{tip}"], repo)
    if names.returncode != 0:
        raise AssetsError(
            f"git diff {base}...{tip} failed: {names.stderr.strip()}. Next: pass a base and a "
            "tip this repository holds."
        )
    changed = {name for name in names.stdout.split("\0") if name and not matches(assets, name)}
    if not changed:
        return []
    tree = git.run(["ls-tree", "-r", "-l", "-z", tip], repo)
    if tree.returncode != 0:
        raise AssetsError(
            f"git ls-tree {tip} failed: {tree.stderr.strip()}. Next: pass a tip this repository "
            "holds, the branch or commit the judges read."
        )
    found: list[Oversized] = []
    for entry in tree.stdout.split("\0"):
        meta, _, path = entry.partition("\t")
        parts = meta.split()
        if path not in changed or len(parts) != 4 or not parts[3].isdigit():
            continue
        size = int(parts[3])
        if size > assets.max_bytes:
            found.append(Oversized(path, size, pathspec_safe(path)))
    return sorted(found, key=lambda item: item.path)


def lines(assets: Assets, big: list[Oversized]) -> list[str]:
    # 0192: what the assets subcommand prints; agents copy the tails, never compose them.
    extra = tuple(item.path for item in big if item.excluded)
    tail = diff_tail(assets, extra)
    if not tail:
        return ["Assets: none"]
    out = [f"Assets: {tail}", f"Assets log-opts: {log_opts_tail(assets, extra)}"]
    for item in big:
        kept = "" if item.excluded else ", kept in the diff: no exclusion can carry its name"
        out.append(f"Over size: {item.path} ({item.size} bytes{kept})")
    return out


def sources_in_roots(root: Path, assets: Assets) -> list[str]:
    # 0192: project-relative source files under an asset root, for the doctor's warning lines.
    found: list[str] = []
    for entry in assets.roots:
        folder = root / entry.rstrip("/")
        if not folder.is_dir() or folder.is_symlink():
            continue
        for path in sorted(folder.rglob("*")):
            if path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS:
                found.append(path.relative_to(root).as_posix())
    return found

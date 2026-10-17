# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
"""The one reader of <repo>/service-manifest.json; ledger.py and the jail both use it."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MANIFEST_NAME = "service-manifest.json"
NARROWING_KEYS = ("forbidden_paths", "forbidden_extensions")
_GLOB = frozenset("*?[]")


class ManifestError(ValueError):
    pass


@dataclass(frozen=True)
class Manifest:
    forbidden_paths: tuple[str, ...] = ()
    forbidden_extensions: tuple[str, ...] = ()


def read_raw(repo: Path) -> Any:
    # 0054: None when absent; unreadable or malformed JSON raises with a Next line.
    target = repo / MANIFEST_NAME
    if not target.is_file():
        return None
    try:
        return json.loads(target.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ManifestError(
            f"{target} could not be read as JSON ({exc}). Next: fix the manifest syntax."
        ) from exc


def _shape_error(target: Path, detail: str) -> ManifestError:
    return ManifestError(
        f"{target} jail_narrowing {detail}. Next: fix jail_narrowing to match the example "
        "in docs/project-requirements.md."
    )


def _path_ok(entry: str) -> bool:
    # 0054: repo-relative, forward slashes, no glob; a trailing slash marks a folder prefix.
    if not entry or entry.startswith("/") or "\\" in entry or _GLOB & set(entry):
        return False
    parts = entry.removesuffix("/").split("/")
    return all(part not in {"", ".", ".."} for part in parts)


def _extension_ok(entry: str) -> bool:
    banned = {"/", "\\"} | _GLOB
    return entry.startswith(".") and bool(entry.strip(".")) and not banned & set(entry)


def _strings(target: Path, block: dict[str, Any], key: str) -> tuple[str, ...]:
    value = block.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _shape_error(target, f"{key} must be a list of strings")
    return tuple(value)


def load(repo: Path) -> Manifest | None:
    raw = read_raw(repo)
    if raw is None:
        return None
    target = repo / MANIFEST_NAME
    if not isinstance(raw, dict):
        raise ManifestError(
            f"{target} is not a JSON object. Next: start from the example in "
            "docs/project-requirements.md."
        )
    block = raw.get("jail_narrowing", {})
    if not isinstance(block, dict):
        raise _shape_error(target, "must be an object")
    unknown = sorted(set(block) - set(NARROWING_KEYS))
    if unknown:
        raise _shape_error(target, f"has unknown keys {', '.join(unknown)}")
    paths = _strings(target, block, "forbidden_paths")
    extensions = _strings(target, block, "forbidden_extensions")
    bad_paths = [p for p in paths if not _path_ok(p)]
    if bad_paths:
        raise _shape_error(
            target,
            f"forbidden_paths entries {bad_paths} are not repo-relative forward-slash paths "
            "without a leading slash, '..' or glob characters",
        )
    bad_ext = [e for e in extensions if not _extension_ok(e)]
    if bad_ext:
        raise _shape_error(
            target,
            f"forbidden_extensions entries {bad_ext} must each start with a dot and hold no "
            "slash or glob characters",
        )
    return Manifest(paths, extensions)


def path_hit(manifest: Manifest, rel: str) -> bool:
    # 0054: casefolded, so a case-insensitive mount cannot dodge an entry by case.
    folded = rel.casefold().removesuffix("/")
    for entry in manifest.forbidden_paths:
        want = entry.casefold()
        bare = want.removesuffix("/")
        # 0054: an ancestor is hit too; rm -r or mv on it would take the entry along.
        if folded == bare or bare.startswith(f"{folded}/"):
            return True
        if want.endswith("/") and folded.startswith(want):
            return True
    return False


def extension_hit(manifest: Manifest, rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1].casefold()
    return any(name.endswith(ext.casefold()) for ext in manifest.forbidden_extensions)

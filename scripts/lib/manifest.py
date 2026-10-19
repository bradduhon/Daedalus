# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
"""The one reader of <repo>/service-manifest.json; ledger.py, the jail and the trains use it."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Literal

MANIFEST_NAME = "service-manifest.json"
NARROWING_KEYS = ("forbidden_paths", "forbidden_extensions")
SCOPE_KINDS = ("repository", "folder")
_GLOB = frozenset("*?[]")


class ManifestError(ValueError):
    pass


@dataclass(frozen=True)
class Features:
    # 0069: spec 3.9 absent defaults; a field typed None-able keeps null as its absent value.
    scope: Literal["repository", "folder"] | None = None
    secrets_scan: bool = False
    scrub_file: str | None = None
    ledger: bool | None = None


# 0073: the one list of feature names; validator check 13 and the key reference import it.
FEATURE_KEYS = tuple(f.name for f in fields(Features))


@dataclass(frozen=True)
class Manifest:
    forbidden_paths: tuple[str, ...] = ()
    forbidden_extensions: tuple[str, ...] = ()
    features: Features = field(default_factory=Features)
    trains_dir: str | None = None
    unit_test_cmd: str | None = None


def read_raw(repo: Path) -> object:
    # 0054: None when absent; unreadable or malformed JSON raises with a Next line.
    target = repo / MANIFEST_NAME
    if not target.is_file():
        return None
    try:
        parsed: object = json.loads(target.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ManifestError(
            f"{target} could not be read as JSON ({exc}). Next: fix the manifest syntax."
        ) from exc
    return parsed


def _shape_error(target: Path, detail: str) -> ManifestError:
    return ManifestError(
        f"{target} jail_narrowing {detail}. Next: fix jail_narrowing to match the example "
        "in docs/project-requirements.md."
    )


def _key_error(target: Path, key: str, detail: str) -> ManifestError:
    return ManifestError(
        f"{target} {key} {detail}. Next: correct the {key} value in the service manifest, "
        "then rerun."
    )


def repo_relative(entry: str) -> bool:
    # 0054: repo-relative, forward slashes, no glob; a trailing slash marks a folder prefix.
    if not entry or entry.startswith("/") or "\\" in entry or _GLOB & set(entry):
        return False
    parts = entry.removesuffix("/").split("/")
    return all(part not in {"", ".", ".."} for part in parts)


def _extension_ok(entry: str) -> bool:
    banned = {"/", "\\"} | _GLOB
    return entry.startswith(".") and bool(entry.strip(".")) and not banned & set(entry)


def _strings(target: Path, block: dict[str, object], key: str) -> tuple[str, ...]:
    value = block.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _shape_error(target, f"{key} must be a list of strings")
    return tuple(str(item) for item in value)


def _narrowing(target: Path, raw: dict[str, object]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    block = raw.get("jail_narrowing", {})
    if not isinstance(block, dict):
        raise _shape_error(target, "must be an object")
    unknown = sorted(set(block) - set(NARROWING_KEYS))
    if unknown:
        raise _shape_error(target, f"has unknown keys {', '.join(unknown)}")
    paths = _strings(target, block, "forbidden_paths")
    extensions = _strings(target, block, "forbidden_extensions")
    bad_paths = [p for p in paths if not repo_relative(p)]
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
    return paths, extensions


def _features(target: Path, raw: dict[str, object]) -> Features:
    # 0073: an unknown key or a value outside its field's type is refused, never ignored.
    block = raw.get("features", {})
    if not isinstance(block, dict):
        raise _key_error(target, "features", "must be an object")
    unknown = sorted(str(key) for key in set(block) - set(FEATURE_KEYS))
    if unknown:
        known = ", ".join(FEATURE_KEYS)
        raise _key_error(target, "features", f"has unknown keys {unknown} (known: {known})")
    scope = block.get("scope")
    if scope is not None and scope not in SCOPE_KINDS:
        raise _key_error(target, "features.scope", f"must be one of {SCOPE_KINDS} or null")
    secrets = block.get("secrets_scan", False)
    if not isinstance(secrets, bool):
        raise _key_error(target, "features.secrets_scan", "must be true or false")
    scrub = block.get("scrub_file")
    if scrub is not None and not (isinstance(scrub, str) and repo_relative(scrub)):
        raise _key_error(
            target,
            "features.scrub_file",
            "must be null or a project-relative path without a leading slash, '..' or globs",
        )
    ledger = block.get("ledger")
    if ledger is not None and not isinstance(ledger, bool):
        raise _key_error(target, "features.ledger", "must be true, false or null")
    kind: Literal["repository", "folder"] | None = (
        "repository" if scope == "repository" else "folder" if scope == "folder" else None
    )
    return Features(kind, secrets, scrub, ledger)


def _trains_dir(target: Path, raw: dict[str, object]) -> str | None:
    value = raw.get("trains_dir")
    if value is None:
        return None
    if not isinstance(value, str) or not repo_relative(value):
        raise _key_error(
            target,
            "trains_dir",
            "must be a project-relative folder path without a leading slash, '..' or globs",
        )
    return value


def _unit_test_cmd(target: Path, raw: dict[str, object]) -> str | None:
    stack = raw.get("stack", {})
    if not isinstance(stack, dict):
        raise _key_error(target, "stack", "must be an object")
    value = stack.get("unit_test_cmd")
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise _key_error(target, "stack.unit_test_cmd", "must be null or a non-empty string")
    return value


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
    paths, extensions = _narrowing(target, raw)
    return Manifest(
        paths,
        extensions,
        features=_features(target, raw),
        trains_dir=_trains_dir(target, raw),
        unit_test_cmd=_unit_test_cmd(target, raw),
    )


def features(repo: Path) -> Features:
    # 0069: no manifest means every feature at its absent default.
    loaded = load(repo)
    return loaded.features if loaded is not None else Features()


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

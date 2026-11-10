# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0235: the operator file, ~/.claude/daedalus/operator.json, and its per-repository override;
# 0234, 0237: defined and read here only, no check or hook acts on it yet.
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, fields
from pathlib import Path

from lib.manifest import LITERACY_LEVELS, LITERACY_PROFILE, _literacy_ok

OPERATOR_FILE = Path(".claude") / "daedalus" / "operator.json"
MAX_BYTES = 64 * 1024
# 0234: the typed allow list of warning classes the main session may turn into refusals.
MAIN_REFUSAL_CLASSES: tuple[str, ...] = (
    "commit_on_main",
    "push_merged_branch",
    "redirect_to_file",
    "download_to_shell",
    "credential_export",
    "credential_read",
)
TOP_KEYS = ("main_refusals", "profile")
PROFILE_KEYS = ("literacy", "dash_ban")
_NEXT = "Next: correct the value named, or remove it to use the defaults."


class OperatorError(ValueError):
    pass


@dataclass(frozen=True)
class Operator:
    main_refusals: tuple[str, ...] = ()
    literacy: str | None = None
    dash_ban: bool | None = None


OPERATOR_KEYS = tuple(f.name for f in fields(Operator))


def operator_path() -> Path:
    # 0235: resolved at call time, so a test points HOME at a temp folder.
    return Path.home() / OPERATOR_FILE


def _fail(where: str, key: str, detail: str) -> OperatorError:
    return OperatorError(f"{where} {key} {detail}. {_NEXT}")


def _refusals(value: object, where: str, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise _fail(where, key, "must be a list of strings")
    unknown = [v for v in value if v not in MAIN_REFUSAL_CLASSES]
    if unknown:
        raise _fail(where, key, f"names {unknown!r}, not one of {', '.join(MAIN_REFUSAL_CLASSES)}")
    if len(set(value)) != len(value):
        raise _fail(where, key, "names a class twice")
    return tuple(value)


def _profile(value: object, where: str, prefix: str) -> dict[str, object]:
    key = f"{prefix}profile"
    if not isinstance(value, dict):
        raise _fail(where, key, "must be an object")
    unknown = sorted(str(k) for k in set(value) - set(PROFILE_KEYS))
    if unknown:
        raise _fail(where, key, f"has unknown keys {unknown} (known: {', '.join(PROFILE_KEYS)})")
    out: dict[str, object] = {}
    if "literacy" in value:
        literacy = value["literacy"]
        # 0134: the value set is the manifest docs.literacy one, imported, never copied.
        if not isinstance(literacy, str) or not _literacy_ok(literacy):
            levels = ", ".join(f'"{level}"' for level in LITERACY_LEVELS)
            raise _fail(
                where,
                f"{key}.literacy",
                f"must be one of {levels}, or {LITERACY_PROFILE}<project-relative path>",
            )
        out["literacy"] = literacy
    if "dash_ban" in value:
        if not isinstance(value["dash_ban"], bool):
            raise _fail(where, f"{key}.dash_ban", "must be true or false")
        out["dash_ban"] = value["dash_ban"]
    return out


def validate(raw: object, where: str, prefix: str = "") -> dict[str, object]:
    # 0235: the one validator; returns only the Operator fields the object sets.
    if not isinstance(raw, dict):
        raise _fail(where, prefix.rstrip(".") or "the file", "must be a JSON object")
    unknown = sorted(str(k) for k in set(raw) - set(TOP_KEYS))
    if unknown:
        raise _fail(
            where,
            prefix.rstrip(".") or "the file",
            f"has unknown keys {unknown} (known: {', '.join(TOP_KEYS)})",
        )
    out: dict[str, object] = {}
    if "main_refusals" in raw:
        out["main_refusals"] = _refusals(raw["main_refusals"], where, f"{prefix}main_refusals")
    if "profile" in raw:
        out.update(_profile(raw["profile"], where, prefix))
    return out


def _read(path: Path) -> object:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        raise _fail(str(path), "file", f"could not be opened ({exc.strerror})") from exc
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise _fail(str(path), "file", "must be a regular file")
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise _fail(str(path), "file", f"is larger than {MAX_BYTES // 1024} KiB")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise _fail(str(path), "file", f"is not valid UTF-8 JSON ({type(exc).__name__})") from exc


def load_user() -> Operator:
    path = operator_path()
    if not path.is_symlink() and not path.exists():
        return Operator()
    if path.is_symlink():
        raise _fail(str(path), "file", "must be a regular file, not a symlink")
    return Operator(**validate(_read(path), str(path)))  # type: ignore[arg-type]


def overlay(base: Operator, override: dict[str, object]) -> Operator:
    # 0235: a key the override sets replaces the base value (a list replaces); the rest inherit.
    return Operator(**{**{k: getattr(base, k) for k in OPERATOR_KEYS}, **override})  # type: ignore[arg-type]


def load(repo_root: Path) -> Operator:
    from lib.config import load_config

    return overlay(load_user(), load_config(cwd=str(repo_root)).operator)

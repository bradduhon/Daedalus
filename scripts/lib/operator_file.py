# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0235: the operator file, ~/.claude/daedalus/operator.json, and its per-repository override;
# 0234, 0237: defined and read here; apart from self_assessment, no check or hook acts on it yet.
from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass, fields
from pathlib import Path

from lib.manifest import LITERACY_LEVELS, LITERACY_PROFILE, _literacy_ok
from lib.settings_maps import SCHEMA_KEY, current, number_problem
from lib.user_keys import USER_KEY_CLAUSE, unknown_keys
from lib.work_classes import (
    DEFAULT_CLASSES,
    DEFAULT_MODELS,
    parse_classes,
    parse_models,
    unlisted,
)

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
# 0245: the JSON names of the personal file, in key-table order.
TOP_KEYS = (
    SCHEMA_KEY,
    "hard_stops",
    "reading_level",
    "no_long_dashes",
    "guidance_source",
    "script_language",
    "self_assessment",
    "developer_profile",
    "work_classes",
    "class_models",
    "context_limit",
)
# 0284: tokens an agent in a run may hold before it must hand off; 0 or null turns it off.
CONTEXT_LIMIT = 250_000
# 0244: where the guidance layer is read from; claude is the default.
GUIDANCE_SOURCES = ("claude", "daedalus")
_LANGUAGE = re.compile(r"[a-z][a-z0-9+#-]{0,31}")
_NEXT = "Next: correct the value named, or remove it to use the defaults."


class OperatorError(ValueError):
    pass


@dataclass(frozen=True)
class Operator:
    main_refusals: tuple[str, ...] = ()
    literacy: str | None = None
    dash_ban: bool | None = None
    guidance_source: str = "claude"
    script_language: str | None = None
    self_assessment: bool = False
    developer_profile: bool = False
    # 0270: absent reads as the shipped defaults; an empty list means no classes.
    work_classes: tuple[tuple[str, str], ...] = DEFAULT_CLASSES
    class_models: tuple[tuple[str, str], ...] = DEFAULT_MODELS
    context_limit: int | None = CONTEXT_LIMIT


OPERATOR_KEYS = tuple(f.name for f in fields(Operator))
# 0245: each Operator field's JSON name, for lines a person reads.
JSON_NAMES = dict(zip(OPERATOR_KEYS, TOP_KEYS[1:], strict=True))


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


def _choices(raw: dict[str, object], where: str, prefix: str) -> dict[str, object]:
    # 0245: null is the same as absent for every choice; a set value is checked by its type.
    out: dict[str, object] = {}
    literacy = raw.get("reading_level")
    if literacy is not None:
        # 0134: the value set is the manifest docs.reading_level one, imported, never copied.
        if not isinstance(literacy, str) or not _literacy_ok(literacy):
            levels = ", ".join(f'"{level}"' for level in LITERACY_LEVELS)
            raise _fail(
                where,
                f"{prefix}reading_level",
                f"must be null, one of {levels}, or {LITERACY_PROFILE}<project-relative path>",
            )
        out["literacy"] = literacy
    dashes = raw.get("no_long_dashes")
    if dashes is not None:
        if not isinstance(dashes, bool):
            raise _fail(where, f"{prefix}no_long_dashes", "must be true, false or null")
        out["dash_ban"] = dashes
    source = raw.get("guidance_source")
    if source is not None:
        if source not in GUIDANCE_SOURCES:
            raise _fail(
                where, f"{prefix}guidance_source", f"must be one of {', '.join(GUIDANCE_SOURCES)}"
            )
        out["guidance_source"] = source
    language = raw.get("script_language")
    if language is not None:
        if not isinstance(language, str) or not _LANGUAGE.fullmatch(language):
            raise _fail(
                where, f"{prefix}script_language", "must be null or a lowercase language name"
            )
        out["script_language"] = language
    if "self_assessment" in raw:
        # A1: true or false only; null is refused, the default is false.
        if not isinstance(raw["self_assessment"], bool):
            raise _fail(where, f"{prefix}self_assessment", "must be true or false")
        out["self_assessment"] = raw["self_assessment"]
    if "developer_profile" in raw:
        # 0252: true or false only; null is refused, the default is false.
        if not isinstance(raw["developer_profile"], bool):
            raise _fail(where, f"{prefix}developer_profile", "must be true or false")
        out["developer_profile"] = raw["developer_profile"]
    if "context_limit" in raw:
        # 0284: null is kept, not dropped, because it turns the check off over a set value.
        limit = raw["context_limit"]
        if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int)):
            raise _fail(where, f"{prefix}context_limit", "must be a whole number of tokens or null")
        if limit is not None and limit < 0:
            raise _fail(where, f"{prefix}context_limit", "must be 0 or more")
        out["context_limit"] = limit
    return out


def validate(raw: object, where: str, prefix: str = "") -> dict[str, object]:
    # 0235: the one validator; returns only the Operator fields the object sets.
    if not isinstance(raw, dict):
        raise _fail(where, prefix.rstrip(".") or "the file", "must be a JSON object")
    # 0264: the schema number belongs to the file itself, never to a personal_overrides copy.
    known = TOP_KEYS if not prefix else TOP_KEYS[1:]
    unknown = unknown_keys(raw, known)
    if unknown:
        raise _fail(
            where,
            prefix.rstrip(".") or "the file",
            f"has unknown keys {unknown} (known: {', '.join(known)}); {USER_KEY_CLAUSE}",
        )
    problem = number_problem(raw[SCHEMA_KEY], current("operator")) if SCHEMA_KEY in raw else None
    if problem is not None:
        raise OperatorError(f"{where} {problem}")
    out: dict[str, object] = {}
    if raw.get("hard_stops") is not None:
        out["main_refusals"] = _refusals(raw["hard_stops"], where, f"{prefix}hard_stops")
    out.update(_choices(raw, where, prefix))
    out.update(_classes(raw, where, prefix))
    return out


def _unlisted_error(where: str, key: str, names: list[str]) -> OperatorError:
    return OperatorError(
        f"{where} {key} maps {names!r}, which the classes list does not hold. Next: add each "
        "to work_classes, or remove it from class_models."
    )


def _classes(raw: dict[str, object], where: str, prefix: str) -> dict[str, object]:
    # 0270: null is the same as absent, which reads as the shipped defaults.
    out: dict[str, object] = {}
    classes: tuple[tuple[str, str], ...] | None = None
    models: tuple[tuple[str, str], ...] | None = None
    if raw.get("work_classes") is not None:
        try:
            classes = out["work_classes"] = parse_classes(raw["work_classes"])
        except ValueError as exc:
            raise _fail(where, f"{prefix}work_classes", str(exc)) from exc
    if raw.get("class_models") is not None:
        try:
            models = out["class_models"] = parse_models(raw["class_models"])
        except ValueError as exc:
            raise _fail(where, f"{prefix}class_models", str(exc)) from exc
    # 0280: an override with no list of its own is checked against the personal list in load.
    if models is not None and (classes is not None or not prefix):
        names = unlisted(classes if classes is not None else DEFAULT_CLASSES, models)
        if names:
            raise _unlisted_error(where, f"{prefix}class_models", names)
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

    base, override = load_user(), load_config(cwd=str(repo_root)).operator
    check_override(base, override)
    return overlay(base, override)


def check_override(base: Operator, override: dict[str, object]) -> None:
    # 0280: a project's own mapping names only classes of the list it inherits; setup calls it too.
    models = override.get("class_models")
    if isinstance(models, tuple) and "work_classes" not in override:
        names = unlisted(base.work_classes, models)
        if names:
            raise _unlisted_error("config.json", "personal_overrides.class_models", names)

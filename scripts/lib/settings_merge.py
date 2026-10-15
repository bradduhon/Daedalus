# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import copy
import difflib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

# spec 4: the dotted paths /daedalus:setup merges from settings.recommended.json.
MERGED_KEYS = ("sandbox", "permissions.deny", "promptCacheTtl", "subagentPromptCacheTtl")
# spec 4: deny lists gain missing entries; every other existing value stays as the user set it.
APPEND_KEYS = frozenset({"deny", "denyRead", "denyWrite"})


class SettingsMergeError(ValueError):
    pass


def read_settings(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError) as exc:
        raise SettingsMergeError(
            f"{path} cannot be read ({exc}). Next: make it a readable UTF-8 file."
        ) from exc
    try:
        data = json.loads(text) if text.strip() else {}
    except (ValueError, RecursionError) as exc:
        raise SettingsMergeError(
            f"{path} is not valid JSON ({exc}). Next: fix the syntax, then rerun /daedalus:setup."
        ) from exc
    if not isinstance(data, dict):
        raise SettingsMergeError(
            f"{path} must hold a JSON object. Next: fix it, then rerun /daedalus:setup."
        )
    return data


def _pick(recommended: dict[str, Any]) -> dict[str, Any]:
    picked: dict[str, Any] = {}
    for dotted in MERGED_KEYS:
        *parents, leaf = dotted.split(".")
        node: Any = recommended
        for part in [*parents, leaf]:
            node = node.get(part) if isinstance(node, dict) else None
        if node is None:
            continue
        slot = picked
        for part in parents:
            slot = slot.setdefault(part, {})
        slot[leaf] = node
    return picked


def _conflict(dotted: str, want: str) -> SettingsMergeError:
    return SettingsMergeError(
        f"settings key {dotted} is not {want}, so setup cannot merge into it."
        f" Next: make {dotted} {want} or remove it, then rerun /daedalus:setup."
    )


def _merge_into(target: dict[str, Any], source: dict[str, Any], prefix: str = "") -> None:
    for key, value in source.items():
        dotted = f"{prefix}{key}"
        if key not in target:
            target[key] = copy.deepcopy(value)
        elif isinstance(value, dict):
            # spec 4 never-overwrite: a type conflict raises rather than replacing the value.
            if not isinstance(target[key], dict):
                raise _conflict(dotted, "a JSON object")
            _merge_into(target[key], value, f"{dotted}.")
        elif key in APPEND_KEYS and isinstance(value, list):
            if not isinstance(target[key], list):
                raise _conflict(dotted, "a JSON list")
            for item in value:
                if item not in target[key]:
                    target[key].append(copy.deepcopy(item))


def merge(existing: dict[str, Any], recommended: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(existing)
    _merge_into(merged, _pick(recommended))
    return merged


def render(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2) + "\n"


def unified_diff(old: str, new: str, path: Path) -> str:
    return "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            f"{path} (before)",
            f"{path} (after)",
        )
    )


def write_atomic(path: Path, text: str) -> None:
    # spec 4: temp file and rename; write through a dotfiles symlink, never replace the link.
    real = path.resolve() if path.is_symlink() else path
    real.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".settings-", suffix=".json", dir=real.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        if real.exists():
            os.chmod(tmp, real.stat().st_mode & 0o777)
        os.replace(tmp, real)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise

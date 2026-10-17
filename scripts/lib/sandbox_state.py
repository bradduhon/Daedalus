# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ON = "on"
OFF = "off"
CONFIGURED_UNAVAILABLE = "configured-unavailable"
# 0020: setup is disable-model-invocation; only the operator can start it.
SETUP_NEXT = "type /daedalus:setup yourself; the model cannot run it"
PROJECT_SETTINGS = (".claude/settings.json", ".claude/settings.local.json")


class SettingsError(ValueError):
    pass


def required_binaries() -> tuple[str, ...]:
    # 0020: Linux and WSL2 sandbox through bwrap and socat; macOS needs neither.
    return () if sys.platform == "darwin" else ("bwrap", "socat")


def missing_binaries() -> list[str]:
    return [name for name in required_binaries() if shutil.which(name) is None]


def settings_paths(repo: Path, home: Path) -> tuple[Path, ...]:
    return (home / ".claude" / "settings.json", *(repo / p for p in PROJECT_SETTINGS))


def _sandbox_blocks(repo: Path, home: Path) -> list[tuple[Path, dict[str, object]]]:
    # Plan 4 spec 5: home, then project, then local; home is read only, never written (0029).
    blocks: list[tuple[Path, dict[str, object]]] = []
    for path in settings_paths(repo, home):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            continue
        except (OSError, UnicodeDecodeError) as exc:
            raise SettingsError(
                f"{path} cannot be read ({exc}). Next: make {path} a readable UTF-8 file"
            ) from exc
        except (ValueError, RecursionError) as exc:
            raise SettingsError(
                f"{path} is not valid JSON ({exc}). Next: fix the JSON syntax in {path}"
            ) from exc
        block = data.get("sandbox") if isinstance(data, dict) else None
        if isinstance(block, dict):
            blocks.append((path, block))
    return blocks


def _winner(repo: Path, home: Path) -> tuple[object, Path | None]:
    # Plan 4 spec 5: later files override earlier ones.
    value: object = None
    source: Path | None = None
    for path, block in _sandbox_blocks(repo, home):
        if "enabled" in block:
            value, source = block["enabled"], path
    return value, source


def excluded_commands(repo: Path, home: Path) -> list[str]:
    # 0028: the union across files, since array settings merge across scopes (ASSUMED).
    found: list[str] = []
    for _, block in _sandbox_blocks(repo, home):
        entries = block.get("excludedCommands")
        if isinstance(entries, list):
            found += [e for e in entries if isinstance(e, str) and e not in found]
    return found


def sandbox_enabled(repo: Path, home: Path) -> bool:
    return _winner(repo, home)[0] is True


def sandbox_source(repo: Path, home: Path) -> Path | None:
    return _winner(repo, home)[1]


def sandbox_state(repo: Path, home: Path | None = None) -> str:
    if not sandbox_enabled(repo, Path.home() if home is None else home):
        return OFF
    return CONFIGURED_UNAVAILABLE if missing_binaries() else ON


def sandbox_line(state: str) -> tuple[bool, str]:
    if state == ON:
        return True, "OK   sandbox: on"
    return False, f"MISS sandbox: {state}. Next: {SETUP_NEXT}"


def sandbox_check(repo: Path, home: Path | None = None) -> tuple[bool, str]:
    # 0020: one line for the doctor and the SessionStart notice; bad settings name the file.
    try:
        return sandbox_line(sandbox_state(repo, home))
    except SettingsError as exc:
        return False, f"MISS sandbox: {exc}"

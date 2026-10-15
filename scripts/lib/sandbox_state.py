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
SETUP_NEXT = "run /daedalus:setup"
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


def sandbox_enabled(repo: Path, home: Path) -> bool:
    # 0020: later files override earlier ones, the order the doctor always used.
    value: object = None
    for path in settings_paths(repo, home):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            continue
        except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise SettingsError(f"{path} is not valid JSON ({exc}). Next: fix {path}") from exc
        block = data.get("sandbox") if isinstance(data, dict) else None
        if isinstance(block, dict) and "enabled" in block:
            value = block["enabled"]
    return value is True


def sandbox_state(repo: Path, home: Path | None = None) -> str:
    if not sandbox_enabled(repo, Path.home() if home is None else home):
        return OFF
    return CONFIGURED_UNAVAILABLE if missing_binaries() else ON


def sandbox_line(state: str) -> tuple[bool, str]:
    if state == ON:
        return True, "OK   sandbox: on"
    return False, f"MISS sandbox: {state}. Next: {SETUP_NEXT}"

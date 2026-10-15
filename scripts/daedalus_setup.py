#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.sandbox_state import SettingsError, missing_binaries  # noqa: E402
from lib.settings_merge import (  # noqa: E402
    SettingsMergeError,
    merge,
    read_settings,
    render,
    unified_diff,
    write_atomic,
)

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
OS_RELEASE = Path("/etc/os-release")
PACKAGES = {"bwrap": "bubblewrap", "socat": "socat"}


def _debian_family(os_release: Path) -> bool:
    try:
        text = os_release.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    fields = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    ids = f"{fields.get('ID', '')} {fields.get('ID_LIKE', '')}".replace('"', "").split()
    return bool({"debian", "ubuntu"} & set(ids))


def install_line(missing: list[str], os_release: Path) -> str:
    packages = " ".join(PACKAGES[name] for name in missing)
    if _debian_family(os_release):
        return f"run sudo apt-get install -y {packages}"
    return f"install the packages {packages} with your distribution's package manager"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Merge the Daedalus sandbox settings.")
    parser.add_argument("--settings", type=Path, default=Path.home() / ".claude" / "settings.json")
    parser.add_argument(
        "--recommended", type=Path, default=PLUGIN_ROOT / "settings.recommended.json"
    )
    parser.add_argument("--os-release", type=Path, default=OS_RELEASE)
    args = parser.parse_args(argv)
    # 0020: failIfUnavailable before the binaries exist kills Bash in every session.
    missing = missing_binaries()
    if missing:
        print(
            f"daedalus setup: {', '.join(missing)} not on PATH; nothing written. "
            f"Next: {install_line(missing, args.os_release)}, then rerun /daedalus:setup"
        )
        return 1
    try:
        existing = read_settings(args.settings)
        merged = merge(existing, read_settings(args.recommended))
    except (SettingsMergeError, SettingsError) as exc:
        print(f"daedalus setup: {exc}", file=sys.stderr)
        return 1
    if merged == existing:
        print(
            f"daedalus setup: {args.settings} already holds the recommended settings; "
            "nothing written."
        )
        return 0
    old = args.settings.read_text(encoding="utf-8") if args.settings.exists() else ""
    new = render(merged)
    write_atomic(args.settings, new)
    print(unified_diff(old, new, args.settings), end="")
    print("Restart Claude Code to apply")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

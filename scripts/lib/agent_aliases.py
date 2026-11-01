# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0190: the one table of old agent names, read as their new names for one release (as 0174).
# Standard library only; operator files (config, manifest, train definitions) map through it.
from __future__ import annotations

OLD_NAMES: dict[str, str] = {
    "repo-coder": "coder",
    "security-auditor": "auditor",
    "pr-train-conductor": "releaser",
    "change-logger": "comparer",
    "docs-writer": "writer",
    "doc-deriver": "writer",
}


def current(name: str) -> str:
    # 0190: an old name reads as its new name; any other name is returned unchanged.
    return OLD_NAMES.get(name, name)


def renamed_line(old: str, where: str) -> str:
    # 0190: the doctor's one-line warning, at its non-failing OPT level, for an old name in use.
    new = OLD_NAMES[old]
    return (
        f"OPT  agent name {old} in {where}: renamed to {new}; the old name reads as {new} for "
        f"this release only (0190). Next: write {new} in place of {old}"
    )

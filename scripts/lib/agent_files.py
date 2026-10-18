# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044: reads agents/<name>.md; unit 1.2 ships the frontmatter reader, unit 1.3 the full parser.
from __future__ import annotations

import re
from pathlib import Path

_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_]*")


class AgentFileError(ValueError):
    pass


def frontmatter(path: Path) -> dict[str, str]:
    # 0044: top-level `key: value` lines only; nested, comment and list lines are skipped.
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise AgentFileError(
            f"{path} could not be read ({exc}). Next: restore the agent file from git."
        ) from exc
    if not lines or lines[0] != "---":
        raise AgentFileError(f"{path} has no frontmatter. Next: start the file with a --- line.")
    if "---" not in lines[1:]:
        raise AgentFileError(
            f"{path} frontmatter never closes. Next: end the frontmatter with a --- line."
        )
    out: dict[str, str] = {}
    for line in lines[1 : lines.index("---", 1)]:
        if not line.strip() or line[0] in " \t#-":
            continue
        key, sep, value = line.partition(":")
        if not sep or not _KEY.fullmatch(key):
            raise AgentFileError(
                f"{path} frontmatter line {line!r} is not `key: value`. "
                "Next: write each top-level field as key: value."
            )
        out[key] = value.strip()
    return out

# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# The plain helpers more than one test module shares; fixtures live in tests/conftest.py.
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from lib import train_state

from tests.conftest import REPO_ROOT


def flatten(text: str) -> str:
    return " ".join(text.split())


def flatten_file(path: Path) -> str:
    return flatten(path.read_text(encoding="utf-8"))


# 0232: the jail and parser files whose change takes the table-diff form.
TABLE_DIFF_PATHS = (
    "scripts/lib/jail.py",
    "scripts/lib/admit.py",
    "scripts/lib/shell.py",
    "scripts/lib/shparse.py",
    "scripts/lib/credential_paths.py",
    "scripts/enforce_agent_jail.py",
    "scripts/checks/",
    "tests/adversarial/",
)


def table_diff_list() -> str:
    # The six files, then the two folders, as the audit skill, auditor and coder list them.
    files = ", ".join(f"`{path}`" for path in TABLE_DIFF_PATHS[:6])
    return f"{files}, a path under `scripts/checks/` or a path under `tests/adversarial/`"


def ends_with_next(message: str) -> bool:
    head, sep, tail = message.rpartition(". Next: ")
    return bool(head and sep and tail.endswith(".")) and message.count("Next:") == 1


def write_manifest(repo: Path, payload: object) -> None:
    (repo / "service-manifest.json").write_text(json.dumps(payload), encoding="utf-8")


def sha256_hex(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def strip_unit_audit(state: dict[str, object]) -> None:
    state["units"] = [
        {k: v for k, v in u.items() if k != "audit"} for u in train_state.units(state)
    ]


def orchestrated(text: str) -> str:
    # 0135, 0174: derived document mode runs in the main session, never in the orchestrator.
    head, derived, tail = text.partition("### Derived document mode\n")
    return head + "## " + tail.split("\n## ", 1)[1] if derived else text


def phase_text(name: str) -> str:
    # 0060: the orchestrator writes the plugin root out in full; its hook refuses the variable.
    text = (REPO_ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8")
    return orchestrated(text).replace("${CLAUDE_PLUGIN_ROOT}", "<plugin root>")


# 0164, 0158, 0196: a coder chain refusal of a runner, terraform or install row names a ruling.
RULING_MARKERS = ("0164)", "(0158)", "(0196)")

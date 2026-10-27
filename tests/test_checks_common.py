# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, Plan 10 spec 5: the three per-hook properties every check shares, one table for all.
# Each row keeps the exact tool, payload and flags its check file passed before the move.
from __future__ import annotations

from typing import NamedTuple

import pytest

from tests.conftest import CWD
from tests.hook_chain import (
    malformed_input_denies,
    outside_tools_allow,
    payload,
    unknown_flag_denies,
)

CONDUCTOR = "pr-train-conductor"


class Row(NamedTuple):
    script: str
    outside_tool: str | None
    outside_flags: tuple[str, ...]
    inside: str | None
    unknown_flags: tuple[str, ...]
    malformed_flags: tuple[str, ...]


# Spec 5: None marks a property its check file keeps, because that test asserts more there.
ROWS = (
    Row("workspace_integrity", "Read", (), payload("Write", file_path=f"{CWD}/src/a.py"), (), ()),
    Row(
        "root_writes",
        "Read",
        ("--touch", "docs"),
        payload("Write", file_path=f"{CWD}/docs/a.md"),
        ("--touch", "docs"),
        ("--touch", "docs"),
    ),
    Row("tool_bound", None, (), payload("Read"), (), ()),
    Row(
        "gh_classes",
        "Write",
        ("--conductor",),
        payload("Bash", agent=CONDUCTOR, command="gh run list"),
        (),
        ("--conductor",),
    ),
    Row("network_tools", "Read", (), payload("Bash", command="ls"), (), ("--web",)),
    Row(
        "git_grammar",
        "Write",
        ("--allow", "coder"),
        payload("Bash", command="git status"),
        (),
        ("--allow", "coder"),
    ),
    Row(
        "read_only_bash",
        "Write",
        ("--git", "read-only"),
        payload("Bash", command="ls"),
        (),
        ("--git", "read-only"),
    ),
    Row("credential_paths", "WebFetch", (), payload("Read", file_path=f"{CWD}/a.py"), (), ()),
    Row("shell_tripwires", "Write", (), None, (), ()),
    Row("unit_writes", "Read", (), payload("Bash", command="ls"), (), ()),
    Row(
        "command_allowlist",
        "Write",
        ("--allow", "git"),
        payload("Bash", command="git status"),
        ("--allow", "git"),
        ("--allow", "git"),
    ),
    Row("git_push", "Write", (), payload("Bash", command="git status"), (), ("--conductor",)),
)


def _rows(field: str) -> list[Row]:
    return [row for row in ROWS if getattr(row, field) is not None]


@pytest.mark.parametrize("row", _rows("outside_tool"), ids=lambda row: row.script)
def test_allows_tools_outside_its_tools(row: Row) -> None:
    assert row.outside_tool is not None
    outside_tools_allow(row.script, row.outside_tool, *row.outside_flags)


@pytest.mark.parametrize("row", _rows("inside"), ids=lambda row: row.script)
def test_unknown_flag_denies(row: Row) -> None:
    assert row.inside is not None
    unknown_flag_denies(row.script, row.inside, *row.unknown_flags)


@pytest.mark.parametrize("row", ROWS, ids=lambda row: row.script)
def test_malformed_input_denies(row: Row) -> None:
    malformed_input_denies(row.script, *row.malformed_flags)

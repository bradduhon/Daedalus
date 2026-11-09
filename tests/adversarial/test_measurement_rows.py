# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0229: the 2026-11-08 measurement rows, each judged by the hooks its agent meets on main: lib.jail
# for an agent Daedalus did not start, its own chain then the excluded roots check for ours.
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pytest
from lib import hook_io, jail
from lib.config import Config, ExcludedRootDecl

from tests.adversarial.corpus import P3_MEASURE_A2, P3_MEASURE_A3, assert_denied
from tests.conftest import CFG
from tests.hook_chain import CHAINS, decide, evaluate
from tests.jail_cases import _unit_repo
from tests.payloads import _cred

Row = tuple[str, str, str, str]
# 0229: rows main judges against the spec; the reason leads with the owning issue, else gap.
# 228 S4: A3-32 and A3-33 pass, a -m value being text (225); no row is expected to fail.
XFAIL: dict[str, str] = {}


def _params(rows: Iterable[Row]) -> list[object]:
    def one(row: Row) -> object:
        if row[3] not in XFAIL:
            return pytest.param(*row)
        return pytest.param(*row, marks=pytest.mark.xfail(strict=True, reason=XFAIL[row[3]]))

    return [one(row) for row in rows]


def _unit(tmp_path: Path) -> tuple[Path, Path]:
    # 0229: a registered unit worktree holding tests/test_excluded_roots.py's notes and src.
    repo, wt = _unit_repo(tmp_path / "u")
    for name in ("notes", "src"):
        (wt / name).mkdir(exist_ok=True)
        (wt / name / "a.md").write_text("x\n", encoding="utf-8")
    return repo, wt


def _judge(
    folders: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    row: Row,
) -> None:
    agent, folder, verdict, form = row
    repo, cwd = _unit(tmp_path) if folder == "unit" else (folders[folder], folders[folder])
    roots = Config(excluded_roots=(ExcludedRootDecl("path", str(repo / "notes")),))
    monkeypatch.setattr(hook_io, "hook_config", lambda cwd: roots)
    command = form.replace("{repo}", str(folders["marked"]))
    hook_input = {**_cred(agent, "Bash", str(cwd), command=command), "session_id": "s"}
    # 0136: the router runs the excluded roots check after a Daedalus agent's own chain.
    excluded = evaluate("excluded_roots", hook_input) if agent in CHAINS else None
    if verdict == "admit":
        got = decide(hook_input, CFG) if agent in CHAINS else jail.decide(hook_input, CFG)
        assert got.allow and not got.warn and excluded is None, (command, got.reason, excluded)
    elif excluded is None:
        assert_denied(hook_input)


@pytest.mark.parametrize(("agent", "folder", "verdict", "form"), _params(P3_MEASURE_A2))
def test_an_a2_measurement_row_meets_its_spec_verdict(
    marked_repo: Path,
    other_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    agent: str,
    folder: str,
    verdict: str,
    form: str,
) -> None:
    folders = {"marked": marked_repo, "unmarked": other_repo}
    _judge(folders, monkeypatch, tmp_path, (agent, folder, verdict, form))


@pytest.mark.parametrize(("agent", "folder", "verdict", "form"), _params(P3_MEASURE_A3))
def test_an_a3_measurement_row_meets_its_spec_verdict(
    marked_repo: Path,
    other_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    agent: str,
    folder: str,
    verdict: str,
    form: str,
) -> None:
    folders = {"marked": marked_repo, "unmarked": other_repo}
    _judge(folders, monkeypatch, tmp_path, (agent, folder, verdict, form))


def test_the_groups_carry_every_measurement_row() -> None:
    # 0229: 23 A2 and 61 A3 rows; A2-7 and A3-25 carry no command.
    assert (len(P3_MEASURE_A2), len(P3_MEASURE_A3)) == (23, 61)
    forms = [row[3] for row in (*P3_MEASURE_A2, *P3_MEASURE_A3)]
    assert len(set(forms)) == len(forms) and set(XFAIL) <= set(forms)

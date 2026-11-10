# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 266: the data folder check and the pack verify reader read each role's typed record; the hunt
# classes against both, and the forms that reach the data folder through a link on a real tree.
from __future__ import annotations

from pathlib import Path

import pytest
from lib import jail
from lib.packs import pack_problems

from tests.adversarial.corpus import DATA_FOLDER_HUNT_266, PACK_VERIFY_HUNT_266, assert_denied
from tests.conftest import CFG, CWD
from tests.payloads import _b
from tests.test_framework_packs import _control, _make

pytestmark = pytest.mark.usefixtures("jail_fakes")


def _named(name: str | None) -> str | None:
    return None if name is None else str(getattr(jail, name))


@pytest.mark.parametrize(("cls", "form", "main", "coder"), DATA_FOLDER_HUNT_266)
def test_a_data_folder_hunt_form_meets_the_typed_check(
    cls: str, form: str, main: str | None, coder: str | None
) -> None:
    # 266, 0224: each role's admitted record is judged; a refused form by its folder alone.
    command = form.format(repo=CWD)
    for agent, want in (("main", main), ("coder", coder)):
        got = jail.integrity_reason("Bash", {"command": command}, CWD, agent)
        assert got == _named(want), (cls, agent, command, got)
    if not jail.admitted(command, "coder", CWD):
        assert_denied(_b("coder", command))
    if not jail.admitted(command, "main", CWD):
        # 0105: main is warned with the word its grammar refused, never refused.
        warned = jail.decide(_b(None, command), CFG)
        assert warned.warn and "Refused: " in str(warned.reason), (cls, warned.reason)


def test_a_refused_command_standing_in_the_data_folder_is_named() -> None:
    # 0224: no typed operand to judge, so the folder the command stands in is judged.
    inside = f"{CWD}/.claude/daedalus"
    for agent in ("main", "coder", "auditor"):
        got = jail.integrity_reason("Bash", {"command": "echo x > y"}, inside, agent)
        assert got == jail.R_DATA_DIR, agent
    assert jail.integrity_reason("Bash", {"command": "echo x > y"}, CWD, "coder") is None


def test_a_write_through_a_link_into_the_data_folder_is_named(tmp_path: Path) -> None:
    # 266: a typed path is judged by its spelled name and by the path its links resolve to.
    repo = tmp_path / "r"
    (repo / ".claude" / "daedalus").mkdir(parents=True)
    (repo / "lnk").symlink_to(repo / ".claude" / "daedalus")
    (repo / "dot").symlink_to(repo / ".claude")
    forms = (
        ("touch lnk/x", jail.R_DATA_DIR),
        (f"cd {repo}/lnk && touch x", jail.R_DATA_DIR),
        ("touch dot/daedalus/x", jail.R_DATA_DIR),
        (f"git -C {repo}/dot add daedalus", jail.R_DATA_DIR_GIT),
        ("touch dot/settings.json", None),
    )
    for command, want in forms:
        got = jail.integrity_reason("Bash", {"command": command}, str(repo), "coder")
        assert got == want, (command, got)


@pytest.mark.parametrize(("cls", "verify", "outcome"), PACK_VERIFY_HUNT_266)
def test_a_pack_verify_hunt_form(tmp_path: Path, cls: str, verify: str, outcome: str) -> None:
    # 266: an admitted verify's typed paths stay in the tree; a refused one names its word.
    folder = _make(tmp_path / "p", [_control(verify=verify)])
    found = "\n".join(pack_problems(folder, known=()))
    kind, _, word = outcome.partition(" ")
    if kind == "ok":
        assert found == "", (cls, found)
    elif kind == "outside":
        assert f"verify searches {word!r} outside the project tree" in found, (cls, found)
    else:
        assert "verify is refused by the auditor's jail: " in found, (cls, found)
        assert word in found and "outside the project tree" not in found, (cls, found)

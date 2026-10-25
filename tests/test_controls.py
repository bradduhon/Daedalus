# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# spec 8, pin B2: every hook script and every R_ constant names its failure and its premise test.
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest
from lib import controls, dispatch_binding, jail, shell

from tests.conftest import CWD, REPO_ROOT, WT
from tests.hook_chain import evaluate, load
from tests.payloads import _b

pytestmark = pytest.mark.usefixtures("jail_fakes")
SCAN = (REPO_ROOT / "scripts" / "lib", REPO_ROOT / "scripts" / "checks")
_HOOK_SCRIPT = re.compile(r"scripts/([A-Za-z0-9_]+)\.py")


def _module_constants(path: Path) -> set[str]:
    found: set[str] = set()
    for stmt in ast.parse(path.read_text(encoding="utf-8")).body:
        targets = stmt.targets if isinstance(stmt, ast.Assign) else []
        targets = [stmt.target] if isinstance(stmt, ast.AnnAssign) else targets
        for target in targets:
            names = (n.id for n in ast.walk(target) if isinstance(n, ast.Name))
            found |= {n for n in names if n.startswith("R_")}
    return found


def _constants() -> dict[str, set[str]]:
    # Stems shared by scripts/lib and scripts/checks pool their constants under one stem.
    out: dict[str, set[str]] = {}
    for folder in SCAN:
        for path in sorted(folder.glob("*.py")):
            out.setdefault(path.stem, set()).update(_module_constants(path))
    return out


def _hook_scripts() -> set[str]:
    names = {p.stem for p in (REPO_ROOT / "scripts" / "checks").glob("*.py")}
    hooks = json.loads((REPO_ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
    for groups in hooks["hooks"].values():
        for group in groups:
            for hook in group["hooks"]:
                names |= set(_HOOK_SCRIPT.findall(hook.get("command", "")))
    return {f"{controls.HOOK_PREFIX}{n}" for n in names}


def _test_exists(node: str) -> bool:
    # A premise test is tests/<file>.py::<function> or tests/<file>.py::<Class>::<method>.
    file, _, rest = node.partition("::")
    path = REPO_ROOT / file
    if not re.fullmatch(r"tests/[A-Za-z0-9_]+\.py", file) or not path.is_file() or not rest:
        return False
    body: list[ast.stmt] = ast.parse(path.read_text(encoding="utf-8")).body
    *classes, name = rest.split("::")
    for cls in classes:
        found = [s for s in body if isinstance(s, ast.ClassDef) and s.name == cls]
        if not found:
            return False
        body = found[0].body
    return name.startswith("test") and any(
        isinstance(s, ast.FunctionDef) and s.name == name for s in body
    )


ROWS = controls.load()


def test_every_hook_script_and_constant_has_a_row() -> None:
    wanted = _hook_scripts()
    for stem, names in _constants().items():
        wanted |= {f"{stem}.{n}" for n in names}
    assert sorted(wanted - set(ROWS)) == []


def test_every_row_fills_both_fields() -> None:
    empty = [
        k for k, row in ROWS.items() if not row.failure.strip() or not row.premise_test.strip()
    ]
    assert empty == []


def test_every_failure_names_its_id_and_never_the_router_ruling() -> None:
    # code-comments.md: id first, then the failure in words; 0044 is the mechanism, never a failure.
    shaped = re.compile(
        r"(?:\d{4}|issue \d+|audit [A-Z0-9-]+|finding [A-Z0-9]+|spec [\d.]+|C\.1): \S"
    )
    bad = [k for k, row in ROWS.items() if not shaped.match(row.failure) or "0044" in row.failure]
    assert bad == []


def test_every_premise_test_exists() -> None:
    missing = [
        f"{k}: {r.premise_test}" for k, r in ROWS.items() if not _test_exists(r.premise_test)
    ]
    assert missing == []


def test_every_constant_row_names_a_live_constant() -> None:
    # pin B2: a row for a module this branch lacks waits for its unit; a module that lacks it fails.
    known = _constants()
    hooks = _hook_scripts()
    stale: list[str] = []
    for key in ROWS:
        if key.startswith(controls.HOOK_PREFIX):
            stem = key.removeprefix(controls.HOOK_PREFIX)
            on_disk = any(
                (REPO_ROOT / "scripts" / d / f"{stem}.py").is_file() for d in ("", "checks")
            )
            stale += [key] if on_disk and key not in hooks else []
            continue
        stem, _, name = key.partition(".")
        if stem in known and name not in known[stem]:
            stale.append(key)
    assert stale == []


def _fragment(folder: Path, name: str, text: str) -> None:
    folder.mkdir(exist_ok=True)
    (folder / name).write_text(text, encoding="utf-8")


ROW = '{"failure": "0001: x", "premise_test": "tests/test_controls.py::test_x"}'


def test_load_reads_every_fragment(tmp_path: Path) -> None:
    _fragment(tmp_path, "base.json", '{"a.R_X": ' + ROW + "}")
    _fragment(tmp_path, "b6.json", '{"checks/dispatch_gate": ' + ROW + "}")
    assert sorted(controls.load(tmp_path)) == ["a.R_X", "checks/dispatch_gate"]


@pytest.mark.parametrize(
    "files",
    [
        {"base.json": '{"a.R_X": ' + ROW + "}", "b3.json": '{"a.R_X": ' + ROW + "}"},
        {"base.json": '{"a.R_X": ' + ROW + ', "a.R_X": ' + ROW + "}"},
    ],
)
def test_load_refuses_a_duplicate_key(tmp_path: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        _fragment(tmp_path, name, text)
    with pytest.raises(controls.ControlsError, match="a.R_X"):
        controls.load(tmp_path)


@pytest.mark.parametrize(
    "text",
    [
        "[]",
        '{"a.R_X": {"failure": "0001: x"}}',
        '{"a.R_X": {"failure": 1, "premise_test": "t"}}',
        "{bad",
    ],
)
def test_load_refuses_a_malformed_fragment(tmp_path: Path, text: str) -> None:
    _fragment(tmp_path, "base.json", text)
    with pytest.raises(controls.ControlsError, match="Next:"):
        controls.load(tmp_path)


def test_failure_line_names_the_row_or_none() -> None:
    jail_row = ROWS["checks/enforce_agent_jail"].failure
    assert controls.failure_line("jail", ROWS) == f"failure: {jail_row}"
    assert controls.failure_line("config (ask)", ROWS) == f"failure: {jail_row}"
    unit = ROWS["checks/unit_writes"].failure
    assert controls.failure_line("unit_writes", ROWS) == f"failure: {unit}"
    assert controls.failure_line("unprefixed", ROWS) == "failure: none"


def test_git_without_a_grant_is_refused() -> None:
    want = load("git_grammar").R_NO_GIT
    assert evaluate("git_grammar", _b("repo-coder", "git status")) == want


def test_find_that_writes_is_refused() -> None:
    for command in ("find . -delete", "find . -exec ls {} +", f"find . -fprint {WT}/x"):
        assert evaluate("shell_tripwires", _b("repo-coder", command)) == shell.R_FIND_WRITE, command


def test_coder_write_without_an_id_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(dispatch_binding, "active_train", lambda repo: "20261019-000000")
    got = dispatch_binding._binding_reason({}, str(tmp_path), {"u1"})
    assert got == dispatch_binding.R_NO_CODER_ID


def test_basetemp_root_is_unseen_by_the_write_checks() -> None:
    # issue 56: red here means the write checks now judge the temp root and R_BASETEMP can retire.
    for segment in (["pytest", "--basetemp=/tmp/x"], ["pytest", "--basetemp", "/tmp/x"]):
        assert jail._coder_bash_reason(segment, CWD, lambda: "") is None, segment
    assert evaluate("unit_writes", _b("repo-coder", "pytest --basetemp=/tmp/x")) == jail.R_BASETEMP

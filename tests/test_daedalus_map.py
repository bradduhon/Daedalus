# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# Pins MAP -> REQ and MAP -> VER: the dependency map's five tables, its ownership and --check.
from __future__ import annotations

import json
from pathlib import Path

import daedalus_map
import pytest

from tests.conftest import REPO_ROOT, run_cli

_BODY = "\n".join(
    [
        "",
        "def {name}(items, limit):",
        "    total = 0",
        "    seen = set()",
        "    for item in items:",
        "        if item in seen or item.size > limit:",
        "            continue",
        "        seen.add(item)",
        "        total += item.size * 2 + len(item.name)",
        "    if total > limit:",
        '        raise ValueError("over the limit")',
        "    return total, sorted(seen, key=lambda x: x.name)",
        "",
    ]
)
_PLAN = "\n".join(
    [
        "# Plan",
        "",
        "```plan",
        "unit: A | title: a | files: scripts/b.py, tests/ | base: integration",
        "unit: B | title: b | files: scripts/b.py, tests/test_b.py | base: integration",
        "edge: A ~ B | kind: overlap | files: scripts/b.py | merge: A then B",
        "graph: units=2 critical_path=1 width=2 overlap_only=A~B",
        "```",
        "",
    ]
)


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    _write(root, "scripts/lib/__init__.py", "")
    _write(root, "scripts/lib/a.py", "LIMIT = 3\n\n\ndef helper() -> int:\n    return LIMIT\n")
    _write(
        root,
        "scripts/b.py",
        "import os\nfrom lib import a\n\n"
        'TOKEN_ENV = "MY_TOKEN"\n\n\n'
        "def run() -> None:\n"
        "    a.helper()\n"
        "    os.environ.get(TOKEN_ENV)\n"
        '    print("[STATUS: COMPLETE] done")\n'
        '    record = {"event": "SubagentStop", "charter_root": None}\n'
        "    print(record)\n" + _BODY.format(name="tally"),
    )
    _write(
        root,
        "scripts/c.py",
        "from lib.a import helper\n\n\n"
        "def judge(line: str, record: dict) -> bool:\n"
        '    if record.get("event") == "SubagentStop":\n'
        "        helper()\n"
        '    return line.startswith("[STATUS: COMPLETE]")\n' + _BODY.format(name="count"),
    )
    _write(root, "tests/test_b.py", 'import b\n\nSCRIPT = "c.py"\n')
    _write(root, "tests/test_a.py", "from lib.a import helper\n")
    _write(root, "agents/x.md", "End with `[STATUS: COMPLETE]`. Hooks read `SubagentStop`.\n")
    _write(root, ".hidden/skip.py", 'print("[STATUS: HIDDEN]")\n')
    _write(root, "docs/plan.md", _PLAN)
    return root


def _map(repo: Path, *extra: str) -> tuple[int, str]:
    done = run_cli("daedalus_map.py", "--repo", str(repo), "--out", str(repo / "out"), *extra)
    return done.returncode, done.stdout + done.stderr


def _json(repo: Path) -> dict[str, object]:
    data = json.loads((repo / "out" / "map.json").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_map_writes_both_files_with_the_five_pinned_keys(repo: Path) -> None:
    code, out = _map(repo)
    assert code == 0, out
    assert (repo / "out" / "map.md").is_file()
    assert set(_json(repo)) == {"imports", "coverage", "readers", "ownership", "duplicates"}
    assert f"sha256={daedalus_map._sha256((repo / 'out' / 'map.json').read_text())}" in out
    md = (repo / "out" / "map.md").read_text(encoding="utf-8")
    for heading in ("Import graph", "coverage", "Readers and writers", "ownership", "Near-dup"):
        assert heading in md, heading


def test_fan_in_lists_the_modules_that_import_each_module(repo: Path) -> None:
    assert _map(repo)[0] == 0
    imports = _json(repo)["imports"]
    assert isinstance(imports, dict)
    row = imports["scripts/lib/a.py"]
    assert row["fan_in"] == ["scripts/b.py", "scripts/c.py"]
    assert row["symbols"] == {"helper": ["scripts/b.py", "scripts/c.py"]}
    assert imports["scripts/b.py"]["imports"] == ["scripts/lib/a.py"]
    assert "tests/test_b.py" not in imports


def test_coverage_counts_imports_and_named_scripts(repo: Path) -> None:
    assert _map(repo)[0] == 0
    coverage = _json(repo)["coverage"]
    assert coverage == {
        "scripts/b.py": ["tests/test_b.py"],
        "scripts/c.py": ["tests/test_b.py"],
        "scripts/lib/__init__.py": [],
        "scripts/lib/a.py": ["tests/test_a.py"],
    }


def test_readers_split_readers_writers_and_mentions(repo: Path) -> None:
    assert _map(repo)[0] == 0
    readers = _json(repo)["readers"]
    assert isinstance(readers, dict)
    status = readers["[STATUS: COMPLETE]"]
    assert status["kind"] == "status" and status["security"] is False
    assert status["readers"] == ["scripts/c.py:7"]
    assert status["writers"] == ["scripts/b.py:10"]
    assert status["mentions"] == ["agents/x.md:1"]
    event = readers["SubagentStop"]
    assert event["security"] is True
    assert event["readers"] == ["scripts/c.py:5"]
    assert event["writers"] == ["scripts/b.py:11"]
    env = readers["MY_TOKEN"]
    assert env["kind"] == "env" and env["security"] is True
    assert env["readers"] == ["scripts/b.py:9"]
    assert readers["charter_root"]["writers"] == ["scripts/b.py:11"]
    assert "[STATUS: HIDDEN]" not in readers


def test_ownership_comes_from_the_plan(repo: Path) -> None:
    assert _map(repo, "--plan", str(repo / "docs" / "plan.md"))[0] == 0
    assert _json(repo)["ownership"] == {
        "scripts/b.py": ["A", "B"],
        "tests/": ["A", "B"],
        "tests/test_a.py": ["A"],
        "tests/test_b.py": ["A", "B"],
    }
    assert "| scripts/b.py | A, B |" in (repo / "out" / "map.md").read_text(encoding="utf-8")


def test_no_plan_leaves_ownership_empty(repo: Path) -> None:
    assert _map(repo)[0] == 0
    assert _json(repo)["ownership"] == {}
    assert "No plan given" in (repo / "out" / "map.md").read_text(encoding="utf-8")


def test_unreadable_plan_exits_2(repo: Path) -> None:
    code, out = _map(repo, "--plan", str(repo / "missing.md"))
    assert code == 2 and "Next:" in out
    assert not (repo / "out").exists()


def test_near_duplicate_block_lists_both_ranges(repo: Path) -> None:
    assert _map(repo)[0] == 0
    duplicates = _json(repo)["duplicates"]
    assert isinstance(duplicates, list) and len(duplicates) == 1
    (block,) = duplicates
    assert [r.split(":")[0] for r in block] == ["scripts/b.py", "scripts/c.py"]
    for spot in block:
        start, end = spot.rsplit(":", 1)[1].split("-")
        assert int(end) - int(start) + 1 >= daedalus_map.MIN_LINES, spot


def test_output_is_deterministic(repo: Path) -> None:
    plan = str(repo / "docs" / "plan.md")
    assert _map(repo, "--plan", plan)[0] == 0
    first = {n: (repo / "out" / n).read_bytes() for n in ("map.json", "map.md")}
    assert _map(repo, "--plan", plan)[0] == 0
    assert first == {n: (repo / "out" / n).read_bytes() for n in ("map.json", "map.md")}
    assert str(repo).encode() not in first["map.json"] + first["map.md"]


def test_check_passes_on_a_current_map_and_fails_when_stale(repo: Path) -> None:
    plan = str(repo / "docs" / "plan.md")
    assert _map(repo, "--plan", plan)[0] == 0
    code, out = _map(repo, "--plan", plan, "--check")
    assert code == 0 and "is current" in out, out
    _write(repo, "scripts/d.py", "from lib import a\n")
    before = (repo / "out" / "map.json").read_bytes()
    code, out = _map(repo, "--plan", plan, "--check")
    assert code == 1 and "STALE map" in out and "Next:" in out
    assert (repo / "out" / "map.json").read_bytes() == before


def test_check_fails_without_a_map(repo: Path) -> None:
    code, out = _map(repo, "--check")
    assert code == 1 and "does not exist" in out


def test_check_against_another_plan_is_stale(repo: Path) -> None:
    assert _map(repo)[0] == 0
    assert _map(repo, "--plan", str(repo / "docs" / "plan.md"), "--check")[0] == 1


def test_out_outside_the_repo_is_refused(repo: Path, tmp_path: Path) -> None:
    for out in (tmp_path / "elsewhere", repo, repo / ".." / "x"):
        done = run_cli("daedalus_map.py", "--repo", str(repo), "--out", str(out))
        assert done.returncode == 2 and "not inside the repository" in done.stdout, out
    assert not (tmp_path / "elsewhere").exists()


def test_abbreviated_flags_are_refused(repo: Path) -> None:
    done = run_cli("daedalus_map.py", "--rep", str(repo), "--out", str(repo / "out"))
    assert done.returncode == 2


def test_out_folder_is_left_out_of_the_scan(repo: Path) -> None:
    out = repo / "scratch"
    _write(repo, "scratch/old.py", 'print("[STATUS: SCRATCH]")\n')
    done = run_cli("daedalus_map.py", "--repo", str(repo), "--out", str(out))
    assert done.returncode == 0, done.stdout
    assert "[STATUS: SCRATCH]" not in (out / "map.json").read_text(encoding="utf-8")


def test_excluded_roots_are_left_out_of_the_scan(repo: Path) -> None:
    # 99, D.2.1: every excluded root of the project config is skipped, a relative one included.
    roots = [
        {"kind": "path", "path": "<repo_root>/private/"},
        {"kind": "path", "path": "docs/inner"},
    ]
    _write(repo, ".claude/daedalus/config.json", json.dumps({"excluded_roots": roots}))
    _write(repo, "private/leak.py", 'print("[STATUS: PRIVATE]")\n')
    _write(repo, "docs/inner/notes.md", "Reply `[STATUS: INNER]` here.\n")
    _write(repo, "docs/kept.md", "Reply `[STATUS: KEPT]` here.\n")
    code, out = _map(repo)
    assert code == 0, out
    text = (repo / "out" / "map.json").read_text(encoding="utf-8")
    assert "[STATUS: KEPT]" in text
    assert "[STATUS: PRIVATE]" not in text and "private/leak.py" not in text
    assert "[STATUS: INNER]" not in text and "docs/inner" not in text


def test_unreadable_excluded_roots_exit_2_and_write_nothing(repo: Path) -> None:
    # 99: the walk fails closed when the excluded roots cannot be resolved.
    _write(repo, ".claude/daedalus/config.json", json.dumps({"excluded_roots": "private/"}))
    code, out = _map(repo)
    assert code == 2 and "excluded roots" in out and out.count("Next:") == 1, out
    assert not (repo / "out").exists()


def test_a_root_error_without_a_next_line_gets_one(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # 99: a cause lacking its own Next line gets the map's.
    def refuse(_repo: Path) -> frozenset[Path]:
        raise daedalus_map.ConfigError("roots unreadable")

    monkeypatch.setattr(daedalus_map, "excluded_paths", refuse)
    assert daedalus_map.main(["--repo", str(repo), "--out", "out"]) == 2
    out = capsys.readouterr().out
    assert "roots unreadable" in out and out.count("Next:") == 1, out


def test_plugin_tree_maps_its_own_plan_loader() -> None:
    # Pin MAP -> REQ: validate_plan.py reads the plan record, so the record's fan-in names it.
    scan = daedalus_map.scan_tree(REPO_ROOT, REPO_ROOT / "docs" / ".tmp")
    trees = daedalus_map._parse(scan)
    imports = daedalus_map.imports_table(scan, trees)
    assert "scripts/validate_plan.py" in imports["scripts/lib/plan_record.py"]["fan_in"]
    coverage = daedalus_map.coverage_table(scan, trees)
    assert "tests/test_daedalus_map.py" in coverage["scripts/daedalus_map.py"]
    assert (
        "tests/test_checks_command_allowlist.py" in coverage["scripts/checks/command_allowlist.py"]
    )

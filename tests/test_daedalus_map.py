# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# Pins MAP -> REQ and MAP -> VER: the dependency map's five tables, its ownership and --check.
from __future__ import annotations

import json
import os
from pathlib import Path

import daedalus_map
import pytest
from lib import train_state
from lib.workspace import begin, lock

from tests.conftest import REPO_ROOT, git, run_cli, write_train_marker

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
        '    record = {"event": "SubagentStop", "local_docs_folder": None}\n'
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
    assert readers["local_docs_folder"]["writers"] == ["scripts/b.py:11"]
    assert "[STATUS: HIDDEN]" not in readers


@pytest.mark.parametrize(
    "name",
    ["contract_skip", "lock_sha", "skip", "plan_record", "pack_dir", "verify", "--ignore-file"],
)
def test_train_control_names_are_security_relevant(name: str) -> None:
    # Train 10 audit-miss root cause 1: skip, lock, pack, verify and ignore names reach the auditor.
    assert daedalus_map.SECURITY.search(name)


def test_plain_names_stay_out_of_the_security_words() -> None:
    assert not daedalus_map.SECURITY.search("[STATUS: COMPLETE]")
    assert not daedalus_map.SECURITY.search("charter_root")


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
    _write(repo, ".claude/daedalus/config.json", json.dumps({"git_excluded_folders": roots}))
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
    config = json.dumps({"git_excluded_folders": "private/"})
    _write(repo, ".claude/daedalus/config.json", config)
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


# 0261: the map check inside a run rebuilds a stale map itself and goes on.
TRAIN = "20261112-120000"


def _run_out(root: Path, train: str = TRAIN) -> Path:
    return root / "docs" / ".tmp" / "daedalus" / train / "map"


@pytest.fixture
def run_repo(repo: Path, isolated_env: None) -> Path:
    # 0261: the map fixture as a git checkout whose marked run recorded docs/plan.md.
    git(repo, "init", "-q", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "init")
    write_train_marker(repo, TRAIN)
    plan = {"path": str(repo / "docs" / "plan.md"), "sha256": "0" * 64}
    train_state.save(repo, TRAIN, {"train_id": TRAIN, train_state.PLAN: plan})
    return repo


def _run_map(root: Path, *extra: str, train: str = TRAIN) -> tuple[int, list[str]]:
    out = str(_run_out(root, train))
    done = run_cli("daedalus_map.py", "--repo", str(root), "--out", out, *extra)
    return done.returncode, (done.stdout + done.stderr).splitlines()


def _bytes(out: Path) -> dict[str, bytes]:
    return {n: (out / n).read_bytes() for n in ("map.json", "map.md")}


def _rebuilt_line(root: Path, train: str = TRAIN) -> str:
    path = _run_out(root, train) / "map.json"
    sha = daedalus_map._sha256(path.read_text(encoding="utf-8"))
    tip = git(root, "rev-parse", "HEAD").stdout.strip()
    return f"map rebuilt: {path} from tip {tip} sha256={sha}"


def test_run_check_rebuilds_a_stale_map_once_and_the_next_check_finds_it_current(
    run_repo: Path,
) -> None:
    assert (run_repo / ".git").is_dir()
    plan = str(run_repo / "docs" / "plan.md")
    assert _run_map(run_repo, "--plan", plan)[0] == 0
    _write(run_repo, "scripts/d.py", 'from lib import a\nprint("[STATUS: NEWLY]")\n')
    code, lines = _run_map(run_repo, "--plan", plan, "--check")
    assert code == 0 and lines == [_rebuilt_line(run_repo)], lines
    assert "[STATUS: NEWLY]" in (_run_out(run_repo) / "map.json").read_text(encoding="utf-8")
    code, lines = _run_map(run_repo, "--plan", plan, "--check")
    assert (
        code == 0
        and len(lines) == 1
        and lines[0].endswith(
            f"is current sha256={_rebuilt_line(run_repo).rpartition('sha256=')[2]}"
        )
    ), lines


def test_run_check_on_a_current_map_rebuilds_nothing(run_repo: Path) -> None:
    plan = str(run_repo / "docs" / "plan.md")
    assert _run_map(run_repo, "--plan", plan)[0] == 0
    out = _run_out(run_repo)
    before = _bytes(out)
    stamps = {n: (out / n).stat().st_mtime_ns for n in before}
    code, lines = _run_map(run_repo, "--plan", plan, "--check")
    assert code == 0 and len(lines) == 1 and "is current" in lines[0], lines
    assert _bytes(out) == before
    assert {n: (out / n).stat().st_mtime_ns for n in before} == stamps


def test_run_check_without_a_plan_uses_the_plan_the_run_recorded(run_repo: Path) -> None:
    assert _run_map(run_repo, "--plan", str(run_repo / "docs" / "plan.md"))[0] == 0
    before = _bytes(_run_out(run_repo))
    code, lines = _run_map(run_repo, "--check")
    assert code == 0 and "is current" in lines[0], lines
    assert _bytes(_run_out(run_repo)) == before


def test_run_check_refuses_when_the_rebuild_cannot_write(run_repo: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root writes through a read-only folder")
    assert _run_map(run_repo)[0] == 0
    out = _run_out(run_repo)
    before = _bytes(out)
    _write(run_repo, "scripts/d.py", "from lib import a\n")
    out.chmod(0o500)
    try:
        code, lines = _run_map(run_repo, "--check")
    finally:
        out.chmod(0o700)
    assert code == 2 and len(lines) == 1, lines
    assert lines[0].startswith(f"The map could not be written to {out} (") and "Next:" in lines[0]
    assert _bytes(out) == before


def test_run_check_refuses_when_the_recorded_plan_is_gone(run_repo: Path) -> None:
    assert _run_map(run_repo, "--plan", str(run_repo / "docs" / "plan.md"))[0] == 0
    before = _bytes(_run_out(run_repo))
    (run_repo / "docs" / "plan.md").unlink()
    code, lines = _run_map(run_repo, "--check")
    assert code == 2 and lines[0].startswith("The map could not read the plan"), lines
    assert lines[-1].startswith("Next:")
    assert _bytes(_run_out(run_repo)) == before


def test_check_outside_the_run_map_folder_still_stops_on_a_stale_map(run_repo: Path) -> None:
    # 0261: only the run's own map folder is rebuilt; any other --out keeps exit 1.
    assert _map(run_repo)[0] == 0
    _write(run_repo, "scripts/d.py", "from lib import a\n")
    before = (run_repo / "out" / "map.json").read_bytes()
    code, out = _map(run_repo, "--check")
    assert code == 1 and "STALE map" in out and "rebuilt" not in out, out
    assert (run_repo / "out" / "map.json").read_bytes() == before


@pytest.fixture
def lock_repo(project_data: Path, isolated_env: None) -> Path:
    # 0261: the smallest repository the real begin and lock accept.
    root = project_data.parent.parent
    (project_data / ".gitignore").write_text("*\n")
    _write(root, "docs/decisions.md", "| Id | Date | Ruling | Supersedes | Follow-ups |\n")
    _write(root, "service-manifest.json", json.dumps({"docs": {"decisions_filename": "x.md"}}))
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "init")
    return root


def test_a_contract_revise_then_the_map_check_rebuilds_and_goes_on(lock_repo: Path) -> None:
    train = begin(lock_repo)[0].split()[1]
    _write(lock_repo, "contracts/api.md", "Reply `[STATUS: COMPLETE]` when done.\n")
    lock(lock_repo, "contracts/api.md", 1)
    assert _run_map(lock_repo, train=train)[0] == 0
    _write(lock_repo, "contracts/api.md", "Reply `[STATUS: REVISED]` when done.\n")
    lock(lock_repo, "contracts/api.md", 2)
    code, lines = _run_map(lock_repo, "--check", train=train)
    assert code == 0 and lines == [_rebuilt_line(lock_repo, train)], lines
    tip = git(lock_repo, "rev-parse", f"daedalus/{train}").stdout.strip()
    assert f"from tip {tip} " in lines[0]
    text = (_run_out(lock_repo, train) / "map.json").read_text(encoding="utf-8")
    assert "[STATUS: REVISED]" in text and "[STATUS: COMPLETE]" not in text
    code, lines = _run_map(lock_repo, "--check", train=train)
    assert code == 0 and len(lines) == 1 and "is current" in lines[0], lines

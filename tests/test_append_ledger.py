# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest
from lib.audit import project_data_dir

from tests.conftest import SCRIPTS_DIR, git, run_cli
from tests.test_ledger import FIX, _name

SCRIPT = SCRIPTS_DIR / "append_ledger.py"
TODAY = datetime.now(UTC).date().isoformat()


def _run(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return run_cli("append_ledger.py", *args, "--cwd", str(repo))


def _append(repo: Path, seq: int, entry: Path) -> subprocess.CompletedProcess[str]:
    return _run(
        repo,
        *("--expected-seq", str(seq), "--entry-file", str(entry), "--repo", "TST"),
        *("--type", "PLT"),
    )


def _plain(repo: Path, seq: int, entry: Path) -> subprocess.CompletedProcess[str]:
    # 0247: a file whose ids are plain numbers takes no --repo and no --type.
    return _run(repo, "--expected-seq", str(seq), "--entry-file", str(entry))


def _entry(repo: Path, text: str, name: str = "e.md") -> Path:
    path = repo / "docs" / ".tmp" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def table_repo(repo_cwd: Path) -> Path:
    (repo_cwd / "docs").mkdir()
    shutil.copy(FIX / "table.md", repo_cwd / "docs" / "decisions.md")
    _name(repo_cwd, "decisions.md")
    project_data_dir(str(repo_cwd)).mkdir(parents=True)
    return repo_cwd


@pytest.fixture
def heading_repo(repo_cwd: Path) -> Path:
    (repo_cwd / "docs").mkdir()
    shutil.copy(FIX / "heading.md", repo_cwd / "docs" / "LEDGER.md")
    _name(repo_cwd, "LEDGER.md")
    project_data_dir(str(repo_cwd)).mkdir(parents=True)
    return repo_cwd


def test_probe_reports_table_ledger(table_repo: Path) -> None:
    out = _run(table_repo, "--probe")
    ledger = table_repo / "docs" / "decisions.md"
    assert out.returncode == 0, out.stderr
    assert out.stdout == f"ledger: {ledger} (manifest, markdown-table-row, seq=2)\n"


def test_probe_reports_none(repo_cwd: Path) -> None:
    out = _run(repo_cwd, "--probe")
    assert out.returncode == 0, out.stderr
    assert out.stdout.startswith("decisions: no decisions file is named, so no decision is")


def test_a_conventional_file_never_named_takes_no_append(repo_cwd: Path) -> None:
    # 0247: no probe by conventional name; the append refuses and the file is untouched.
    (repo_cwd / "docs").mkdir()
    ledger = repo_cwd / "docs" / "decisions.md"
    shutil.copy(FIX / "table.md", ledger)
    before = ledger.read_bytes()
    out = _append(repo_cwd, 2, _entry(repo_cwd, "Third ruling. | None. | None"))
    assert out.returncode == 1 and "Next: set docs.decisions_filename" in out.stderr
    assert ledger.read_bytes() == before


def test_a_named_file_not_yet_written_is_created_as_a_table(repo_cwd: Path) -> None:
    # 0247: the first decision creates the named file with the default table.
    (repo_cwd / "docs").mkdir()
    _name(repo_cwd, "decisions.md")
    ledger = repo_cwd / "docs" / "decisions.md"
    probe = _run(repo_cwd, "--probe")
    assert probe.stdout == f"ledger: {ledger} (manifest, markdown-table-row, seq=0)\n"
    assert not ledger.exists()
    out = _plain(repo_cwd, 0, _entry(repo_cwd, "First ruling. | None. | None"))
    assert out.returncode == 0, out.stderr
    # 0247: a new file numbers its rows as plain four-digit numbers.
    assert out.stdout == "appended 0001\n"
    row = f"| 0001 | {TODAY} | First ruling. | None. | None |\n"
    assert ledger.read_text(encoding="utf-8") == HEADER_ONLY + row
    refused = _append(repo_cwd, 1, _entry(repo_cwd, "Second ruling. | None. | None"))
    assert refused.returncode == 1 and "--repo and --type name a part of a three-part id" in (
        refused.stderr
    )
    assert "Next: append again without --repo and --type" in refused.stderr


def test_a_named_file_with_no_docs_folder_on_disk_is_refused(repo_cwd: Path) -> None:
    # 0247: the docs folder is never created for the operator; the append names it.
    _name(repo_cwd, "decisions.md", folder="notes")
    entry = repo_cwd / "e.md"
    entry.write_text("First ruling. | None. | None", encoding="utf-8")
    probe = _run(repo_cwd, "--probe")
    assert probe.returncode == 0 and "seq=0" in probe.stdout
    out = _plain(repo_cwd, 0, entry)
    assert out.returncode == 1, out.stdout
    assert f"the docs folder {repo_cwd / 'notes'} does not exist. Next:" in out.stderr
    assert not (repo_cwd / "notes").exists()


def test_append_writes_last_table_row(table_repo: Path) -> None:
    out = _append(table_repo, 2, _entry(table_repo, "Third ruling. | None. | None\n"))
    assert out.returncode == 0, out.stderr
    assert out.stdout == "appended 0003-TST-PLT\n"
    lines = (table_repo / "docs" / "decisions.md").read_text(encoding="utf-8").splitlines()
    assert lines[-1] == f"| 0003-TST-PLT | {TODAY} | Third ruling. | None. | None |"
    lock_dir = table_repo / ".claude" / "daedalus" / "ledger-locks"
    assert lock_dir.stat().st_mode & 0o777 == 0o700
    assert len(list(lock_dir.glob("*.lock"))) == 1


def test_stale_expected_seq_exits_2(table_repo: Path) -> None:
    entry = _entry(table_repo, "Third ruling. | None. | None")
    assert _append(table_repo, 2, entry).returncode == 0
    out = _append(table_repo, 2, entry)
    assert out.returncode == 2
    assert out.stderr.startswith("sequence mismatch: ledger=3 expected=2. Next: re-read")
    assert out.stdout == ""


def test_row_lands_after_table_not_at_eof(table_repo: Path) -> None:
    ledger = table_repo / "docs" / "decisions.md"
    ledger.write_text(ledger.read_text(encoding="utf-8") + "\nTrailing prose.\n", "utf-8")
    assert (
        _append(table_repo, 2, _entry(table_repo, "Third ruling. | None. | None")).returncode == 0
    )
    lines = ledger.read_text(encoding="utf-8").splitlines()
    assert lines[-3:] == [
        f"| 0003-TST-PLT | {TODAY} | Third ruling. | None. | None |",
        "",
        "Trailing prose.",
    ]


@pytest.mark.parametrize("index_id", ["0001-TST-PLT", "0002-TST-PLT"])
def test_append_lands_in_the_main_log_below_an_index(table_repo: Path, index_id: str) -> None:
    # issue 186: the highest id across Id tables, and on a tie the table with more rows.
    ledger = table_repo / "docs" / "decisions.md"
    index = f"| Id | Name |\n|---|---|\n| {index_id} | Index row |\n\n"
    ledger.write_text(index + ledger.read_text(encoding="utf-8"), encoding="utf-8")
    out = _append(table_repo, 2, _entry(table_repo, "Third ruling. | None. | None"))
    assert out.returncode == 0, out.stderr
    text = ledger.read_text(encoding="utf-8")
    assert text.startswith(index)
    assert text.splitlines()[-1] == f"| 0003-TST-PLT | {TODAY} | Third ruling. | None. | None |"


@pytest.mark.parametrize(
    "extra",
    [
        "\nA note names 0003-TST-PLT ahead of time.\n",
        "\n| Id | Name |\n|---|---|\n| x | 0003-TST-PLT |\n",
    ],
)
def test_append_of_an_id_already_in_the_file_refused(table_repo: Path, extra: str) -> None:
    # issue 186: refused under the lock before any write, naming the id and its first line.
    ledger = table_repo / "docs" / "decisions.md"
    ledger.write_text(ledger.read_text(encoding="utf-8") + extra, encoding="utf-8")
    before = ledger.read_bytes()
    line = next(n for n, row in enumerate(before.decode().splitlines(), 1) if "0003-TST" in row)
    out = _append(table_repo, 2, _entry(table_repo, "Third ruling. | None. | None"))
    assert out.returncode == 1, out.stdout
    assert f"Next: fix the numbering where 0003-TST-PLT first appears, {ledger} line {line}," in (
        out.stderr
    )
    assert ledger.read_bytes() == before


@pytest.mark.parametrize(
    ("worktree", "branch", "code"),
    [(False, "main", 0), (False, "release", 1), (True, "main", 0), (True, "side", 1)],
)
def test_branch_pinned_ledger_writes_only_on_its_branch(
    table_repo: Path, tmp_path: Path, worktree: bool, branch: str, code: int
) -> None:
    # issue 186: HEAD is read from the checkout holding the file, never the caller's worktree.
    _name(table_repo, "decisions.md", git_branch=branch)
    cwd = table_repo
    if worktree:
        git(table_repo, "add", "docs", "service-manifest.json")
        git(table_repo, "commit", "-q", "-m", "ledger")
        cwd = tmp_path.resolve() / "side"
        git(table_repo, "worktree", "add", "-q", "-b", "side", str(cwd))
    ledger = table_repo / "docs" / "decisions.md"
    before = ledger.read_bytes()
    probe = _run(cwd, "--probe")
    out = _append(cwd, 2, _entry(cwd, "Third ruling. | None. | None"))
    assert (probe.returncode, out.returncode) == (code, code), out.stderr
    if code:
        for done in (probe, out):
            assert (
                f"Next: switch the checkout {table_repo} from branch main to branch {branch}"
                in (done.stderr)
            )
        assert ledger.read_bytes() == before


def test_crlf_ledger_keeps_crlf(table_repo: Path) -> None:
    ledger = table_repo / "docs" / "decisions.md"
    ledger.write_bytes(ledger.read_bytes().replace(b"\n", b"\r\n"))
    assert (
        _append(table_repo, 2, _entry(table_repo, "Third ruling. | None. | None")).returncode == 0
    )
    raw = ledger.read_bytes()
    assert raw.endswith(f"| 0003-TST-PLT | {TODAY} | Third ruling. | None. | None |\r\n".encode())
    assert b"\n" not in raw.replace(b"\r\n", b"")


def test_heading_frontmatter_bumps_sequence(heading_repo: Path) -> None:
    out = _plain(heading_repo, 7, _entry(heading_repo, "Eight.\n"))
    assert out.returncode == 0, out.stderr
    assert out.stdout == "appended 8\n"
    text = (heading_repo / "docs" / "LEDGER.md").read_text(encoding="utf-8")
    assert text.startswith("---\nsequence_id: 8\n---\n")
    assert text.endswith(f"Seven.\n\n## Entry 8 - {TODAY}\n\nEight.\n")


def test_heading_body_cannot_inject_entry_heading(heading_repo: Path) -> None:
    out = _plain(heading_repo, 7, _entry(heading_repo, "x\n## Entry 99 - d\n"))
    assert out.returncode == 1 and "Next:" in out.stderr
    assert "sequence_id: 7" in (heading_repo / "docs" / "LEDGER.md").read_text(encoding="utf-8")


def test_missing_entry_file_exits_1(table_repo: Path) -> None:
    out = _append(table_repo, 2, table_repo / "docs" / ".tmp" / "absent.md")
    assert out.returncode == 1 and "Next:" in out.stderr and out.stdout == ""


def test_bare_pipe_in_cell_rejected(table_repo: Path) -> None:
    out = _append(table_repo, 2, _entry(table_repo, "a | b | None | None"))
    assert out.returncode == 1 and "escape pipes as \\|" in out.stderr
    escaped = _append(table_repo, 2, _entry(table_repo, "Pipe a \\| b. | None. | None"))
    assert escaped.returncode == 0, escaped.stderr


def test_usage_error_exits_1(table_repo: Path) -> None:
    out = _run(table_repo, "--expected-seq", "2", "--repo", "TST", "--type", "PLT")
    assert out.returncode == 1 and "Next:" in out.stderr


def test_concurrent_appends_get_consecutive_ids(table_repo: Path) -> None:
    """Four processes each loop probe-then-append (retry on exit 2, max 10) under the lock."""

    def worker(k: int) -> str:
        entry = _entry(table_repo, f"Worker {k}. | None. | None", f"w{k}.md")
        for _ in range(10):
            probe = _run(table_repo, "--probe")
            match = re.search(r"seq=(\d+)\)", probe.stdout)
            assert match is not None, probe.stdout
            out = _append(table_repo, int(match.group(1)), entry)
            if out.returncode != 2:
                assert out.returncode == 0, out.stderr
                return out.stdout.split()[1]
        raise AssertionError(f"worker {k} never won the sequence")

    with ThreadPoolExecutor(max_workers=4) as pool:
        ids = list(pool.map(worker, range(4)))
    assert sorted(ids) == ["0003-TST-PLT", "0004-TST-PLT", "0005-TST-PLT", "0006-TST-PLT"]
    rows = (table_repo / "docs" / "decisions.md").read_text(encoding="utf-8").splitlines()[-4:]
    assert [row.split(" | ")[0] for row in rows] == [f"| 000{n}-TST-PLT" for n in range(3, 7)]


def _race(repos: list[Path], ledger: Path) -> list[str]:
    def worker(k: int) -> str:
        repo = repos[k % len(repos)]
        entry = _entry(repo, f"Worker {k}. | None. | None", f"w{k}.md")
        for _ in range(10):
            match = re.search(r"seq=(\d+)\)", _run(repo, "--probe").stdout)
            assert match is not None
            out = _append(repo, int(match.group(1)), entry)
            if out.returncode != 2:
                assert out.returncode == 0, out.stderr
                return out.stdout.split()[1]
        raise AssertionError(f"worker {k} never won the sequence")

    with ThreadPoolExecutor(max_workers=4) as pool:
        ids = list(pool.map(worker, range(4)))
    rows = [r for r in ledger.read_text(encoding="utf-8").splitlines() if "Worker" in r]
    assert len(rows) == 4
    return sorted(ids)


def test_shared_charter_ledger_locks_in_owning_repo(tmp_path: Path) -> None:
    """C1: two repos, two workers each, one charter ledger; the lock lives in the charter repo."""
    base = tmp_path.resolve()
    charter = base / "charter"
    subprocess.run(["git", "init", "-q", "-b", "main", str(charter)], check=True)
    shutil.copy(FIX / "table.md", charter / "decision-log.md")
    repos = []
    for name in ("a", "b"):
        repo = base / name
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
        data = project_data_dir(str(repo))
        data.mkdir(parents=True)
        config = {"local_docs_folder": str(charter)}
        (data / "config.json").write_text(json.dumps(config), "utf-8")
        _name(repo, "decision-log.md")
        repos.append(repo)
    ids = _race(repos, charter / "decision-log.md")
    assert ids == ["0003-TST-PLT", "0004-TST-PLT", "0005-TST-PLT", "0006-TST-PLT"]
    assert len(list((charter / ".claude" / "daedalus" / "ledger-locks").glob("*.lock"))) == 1
    assert not any(base.glob("[ab]/.claude/daedalus/ledger-locks"))


def test_symlink_and_real_path_share_one_lock(table_repo: Path) -> None:
    os.symlink("decisions.md", table_repo / "docs" / "decision-log.md")
    _name(table_repo, "decision-log.md")
    assert "decision-log.md" in _run(table_repo, "--probe").stdout
    assert (
        _append(table_repo, 2, _entry(table_repo, "Third ruling. | None. | None")).returncode == 0
    )
    _name(table_repo, "decisions.md")
    assert "docs/decisions.md" in _run(table_repo, "--probe").stdout
    assert (
        _append(table_repo, 3, _entry(table_repo, "Fourth ruling. | None. | None")).returncode == 0
    )
    assert len(list((table_repo / ".claude/daedalus/ledger-locks").glob("*.lock"))) == 1


def test_line_break_beside_pipe_rejected(table_repo: Path) -> None:
    out = _append(table_repo, 2, _entry(table_repo, "a | b\n| c"))
    assert out.returncode == 1 and "Next:" in out.stderr


def test_empty_entry_file_rejected(table_repo: Path) -> None:
    out = _append(table_repo, 2, _entry(table_repo, ""))
    assert out.returncode == 1 and "entry file is empty" in out.stderr


def test_entry_bom_is_stripped(table_repo: Path) -> None:
    entry = _entry(table_repo, "\ufeffThird ruling. | None. | None")
    assert _append(table_repo, 2, entry).returncode == 0
    last = (table_repo / "docs" / "decisions.md").read_text(encoding="utf-8").splitlines()[-1]
    assert last == f"| 0003-TST-PLT | {TODAY} | Third ruling. | None. | None |"


def test_header_column_two_must_be_date(table_repo: Path) -> None:
    ledger = table_repo / "docs" / "decisions.md"
    text = ledger.read_text(encoding="utf-8").replace(
        "| Id | Date | Ruling |", "| Id | Ruling | Date |"
    )
    ledger.write_text(text, encoding="utf-8")
    out = _append(table_repo, 2, _entry(table_repo, "Third ruling. | None. | None"))
    assert out.returncode == 1 and "must be `| Id | Date | ... |`" in out.stderr


def test_fifo_at_lock_path_fails_fast(table_repo: Path) -> None:
    _run(table_repo, "--probe")
    locks = table_repo / ".claude" / "daedalus" / "ledger-locks"
    locks.mkdir(mode=0o700)
    real = os.path.realpath(table_repo / "docs" / "decisions.md")
    os.mkfifo(locks / (hashlib.sha256(real.encode()).hexdigest()[:16] + ".lock"))
    entry = _entry(table_repo, "Third ruling. | None. | None")
    out = subprocess.run(
        [sys.executable, str(SCRIPT), "--expected-seq", "2", "--entry-file", str(entry)]
        + ["--repo", "TST", "--type", "PLT", "--cwd", str(table_repo)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert out.returncode == 1 and "not a regular file" in out.stderr and "Next:" in out.stderr


def test_missing_cwd_named(tmp_path: Path) -> None:
    gone = tmp_path / "gone"
    out = _run(gone, "--probe")
    assert out.returncode == 1 and str(gone) in out.stderr and "Next:" in out.stderr


def test_symlinked_ledger_locks_rejected(table_repo: Path, tmp_path: Path) -> None:
    (tmp_path / "elsewhere").mkdir()
    os.symlink(tmp_path / "elsewhere", table_repo / ".claude" / "daedalus" / "ledger-locks")
    out = _append(table_repo, 2, _entry(table_repo, "Third ruling. | None. | None"))
    assert out.returncode == 1 and "symlink" in out.stderr and "Next:" in out.stderr
    assert not any((tmp_path / "elsewhere").iterdir())


def test_symlinked_data_dir_rejected(repo_cwd: Path, tmp_path: Path) -> None:
    (repo_cwd / "docs").mkdir()
    shutil.copy(FIX / "table.md", repo_cwd / "docs" / "decisions.md")
    _name(repo_cwd, "decisions.md")
    (tmp_path / "elsewhere").mkdir()
    (repo_cwd / ".claude").mkdir()
    os.symlink(tmp_path / "elsewhere", repo_cwd / ".claude" / "daedalus")
    out = _append(repo_cwd, 2, _entry(repo_cwd, "Third ruling. | None. | None"))
    assert out.returncode == 1 and "symlink" in out.stderr and "Next:" in out.stderr


def test_ledger_byte_identical_after_mismatch(table_repo: Path) -> None:
    ledger = table_repo / "docs" / "decisions.md"
    before = ledger.read_bytes()
    assert (
        _append(table_repo, 5, _entry(table_repo, "Third ruling. | None. | None")).returncode == 2
    )
    assert ledger.read_bytes() == before


def test_crlf_heading_ledger_append(heading_repo: Path) -> None:
    ledger = heading_repo / "docs" / "LEDGER.md"
    ledger.write_bytes(ledger.read_bytes().replace(b"\n", b"\r\n"))
    assert _plain(heading_repo, 7, _entry(heading_repo, "Eight.")).returncode == 0
    raw = ledger.read_bytes()
    assert raw.startswith(b"---\r\nsequence_id: 8\r\n---\r\n")
    assert raw.endswith(f"Seven.\r\n\r\n## Entry 8 - {TODAY}\r\n\r\nEight.\r\n".encode())
    assert b"\n" not in raw.replace(b"\r\n", b"")


def test_non_git_cwd_refused(tmp_path: Path) -> None:
    plain = tmp_path.resolve() / "plain"
    (plain / "docs").mkdir(parents=True)
    shutil.copy(FIX / "table.md", plain / "docs" / "decisions.md")
    _name(plain, "decisions.md")
    entry = tmp_path / "e.md"
    entry.write_text("Third ruling. | None. | None", encoding="utf-8")
    out = _append(plain, 2, entry)
    assert out.returncode == 1 and "is not inside a git repository. Next:" in out.stderr
    assert not list(plain.rglob(".claude"))


def test_non_git_charter_root_refused(repo_cwd: Path, tmp_path: Path) -> None:
    charter = tmp_path.resolve() / "charter"
    charter.mkdir()
    shutil.copy(FIX / "table.md", charter / "decision-log.md")
    data = project_data_dir(str(repo_cwd))
    data.mkdir(parents=True)
    (data / "config.json").write_text(json.dumps({"local_docs_folder": str(charter)}), "utf-8")
    _name(repo_cwd, "decision-log.md")
    out = _append(repo_cwd, 2, _entry(repo_cwd, "Third ruling. | None. | None"))
    assert out.returncode == 1 and f"{charter} is not inside a git repository" in out.stderr
    assert not (charter / ".claude").exists()


def test_non_git_cwd_refused_with_a_git_owned_ledger(table_repo: Path, tmp_path: Path) -> None:
    # M5: the owner check passes here, so only the cwd check refuses the append.
    plain = tmp_path.resolve() / "plain"
    data = plain / ".claude" / "daedalus"
    data.mkdir(parents=True)
    ledger = table_repo / "docs" / "decisions.md"
    config = {"local_docs_folder": str(table_repo / "docs")}
    (data / "config.json").write_text(json.dumps(config), "utf-8")
    _name(plain, "decisions.md")
    before = ledger.read_bytes()
    out = _append(plain, 2, _entry(plain, "Third ruling. | None. | None"))
    assert out.returncode == 1, out.stdout + out.stderr
    assert f"{plain} is not inside a git repository. Next:" in out.stderr
    assert ledger.read_bytes() == before


HEADER_ONLY = "| Id | Date | Ruling | Supersedes | Follow-ups |\n|---|---|---|---|---|\n"


def test_header_only_ledger_probes_seq_zero_and_appends_0001(repo_cwd: Path) -> None:
    # C1: the build-train create path writes header and separator only.
    (repo_cwd / "docs").mkdir()
    ledger = repo_cwd / "docs" / "decisions.md"
    ledger.write_text(HEADER_ONLY, encoding="utf-8")
    _name(repo_cwd, "decisions.md")
    project_data_dir(str(repo_cwd)).mkdir(parents=True)
    out = _run(repo_cwd, "--probe")
    assert out.returncode == 0, out.stderr
    assert out.stdout == f"ledger: {ledger} (manifest, markdown-table-row, seq=0)\n"
    missing = _run(repo_cwd, "--expected-seq", "0", "--entry-file", "x.md", "--repo", "TST")
    assert missing.returncode == 1 and "--repo names a part of a three-part id" in missing.stderr
    out = _plain(repo_cwd, 0, _entry(repo_cwd, "First ruling. | None. | None\n"))
    assert out.returncode == 0, out.stderr
    # 0247: an empty table numbers its first row as a plain four-digit number.
    assert out.stdout == "appended 0001\n"
    row = f"| 0001 | {TODAY} | First ruling. | None. | None |\n"
    assert ledger.read_text(encoding="utf-8") == HEADER_ONLY + row


def test_empty_table_above_populated_one_exits_1(repo_cwd: Path) -> None:
    # R2-1 stays an error after C1.
    (repo_cwd / "docs").mkdir()
    text = HEADER_ONLY + "\n" + (FIX / "table.md").read_text(encoding="utf-8")
    (repo_cwd / "docs" / "decisions.md").write_text(text, encoding="utf-8")
    _name(repo_cwd, "decisions.md")
    project_data_dir(str(repo_cwd)).mkdir(parents=True)
    out = _run(repo_cwd, "--probe")
    assert out.returncode == 1
    assert "the first Id table has a header but no rows" in out.stderr
    assert "Next: keep one ledger table." in out.stderr


def test_two_empty_id_tables_exit_1(repo_cwd: Path) -> None:
    (repo_cwd / "docs").mkdir()
    text = HEADER_ONLY + "\n" + HEADER_ONLY
    (repo_cwd / "docs" / "decisions.md").write_text(text, encoding="utf-8")
    _name(repo_cwd, "decisions.md")
    project_data_dir(str(repo_cwd)).mkdir(parents=True)
    out = _run(repo_cwd, "--probe")
    assert out.returncode == 1
    assert (
        "has two or more empty Id tables. Next: keep one ledger table and delete the others."
    ) in out.stderr


@pytest.mark.parametrize(
    "cell",
    [
        "None.",
        "Supersedes: 0001-TST-PLT.",
        "Supersedes: 0001-TST-PLT, 0002-TST-PLT. Amends: 0001-TST-PLT.",
        "Amends: 0002-TST-PLT. Applies: the ledger rule.",
        "None. Applies: 0001-TST-PLT (first ruling).",
    ],
)
def test_machine_readable_supersedes_cell_appends(table_repo: Path, cell: str) -> None:
    out = _append(table_repo, 2, _entry(table_repo, f"Third ruling. | {cell} | None"))
    assert out.returncode == 0, out.stderr


@pytest.mark.parametrize(
    "cell",
    [
        "None",
        "",
        "None. Amends: 0001-TST-PLT.",
        "Amends: the build-train skill's three-round cap.",
        "Supersedes: 0001-TST-PLT",
        "Supersedes: 1.",
        "Refines 0001-TST-PLT.",
        "None. Applies 0001-TST-PLT.",
        "Applies: 0001-TST-PLT.",
    ],
)
def test_malformed_supersedes_cell_refused(table_repo: Path, cell: str) -> None:
    # 0090: the appended row only; the ledger is left byte-identical.
    ledger = table_repo / "docs" / "decisions.md"
    before = ledger.read_bytes()
    out = _append(table_repo, 2, _entry(table_repo, f"Third ruling. | {cell} | None"))
    assert out.returncode == 1, out.stdout
    assert "is not in the machine-readable form (0090). Next: write `None.`" in out.stderr
    assert ledger.read_bytes() == before


@pytest.mark.parametrize(
    "cell", ["Open composition. Rest of the ruling.", "Plan seven train build record."]
)
def test_named_ruling_cell_appends(table_repo: Path, cell: str) -> None:
    out = _append(table_repo, 2, _entry(table_repo, f"{cell} | None. | None"))
    assert out.returncode == 0, out.stderr


@pytest.mark.parametrize(
    "cell",
    [
        "Third.",
        "Six words is one too many. Then the ruling.",
        "A ruling with no period at all",
        "Two words.then no space",
    ],
)
def test_malformed_ruling_cell_refused(table_repo: Path, cell: str) -> None:
    # 0094: a Ruling cell begins with a name of two to five words and a period.
    ledger = table_repo / "docs" / "decisions.md"
    before = ledger.read_bytes()
    out = _append(table_repo, 2, _entry(table_repo, f"{cell} | None. | None"))
    assert out.returncode == 1, out.stdout
    assert "must begin with a name of 2 to 5 words and a period (0094)" in out.stderr
    assert "Next: begin the cell with the ruling's short name" in out.stderr
    assert ledger.read_bytes() == before


def test_cell_checks_skip_a_ledger_without_the_columns(repo_cwd: Path) -> None:
    (repo_cwd / "docs").mkdir()
    ledger = repo_cwd / "docs" / "decisions.md"
    ledger.write_text("| Id | Date | Note |\n|---|---|---|\n", encoding="utf-8")
    _name(repo_cwd, "decisions.md")
    project_data_dir(str(repo_cwd)).mkdir(parents=True)
    out = _plain(repo_cwd, 0, _entry(repo_cwd, "free text"))
    assert out.returncode == 0, out.stderr

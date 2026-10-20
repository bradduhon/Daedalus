#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
"""Append one entry to the declared or probed ledger under a lock (0004).

--probe prints the resolved ledger and its sequence. An append checks --expected-seq
against the ledger under the lock and exits 2 on a mismatch, 1 on any other error.
A table row's Supersedes and Ruling cells are checked when the header has the column
(0090, 0094); rows already in the ledger are never re-checked.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.audit import DataDirError, ensure_project_data_dir, root_info  # noqa: E402
from lib.config import ConfigError, load_config  # noqa: E402
from lib.ledger import (  # noqa: E402
    LedgerError,
    ResolvedLedger,
    body_cell_problem,
    format_entry,
    id_table_span,
    next_id,
    read_sequence,
    resolve_ledger,
    split_row,
)
from lib.locks import bounded_flock  # noqa: E402
from lib.project_root import project_root  # noqa: E402

NONE_FOUND = (
    "ledger: none declared and none found. "
    "Next: declare a ledger block or create one (docs/project-requirements.md)"
)
_CODE = re.compile(r"[A-Za-z0-9_-]+")
_ENTRY_LINE = re.compile(r"^## Entry [0-9]")
LOCK_TIMEOUT_S = 5.0


class AppendError(Exception):
    pass


class SequenceMismatch(Exception):
    pass


@dataclass(frozen=True)
class _Ids:
    seq: int
    repo: str
    type_: str
    date: str


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # 0004: exit 2 is reserved for a sequence mismatch; usage errors exit 1.
        self.exit(1, f"append_ledger: {message}. Next: run with --help for the usage.\n")


def _parse(argv: list[str]) -> argparse.Namespace:
    # I2: no prefix abbreviations, so --cwd has exactly one spelling for the jail to fence.
    parser = _Parser(prog="append_ledger.py", description=__doc__, allow_abbrev=False)
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--expected-seq", type=int)
    parser.add_argument("--entry-file")
    parser.add_argument("--repo")
    parser.add_argument("--type", dest="type_")
    parser.add_argument("--cwd", default=os.getcwd())
    args = parser.parse_args(argv)
    if not args.probe:
        missing = [
            flag
            for flag, value in (
                ("--expected-seq", args.expected_seq),
                ("--entry-file", args.entry_file),
                ("--repo", args.repo),
                ("--type", args.type_),
            )
            if value is None
        ]
        if missing:
            parser.error(f"an append needs {', '.join(missing)}")
        for flag, value in (("--repo", args.repo), ("--type", args.type_)):
            if not _CODE.fullmatch(value):
                parser.error(f"{flag} must match [A-Za-z0-9_-]+")
    args.cwd = os.path.abspath(args.cwd)
    if not os.path.isdir(args.cwd):
        parser.exit(
            1,
            f"append_ledger: --cwd {args.cwd} is not an existing directory. "
            "Next: pass the repo directory that holds the ledger.\n",
        )
    return args


def _resolve(cwd: str) -> ResolvedLedger | None:
    return resolve_ledger(cwd, load_config(cwd=cwd))


def _read_entry(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig")
    except FileNotFoundError as exc:
        raise AppendError(
            f"entry file {path} does not exist. Next: write the entry to docs/.tmp/ first."
        ) from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise AppendError(
            f"entry file {path} could not be read ({exc}). Next: write it as UTF-8 text."
        ) from exc


def _eol(line: str) -> str:
    return "\r\n" if line.endswith("\r\n") else "\n"


def _table_body(entry: str, header: str, id_scheme: str) -> str:
    columns = split_row(header)[2:]
    want = len(columns)
    if want < 1:
        raise AppendError(
            "the ledger table has no columns after Id and Date. "
            "Next: add the ledger's body columns to its header."
        )
    if not entry:
        raise AppendError("entry file is empty. Next: write the row's cells after Id and Date.")
    if entry.splitlines() != [entry]:
        raise AppendError(
            "a table entry is one line; the entry file holds a line break. "
            "Next: join the cells onto one line."
        )
    cells = split_row(entry)
    if len(cells) != want:
        raise AppendError(
            f"entry has {len(cells)} cell(s); the ledger table has {want} after Id and Date. "
            "Next: escape pipes as \\| inside a cell, or match the column count."
        )
    problem = body_cell_problem(columns, cells, id_scheme)
    if problem:
        raise AppendError(problem)
    return " | ".join(cells)


def _table_text(lines: list[str], ledger: ResolvedLedger, entry: str, ids: _Ids) -> str:
    bare = "".join(lines).splitlines()
    span = id_table_span(bare)
    if span is None:
        raise AppendError(f"{ledger.path} has no Id table. Next: add a header and separator row.")
    start, column, end = span
    if column != 0:
        raise AppendError(
            f"{ledger.path} Id column is not the first column. "
            "Next: move Id to the first column; rows are written as | Id | Date | ...."
        )
    header = split_row(bare[start])
    if len(header) < 2 or header[1].lower() != "date":
        raise AppendError(
            f"{ledger.path} header column 2 is not Date. "
            "Next: the ledger table must be `| Id | Date | ... |`; "
            "declare a different format once one is supported."
        )
    eol = _eol(lines[start])
    body = _table_body(entry.strip(), bare[start], ledger.id_scheme)
    row = format_entry(ledger, ids.seq, ids.repo, ids.type_, ids.date, body).rstrip("\n") + eol
    out = list(lines)
    if out[end - 1] == bare[end - 1]:
        out[end - 1] += eol
    out.insert(end, row)
    return "".join(out)


def _heading_text(lines: list[str], ledger: ResolvedLedger, entry: str, ids: _Ids) -> str:
    body = entry.strip("\r\n")
    # 0004: an injected entry heading would move a last-row-id sequence.
    if any(_ENTRY_LINE.match(line) for line in body.splitlines()):
        raise AppendError(
            "entry body contains a '## Entry N' heading. Next: use a lower heading level."
        )
    eol = _eol(lines[0]) if lines else "\n"
    out = list(lines)
    source = ledger.sequence_source
    if source.startswith("frontmatter:"):
        _bump_frontmatter(out, source.removeprefix("frontmatter:"), ids.seq, ledger)
    text = "".join(out).rstrip("\r\n")
    formatted = format_entry(ledger, ids.seq, ids.repo, ids.type_, ids.date, body)
    return text + formatted.replace("\n", eol)


def _bump_frontmatter(lines: list[str], key: str, seq: int, ledger: ResolvedLedger) -> None:
    # 0004: the last occurrence wins, matching lib.ledger._frontmatter.
    hit: int | None = None
    for i in range(1, len(lines)):
        line = lines[i].rstrip("\r\n")
        if line.strip() == "---":
            break
        name, sep, _ = line.partition(":")
        if sep and name.strip() == key:
            hit = i
    if hit is not None:
        line = lines[hit].rstrip("\r\n")
        lines[hit] = f"{line.partition(':')[0]}: {seq}" + lines[hit][len(line) :]
        return
    raise AppendError(
        f"{ledger.path} frontmatter has no {key!r}. "
        f"Next: add the sequence line '{key}: <n>' to the ledger frontmatter."
    )


def _write_atomic(path: Path, text: str) -> None:
    target = Path(os.path.realpath(path))
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, target.stat().st_mode & 0o7777)
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _require_git(path: str) -> None:
    # M6, 0077: the owner resolves as the jail resolves it; a non-git root is refused.
    if root_info(str(project_root(Path(path))))[1] != "git":
        raise AppendError(
            f"{path} is not inside a git repository. Next: run from the repo that declares "
            "the ledger, or initialize the charter repo."
        )


def _lock_path(ledger: ResolvedLedger) -> Path:
    real = os.path.realpath(ledger.path)
    if not os.path.isfile(real):
        raise AppendError(
            f"ledger {ledger.path} does not exist. Next: create it or fix the declared path."
        )
    owner = str(project_root(Path(real).parent))
    _require_git(owner)
    # C1, 0077: the lock lives in the project that owns the ledger, so every caller shares it.
    locks = ensure_project_data_dir(owner) / "ledger-locks"
    if locks.is_symlink():
        raise AppendError(f"{locks} is a symlink. Next: remove it; the plugin recreates it.")
    locks.mkdir(mode=0o700, exist_ok=True)
    os.chmod(locks, 0o700)
    name = hashlib.sha256(real.encode()).hexdigest()[:16] + ".lock"
    return locks / name


def _open_lock(path: str) -> int:
    # M5: O_NONBLOCK so a planted FIFO cannot hang the open; only a regular file is a lock.
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise AppendError(f"lock {path} is not a regular file. Next: remove it and retry.")
    return fd


def _append(args: argparse.Namespace, ledger: ResolvedLedger) -> str:
    entry = _read_entry(Path(args.cwd, args.entry_file))
    date = datetime.now(UTC).date().isoformat()
    lock = _lock_path(ledger)
    with open(lock, "r+", opener=lambda path, _flags: _open_lock(path)) as lock_fh:
        try:
            bounded_flock(lock_fh, LOCK_TIMEOUT_S, label="ledger lock")
        except RuntimeError as exc:
            held = str(exc).split(" Next:")[0]
            raise AppendError(
                f"{held} Next: retry after the other append finishes; do not delete the .lock file."
            ) from exc
        current = read_sequence(ledger)
        if current != args.expected_seq:
            raise SequenceMismatch(
                f"sequence mismatch: ledger={current} expected={args.expected_seq}. "
                "Next: re-read the ledger and retry with the current id."
            )
        ids = _Ids(current + 1, args.repo, args.type_, date)
        try:
            with open(ledger.path, encoding="utf-8", newline="") as fh:
                raw = fh.read()
        except (OSError, UnicodeDecodeError) as exc:
            raise AppendError(
                f"ledger {ledger.path} could not be read ({exc}). "
                "Next: make the ledger file readable UTF-8 text."
            ) from exc
        bom = "\ufeff" if raw.startswith("\ufeff") else ""
        lines = raw.removeprefix(bom).splitlines(keepends=True)
        if ledger.format == "markdown-table-row":
            text = _table_text(lines, ledger, entry, ids)
        else:
            text = _heading_text(lines, ledger, entry, ids)
        _write_atomic(ledger.path, bom + text)
    return next_id(ledger, ids.seq, ids.repo, ids.type_)


def main(argv: list[str] | None = None) -> int:
    args = _parse(sys.argv[1:] if argv is None else argv)
    try:
        ledger = _resolve(args.cwd)
        if args.probe:
            if ledger is None:
                print(NONE_FOUND)
            else:
                seq = read_sequence(ledger)
                print(f"ledger: {ledger.path} ({ledger.origin}, {ledger.format}, seq={seq})")
            return 0
        if ledger is None:
            raise AppendError(NONE_FOUND.removeprefix("ledger: "))
        _require_git(args.cwd)
        print(f"appended {_append(args, ledger)}")
        return 0
    except SequenceMismatch as exc:
        print(exc, file=sys.stderr)
        return 2
    except (AppendError, LedgerError, ConfigError, DataDirError) as exc:
        print(f"append_ledger: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(
            f"append_ledger: {exc}. Next: check permissions on the ledger and data dir.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import atomic, locks  # noqa: E402
from lib.audit import DataDirError, ensure_project_data_dir, root_info  # noqa: E402
from lib.config import ConfigError, load_config  # noqa: E402
from lib.ledger import (  # noqa: E402
    LedgerError,
    ResolvedLedger,
    body_cell_problem,
    format_entry,
    highest_id_table,
    id_table_span,
    next_id,
    read_sequence,
    resolve_ledger,
    split_row,
    uses_codes,
)
from lib.project_root import project_root  # noqa: E402
from lib.repo_root import checkout_git_dir  # noqa: E402

# 22: the --help text, kept below the future import as a plain string.
DESCRIPTION = (
    "Append one entry to the decisions file the service manifest names under a lock (0004, "
    "0247). --probe prints the named decisions file, its layout and its sequence, and appends "
    "nothing. A named file that does not exist yet is created as a table on the first append. "
    "An append checks --expected-seq against the file under the lock and exits 2 on a "
    "mismatch, 1 on any other error. A table row's Supersedes and Ruling cells are checked when "
    "the header has the column (0090, 0094); rows already in the file are never re-checked. The "
    "next id follows the highest id of any Id table, in the shape of the last id: a plain "
    "number keeps its width, and a number with a repository code and a type takes --repo and "
    "--type, which a plain-number file refuses. An empty table or a new file starts at 0001. An "
    "id already in the file is refused. A docs.git_branch refuses the append and the probe on "
    "any other branch (issue 186)."
)
NONE_FOUND = (
    "decisions: no decisions file is named, so no decision is recorded. "
    "Next: set docs.decisions_filename in service-manifest.json to record decisions"
)
# 0247: the header a named decisions file is created with on its first decision.
DEFAULT_TABLE = "| Id | Date | Ruling | Supersedes | Follow-ups |\n|---|---|---|---|---|\n"
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
    parser = _Parser(prog="append_ledger.py", description=DESCRIPTION, allow_abbrev=False)
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
            )
            if value is None
        ]
        if missing:
            parser.error(f"an append needs {', '.join(missing)}")
        for flag, value in (("--repo", args.repo), ("--type", args.type_)):
            if value is not None and not _CODE.fullmatch(value):
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
    # issue 186: the row joins the table holding the highest id; a lone empty table takes it.
    found = highest_id_table(bare)
    span = found[0] if found is not None else id_table_span(bare)
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


def _refuse_duplicate(text: str, new_id: str, ledger: ResolvedLedger) -> None:
    # issue 186: an id already anywhere in the ledger, as a whole word, is never written again.
    match = re.search(rf"(?<!\w){re.escape(new_id)}(?!\w)", text)
    if match is None:
        return
    line = text.count("\n", 0, match.start()) + 1
    raise AppendError(
        f"{ledger.path} already holds the id {new_id}, so the append would write it twice. "
        f"Next: fix the numbering where {new_id} first appears, {ledger.path} line {line}, "
        "from your own shell, then probe and retry."
    )


def _require_branch(ledger: ResolvedLedger) -> None:
    # issue 186, 0069: HEAD is read from the filesystem, never by git; never switched.
    if ledger.branch is None:
        return
    found = checkout_git_dir(os.path.dirname(os.path.realpath(ledger.path)))
    checkout, gitdir = found if found is not None else (Path(ledger.path).parent, None)
    try:
        head = (gitdir / "HEAD").read_text(encoding="utf-8").strip() if gitdir else ""
    except (OSError, UnicodeDecodeError):
        head = ""
    prefix = "ref: refs/heads/"
    have = head.removeprefix(prefix) if head.startswith(prefix) else None
    if have == ledger.branch:
        return
    shown = f"branch {have}" if have else "a detached or unreadable HEAD"
    raise AppendError(
        f"ledger {ledger.path} is written only on branch {ledger.branch}, and its checkout is "
        f"on {shown}. Next: switch the checkout {checkout} from {shown} to branch "
        f"{ledger.branch} from your own shell, then rerun; Daedalus never switches it."
    )


def _require_codes(args: argparse.Namespace, ledger: ResolvedLedger) -> None:
    # 0247: --repo and --type go only with ids that carry a repository code and a type.
    given = [flag for flag, value in (("--repo", args.repo), ("--type", args.type_)) if value]
    if uses_codes(ledger):
        missing = sorted({"--repo", "--type"} - set(given))
        if missing:
            raise AppendError(
                f"the ids of {ledger.path} carry a repository code and a type, so an append "
                f"needs {' and '.join(missing)}. Next: pass both, as in --repo SVC --type PLT."
            )
        return
    if given:
        flags = " and ".join(given)
        raise AppendError(
            f"{flags} {'name' if len(given) > 1 else 'names'} a part of a three-part id, but the "
            f"ids of {ledger.path} are plain numbers. Next: append again without {flags}, "
            "since the next id is a plain number too."
        )


def _require_git(path: str) -> None:
    # M6, 0077: the owner resolves as the jail resolves it; a non-git root is refused.
    if root_info(str(project_root(Path(path))))[1] != "git":
        raise AppendError(
            f"{path} is not inside a git repository. Next: run from the repo that names the "
            "decisions file, or initialize the docs folder's own repository."
        )


def _create_named(ledger: ResolvedLedger) -> None:
    # 0247: the named file is created at its path with the default table, never a folder.
    if os.path.lexists(ledger.path):
        return
    if not ledger.path.parent.is_dir():
        raise AppendError(
            f"the docs folder {ledger.path.parent} does not exist. Next: create the folder, or "
            "correct docs.folder or local_docs_folder, then record the decision again."
        )
    _require_git(os.path.realpath(ledger.path.parent))
    try:
        atomic.create_once(ledger.path, DEFAULT_TABLE, 0o644)
    except FileExistsError:
        return


def _lock_path(ledger: ResolvedLedger) -> Path:
    real = os.path.realpath(ledger.path)
    if not os.path.isfile(real):
        raise AppendError(
            f"decisions file {ledger.path} is not a file. Next: correct "
            "docs.decisions_filename or move what sits at that path."
        )
    owner = str(project_root(Path(real).parent))
    _require_git(owner)
    # C1, 0077: the lock lives in the project that owns the ledger, so every caller shares it.
    folder = ensure_project_data_dir(owner) / "ledger-locks"
    if folder.is_symlink():
        raise AppendError(f"{folder} is a symlink. Next: remove it; the plugin recreates it.")
    folder.mkdir(mode=0o700, exist_ok=True)
    os.chmod(folder, 0o700)
    name = hashlib.sha256(real.encode()).hexdigest()[:16] + ".lock"
    return folder / name


def _append(args: argparse.Namespace, ledger: ResolvedLedger) -> str:
    entry = _read_entry(Path(args.cwd, args.entry_file))
    date = datetime.now(UTC).date().isoformat()
    _create_named(ledger)
    lock = _lock_path(ledger)
    with ExitStack() as stack:
        try:
            # M5, 75: the one opener refuses a planted FIFO instead of hanging on it.
            stack.enter_context(locks.locked(lock, LOCK_TIMEOUT_S, label="ledger lock"))
        except locks.LockRefused as exc:
            raise AppendError(str(exc)) from exc
        except locks.LockHeld as exc:
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
        ids = _Ids(current + 1, args.repo or "", args.type_ or "", date)
        try:
            with open(ledger.path, encoding="utf-8", newline="") as fh:
                raw = fh.read()
        except (OSError, UnicodeDecodeError) as exc:
            raise AppendError(
                f"ledger {ledger.path} could not be read ({exc}). "
                "Next: make the ledger file readable UTF-8 text."
            ) from exc
        bom = "\ufeff" if raw.startswith("\ufeff") else ""
        _refuse_duplicate(
            raw.removeprefix(bom), next_id(ledger, ids.seq, ids.repo, ids.type_), ledger
        )
        lines = raw.removeprefix(bom).splitlines(keepends=True)
        if ledger.format == "markdown-table-row":
            text = _table_text(lines, ledger, entry, ids)
        else:
            text = _heading_text(lines, ledger, entry, ids)
        # W1.1: the realpath is written, so a ledger reached through a link keeps that link.
        atomic.write_atomic(Path(os.path.realpath(ledger.path)), bom + text)
    return next_id(ledger, ids.seq, ids.repo, ids.type_)


def main(argv: list[str] | None = None) -> int:
    args = _parse(sys.argv[1:] if argv is None else argv)
    try:
        ledger = _resolve(args.cwd)
        if ledger is not None:
            _require_branch(ledger)
        if args.probe:
            if ledger is None:
                print(NONE_FOUND)
            else:
                seq = read_sequence(ledger)
                print(f"ledger: {ledger.path} ({ledger.origin}, {ledger.format}, seq={seq})")
            return 0
        if ledger is None:
            raise AppendError(NONE_FOUND)
        _require_codes(args, ledger)
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

# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# line 70, rulings 0221 and 0229: every corpus row with a verdict, mutated by each operator and
# judged by the hooks its agent meets on main. A mutant of an admitted row is refused or keeps
# the row's typed record; every mutant of a refused row is refused.
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import daedalus_confine
import pytest
from lib import hook_io, jail, shell, shparse
from lib.admit import Admitted, AdmittedCommand, Typed, admit
from lib.config import Config, ExcludedRootDecl

from tests.adversarial import corpus as C
from tests.adversarial import test_admit_corpus as AC
from tests.adversarial.mutation import BY_NAME, OPERATORS, PROBE, WRITE_FILE, Mutant, Operator
from tests.conftest import CFG, CWD, SCRIPTS_DIR, WT, git, write_train_marker
from tests.hook_chain import CHAINS, decide, evaluate, load
from tests.jail_cases import _unit_repo
from tests.payloads import _cred

pytestmark = pytest.mark.usefixtures("jail_fakes")
# line 70: read at import, before the conftest fixture swaps the confine check out of the chain.
REAL_CONFINE = load("confine").judge
KERNEL_ON = daedalus_confine.Support("x86_64", 3, True)
# line 70: a folder names where a row runs: a real unit worktree (its path replaces WT), the fake
# train repo, a real marked repo (its path replaces {repo} and the admit corpus's REPO).
WT_FOLDER, REPO_FOLDER, MARKED, UNIT = "wt", "repo", "marked", "unit"
Slot = tuple[str, bool]
Fields = tuple[tuple[Slot, ...], ...]
Record = tuple[Fields, ...] | None
# line 70: operators that write a different option or path; a table row may type it otherwise.
RESPELL = frozenset({"option_case"})


@dataclass(frozen=True)
class Row:
    source: str
    agent: str
    verdict: str
    command: str
    folder: str


def _admit_corpus(rows: list[AC.Row], verdict: str) -> Iterator[Row]:
    for source, agent, command in rows:
        if agent in ("foreign", "main"):
            yield Row(source, "Explore" if agent == "foreign" else agent, verdict, command, MARKED)
        else:
            folder = WT_FOLDER if agent == "coder" else REPO_FOLDER
            yield Row(source, agent, verdict, command, folder)


def _measured() -> Iterator[Row]:
    # line 70: an unmarked folder polices no foreign call, so its rows have no table to mutate.
    for i, (agent, folder, verdict, form) in enumerate((*C.P3_MEASURE_A2, *C.P3_MEASURE_A3)):
        if folder != "unmarked":
            place = UNIT if folder == "unit" else MARKED
            yield Row(f"P3_MEASURE {i}", agent, verdict, form, place)


def _claims(form: str) -> str:
    return form.format(claims=SCRIPTS_DIR / "daedalus_claims.py", wt=WT)


def admitted_rows() -> list[Row]:
    claims = (_claims(f) for f in C.CLAIMS_ADMITTED)
    return [
        *_admit_corpus(AC.ADMITTED, "admit"),
        *(r for r in _measured() if r.verdict == "admit"),
        *(Row("CLAIMS_ADMITTED", "verifier", "admit", c, REPO_FOLDER) for c in claims),
    ]


def refused_rows() -> list[Row]:
    hunt = (f.format(wt=WT, repo=CWD, conf=shell.CONFINE_PATH) for _, _, f in C.S3C_HUNT)
    claims = (_claims(f) for f in C.CLAIMS_REFUSED)
    return [
        *_admit_corpus(AC.REFUSED, "refuse"),
        *(r for r in _measured() if r.verdict == "refuse"),
        *(Row("CLAIMS_REFUSED", "verifier", "refuse", c, REPO_FOLDER) for c in claims),
        *(Row("S3C_HUNT", "coder", "refuse", c, REPO_FOLDER) for c in hunt),
    ]


@dataclass
class World:
    marked: Path
    unit_repo: Path
    unit_wt: Path
    baseline: dict[Row, tuple[bool, Record]] = field(default_factory=dict)


@pytest.fixture(scope="module")
def world(tmp_path_factory: pytest.TempPathFactory) -> World:
    root = tmp_path_factory.mktemp("mutations").resolve()
    marked = root / "marked"
    marked.mkdir()
    git(marked, "init", "-q", "-b", "main")
    write_train_marker(marked, "20261015-120000")
    repo, wt = _unit_repo(root / "u")
    for name in ("notes", "src"):
        (wt / name).mkdir(exist_ok=True)
        (wt / name / "a.md").write_text("x\n", encoding="utf-8")
    return World(marked, repo, wt)


def _setup(monkeypatch: pytest.MonkeyPatch, world: World) -> None:
    # line 70: the coder chain as main runs it, the confine check in, on a usable kernel.
    monkeypatch.setattr(load("confine"), "judge", REAL_CONFINE)
    monkeypatch.setattr(daedalus_confine, "kernel_support", lambda: KERNEL_ON)
    roots = Config(excluded_roots=(ExcludedRootDecl("path", str(world.unit_repo / "notes")),))
    monkeypatch.setattr(hook_io, "hook_config", lambda cwd: roots)


def _place(world: World, row: Row, text: str) -> tuple[str, str]:
    marked = str(world.marked)
    if row.folder == MARKED:
        return marked, text.replace(AC.REPO, marked).replace("{repo}", marked)
    if row.folder == UNIT:
        return str(world.unit_wt), text.replace("{repo}", marked)
    if row.folder == WT_FOLDER:
        return str(world.unit_wt), text.replace(WT, str(world.unit_wt))
    return CWD, text


def _seam(row: Row, command: str, cwd: str) -> bool:
    # line 70: as tests/adversarial/test_measurement_rows.py judges; True is admitted.
    if row.agent == "main":
        hook_input: dict[str, object] = {"tool_name": "Bash", "tool_input": {"command": command}}
        hook_input["cwd"] = cwd
    else:
        hook_input = {**_cred(row.agent, "Bash", cwd, command=command), "session_id": "s"}
    if row.agent in CHAINS:
        got = decide(hook_input, CFG)
        excluded = evaluate("excluded_roots", hook_input) if row.folder == UNIT else None
        return got.allow and not got.warn and excluded is None
    got = jail.decide(hook_input, CFG)
    return got.allow and not got.warn


def _slots(*items: Typed | None) -> tuple[Slot, ...]:
    return tuple((t.text, t.glob) for t in items if t is not None)


def _fields(c: AdmittedCommand) -> Fields:
    # line 70: the typed fields the brief compares; options, wrappers and spans are not compared.
    return (
        ((c.family, False),),
        _slots(c.subcommand),
        _slots(*c.writes),
        _slots(*c.reads),
        _slots(c.cd_target),
        _slots(c.git_dir),
        _slots(c.script),
        _slots(*c.pathspecs),
    )


def _admit(row: Row, command: str, cwd: str) -> Admitted | None:
    agent = "foreign" if row.agent == "Explore" else row.agent
    got = admit(shparse.parse(command), agent, cwd, text=command)
    return got if isinstance(got, Admitted) else None


def _record(got: Admitted | None) -> Record:
    return None if got is None else tuple(_fields(c) for c in got.commands)


def _expected(mutant: Mutant, got: Record) -> Record:
    # line 70: an append adds one bare probe; a redirect adds its one target to the writes.
    bare: Fields = (((PROBE, False),), (), (), (), (), (), (), ())
    if got and mutant.effect == "append" and got[-1] == bare:
        return got[:-1]
    if got and mutant.effect in ("write", "null"):
        drop = (WRITE_FILE if mutant.effect == "write" else "/dev/null", False)
        return tuple((*c[:2], tuple(w for w in c[2] if w != drop), *c[3:]) for c in got)
    return got


def _same(record: Record, got: Record) -> bool:
    # line 70: normalisation: a slot admit typed unknown (glob) stands for any value in that slot.
    if record is None or got is None:
        return record == got
    if len(record) != len(got):
        return False
    for want_cmd, got_cmd in zip(record, got, strict=True):
        for want, have in zip(want_cmd, got_cmd, strict=True):
            if len(want) != len(have):
                return False
            if any(a != b and not b[1] for a, b in zip(want, have, strict=True)):
                return False
    return True


def _table_knows(got: Admitted, spelling: str) -> bool:
    # line 70: a respelt option the table lists for its command is typed by that row, not a leak.
    opt = spelling.split("=", 1)[0]
    for c in got.commands:
        sub = c.subcommand.text if c.subcommand else ""
        names = [f"{c.family} {sub}", c.family, *(w.text for w in c.wrappers)]
        rows = [shell.OPTION_TABLE.get(n) or shell.WRAPPER_OPTS.get(n) for n in names]
        known = {o for r in rows if r for o in r[0] | r[1]}
        if c.family == "git":
            known |= shell.GIT_GLOBAL_FLAGS | shell._GIT_GLOBAL_WITH_ARG
        if opt in known or (opt[:2] != "--" and f"-{opt[1:2]}" in known):
            return True
    return False


def _baseline(world: World, row: Row) -> tuple[bool, Record]:
    if row not in world.baseline:
        cwd, command = _place(world, row, row.command)
        world.baseline[row] = (_seam(row, command, cwd), _record(_admit(row, command, cwd)))
    return world.baseline[row]


def _report(row: Row, mutant: Mutant, text: str, original: str, why: str) -> str:
    return (
        f"{row.source} | {row.agent} | {original!r}\n"
        f"    operator {mutant.operator} at {mutant.target}: {text!r}\n    {why}"
    )


def _mutants(world: World, op: Operator, row: Row) -> Iterator[tuple[Mutant, str]]:
    # line 70: one judgement per distinct mutant text of a row that meets its verdict.
    admitted, _ = _baseline(world, row)
    if admitted != (row.verdict == "admit"):
        return
    seen: set[str] = set()
    for mutant in op.mutate(row.command):
        _, text = _place(world, row, mutant.text)
        if text not in seen:
            seen.add(text)
            yield mutant, text


def _judge_row(world: World, op: Operator, row: Row, tally: dict[str, int]) -> list[str]:
    # line 70: admit refusing a mutant screens it out; test_the_admit_screen_holds checks that.
    _, record = _baseline(world, row)
    cwd, original = _place(world, row, row.command)
    out: list[str] = []
    for mutant, text in _mutants(world, op, row):
        tally["judged"] += 1
        got = _admit(row, text, cwd)
        if got is None or not _seam(row, text, cwd):
            continue
        tally["admitted"] += 1
        if op.name in RESPELL and _table_knows(got, mutant.word):
            continue
        if row.verdict == "refuse":
            out.append(_report(row, mutant, text, original, "admitted mutant of a refused row"))
            continue
        typed = _expected(mutant, _record(got))
        if not _same(record, typed):
            out.append(
                _report(row, mutant, text, original, f"typed record {record} became {typed}")
            )
    return out


ROWS = (*admitted_rows(), *refused_rows())
# line 70: rows whose verdict needs a fixture this module does not build; source: the reason.
ELSEWHERE: dict[str, str] = {
    "FIX1_RG_GLOBS": "refused beside a reply key repo (test_brace_glob)",
    "PREPUSH_RG_REACH": "refused beside a reply key repo (test_path_traversal)",
    "PREPUSH_IGNORE_SEARCHES": "refused beside ignore files over a key (test_hidden_bodies)",
    "TERRAFORM_INIT_FORM": "needs a manifest that turns terraform validate on (test_confine)",
    "A3_ADMITTED": "main judged with an excluded roots config (test_chain_state)",
}


# line 70: (operator, source, row command): the reason; each pair runs alone as a strict xfail.
# 257 closed by unit S4, 258 by the runner option rows: their pairs now run as plain cases.
XFAIL: dict[tuple[str, str, str], str] = {}


def _params() -> list[object]:
    out: list[object] = [pytest.param(op, None, id=op.name) for op in OPERATORS]
    for n, (key, reason) in enumerate(XFAIL.items()):
        mark = pytest.mark.xfail(strict=True, reason=reason)
        out.append(pytest.param(BY_NAME[key[0]], key, marks=mark, id=f"{key[0]}-{n}"))
    return out


def _rows(op: Operator, pair: tuple[str, str, str] | None) -> list[Row]:
    if pair is not None:
        return [r for r in ROWS if (op.name, r.source, r.command) == pair]
    return [r for r in ROWS if (op.name, r.source, r.command) not in XFAIL]


def test_each_xfail_pair_names_one_row() -> None:
    for name, source, command in XFAIL:
        assert name in BY_NAME, name
        assert sum((r.source, r.command) == (source, command) for r in ROWS) == 1, command


@pytest.mark.parametrize(("op", "pair"), _params())
def test_a_mutant_is_refused_or_keeps_the_typed_record(
    world: World,
    monkeypatch: pytest.MonkeyPatch,
    op: Operator,
    pair: tuple[str, str, str] | None,
) -> None:
    # line 70: a red line reads as a corpus row to add: row, operator, mutant, typed difference.
    _setup(monkeypatch, world)
    tally = {"judged": 0, "admitted": 0}
    failures = [line for row in _rows(op, pair) for line in _judge_row(world, op, row, tally)]
    head = f"{op.name} ({op.probes}): {len(failures)} of {tally['judged']} mutants\n"
    assert not failures, head + "\n".join(failures)


def test_every_row_meets_its_verdict_at_its_seam(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    # line 70: a row its seam judges otherwise is mutated by nothing, so its source is named.
    _setup(monkeypatch, world)
    # 228 tail friction fix: the 225 rows' newline was refused only by the deleted text reader.
    friction = set(C.S4_TYPED_PASS_225)
    off = [
        r
        for r in ROWS
        if _baseline(world, r)[0] != (r.verdict == "admit") and r.command not in friction
    ]
    unnamed = [f"{r.source} | {r.agent} | {r.command!r}" for r in off if r.source not in ELSEWHERE]
    assert not unnamed, "\n".join(unnamed)
    assert {r.source for r in off} == set(ELSEWHERE), sorted(ELSEWHERE)


# line 70: every SAMPLE-th row; each mutant admit refuses must be refused by the seam too.
SAMPLE = 50


def test_the_admit_screen_holds(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    _setup(monkeypatch, world)
    leaks: list[str] = []
    for row in ROWS[::SAMPLE]:
        cwd, original = _place(world, row, row.command)
        for op in OPERATORS:
            for mutant, text in _mutants(world, op, row):
                if _admit(row, text, cwd) is None and _seam(row, text, cwd):
                    leaks.append(
                        _report(row, mutant, text, original, "admit refuses, the seam admits")
                    )
    assert not leaks, "\n".join(leaks)

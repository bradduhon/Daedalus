# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 228 S2: every corpus row through admit. A refused row refuses with a span, or admit types the
# operand its later check reads; an admitted row admits, or it is a named table gap.
from __future__ import annotations

from collections.abc import Callable, Iterable

import pytest
from lib import shell, shparse
from lib.admit import Admitted, AdmittedCommand, Refusal, admit

from tests.adversarial import corpus as C
from tests.conftest import WT

REPO = "/work/marked"
OTHER = "/work/other"
MODULE = f"{WT}/infra"
WRAP = f"{shell.CONFINE_PATH} --unit {WT} --"
READERS = ("coder", "auditor", "verifier")
Row = tuple[str, str, str]


def _fill(form: str, **extra: str) -> str:
    fields = {"repo": REPO, "other": OTHER, "wt": WT, "module": MODULE, **extra}
    return form.format(**fields)


def _rows(source: str, agents: Iterable[str], forms: Iterable[str], fill: bool) -> list[Row]:
    return [(source, a, _fill(f) if fill else f) for f in forms for a in agents]


def _cwd(agent: str) -> str:
    return WT if agent in ("coder", "writer") else REPO


def judge(agent: str, command: str) -> Admitted | Refusal:
    return admit(shparse.parse(command), agent, _cwd(agent), text=command)


ISSUE_107 = C.A1_ISSUE_107.replace("<file>", "{repo}/l").replace("<command>", "true")
_RUN = (*C.A2_FIX1_RUN, *C.A2_FIX2_RUN, *C.A2_FIX3_RUN, *C.A2_FIX4_RUN)
_UNMARKED = (*C.A2_FIX1_UNMARKED, *C.A2_FIX3_UNMARKED, *C.A2_FIX4_UNMARKED, *C.A2_FIX5_UNMARKED)
_RUNNER_REFUSED = (
    *C.DEV_SERVERS,
    *C.WATCH_MODES,
    *C.TERRAFORM_MUTATIONS,
    *C.TERRAFORM_OPERATOR_FORMS,
    *C.INTERPRETER_BINS,
    *C.PACKAGE_DOWNLOADS,
    *C.PACKAGE_INSTALL_CMDS,
    *C.INSTALL_GATE_CMDS,
)
READ_ROWS = (
    *C.A1_ISSUE_204,
    *C.A1_READ_P1,
    *C.A1_READ_P2,
    *C.A1_READ_P3,
    *C.A1_READ_P4,
    *C.A1_READ_P9,
)
# 228 S2: (source, agent, command) per refused row, the agents its own tests deny it to.
REFUSED: list[Row] = [
    *_rows("H1_ENV_SPLIT", ("coder", "foreign"), C.H1_ENV_SPLIT, True),
    *_rows("H1_SHELL_BODY", ("coder", "foreign"), C.H1_SHELL_BODY, True),
    *_rows("H1_DEEP_BODY", ("foreign",), C.H1_DEEP_BODY, True),
    *_rows("H1_WRAPPERS", ("coder", "foreign"), C.H1_WRAPPERS, True),
    *_rows("H1_WRAPPERS_OFF_ROW", ("foreign",), C.H1_WRAPPERS_OFF_ROW, True),
    *_rows("H1_SYMLINK", ("foreign",), C.H1_SYMLINK, True),
    *_rows("H1_ICASE", ("coder",), C.H1_ICASE, False),
    *_rows("A1_READ", ("auditor",), READ_ROWS, False),
    *_rows("A1_EXPANSION", ("auditor", "foreign"), C.A1_EXPANSION, False),
    *_rows("A1_WRAPPER_ROWS", ("foreign",), (*C.A1_WRAPPER_ROWS, ISSUE_107), True),
    *_rows("A1_ISSUE_107", ("coder",), ("flock /tmp/l true",), False),
    *_rows("A2_RULE_ROWS", ("foreign",), (r[3] for r in C.A2_RULE_ROWS), True),
    *_rows("A2_ISSUE_116", ("foreign",), (*C.A2_ISSUE_116, *C.A2_ISSUE_81), False),
    *_rows("A2_FIX_RUN", ("foreign",), (r[1] for r in _RUN), True),
    *_rows("A2_FIX_UNMARKED", ("foreign",), _UNMARKED, True),
    *_rows("A2_FIX5_OPAQUE", ("foreign",), C.A2_FIX5_OPAQUE, True),
    *_rows("A3_ISSUE_121_REFUSED", ("coder",), C.A3_ISSUE_121_REFUSED, False),
    *_rows("A3_RULE_ROWS", ("coder",), (r[1] for r in C.A3_RULE_ROWS), False),
    *_rows("A3_APPEND_ENV", ("coder",), C.A3_APPEND_ENV, False),
    *_rows("A3_UNSEEN", ("coder",), C.A3_UNSEEN, False),
    *_rows("FIX1_RG_GLOBS", READERS, C.FIX1_RG_GLOBS, False),
    *_rows("PREPUSH_IGNORE_SEARCHES", READERS, C.PREPUSH_IGNORE_SEARCHES, False),
    *_rows(
        "PREPUSH_IGNORE_WRITES", ("coder",), (f"tee {p}" for p in C.PREPUSH_IGNORE_WRITES), True
    ),
    *_rows("PREPUSH_RG_REACH", READERS, C.PREPUSH_RG_REACH, False),
    *_rows("PREPUSH2_RG_OPAQUE", READERS, C.PREPUSH2_RG_OPAQUE, False),
    *_rows("PREPUSH2_RG_PROGRAM", ("auditor", "verifier"), C.PREPUSH2_RG_PROGRAM, False),
    *_rows("PREPUSH2_ARCHIVE_WRITES", ("coder", "writer"), C.PREPUSH2_ARCHIVE_WRITES, True),
    *_rows("RUNNERS_BARE", ("coder",), (f"cd {WT} && {c}" for c in _RUNNER_REFUSED), False),
    *_rows(
        "RUNNERS_WRAPPED", ("coder",), (f"cd {WT} && {WRAP} {c}" for c in _RUNNER_REFUSED), False
    ),
    *_rows(
        "TERRAFORM_AUDITOR",
        ("auditor",),
        (*C.TERRAFORM_MUTATIONS, *C.TERRAFORM_OPERATOR_FORMS),
        False,
    ),
    *_rows(
        "TERRAFORM_INIT_MISSES", ("coder",), (f"{WRAP} {c}" for c in C.TERRAFORM_INIT_MISSES), True
    ),
]


def _last(done: Admitted) -> AdmittedCommand:
    return done.commands[-1]


def _texts(cmd: AdmittedCommand, kind: str) -> set[str]:
    return {t.text for t in getattr(cmd, kind)}


def _rg_globs(command: str, done: Admitted) -> bool:
    return {"-g", "--glob", "--iglob"} & _texts(_last(done), "options") != set()


def _rg_reach(command: str, done: Admitted) -> bool:
    return {"-L", "--follow", "--ignore-file"} & _texts(_last(done), "options") != set()


def _rg_root(command: str, done: Admitted) -> bool:
    return _last(done).family == "rg"


def _tee_path(command: str, done: Admitted) -> bool:
    return command.split()[-1] in _texts(_last(done), "writes")


def _tf_folder(command: str, done: Admitted) -> bool:
    cmd = _last(done)
    return cmd.family == "terraform" and bool(cmd.reads or cmd.cd_target)


# 228 S2: refused rows admit admits by shape; the later check named reads the typed operand.
LATER: dict[str, tuple[str, Callable[[str, Admitted], bool]]] = {
    "FIX1_RG_GLOBS": ("the credential check reads the rg glob values", _rg_globs),
    "PREPUSH_IGNORE_SEARCHES": ("the credential check reads ignore files under the root", _rg_root),
    "PREPUSH_IGNORE_WRITES": ("the protected-path check reads the write path", _tee_path),
    "PREPUSH_RG_REACH": ("the credential check reads the rg reach options", _rg_reach),
    "TERRAFORM_AUDITOR": ("the terraform class bounds the fmt folder", _tf_folder),
    "TERRAFORM_INIT_MISSES": ("the terraform class reads the init form", _tf_folder),
    "RUNNERS_BARE": ("the terraform class bounds the fmt folder", _tf_folder),
    "RUNNERS_WRAPPED": ("the terraform class bounds the fmt folder", _tf_folder),
}


def test_every_refused_row_is_refused_with_a_span() -> None:
    # 228 S2 accept: a refused row refuses with its span, or a later check reads its operands.
    leaks: list[str] = []
    for source, agent, command in REFUSED:
        got = judge(agent, command)
        if isinstance(got, Refusal):
            assert got.span[1] > got.span[0] and got.text, (agent, command, got)
            assert got.text == command[got.span[0] : got.span[1]], (agent, command, got)
            assert len(got.sha256) == 64, got
        elif source not in LATER or not LATER[source][1](command, got):
            leaks.append(f"{source} | {agent} | {command!r}")
    assert not leaks, "admitted refused rows:\n" + "\n".join(leaks)


ADMITTED: list[Row] = [
    *_rows("A1_READ_ADMITTED", ("auditor",), C.A1_READ_ADMITTED, False),
    *_rows("A1_EXPANSION_ADMITTED", ("foreign",), C.A1_EXPANSION_ADMITTED, False),
    *_rows(
        "A1_EXPANSION_ADMITTED",
        ("auditor",),
        (
            c
            for c in C.A1_EXPANSION_ADMITTED
            if '"' not in c and c.split()[0] in shell.READ_ONLY_WRITE_OPTS
        ),
        False,
    ),
    *_rows("FIX1_RG_GLOBS_ALLOWED", ("auditor",), C.FIX1_RG_GLOBS_ALLOWED, False),
    *_rows("PREPUSH_IGNORE_SEARCHES", ("auditor",), C.PREPUSH_IGNORE_SEARCHES[:2], False),
    *_rows("GAME_RUNNERS", ("coder",), (f"cd {WT} && {WRAP} {c}" for c in C.GAME_RUNNERS), False),
    *_rows(
        "TERRAFORM_INIT_FORM", ("coder",), (f"cd {WT} && {WRAP} {C.TERRAFORM_INIT_FORM}",), True
    ),
    *_rows("A3_ISSUE_121_ADMITTED", ("main",), C.A3_ISSUE_121_ADMITTED, False),
    *_rows("A3_ADMITTED", ("main",), C.A3_ADMITTED, False),
]
# 228 S2 ruling (main session reads and builtins): the rows admit still refuses.
# [[ is Opaque in the parser; 228 S3 closed the git log --grep <value> row.
TABLE_GAPS: frozenset[tuple[str, str]] = frozenset(
    {("main", "[[ -n x ]] && git commit -m ':i: fix' -- src/a.md")}
)


def friction() -> list[str]:
    out: list[str] = []
    for _, agent, command in ADMITTED:
        got = judge(agent, command)
        if isinstance(got, Refusal) and (agent, command) not in TABLE_GAPS:
            out.append(f"{agent} | {command!r} | {got.reason}")
        elif isinstance(got, Admitted):
            assert got.writes == (), (agent, command, got.writes)
    return out


def test_every_admitted_row_is_admitted_or_a_named_table_gap() -> None:
    # 228 S2 accept: the friction list; each line is agent | command | refusal reason.
    lines = friction()
    assert not lines, f"{len(lines)} friction rows:\n" + "\n".join(lines)


@pytest.mark.parametrize(("agent", "command"), sorted(TABLE_GAPS))
def test_a_table_gap_is_still_refused(agent: str, command: str) -> None:
    # 228 S2: a gap the main session rules on stays listed only while admit refuses it.
    assert isinstance(judge(agent, command), Refusal), (agent, command)

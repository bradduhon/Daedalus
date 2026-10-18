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
    | {"_SHELL_LONG_FLAGS", "_TRUSTED_BIN", "_WRAPPER_OPTS", "_ASSIGN", "_SAFE_ENV"}
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
# 0044: tests/test_jail.py imports split_pipeline from lib.jail and stays unchanged in 1.2.
JAIL_PASSTHROUGH = frozenset({"split_pipeline"})


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
    assert imported <= MOVED
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
        ("ls > f", None),
        ("echo $(id)", None),
    ],
)
def test_worker_segments_drops_only_the_safe_env_prefix(
    command: str, want: list[list[str]] | None
) -> None:
    assert shell.worker_segments(command) == want


def test_git_sets_name_the_moved_lists() -> None:
    assert shell.GIT_SETS == {
        "coder": shell.CODER_GIT,
        "docs": shell.CHARTER_DOCS_GIT,
        "conductor": shell.CONDUCTOR_GIT,
        "specialist": shell.SPECIALIST_GIT,
        "read-only": shell.READ_ONLY_GIT,
    }

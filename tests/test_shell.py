# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, 0043: lib.shell holds the shell model; lib.jail imports it and defines none of it.
from __future__ import annotations

import ast
import os
import re
import shlex
from collections.abc import Iterator
from pathlib import Path

import pytest
from lib import jail, shell

from tests.conftest import SCRIPTS_DIR

# 0044: every name unit 1.2 moved out of lib/jail.py into lib/shell.py (packet section 11).
MOVED = frozenset(
    {"READ_ONLY_CMDS", "READ_ONLY_GIT", "SPECIALIST_GIT", "CHARTER_DOCS_GIT", "CONDUCTOR_GIT"}
    | {"CODER_GIT", "GIT_PLUMBING_REMOTE", "SHELL_VAR_CMDS", "SHELL_STATE_CMDS"}
    | {"WORKER_WRAPPERS", "_VALUE_LONG_NEXT", "_SHELLS", "_SHELL_ARG_OPTS"}
    | {"_SHELL_LONG_FLAGS", "_TRUSTED_BIN", "_ASSIGN", "_SAFE_ENV"}
    | {"_GIT_CONFIG_DENY", "_GIT_GLOBAL_WITH_ARG", "_PUSH_FORBIDDEN", "_PUSH_ALL"}
    | {"_PUSH_ARG_OPTS", "_SIGNABLE_GIT", "_FIND_DENY", "_FALSE"}
    | {"_DEFAULT_BRANCHES", "_REPO_SCRIPTS", "_PROJECT_DATA", "_GLOB_CHARS"}
    | {"_STASH_WITH_ARG", "_HOME", "_PUSH_MIN"}
    | {"_COMMIT_WITH_ARG", "R_LEDGER_LITERAL", "R_UNSUPPORTED", "R_INLINE", "R_GIT_CONFIG"}
    | {"R_ENV", "R_SHELL_VARS", "R_SHELL_STATE", "R_RSYNC_REMOTE", "R_FIND_WRITE"}
    | {"R_HYGIENE", "R_VARIABLE", "R_FORCE_PUSH", "R_CLEAN", "R_STASH_UNTRACKED"}
    | {"R_DESTRUCTIVE", "R_SIGN", "R_DEFAULT_BRANCH", "R_GIT_CONFIG_KEY"}
    | {"R_GIT_PLUMBING", "R_DATA_DIR_GIT", "_under", "_abs"}
    | {"_base", "_cmd_name", "_short_flags"}
    | {"_long_matches", "_git_split", "_git_subcommand", "_git_config_override"}
    | {"_config_settings", "_gpgsign_override", "_config_key_denied", "_push_parts"}
    | {"_push_destination", "_push_to_default", "_rm_target_dangerous", "_rm_reason"}
    | {"_quote_spans", "_strip_wrappers", "_git_reason"}
    | {"_names_project_data", "_force_add", "_pathspecs", "_git_data_dir_reason"}
    | {"_stash_untracked", "_tester_runner_ok", "_exempt_indices", "_rsync_remote"}
    | {"_is_append_ledger"}
)
# 0044: lib.jail imports from lib.shell only the names it uses.
JAIL_PASSTHROUGH: frozenset[str] = frozenset()
# issue 55, issue 76: helpers born in lib.shell that lib.jail shares rather than copies.
SHARED = frozenset(
    {"runs_claude", "WRAPPER_OPTS", "DURATION", "strip_wrappers", "quote_walk", "unwrap"}
    | {"WrapperOption", "WRAPPER_CHDIR", "WRAPPER_WRITES", "FLOCK_BODY"}
    | {"READ_ONLY_WRITE_OPTS", "scan_options", "split_options"}
    | {"command_family", "INTERPRETERS", "CHAR", "CLOSE", "_TRUSTED_BIN"}
)
# 228 S3: the readers the one parse replaced; no file under scripts/ may name one again.
RETIRED = (
    "_bash_write_dirs _write_walk _segment_targets _inner_env _heredoc_walk _chain_folders "
    "_hidden_bodies _segment_bodies _hidden_reason _body_past_cap _policy_segments _rebinds "
    "_set_operands _drop_positionals _heredoc_text _raw_expands _expanding_lead _lead_word "
    "_moved_segment _UNRESOLVED _PIECE_CUT _PARAM_NAME _TOKEN_EXPANSION _read_only_segment "
    "read_segment_ok relative_write _foreign_read_ok _shell_body _BODY_DEPTH _built_value "
    "fed_tokens expansion_opaque shell_params flag_span "
    "_fragments _word_pieces _split_values _SCOPE_DEPTH _CUT_MARK _BODY_CHARS _past_cap "
    "_TARGET_CAP _body_constant _command_body _runs_body _option_body _stdin_operand "
    "_runner_family _STDIN_OPS _NO_BODY _STDIN_FILES _BODY_RUNNERS _piped "
    "R_SHELL_BODY R_INLINE_BODY "
    # 228 S3b: the coder checks' readers the parse then admit_role replaced.
    "_coder_bash_reason coder_installs declared_segments exit_echo_ok _declared_tools "
    "_followed_bases _docs_segment_reason _script_unit _path_trusted "
    # 228 S4: the excluded roots and gh text readers the Admitted record replaced. A name another
    # module defines for its own use (_merge, _spec, _sources, _HEREDOC...) is not listed.
    "_icase_scan _simple_code _plainly_simple _base_scan _foreign_git _expansion_unseen "
    "_heredocs _substitutions _closing _ICASE_TEXT _excluded_text _TextScan _segment_units "
    "_NOT_SIMPLE_RAW _NOT_SIMPLE_WORD _FOREIGN_GIT _SYNTH _JUDGED_WORD R_EXCLUDED_TEXT "
    "_BRACE_LIST _Body _EXCLUDED_GIT _EXCLUDED_WORDS _EXCLUDED_WRITES _GIT_PATH _GIT_WORD "
    "_JUDGED_GIT_WORD _LEADERS _Part _RUNS_GIT_WORD _SETTERS _SHELL_WORD _SIMPLE_HEREDOC "
    "_STASH_READS _TEXT_DEPTH _XARGS _allexport _built_head _excluded_names _excluded_reason "
    "_expanding _foreign_icase _git_parts _heads _heredoc_end _icase_exports _icase_git "
    "_icase_mentions _icase_on _icase_spec _judged_git _judged_heads _masked _names_path "
    "_normalised _opaque_setter _path_unsafe _stdin_message _text_segment "
    "_text_spec _unseen_git _unseen_paths _unset_only _xargs_runs _excluded_named "
    "git_globals_known _GH_WORD _GIT_PUSH _fallback_reason _gh_reason "
    # 228 tail: the chain parser, the regex fallback, the text walkers and their callers' readers.
    "worker_parse worker_segments WorkerChain chain_bases _raw_segments segment_spans "
    "_regex_tripwire _FALLBACK split_pipeline _fd_word _unclosed _REDIRECT_END _REDIRECT_DENY "
    "REDIRECT_SEP _REGEX_TRIPWIRES _HOME_UP _HOME_PARENTS _PUSH_FORCE_ALT _PUSH_ALL_ALT "
    "_prefix_re _RM_RECURSIVE _raw_segment_reason _segment_views _word_parts _command_reason "
    "_segment_reason _shell_code interpreter_code shell_tokens _inline_code _body_scan "
    "_stdin_body _flag_value _option_end _off_end BodyScan stdin_script _STDIN_TAIL "
    "SCRIPT_FLAGS R_ENV_SPLIT R_XARGS R_BRACE_PUSH search_opaque "
    "opaque_word _raw_words _hygiene_bad _worker_hygiene _RESERVED _HYGIENE_CHARS "
    "_plain_segments _admitted_segments _BODY_HEADS _CLAUDE_WORD _nested_claude _bash_env "
    "_loop_union _opaque_values _opaque_targets _moved_base _tree_reader _gh_words "
    "_CREDENTIAL_PART _BINDERS _coder_write_targets "
    # 228 tail: the credential module's command-text readers no caller reached.
    "dotglob_on expand_word _DOTS_QUALIFIER _DOTGLOB_WORDS"
).split()
# 228 tail: names another module defines for its own use, so the grep above cannot list them;
# the import test below proves no module reaches the retired lib.shell ones.
RETIRED_SHELL_IMPORTS = frozenset({"tokenize", "_scan", "_tokens", "_flush", "_redirect"})
RETIRED_SHELL_IMPORTS |= {"_normalize", "_unquoted", "_awaits"}
# 228 tail, SA-4: every re use left in the jail's modules, by top-level name, with the one
# subject it reads; a command-text subject is a named gap outside this unit's files.
RE_SUBJECTS: dict[str, dict[str, str]] = {
    "lib/jail.py": {
        "_BRANCH_NAME": "the branch operand of an admitted conductor push",
        "_INTERPRETER": "a parsed command word, moved_relative (issue 188)",
        "_MODE": "a chmod mode operand of an admitted write",
        "_PATH_OPTION": "an option word of a packs.py verify, _path_positions (gap: packs.py)",
        "_PIP": "an installer word of an admitted command",
        "_REMOTE_URL": "the output of git remote get-url",
        "_flags_ok": "an admitted git option against its grammar row pattern",
        "_gitleaks_ok": "an admitted gitleaks option",
    },
    "lib/shell.py": {
        "DURATION": "a timeout duration word",
        "WRAPPER_OPERAND": "a wrapper's operand word",
        "_ASSIGN": "one parsed word, an assignment shape",
        "_CLAIMS_BRANCH": "the --branch value of the claims call",
        "_GIT_CONFIG_DENY": "a git -c key of an admitted read",
        "_SAFE_ENV": "an assignment prefix name",
        "_SED_PRINT": "a sed script operand",
        "_VERSION_TAIL": "a command word's version suffix",
        "_rsync_remote": "an rsync operand",
        "_strip_wrappers": "a nice priority word",
    },
    "lib/admit.py": {},
    "checks/read_only_bash.py": {"_GREP_PERL": "a grep option word"},
}


def test_no_retired_reader_is_named_under_scripts() -> None:
    hits = [
        f"{path.relative_to(SCRIPTS_DIR)}:{name}"
        for path in sorted(SCRIPTS_DIR.rglob("*.py"))
        for name in RETIRED
        if re.search(rf"(?<!\w){re.escape(name)}(?!\w)", path.read_text(encoding="utf-8"))
    ]
    assert hits == [], hits


def test_no_module_imports_a_retired_shell_reader() -> None:
    # 228 tail: no module under scripts/ reaches worker_parse, tokenize or a retired lib.shell
    # reader, by import or as an attribute of the shell module.
    retired = RETIRED_SHELL_IMPORTS | {"worker_parse", "worker_segments", "split_pipeline"}
    hits: list[str] = []
    for path in sorted(SCRIPTS_DIR.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module in {"lib.shell", "shell"}:
                hits += [f"{path.name}:{a.name}" for a in node.names if a.name in retired]
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id == "shell" and node.attr in retired:
                    hits.append(f"{path.name}:shell.{node.attr}")
    assert hits == [], hits


def _re_users(module: ast.Module) -> set[str]:
    found: set[str] = set()
    for top in module.body:
        names: list[str] = []
        if isinstance(top, ast.FunctionDef | ast.ClassDef):
            names = [top.name]
        elif isinstance(top, ast.Assign):
            names = [t.id for t in top.targets if isinstance(t, ast.Name)]
        elif isinstance(top, ast.AnnAssign) and isinstance(top.target, ast.Name):
            names = [top.target.id]
        for node in ast.walk(top):
            func = node.func if isinstance(node, ast.Call) else None
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id == "re":
                    found |= set(names or ["<module>"])
    return found


@pytest.mark.parametrize("module", sorted(RE_SUBJECTS))
def test_every_re_use_in_a_jail_module_names_a_non_command_subject(module: str) -> None:
    # 228 tail, R5: each re call's top-level home is listed with its subject; a new one fails.
    tree = ast.parse((SCRIPTS_DIR / module).read_text(encoding="utf-8"))
    assert _re_users(tree) == set(RE_SUBJECTS[module]), module


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
    # issue 76, 121, 228 tail: the loops that remain read quote_walk.
    tree = _tree("shell.py")
    users = {"_quote_spans", "_unquoted_expansion", "_unsingled"}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in users:
            source = ast.unparse(node)
            assert "quote_walk(" in source, node.name
            assert "quote = " not in source, node.name


@pytest.mark.parametrize(
    ("text", "spans", "expands"),
    [
        ("a 'b c' d", "a Q d", False),
        ('x "a\\"b" *', "x Q *", True),
        ('"\\"" *', "Q *", True),
        ("a;b|'c;d'", "a;b|Q", False),
        ("e\\ f '$x'", "e\\ f Q", False),
        ("'unclosed", "Q", False),
    ],
)
def test_walker_consumers_share_one_quote_model(text: str, spans: str, expands: bool) -> None:
    assert shell._quote_spans(text) == spans
    assert shell._unquoted_expansion(text) is expands


def test_git_sets_name_the_moved_lists() -> None:
    assert shell.GIT_SETS == {
        "coder": shell.CODER_GIT,
        "docs": shell.CHARTER_DOCS_GIT,
        "conductor": shell.CONDUCTOR_GIT,
        "specialist": shell.SPECIALIST_GIT,
        "read-only": shell.READ_ONLY_GIT,
    }


@pytest.mark.parametrize(
    ("word", "want"),
    [
        ("/usr/bin/bash", "bash"),
        ("./bash", "bash"),
        ("python3.12", "python"),
        ("python3", "python"),
        ("perl5.36.0", "perl"),
        ("node18", "node"),
        ("sha256sum", "sha256sum"),
        ("7z", "7z"),
    ],
)
def test_command_family_strips_the_path_and_folds_the_version(word: str, want: str) -> None:
    # pin A2 -> A3, P5: a path or versioned name reads as its family.
    assert shell.command_family(word) == want


def test_every_host_shell_entry_is_a_listed_shell_or_a_named_non_shell() -> None:
    # P6, fix round 1: the list is static; a new /etc/shells entry fails here, never widens.
    path = Path("/etc/shells")
    if not path.is_file():
        pytest.skip("no /etc/shells on this host")
    lines = (line.strip() for line in path.read_text(encoding="utf-8").splitlines())
    names = {shell.command_family(line) for line in lines if line.startswith("/")}
    assert names <= shell._SHELLS | shell.NOT_SHELLS, names - shell._SHELLS - shell.NOT_SHELLS
    assert not shell._SHELLS & shell.NOT_SHELLS
    assert {"rbash", "mksh", "ash", "ksh93"} <= shell._SHELLS <= shell.WORKER_WRAPPERS


@pytest.mark.parametrize(
    ("name", "command", "operands", "off"),
    [
        ("uniq", "-f 1 in", ["in"], False),
        ("uniq", "-f1 in", ["in"], False),
        ("uniq", "-cf1 in", ["in"], False),
        ("uniq", "-cf 1 in", ["in"], False),
        ("uniq", "--skip-fields=1 in", ["in"], False),
        ("uniq", "--skip-fields 1 in", ["in"], False),
        ("uniq", "--skip-f 1 in", ["in"], False),
        ("uniq", "--skip 1 in", ["1", "in"], True),
        ("uniq", "-Q in", ["in"], True),
        ("uniq", "- out", ["-", "out"], False),
        ("uniq", "-- -c out", ["-c", "out"], False),
        ("uniq", "in out -c", ["in", "out"], False),
        ("uniq", "in -f 1 out", ["in", "out"], False),
        ("sort", "-uo out in", ["in"], False),
        ("find", ". -name x -fprint out", ["."], False),
        # pin A1 -> A3: one row each for the shell variable builtins and git commit.
        ("export", "-n X=1", ["X=1"], False),
        ("declare", "-rx Y=2", ["Y=2"], False),
        ("typeset", "-p", [], False),
        ("git commit", "-am msg -- a.py", ["a.py"], False),
        ("git commit", "--message=m -F f -t t b.py", ["b.py"], False),
    ],
)
def test_split_options_strips_each_valued_option_form(
    name: str, command: str, operands: list[str], off: bool
) -> None:
    # P2 to P4: separate, attached, clustered, =, long separate and prefix; - and -- are operands.
    assert shell.split_options(name, shlex.split(command)) == (operands, off)


@pytest.mark.parametrize(
    ("name", "command", "options"),
    [
        ("sort", "-uo out in", ["-u", "-o"]),
        ("sort", "in --out=f", ["--output"]),
        ("file", "-bC x", ["-b", "-C"]),
        ("find", ". -fprintfout %p", ["-fprintf"]),
        ("find", ". -name -fprint", ["-name"]),
    ],
)
def test_scan_options_names_each_option_met(name: str, command: str, options: list[str]) -> None:
    assert shell.scan_options(name, shlex.split(command)).options == options


def test_each_read_verb_has_an_option_row() -> None:
    # issue 204: the read verbs' write options sit on their own rows.
    assert shell.READ_ONLY_CMDS <= shell.OPTION_TABLE.keys()
    for name, writes in shell.READ_ONLY_WRITE_OPTS.items():
        assert writes <= shell.OPTION_TABLE[name][0] | shell.OPTION_TABLE[name][1], name


RUNNERS = ("setsid", "chroot", "ionice", "taskset", "flock", "unshare", "chrt", "nsenter")


def test_each_runner_wrapper_has_a_row_and_is_a_worker_wrapper() -> None:
    # issue 82: a row per runner wrapper; the runner list H2 widens stays a separate table.
    assert set(RUNNERS) <= shell.WRAPPER_OPTS.keys() <= shell.WORKER_WRAPPERS
    assert set(shell.WRAPPER_OPERAND) == {"timeout", "taskset", "chrt", "flock", "chroot"}
    assert shell.WRAPPER_OPERAND["timeout"] is shell.DURATION
    moves = {"unshare": {"-R", "--root", "-w", "--wd"}}
    moves["nsenter"] = {"-r", "--root", "-w", "--wd", "-W", "--wdns"}
    for name, kept_off in moves.items():
        no_arg, with_arg = shell.WRAPPER_OPTS[name]
        assert not kept_off & (no_arg | with_arg), name


@pytest.mark.parametrize(
    ("command", "want"),
    [
        ("setsid -f -w touch x", ["touch", "x"]),
        ("setsid --fork touch x", ["touch", "x"]),
        ("ionice -c 3 -n 7 -t touch x", ["touch", "x"]),
        ("ionice -c3 touch x", ["touch", "x"]),
        ("ionice --class=idle touch x", ["touch", "x"]),
        ("taskset 0x3 touch x", ["touch", "x"]),
        ("taskset -c 0-2,5 touch x", ["touch", "x"]),
        ("taskset -p 1234", []),
        ("flock /tmp/l touch x", ["touch", "x"]),
        ("flock -x -w 5 /tmp/l touch x", ["touch", "x"]),
        ("flock --timeout=5 -- /tmp/l touch x", ["touch", "x"]),
        ("flock 9", []),
        ("unshare -f -m touch x", ["touch", "x"]),
        ("unshare --mount-proc=/proc -S 0 touch x", ["touch", "x"]),
        ("chrt -o 0 touch x", ["touch", "x"]),
        ("chrt --rr -T 5 10 touch x", ["touch", "x"]),
        ("nsenter -t 1 -m -u touch x", ["touch", "x"]),
        ("nsenter --target=1 --mount=/proc/1/ns/mnt touch x", ["touch", "x"]),
        ("setsid ionice -c 3 nice touch x", ["touch", "x"]),
    ],
)
def test_runner_rows_reach_the_wrapped_command(command: str, want: list[str]) -> None:
    assert shell.strip_wrappers(shlex.split(command)) == want


@pytest.mark.parametrize(
    "command",
    [
        "setsid --frobnicate touch x",
        "chroot / touch x",
        "chroot --userspec=u:g /new touch x",
        "chroot",
        "ionice -Z touch x",
        "taskset touch x",
        "taskset -Z 1 touch x",
        "flock -c 'touch x'",
        "flock /tmp/l -c 'touch x'",
        "flock /tmp/l --command='touch x'",
        "flock",
        "unshare -R / touch x",
        "unshare --root=/ touch x",
        "unshare -w /tmp touch x",
        "unshare --wd /tmp touch x",
        "chrt --other touch x",
        "chrt -Z 5 touch x",
        "nsenter -r touch x",
        "nsenter --root=/ touch x",
        "nsenter -w touch x",
        "nsenter --wd=/tmp touch x",
        "nsenter -W /tmp touch x",
    ],
)
def test_runner_options_off_their_row_fail_closed(command: str) -> None:
    # issue 82: an option, operand or body the rows cannot read leaves the command unknown.
    assert shell.strip_wrappers(shlex.split(command)) is None


@pytest.mark.parametrize(
    ("name", "form"), [(name, form) for name, forms in shell.TEST_RUNNERS.items() for form in forms]
)
def test_each_test_runner_form_is_a_runner_row_and_never_refused(
    name: str, form: tuple[str, ...]
) -> None:
    # 0164: every form the table admits is a test command, and no form is a server or watch.
    tokens = [name, *form]
    assert shell._tester_runner_ok(name, tokens) and shell.runner_row(tokens)
    assert shell.runner_refusal(tokens) is None, tokens


def test_node_is_the_one_runner_that_is_a_worker_wrapper() -> None:
    # 0164: a WORKER_WRAPPERS name in the table is admitted only by its exact form.
    assert set(shell.TEST_RUNNERS) & shell.WORKER_WRAPPERS == {"node"}
    assert shell.TEST_RUNNERS["node"] == (("--test",),)
    for command in ("node t.js", "node -e 1", "node --inspect --test", "node"):
        assert not shell._tester_runner_ok("node", shlex.split(command)), command


@pytest.mark.parametrize(
    ("command", "want"),
    [
        ("vite", shell.R_DEV_SERVER),
        ("vite preview --port 1", shell.R_DEV_SERVER),
        ("./node_modules/.bin/vite serve", shell.R_DEV_SERVER),
        ("pnpm --filter web dev", shell.R_DEV_SERVER),
        ("npx -y vite", shell.R_DEV_SERVER),
        ("pnpm exec vitest", shell.R_VITEST_WATCH),
        ("vitest bench", shell.R_VITEST_WATCH),
        ("tsc -b", shell.R_TSC),
        ("pnpm exec tsc --noEmit -w", shell.R_TSC),
        ("terraform -chdir=/x apply", shell.R_TERRAFORM_MUTATE),
        ("terraform state list", shell.R_TERRAFORM_MUTATE),
        ("node --test --watch", shell.R_WATCH),
        ("node --test --watch-path=.", shell.R_WATCH),
        ("vitest run --watch=true", shell.R_VITEST_WATCH),
        ("tsc --noEmit -watch", shell.R_TSC),
        ("tsc --noEmit --Watch", shell.R_TSC),
        ("tsc --noEmit false", shell.R_TSC),
        ("pnpm test --watch", shell.R_WATCH),
        ("pnpm test -- --watch", shell.R_WATCH),
        ("npm test -- --watch", shell.R_WATCH),
        ("pnpm run -- dev", shell.R_DEV_SERVER),
        ("pnpm -- dev", shell.R_DEV_SERVER),
        ("npm run -- dev", shell.R_DEV_SERVER),
        ("terraform plan", shell.R_TERRAFORM_OPERATOR),
        ("terraform fmt -check=false", shell.R_TERRAFORM_OPERATOR),
        ("terraform untaint a.b", shell.R_TERRAFORM_MUTATE),
        ("vite build", None),
        ("vitest run -t name", None),
        ("tsc -NoEmit", None),
        ("pnpm -w test", None),
        ("terraform -chdir=/x fmt -recursive -check", None),
        ("npm test", None),
    ],
)
def test_runner_refusal_names_the_server_watch_or_state_change(
    command: str, want: str | None
) -> None:
    assert shell.runner_refusal(shlex.split(command)) == want


@pytest.mark.parametrize(
    ("command", "want"),
    [
        ("pnpm exec node -e 1", ["node", "-e", "1"]),
        ("pnpm exec -- node t.js", ["node", "t.js"]),
        ("npx node t.js", ["node", "t.js"]),
        ("pnpm node t.js", ["node", "t.js"]),
        ("pnpm exec pnpm exec bash -c ls", ["bash", "-c", "ls"]),
        ("npm test", None),
        ("pnpm", None),
    ],
)
def test_js_inner_finds_the_bin_a_package_manager_runs(
    command: str, want: list[str] | None
) -> None:
    assert shell.js_inner(shlex.split(command)) == want


def test_under_holds_every_path_under_the_filesystem_root() -> None:
    # 0164: "/" plus os.sep once matched nothing, so "/" slipped past every overlap guard.
    assert shell._under("/srv/x/.ssh", "/") and shell._under("/", "/")
    assert shell._under("/a/b", "/a/") and not shell._under("/ab", "/a")


@pytest.fixture
def which_calls(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[list[str | None]]:
    # suite-cleanup: records the PATH of each shutil.which call; folders a and b hold probe-cmd.
    shell._path_lookup.cache_clear()
    calls: list[str | None] = []
    real_which = shell.shutil.which

    def counted(word: str, mode: int = os.F_OK | os.X_OK, path: str | None = None) -> str | None:
        calls.append(path)
        return real_which(word, mode, path)

    monkeypatch.setattr(shell.shutil, "which", counted)
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "probe-cmd").write_text("#!/bin/sh\n", encoding="utf-8")
        (tmp_path / name / "probe-cmd").chmod(0o755)
    yield calls
    shell._path_lookup.cache_clear()


def test_command_path_looks_a_word_up_once_per_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, which_calls: list[str | None]
) -> None:
    # suite-cleanup: two calls under one PATH reach shutil.which once.
    monkeypatch.setenv("PATH", str(tmp_path / "a"))
    for _ in range(2):
        assert shell.command_path("probe-cmd", "/") == str(tmp_path / "a" / "probe-cmd")
    assert which_calls == [str(tmp_path / "a")]


def test_command_path_looks_again_when_path_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, which_calls: list[str | None]
) -> None:
    # suite-cleanup: PATH is read into the key, so a second PATH value misses the cache.
    for name in ("a", "b"):
        monkeypatch.setenv("PATH", str(tmp_path / name))
        assert shell.command_path("probe-cmd", "/") == str(tmp_path / name / "probe-cmd")
    assert which_calls == [str(tmp_path / "a"), str(tmp_path / "b")]

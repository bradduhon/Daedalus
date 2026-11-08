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
    | {"env_split_values", "R_ENV_SPLIT", "FLOCK_BODY"}
    | {"READ_ONLY_WRITE_OPTS", "scan_options", "split_options"}
    | {"command_family", "interpreter_code", "shell_tokens", "stdin_script", "INTERPRETERS"}
    | {"_expands"}
    | {"CHAR", "CLOSE", "_flag_value", "_raw_words", "_unquoted", "segment_spans"}
    | {"git_globals_known", "_TRUSTED_BIN"}
    | {"INLINE_FLAGS", "_STDIN_TAIL"}
)
# 228 S3: the readers the one parse replaced; no file under scripts/ may name one again.
RETIRED = (
    "_bash_write_dirs _write_walk _segment_targets _inner_env _heredoc_walk _chain_folders "
    "_hidden_bodies _segment_bodies _hidden_reason _body_past_cap _policy_segments _rebinds "
    "_set_operands _drop_positionals _heredoc_text _raw_expands _expanding_lead _lead_word "
    "_moved_segment _UNRESOLVED _PIECE_CUT _PARAM_NAME _TOKEN_EXPANSION _read_only_segment "
    "read_segment_ok relative_write _foreign_read_ok _shell_body _BODY_DEPTH _built_value "
    "fed_tokens expansion_opaque shell_params flag_span"
).split()


def test_no_retired_reader_is_named_under_scripts() -> None:
    hits = [
        f"{path.relative_to(SCRIPTS_DIR)}:{name}"
        for path in sorted(SCRIPTS_DIR.rglob("*.py"))
        for name in RETIRED
        if re.search(rf"(?<!\w){re.escape(name)}(?!\w)", path.read_text(encoding="utf-8"))
    ]
    assert hits == [], hits


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
    # issue 76, 121: the six old loops read quote_walk (segment_spans now holds _raw_segments').
    tree = _tree("shell.py")
    users = {"_scan", "_quote_spans", "segment_spans", "_unquoted_expansion", "_raw_words"}
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


@pytest.mark.parametrize(
    ("command", "want"),
    [
        ("env -S 'touch /x'", ["touch /x"]),
        ("env -S'touch /x'", ["touch /x"]),
        ("env --split-string='touch /x'", ["touch /x"]),
        ("env --split-string 'touch /x'", ["touch /x"]),
        ("env --s='a b'", ["a b"]),
        ("env -iS 'a b'", ["a b"]),
        ("env -i0vS 'a b'", ["a b"]),
        ("env -u HOME -S 'a b'", ["a b"]),
        ("env --unset HOME --split-string 'a b'", ["a b"]),
        ("env -C /tmp -S 'a b'", ["a b"]),
        ("env --frobnicate -S 'a b'", ["a b"]),
        ("env -S", [""]),
        ("nice env -i env -S 'a b'", ["a b"]),
        ("env -uS rm x", []),
        ("env -CS rm x", []),
        ("env FOO=1 -S x", ["x"]),
        ("env -a x -S 'touch y'", ["touch y"]),
        ("env --argv0 x -u A B=1 --split-string=y", ["y"]),
        ("env -ax -iS y", ["y"]),
        ("env {-S,x}", [""]),
        ("env -- -S x", []),
        ("env - -S x", []),
        ("env -i rm x", []),
        ("git commit -m 'env -S x'", []),
    ],
)
def test_env_split_values_reads_getopt_forms(command: str, want: list[str]) -> None:
    # issue 80, 116 (P8): -S in a cluster or long prefix is found; a value or plain word is not.
    assert shell.env_split_values(shlex.split(command)) == want


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
    ("command", "want"),
    [
        ("env -S 'touch /x'", shell.R_ENV_SPLIT),
        ("env -S 'git push --force'", shell.R_FORCE_PUSH),
        ("nice env --split-string='rm -rf /'", shell.R_DESTRUCTIVE),
    ],
)
def test_env_split_is_a_worker_finding(command: str, want: str) -> None:
    # issue 80: workers meet env -S by name; main stays exempt from construct limits.
    assert shell._segment_reason(shlex.split(command), 0, main=False) == want
    assert shell._segment_reason(shlex.split("env -S 'touch /x'"), 0, main=True) == shell._FALLBACK
    assert "Next: write the command without env -S" in shell.R_ENV_SPLIT


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

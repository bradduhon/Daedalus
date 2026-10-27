# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# issue 76: the merged wrapper table and gh parser cover every row of the tables they replaced.
from __future__ import annotations

import ast
import shlex

import pytest
from lib import gh_policy, jail, shell

from tests.conftest import SCRIPTS_DIR

# issue 76: lib/jail.py's wrapper tables at a83accf, copied verbatim.
OLD_JAIL_RUN_WRAPPERS = frozenset(
    {"sudo", "env", "nice", "nohup", "time", "command", "exec", "builtin", "timeout", "stdbuf"}
)
OLD_JAIL_WRAPPER_VALUES = {
    "sudo": frozenset({"-u", "-g"}),
    "nice": frozenset({"-n"}),
    "env": frozenset({"-u"}),
    "timeout": frozenset({"-s", "-k"}),
}
# issue 76: lib/shell.py's _WRAPPER_OPTS at a83accf, copied verbatim.
OLD_SHELL_WRAPPER_OPTS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "sudo": (
        frozenset({"-E", "-H", "-n", "-S", "-i", "-s", "-b", "-k", "-P"}),
        frozenset({"-u", "-g", "-h", "-p", "-C", "-U", "-D", "-r", "-t"}),
    ),
    "doas": (frozenset({"-n", "-s"}), frozenset({"-u", "-C"})),
    "env": (
        frozenset({"-i", "--ignore-environment", "-0", "--null", "-"}),
        frozenset({"-u", "--unset", "-C", "--chdir"}),
    ),
    "nice": (frozenset(), frozenset({"-n", "--adjustment"})),
    "nohup": (frozenset(), frozenset()),
    "stdbuf": (frozenset(), frozenset({"-i", "-o", "-e"})),
    "timeout": (
        frozenset({"--preserve-status", "--foreground", "-v", "--verbose"}),
        frozenset({"-s", "--signal", "-k", "--kill-after"}),
    ),
    "exec": (frozenset({"-c", "-l"}), frozenset({"-a"})),
    "command": (frozenset({"-p"}), frozenset()),
    "builtin": (frozenset(), frozenset()),
    "time": (frozenset({"-p", "-v", "--verbose", "--portability"}), frozenset({"-f", "-o"})),
    "xargs": (
        frozenset({"-0", "--null", "-r", "--no-run-if-empty", "-t", "--verbose", "-p", "-x"}),
        frozenset({"-I", "-n", "-P", "-d", "-L", "-s", "-E", "-a", "--arg-file", "--delimiter"}),
    ),
}
OLD_WORKER_WRAPPERS = frozenset(
    {"env", "nice", "nohup", "stdbuf", "timeout", "exec", "eval", "xargs", "command"}
    | {"builtin", "source", ".", "sh", "bash", "zsh", "dash", "ksh", "python", "python3"}
    | {"node", "perl", "ruby", "sudo", "doas", "time"}
)
# issue 76: the gh value flags lib/gh_policy.py and lib/jail.py parsed at a83accf.
OLD_GH_VALUE_FLAGS = frozenset({"-R", "--repo"})
OLD_API_SHORT_VALUE = frozenset("XfFHqtp")
OLD_API_LONG_VALUE = frozenset(
    {"--method", "--raw-field", "--field", "--header", "--input", "--jq", "--template"}
    | {"--preview", "--hostname", "--cache"}
)
OLD_PR_CREATE_SHORT_VALUE = frozenset("aBbFHlmprRTt")
OLD_PR_CREATE_LONG_VALUE = frozenset(
    {"--assignee", "--base", "--body", "--body-file", "--head", "--label", "--milestone"}
    | {"--project", "--reviewer", "--repo", "--recover", "--template", "--title"}
)
# jail.py: (path, long, short) pairs its pr write checks read a value from.
OLD_JAIL_PR_VALUES = (
    (("pr", "create"), "--repo", "R"),
    (("pr", "create"), "--head", "H"),
    (("pr", "create"), "--body-file", "F"),
    (("pr", "edit"), "--body-file", "F"),
    (("pr", "comment"), "--body-file", "F"),
    (("pr", "create"), "--body", "b"),
    (("pr", "edit"), "--body", "b"),
    (("pr", "comment"), "--body", "b"),
    (("pr", "edit"), "--base", "B"),
)


def test_wrapper_table_is_a_superset_of_the_jail_table() -> None:
    assert OLD_JAIL_RUN_WRAPPERS <= shell.WRAPPER_OPTS.keys()
    for name, values in OLD_JAIL_WRAPPER_VALUES.items():
        assert values <= shell.WRAPPER_OPTS[name][1], name


def test_wrapper_table_is_a_superset_of_the_shell_table() -> None:
    for name, (plain, valued) in OLD_SHELL_WRAPPER_OPTS.items():
        assert plain <= shell.WRAPPER_OPTS[name][0], name
        assert valued <= shell.WRAPPER_OPTS[name][1], name


def test_stdbuf_has_its_row_and_worker_wrappers_are_unchanged() -> None:
    assert {"-i", "-o", "-e", "--input", "--output", "--error"} <= shell.WRAPPER_OPTS["stdbuf"][1]
    # pin U2 -> E6, issue 82: the kernel wrapper's row and the runner wrapper rows since a83accf.
    runners = {"setsid", "chroot", "ionice", "taskset", "flock", "unshare", "chrt", "nsenter"}
    assert shell.WORKER_WRAPPERS == OLD_WORKER_WRAPPERS | {shell.CONFINE} | runners
    assert shell.WRAPPER_OPTS.keys() <= shell.WORKER_WRAPPERS
    assert shell.WRAPPER_OPTS[shell.CONFINE] == (frozenset({"--"}), frozenset({"--unit"}))


def _assigned(module: str) -> set[str]:
    tree = ast.parse((SCRIPTS_DIR / "lib" / module).read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else []
        targets = [node.target] if isinstance(node, ast.AnnAssign) else targets
        names |= {t.id for t in targets if isinstance(t, ast.Name)}
    return names


def test_one_wrapper_table_and_one_duration_regex() -> None:
    # pin U2 -> U4: lib.shell owns them; lib.jail keeps no second copy.
    assert not {"_DURATION", "_RUN_WRAPPERS", "_WRAPPER_VALUES"} & _assigned("jail.py")
    assert not {"_WRAPPER_OPTS", "_DURATION"} & _assigned("shell.py")
    assert jail.strip_wrappers is shell.strip_wrappers
    for good in ("5", "1.5", "2m", "10s", "1h", "3d"):
        assert shell.DURATION.fullmatch(good), good
    for bad in ("KILL", "-5", "5x", ""):
        assert not shell.DURATION.fullmatch(bad), bad


@pytest.mark.parametrize(
    ("command", "want"),
    [
        ("env -C /tmp rm -rf x", ["rm", "-rf", "x"]),
        ("env --chdir /tmp rm x", ["rm", "x"]),
        ("env --chdir=/tmp rm x", ["rm", "x"]),
        ("env -C/tmp FOO=1 rm x", ["rm", "x"]),
        ("timeout --signal KILL 5 rm x", ["rm", "x"]),
        ("timeout --kill-after 1 5 rm x", ["rm", "x"]),
        ("timeout -s KILL 1.5s rm x", ["rm", "x"]),
        ("sudo -h host -p pw -C 3 -U u -D /tmp -r r -t t rm x", ["rm", "x"]),
        ("sudo -u root -g wheel rm x", ["rm", "x"]),
        ("stdbuf -o L -i 0 -e 0 rm x", ["rm", "x"]),
        ("stdbuf -oL --error=0 rm x", ["rm", "x"]),
        ("nice -n 5 nohup rm x", ["rm", "x"]),
        ("nice -5 rm x", ["rm", "x"]),
        ("command -v rm", []),
        ("rm x", ["rm", "x"]),
    ],
)
def test_strip_wrappers_reaches_the_wrapped_command(command: str, want: list[str]) -> None:
    assert shell.strip_wrappers(shlex.split(command)) == want


@pytest.mark.parametrize(
    "command",
    ["env --frobnicate /tmp rm x", "timeout KILL rm x", "timeout", "stdbuf -Z L rm", "sudo -Z rm"],
)
def test_strip_wrappers_refuses_an_option_off_the_table(command: str) -> None:
    assert shell.strip_wrappers(shlex.split(command)) is None


@pytest.mark.parametrize(
    ("command", "at"),
    [
        ("env -C /tmp rm -rf x", 3),
        ("timeout --signal KILL 5 rm x", 4),
        ("sudo -h host rm x", 3),
        ("stdbuf -o L rm x", 3),
        ("if ! env -u X rm x", 5),
        ("FOO=1 time rm x", 2),
        ("command -v rm", None),
        ("env --frobnicate /tmp rm x", -1),
    ],
)
def test_jail_command_at_follows_the_shared_stripper(command: str, at: int | None) -> None:
    # issue 76: lib.jail finds the command word through shell.unwrap.
    assert jail._command_at(command.split(), set()) == at


def test_unwrap_reports_the_options_it_passed() -> None:
    # issue 76: each value sits at tokens[at][len(prefix):], so jail can move the folder.
    tokens = shlex.split("env -C /a --chdir=/b -C/c sudo -D d -u root time -o t rm x")
    unwrapped = shell.unwrap(tokens)
    assert unwrapped is not None
    rest, options = unwrapped
    assert rest == ["rm", "x"]
    values = [(o.wrapper, o.option, tokens[o.at][len(o.prefix) :]) for o in options]
    assert values == [
        ("env", "-C", "/a"),
        ("env", "--chdir", "/b"),
        ("env", "-C", "/c"),
        ("sudo", "-D", "d"),
        ("sudo", "-u", "root"),
        ("time", "-o", "t"),
    ]
    chdir = {("env", "-C"), ("env", "--chdir"), ("sudo", "-D"), ("sudo", "--chdir")}
    assert chdir == shell.WRAPPER_CHDIR
    assert {("time", "-o"), ("time", "--output")} == shell.WRAPPER_WRITES


@pytest.mark.parametrize(
    ("command", "want"),
    [
        ("env --ch=/m rm", ("env", "--chdir", "/m")),
        ("env --chd /m rm", ("env", "--chdir", "/m")),
        ("env --c=/m rm", ("env", "--chdir", "/m")),
        ("sudo --chdir=/m rm", ("sudo", "--chdir", "/m")),
        ("sudo --ch /m rm", ("sudo", "--chdir", "/m")),
        ("time --out=/t rm", ("time", "--output", "/t")),
        ("timeout --sig=KILL 5 rm", ("timeout", "--signal", "KILL")),
    ],
)
def test_a_unique_long_prefix_reads_as_its_option(command: str, want: tuple[str, ...]) -> None:
    # issue 76: getopt_long takes any unique prefix, so the table matches one the same way.
    tokens = shlex.split(command)
    unwrapped = shell.unwrap(tokens)
    assert unwrapped is not None and unwrapped[0] == ["rm"]
    found = [(o.wrapper, o.option, tokens[o.at][len(o.prefix) :]) for o in unwrapped[1]]
    assert found == [want]


@pytest.mark.parametrize("command", ["xargs --n rm", "sudo --user root rm", "env --zz=/m rm"])
def test_an_ambiguous_or_unknown_long_option_is_refused(command: str) -> None:
    assert shell.strip_wrappers(shlex.split(command)) is None


def test_opaque_values_take_the_value_inside_an_option_word() -> None:
    # issue 76, audit round 1: --x=v, -X=v and every suffix of a short cluster may name a folder.
    words = ["env", "--zz=/m", "-Q/n", "-R=o", "rm", "x"]
    assert jail._opaque_values(words, set(range(len(words)))) == [
        "env",
        "/m",
        "/n",
        "n",
        "o",
        "=o",
        "rm",
        "x",
    ]
    assert "/m/x" in jail._opaque_targets(words, set(range(len(words))), "/c")
    cluster = ["env", "-iZQ/p", "rm", "x"]
    assert "/p/x" in jail._opaque_targets(cluster, set(range(len(cluster))), "/c")


@pytest.mark.parametrize(
    ("command", "want"),
    [
        ("env -iC/m rm", [("env", "-C", "/m")]),
        ("env -0iC /m rm", [("env", "-C", "/m")]),
        ("sudo -nD/m rm", [("sudo", "-D", "/m")]),
        ("sudo -nED /m rm", [("sudo", "-D", "/m")]),
        ("sudo -Hu root rm", [("sudo", "-u", "root")]),
        ("time -po/t rm", [("time", "-o", "/t")]),
        ("time -vao /t rm", [("time", "-o", "/t")]),
        ("env -i0 rm", []),
        ("env -C=/m rm", [("env", "-C", "=/m")]),
        ("env -iC=/m rm", [("env", "-C", "=/m")]),
        ("sudo -D=d rm", [("sudo", "-D", "=d")]),
        ("time -o=t rm", [("time", "-o", "=t")]),
        ("env --chdir=/m rm", [("env", "--chdir", "/m")]),
    ],
)
def test_a_short_cluster_is_read_letter_by_letter(
    command: str, want: list[tuple[str, str, str]]
) -> None:
    # audit round 1: no-argument letters continue; the first one-argument letter takes the rest.
    tokens = shlex.split(command)
    unwrapped = shell.unwrap(tokens)
    assert unwrapped is not None and unwrapped[0] == ["rm"]
    found = [(o.wrapper, o.option, tokens[o.at][len(o.prefix) :]) for o in unwrapped[1]]
    assert found == want


@pytest.mark.parametrize(
    "command", ["env -iZ/m rm", "sudo -nQ rm", "time -pz rm", "env -i=x rm", "sudo -n=x rm"]
)
def test_a_cluster_letter_off_the_row_is_refused(command: str) -> None:
    assert shell.strip_wrappers(shlex.split(command)) is None


@pytest.mark.parametrize(
    ("command", "cwd", "want"),
    [
        ("env -C /m rm -rf x", "/c", ["/m", "/m/x"]),
        ("env -C /a env -C ../m rm x", "/c", ["/m", "/m/x"]),
        ("sudo -D m rm x > out", "/c", ["/c/out", "/c/m", "/c/m/x"]),
        ("time -o /t/log rm x", "/c", ["/t/log", "/c/x"]),
        ("time -p rm -rf /m/x", "/c", ["/m/x"]),
        # audit round 2: a short -C=v keeps the =, so the folder is cwd/=v, never /v.
        ("env -C=/../../m rm x", "/c/o", ["/c/m", "/c/m/x"]),
        ("sudo -D=/m rm x", "/c/o", ["/c/o/=/m", "/c/o/=/m/x"]),
        ("time -o=/../../t rm x", "/c/o", ["/c/t", "/c/o/x"]),
    ],
)
def test_write_dirs_follow_the_wrapper_folder(command: str, cwd: str, want: list[str]) -> None:
    # issue 76: relative operands resolve in the folder the wrapper moves to; redirects in cwd.
    assert jail._bash_write_dirs(command, cwd) == want


def test_gh_tables_are_supersets_of_both_old_tables() -> None:
    short, long = gh_policy._GH_PERSISTENT
    assert {f[1:] for f in OLD_GH_VALUE_FLAGS if not f.startswith("--")} <= short
    assert {f for f in OLD_GH_VALUE_FLAGS if f.startswith("--")} <= long
    api_short, api_long = gh_policy._GH_VALUES[("api",)]
    assert OLD_API_SHORT_VALUE <= api_short and OLD_API_LONG_VALUE <= api_long
    pr_short, pr_long = gh_policy._GH_VALUES[("pr", "create")]
    assert OLD_PR_CREATE_SHORT_VALUE <= pr_short and OLD_PR_CREATE_LONG_VALUE <= pr_long
    for path, (short, long) in gh_policy._GH_VALUES.items():
        if path[0] in {"pr", "run", "issue"}:
            assert "R" in short and "--repo" in long, path
    for path, flag_long, flag_short in OLD_JAIL_PR_VALUES:
        short, long = gh_policy._GH_VALUES[path]
        assert flag_short in short and flag_long in long, (path, flag_long)


@pytest.mark.parametrize(
    ("command", "name", "value"),
    [
        ("gh pr create --head x", "--head", "x"),
        ("gh pr create --head=x", "--head", "x"),
        ("gh pr create -H x", "-H", "x"),
        ("gh pr create -Hx", "-H", "x"),
        ("gh pr create -H=x", "-H", "x"),
        ("gh -R o/r pr view 3", "-R", "o/r"),
        ("gh pr view 3 --repo=o/r", "--repo", "o/r"),
        ("gh pr edit 3 -Fdocs/.tmp/b.md", "-F", "docs/.tmp/b.md"),
        ("gh pr comment 3 -F /tmp/c.md", "-F", "/tmp/c.md"),
        ("gh pr edit 3 -B main", "-B", "main"),
        ("gh api -XDELETE repos/o/r", "-X", "DELETE"),
        ("gh api --method DELETE repos/o/r", "--method", "DELETE"),
        ("gh api -f title=x repos/o/r", "-f", "title=x"),
    ],
)
def test_gh_parser_pairs_every_form_the_old_parsers_paired(
    command: str, name: str, value: str
) -> None:
    parsed = gh_policy.gh_args(shlex.split(command)[1:])
    assert parsed is not None
    assert [f.value for f in parsed.flags if f.name == name] == [value]

# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0044, 0043: the shell model the jail and the hook scripts share; moved verbatim from lib.jail.
# It imports nothing from lib.jail.
from __future__ import annotations

import itertools
import os
import re
import shlex
import shutil
from collections.abc import Callable, Iterable, Iterator
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

READ_ONLY_CMDS = frozenset(
    {
        "cat",
        "rg",
        "grep",
        "ls",
        "find",
        "jq",
        "head",
        "tail",
        "wc",
        "sha256sum",
        "file",
        "stat",
        "sort",
        "uniq",
    }
)
# spec 6: grep, worktree and merge-base pass only the read forms of their grammar rows.
READ_ONLY_GIT = frozenset(
    {"diff", "log", "show", "status", "rev-parse", "ls-files", "branch"}
    | {"grep", "worktree", "merge-base"}
)
SPECIALIST_GIT = frozenset({"diff", "show", "log"})
# M1: charter-docs git is add/commit/status/log/diff only (4.2); no merge, no worktree.
CHARTER_DOCS_GIT = frozenset({"add", "commit", "status", "log", "diff"})
# 0084: charter-docs reads as (flag letters, value-taking letters); long options refuse.
DOCS_READS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "cat": (frozenset("AbeEnstTuv"), frozenset()),
    "grep": (frozenset("cEFhHiIlLnoqrsvwx"), frozenset("eABCm")),
    "head": (frozenset("qv"), frozenset("nc")),
    "tail": (frozenset("qv"), frozenset("nc")),
    "wc": (frozenset("clmwL"), frozenset()),
    "ls": (frozenset("1aAdFhlrRSt"), frozenset()),
    "diff": (frozenset("abBiNqsuwy"), frozenset("U")),
    "sed": (frozenset("nErsu"), frozenset("e")),
}
CONDUCTOR_GIT = frozenset({"push", "status", "log", "rev-parse", "branch", "diff", "add", "commit"})
# Final review I1: transport plumbing and credential helpers reach remotes without push.
GIT_PLUMBING_REMOTE = frozenset(
    {"send-pack", "http-push", "receive-pack", "upload-pack", "fetch-pack"}
    | {"credential", "credential-store", "credential-cache"}
)
# Final review I3a: coder git is an allowlist; everything else blocks.
CODER_GIT = frozenset(
    {"add", "commit", "status", "diff", "log", "show", "rev-parse", "ls-files", "branch"}
    | {"stash", "restore", "checkout", "worktree", "config", "grep", "blame", "merge-base"}
)
# 0044: the named git grants a hook flag selects (git_grammar --allow, read_only_bash --git).
GIT_SETS: dict[str, frozenset[str]] = {
    "coder": CODER_GIT,
    "docs": CHARTER_DOCS_GIT,
    "conductor": CONDUCTOR_GIT,
    "specialist": SPECIALIST_GIT,
    "read-only": READ_ONLY_GIT,
}
# 0022: long options whose =x or next-token value is not a path; --preserve takes =x only.
_VALUE_LONG_NEXT = frozenset(
    {"--mode", "--owner", "--group", "--suffix", "--size", "--date", "--from", "--chmod"}
    | {"--exclude", "--include", "--filter", "--exclude-from", "--include-from"}
)
# 0022: shell state a worker could carry into a later segment (GIT_WORK_TREE and kin).
SHELL_VAR_CMDS = frozenset({"export", "declare", "typeset", "readonly", "local"})
# 0022: builtins that rebind what a later segment runs (hash pytest=/bin/rm).
SHELL_STATE_CMDS = frozenset(
    {"hash", "alias", "unalias", "unset", "shopt", "enable", "setopt", "unsetopt"}
    | {"trap", "getopts"}
)
# prepush2-2026-10-27: archive and multi-call tools write targets the jail does not model.
ARCHIVE_CMDS = frozenset(
    {"tar", "bsdtar", "gtar", "unzip", "zip", "busybox", "toybox", "cpio", "pax", "ar"}
    | {"7z", "7za", "7zr", "7zz"}
)
# issue 76: the one wrapper table, (no-argument options, one-argument options) per base name.
# An option off its row makes strip_wrappers return None, so callers fail closed.
WRAPPER_OPTS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "sudo": (
        frozenset({"-E", "-H", "-n", "-S", "-i", "-s", "-b", "-k", "-P"}),
        frozenset({"-u", "-g", "-h", "-p", "-C", "-U", "-D", "-r", "-t", "--chdir"}),
    ),
    "doas": (frozenset({"-n", "-s"}), frozenset({"-u", "-C"})),
    # issue 80: -S and --split-string stay off this row; env_split_values finds them to refuse.
    "env": (
        frozenset({"-i", "--ignore-environment", "-0", "--null", "-"}),
        frozenset({"-u", "--unset", "-C", "--chdir"}),
    ),
    "nice": (frozenset(), frozenset({"-n", "--adjustment"})),
    "nohup": (frozenset(), frozenset()),
    "stdbuf": (frozenset(), frozenset({"-i", "-o", "-e", "--input", "--output", "--error"})),
    "timeout": (
        frozenset({"--preserve-status", "--foreground", "-v", "--verbose"}),
        frozenset({"-s", "--signal", "-k", "--kill-after"}),
    ),
    "exec": (frozenset({"-c", "-l"}), frozenset({"-a"})),
    "command": (frozenset({"-p"}), frozenset()),
    "builtin": (frozenset(), frozenset()),
    "time": (
        frozenset({"-p", "-v", "--verbose", "--portability", "-a", "--append", "-q", "--quiet"}),
        frozenset({"-f", "-o", "--format", "--output"}),
    ),
    "xargs": (
        frozenset({"-0", "--null", "-r", "--no-run-if-empty", "-t", "--verbose", "-p", "-x"}),
        frozenset({"-I", "-n", "-P", "-d", "-L", "-s", "-E", "-a", "--arg-file", "--delimiter"}),
    ),
    # 0048, pin U2 -> E6: the kernel wrapper, daedalus_confine.py --unit <worktree> -- <command>.
    "daedalus_confine.py": (frozenset({"--"}), frozenset({"--unit"})),
    # issue 82: runner wrappers; --root and --wd stay off unshare and nsenter so they fail closed.
    "setsid": (frozenset({"-c", "--ctty", "-f", "--fork", "-w", "--wait"}), frozenset()),
    "chroot": (frozenset({"--skip-chdir"}), frozenset({"--groups", "--userspec"})),
    "ionice": (
        frozenset({"-t", "--ignore"}),
        frozenset({"-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "--pgid"})
        | frozenset({"-u", "--uid"}),
    ),
    "taskset": (frozenset({"-a", "--all-tasks", "-p", "--pid", "-c", "--cpu-list"}), frozenset()),
    "flock": (
        frozenset({"-s", "--shared", "-x", "-e", "--exclusive", "-u", "--unlock", "-n", "--nb"})
        | frozenset({"--nonblock", "-o", "--close", "-F", "--no-fork", "--verbose"}),
        frozenset({"-w", "--wait", "--timeout", "-E", "--conflict-exit-code"}),
    ),
    "unshare": (
        frozenset({"-f", "--fork", "-m", "--mount", "-u", "--uts", "-i", "--ipc", "-n", "--net"})
        | frozenset({"-p", "--pid", "-U", "--user", "-C", "--cgroup", "-T", "--time"})
        | frozenset({"-r", "--map-root-user", "-c", "--map-current-user", "--map-auto"})
        | frozenset({"--mount-proc", "--kill-child", "--keep-caps"}),
        frozenset({"-S", "--setuid", "-G", "--setgid", "-l", "--load-interp", "--propagation"})
        | frozenset({"--setgroups", "--map-user", "--map-group", "--map-users", "--map-groups"})
        | frozenset({"--monotonic", "--boottime"}),
    ),
    "chrt": (
        frozenset({"-a", "--all-tasks", "-b", "--batch", "-d", "--deadline", "-f", "--fifo"})
        | frozenset({"-i", "--idle", "-o", "--other", "-r", "--rr", "-R", "--reset-on-fork"})
        | frozenset({"-m", "--max", "-p", "--pid", "-v", "--verbose"}),
        frozenset({"-T", "--sched-runtime", "-P", "--sched-period", "-D", "--sched-deadline"}),
    ),
    "nsenter": (
        frozenset({"-a", "--all", "-m", "--mount", "-u", "--uts", "-i", "--ipc", "-n", "--net"})
        | frozenset({"-p", "--pid", "-C", "--cgroup", "-U", "--user", "-T", "--time"})
        | frozenset({"--preserve-credentials", "-e", "--env", "-F", "--no-fork"})
        | frozenset({"-Z", "--follow-context", "-c", "--join-cgroup", "--user-parent"}),
        frozenset({"-t", "--target", "-S", "--setuid", "-G", "--setgid"}),
    ),
}
# issue 80: env -S and --split-string pack a whole command into one word.
R_ENV_SPLIT = (
    "env -S and --split-string pack a whole command into one word, so the jail cannot see what "
    "it runs or writes (issue 80). Next: write the command without env -S, one word per argument."
)
CONFINE = "daedalus_confine.py"
# issue 76: options that move the working folder before the wrapped command runs.
WRAPPER_CHDIR = frozenset({("env", "-C"), ("env", "--chdir"), ("sudo", "-D"), ("sudo", "--chdir")})
# issue 76: options whose value is a file the wrapper itself writes.
WRAPPER_WRITES = frozenset({("time", "-o"), ("time", "--output")})
# issue 76: the one duration regex, timeout's first operand.
DURATION: re.Pattern[str] = re.compile(r"[\d.]+[smhd]?")
# issue 82: the operand a wrapper reads before its command; None never matches (chroot re-roots).
WRAPPER_OPERAND: dict[str, re.Pattern[str] | None] = {
    "timeout": DURATION,
    "taskset": re.compile(r"[0-9a-fA-FxX,:-]+"),
    "chrt": re.compile(r"\d+"),
    "flock": re.compile(r"[^-].*"),
    "chroot": None,
}
# issue 82: flock runs a shell body after its file operand; the jail never walks one.
FLOCK_BODY = frozenset({"-c", "--command"})
# 8.5 ruling A: first tokens a worker may never run, bar the allowlisted test runner forms.
WORKER_WRAPPERS = frozenset(WRAPPER_OPTS) | frozenset(
    {"eval", "source", ".", "sh", "bash", "zsh", "dash", "ksh", "python", "python3"}
    | {"node", "perl", "ruby"}
)
_RESERVED = frozenset(
    {"{", "}", "(", ")", "!", "if", "then", "else", "elif", "fi", "do", "done", "while"}
    | {"until", "for", "case", "esac", "select", "function", "coproc", "[[", "time"}
)
_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh"})
_SHELL_ARG_OPTS = frozenset({"-o", "+o", "-O", "+O", "--rcfile", "--init-file"})
_SHELL_LONG_FLAGS = frozenset(
    {"--login", "--norc", "--noprofile", "--posix", "--restricted", "--verbose", "--noediting"}
)
_TRUSTED_BIN = frozenset({"/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin"})
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_SAFE_ENV = re.compile(r"^(?:CI|NODE_ENV|TZ|LANG|LC_ALL|PYTHONDONTWRITEBYTECODE)=")
_GIT_CONFIG_DENY = re.compile(
    r"remote\..+\.(?:mirror|push)|push\.default|protocol\.(?:.+\.)?allow|core\.hookspath"
    r"|core\.fsmonitor|core\.pager|core\.sshcommand|diff\.external|alias\..*",
    re.I,
)
_GIT_GLOBAL_WITH_ARG = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env"}
)
_PUSH_FORBIDDEN = (
    "--force",
    "--force-with-lease",
    "--force-if-includes",
    "--delete",
    "--mirror",
    "--prune",
    "--no-verify",
)
_PUSH_ALL = ("--all", "--branches")
_PUSH_ARG_OPTS = frozenset({"-o", "--push-option", "--repo", "--receive-pack", "--exec"})
_SIGNABLE_GIT = frozenset({"commit", "merge", "rebase", "cherry-pick", "revert", "am", "pull"})
_FIND_DENY = frozenset({"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fls"})
_FALSE = frozenset({"false", "0", "no", "off"})
_HYGIENE_CHARS = frozenset("${}\\")
_DEFAULT_BRANCHES = frozenset({"main", "master"})
# 8.5, F1: the plugin's scripts dir; append_ledger.py runs only by this absolute path.
_REPO_SCRIPTS = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
_FALLBACK = "\x00fallback"
# F1, O7: the variable is empty in agent Bash, so the literal form never reaches the script.
R_LEDGER_LITERAL = (
    "${CLAUDE_PLUGIN_ROOT} is empty in agent Bash. "
    f"Next: run python3 {os.path.join(_REPO_SCRIPTS, 'append_ledger.py')} with the same "
    "arguments; it is the path your brief names."
)

R_UNSUPPORTED = (
    "command uses an unsupported shell construct (newline, background &, substitution, "
    "input redirect, a redirect other than >file, >>file, 2>&1 or >/dev/null, grouping, or |&). "
    "Next: send plain commands joined by &&, || or |."
)
R_INLINE = (
    "wrappers, shells, and interpreters are not permitted for workers. "
    "Next: run an allowlisted command directly."
)
R_GIT_CONFIG = (
    "git config overrides (-c, --config-env, --exec-path, git config writes) are not permitted "
    "for workers. Next: run git without them."
)
R_ENV = (
    "environment assignments in front of a command are not permitted for workers. Next: drop them."
)
R_SHELL_VARS = (
    "setting or exporting shell variables is not permitted for workers. "
    "Next: drop it; only CI, NODE_ENV, TZ, LANG, LC_ALL, PYTHONDONTWRITEBYTECODE "
    "may prefix a command."
)
R_SHELL_STATE = (
    "shell builtins that rebind commands or shell options are not permitted for workers. "
    "Next: run the command directly."
)
R_RSYNC_REMOTE = (
    "rsync may not reach a remote host or choose a remote shell for workers. "
    "Next: copy between local absolute paths only."
)
R_FIND_WRITE = (
    "find may not delete, exec, or write files for workers. "
    "Next: list with find, then act on the paths with an allowed command."
)
R_HYGIENE = (
    "a token contains $, {, }, a backslash, or a leading ~; workers spell arguments literally. "
    "Next: pass the literal value."
)
R_VARIABLE = (
    "command name or git subcommand comes from a variable; the jail cannot judge it. "
    "Next: spell the command out."
)
R_FORCE_PUSH = "force, delete, or mirror push is never permitted. Next: push a new branch instead."
R_CLEAN = "git clean is never run by any Daedalus component. Next: remove files by name."
R_STASH_UNTRACKED = (
    "stash of untracked or ignored files removes the plugin data dir. "
    "Next: stash tracked changes only."
)
R_DESTRUCTIVE = "destructive command. Next: do not run this; ask the operator."
R_SIGN = "signing happens only in the operator's own shell (C.1). Next: leave the commit unsigned."
R_DEFAULT_BRANCH = (
    "the operator merges; never push to the default branch (0001). "
    "Next: push the unit branch instead."
)
R_BRACE_PUSH = (
    "brace expansion in a git push hides the flags and refspec from the jail. "
    "Next: spell the push out literally."
)
R_GIT_CONFIG_KEY = (
    "git -c keys that change push, hook, pager, ssh, protocol, or alias behavior are not "
    "permitted. Next: run git without that -c."
)
R_XARGS = (
    "xargs feeding git push/commit/tag/clean hides the arguments from the jail. "
    "Next: run the git command directly."
)
R_GIT_PLUMBING = (
    "git transport plumbing and credential helpers are not run from a session. "
    "Next: use git push or git fetch by name."
)
R_DATA_DIR_GIT = (
    "the plugin data directory is never committed. Next: leave .claude/daedalus out of git."
)
R_CLAUDE_PATH = (
    "the command runs the claude binary, by name, link or versioned path, and starts a nested "
    "session the jail cannot attribute to an agent (issue 55). Next: run it from your own shell."
)
R_UNTRUSTED_PATH = (
    "a command given as a path runs only from the system bin folders, a unit worktree or the "
    "manifest's declared commands (issue 55). Next: run the tool by name or from your worktree."
)
R_ARCHIVE = (
    "archive and multi-call tools (tar, zip, unzip, cpio, 7z, ar, busybox and kin) write paths "
    "the jail cannot judge, so workers never run them (prepush2-2026-10-27). Next: copy or "
    "write each file by name with an allowed command."
)
CONFINE_PATH = os.path.join(_REPO_SCRIPTS, CONFINE)
CONFINE_NEXT = (
    f"Next: run the plugin's kernel wrapper {CONFINE_PATH} with --unit, your unit worktree "
    "path, then -- and the command."
)
R_CONFINE_FORM = (
    "the kernel wrapper runs in one form only, the plugin's own file with --unit, the unit "
    f"worktree path, then -- and the command (0048). {CONFINE_NEXT}"
)
_PROJECT_DATA = ".claude/daedalus"
_GLOB_CHARS = frozenset("*?[")
_STASH_WITH_ARG = frozenset({"-m", "--message", "--pathspec-from-file"})


def _prefix_re(canonical: str, min_chars: int) -> str:
    base = canonical[: 2 + min_chars]
    tail = ""
    for char in reversed(canonical[2 + min_chars :]):
        tail = f"(?:{re.escape(char)}{tail})?"
    return re.escape(base) + tail + r"(?![A-Za-z-])"


_S = r"[^;&|\n()]"
_W = r"[\s,\[\]{}]"
_HOME = os.path.normpath(os.path.expanduser("~"))
_HOME_PARENTS = [p for p in map(str, Path(_HOME).parents) if p != "/"]
# N4: the home dir's literal ancestors; empty when home sits directly under /.
_HOME_UP = "|".join(re.escape(p) + r"/?\*?" for p in _HOME_PARENTS) or r"(?!)"
# N5: --m is git's unique prefix of --mirror; every other forbidden option needs 2 chars.
_PUSH_MIN = {"--mirror": 1}
_PUSH_FORCE_ALT = "|".join(_prefix_re(c, _PUSH_MIN.get(c, 2)) for c in _PUSH_FORBIDDEN)
_PUSH_ALL_ALT = "|".join(_prefix_re(c, 2) for c in _PUSH_ALL)
_REGEX_TRIPWIRES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            rf"\bgit\b{_S}*?{_W}push\b{_S}*?(?:{_W}(?:{_PUSH_FORCE_ALT}|-[a-zA-Z]*[fd][a-zA-Z]*\b)"
            rf"|(?:^|[\s,:=\-]|\$\{{)[+:])"
        ),
        R_FORCE_PUSH,
    ),
    # 0001: any main/master word blocks here, so feature/main-fix over-blocks in the fallback
    # only; the tokenized path judges the destination's last component and allows it.
    (
        re.compile(
            rf"\bgit\b{_S}*?{_W}push\b{_S}*?(?:{_W}(?:{_PUSH_ALL_ALT})|\*|\b(?i:main|master)\b)"
        ),
        R_DEFAULT_BRANCH,
    ),
    # I1: anchored to the subcommand slot so commit messages naming these words still pass.
    (
        re.compile(
            r"\bgit(?:\s+(?:-[Cc]\s+\S+|--(?:git-dir|work-tree|namespace|config-env)\s+\S+|-\S+))*"
            r"\s+(?:send-pack|http-push|receive-pack|upload-pack|fetch-pack|credential)"
            r"(?![A-Za-z])"
        ),
        R_GIT_PLUMBING,
    ),
    (
        re.compile(
            rf"\bgit\b{_S}*?{_W}-c{_W}+(?:remote\.\S+\.(?:mirror|push)|push\.default"
            r"|protocol\.(?:\S+\.)?allow|core\.(?:hookspath|fsmonitor|pager|sshcommand)"
            r"|diff\.external|alias\.)",
            re.I,
        ),
        R_GIT_CONFIG_KEY,
    ),
    (re.compile(rf"\bgit\b{_S}*?{_W}clean\b"), R_CLEAN),
    (
        re.compile(
            rf"\brm\b(?={_S}*{_W}(?:-[a-zA-Z]*[rR]|--r[a-z]*\b))"
            rf"(?={_S}*{_W}(?:/+\.*\*?|(?:~|{re.escape(_HOME)})(?:/\.\.)*/?\*?|{_HOME_UP})"
            r"(?:[\s;&|),\]]|$))"
        ),
        R_DESTRUCTIVE,
    ),
    (re.compile(rf"\bmkfs\b|\bdd\b{_S}*{_W}if="), R_DESTRUCTIVE),
    (
        re.compile(
            rf"\bgit\b{_S}*?{_W}(?:commit|merge|rebase|cherry-pick|revert|am|pull)\b"
            rf"{_S}*?{_W}(?:-[a-zA-Z]*S|{_prefix_re('--gpg-sign', 2)})"
        ),
        R_SIGN,
    ),
    (re.compile(r"gpgsign\s*=\s*(?!(?:false|0|no|off)\b)", re.I), R_SIGN),
    (re.compile(r"GIT_CONFIG_\w+=\S*sign", re.I), R_SIGN),
    (
        re.compile(
            rf"\bgit\b{_S}*?{_W}tag\b{_S}*?{_W}(?:-[a-zA-Z]*[su]\b"
            rf"|{_prefix_re('--sign', 2)}|{_prefix_re('--local-user', 2)})"
        ),
        R_SIGN,
    ),
    (re.compile(r"(?:^|[\s;&|({/,\[])gpg2?(?=[\s;&|)},\]]|$)"), R_SIGN),
    (re.compile(rf"ssh-keygen\b{_S}*-Y{_W}*sign\b"), R_SIGN),
    (re.compile(rf"\bxargs\b{_S}*\bgit\b{_S}*{_W}(?:push|commit|tag|clean)\b"), R_XARGS),
)


def _under(path: str, root: str) -> bool:
    real_path = os.path.realpath(path)
    real_root = os.path.realpath(root)
    # 0164: the filesystem root holds every path; "/" plus os.sep would match none.
    return real_path == real_root or real_path.startswith(real_root.rstrip(os.sep) + os.sep)


def _abs(path: str, cwd: str) -> str:
    return path if os.path.isabs(path) else os.path.join(cwd, path)


_REDIRECT_END = frozenset(" \t;&|<>()\n\r")
# O3: a write target the jail can judge as one literal path.
_REDIRECT_DENY = frozenset("'\"\\$`*?[]{}~")
REDIRECT_SEP = ">"


def _fd_word(buf: list[str]) -> str | None:
    # O3: a bare 1 or 2 word before > is the fd; any other number is refused.
    text = "".join(buf)
    word = "" if not text or text[-1] in " \t" else text.split()[-1]
    if word in {"1", "2"}:
        return word
    return None if word.isdigit() else ""


def _redirect(command: str, i: int, fd: str) -> tuple[int, str | None] | None:
    # O3: i sits on >; the index past the target and a tee stand-in, or None for a no-op.
    append = command.startswith(">>", i)
    i += 2 if append else 1
    if command[i : i + 1] in {"&", "|"}:
        dup = fd == "2" and not append and command.startswith("&1", i)
        return (i + 2, None) if dup and command[i + 2 : i + 3] in _REDIRECT_END | {""} else None
    while command[i : i + 1] in {" ", "\t"}:
        i += 1
    start = i
    while i < len(command) and command[i] not in _REDIRECT_END:
        i += 1
    target = command[start:i]
    # O3: a leading - would read as a tee option and hide the target.
    if not target or target.startswith("-") or _REDIRECT_DENY & set(target):
        return None
    if target == "/dev/null":
        return i, None
    return i, f"tee -a {target}" if append else f"tee {target}"


def _flush(raws: list[str], seps: list[str], buf: list[str], pending: list[str]) -> None:
    raws.append("".join(buf))
    for stand_in in pending:
        seps.append(REDIRECT_SEP)
        raws.append(stand_in)
    pending.clear()


CHAR, ESCAPE, OPEN, CLOSE = "char", "escape", "open", "close"


class Lexeme(NamedTuple):
    # issue 76: one quote_walk step; quote is its span, and a quote mark carries the one it toggles.
    at: int
    text: str
    quote: str
    kind: str


def quote_walk(text: str) -> Iterator[Lexeme]:
    # issue 76: the one quote model; outside single quotes a backslash pairs with the next char.
    quote = ""
    i = 0
    while i < len(text):
        char = text[i]
        if quote and char == quote:
            yield Lexeme(i, char, quote, CLOSE)
            quote = ""
            i += 1
        elif char == "\\" and quote != "'":
            yield Lexeme(i, text[i : i + 2], quote, ESCAPE)
            i += 2
        elif not quote and char in "'\"":
            quote = char
            yield Lexeme(i, char, quote, OPEN)
            i += 1
        else:
            yield Lexeme(i, char, quote, CHAR)
            i += 1


def _unclosed(last: Lexeme | None) -> bool:
    return last is not None and bool(last.quote) and last.kind != CLOSE


def _scan(command: str, redirects: bool = False) -> tuple[list[str], list[str]] | None:
    # O3: redirects=True is the worker parse; a write redirect becomes a tee segment after its own.
    raws: list[str] = []
    seps: list[str] = []
    buf: list[str] = []
    pending: list[str] = []
    skip = 0
    last: Lexeme | None = None
    for last in quote_walk(command):
        at, chunk, quote, kind = last
        if at < skip:
            continue
        if kind == ESCAPE and chunk[1:] in {"\n", "\r"}:
            return None
        if quote == '"' and kind == CHAR and (chunk == "`" or command.startswith("$(", at)):
            return None
        if quote or kind != CHAR:
            buf.append(chunk)
            continue
        if redirects and (chunk == ">" or command.startswith("&>", at)):
            fd = "&" if chunk == "&" else _fd_word(buf)
            if fd is None:
                return None
            if fd in {"1", "2"}:
                buf.pop()
            step = _redirect(command, at + 1 if fd == "&" else at, fd)
            if step is None:
                return None
            skip, stand_in = step
            pending.extend([stand_in] if stand_in else [])
            continue
        if chunk in "\n\r`<>()" or command.startswith(("$(", "|&"), at):
            return None
        pair = command[at : at + 2]
        if pair in {"&&", "||"} or chunk in "|;":
            _flush(raws, seps, buf, pending)
            seps.append(pair if pair in {"&&", "||"} else chunk)
            buf = []
            skip = at + len(seps[-1])
            continue
        if chunk == "&":
            return None
        buf.append(chunk)
    if _unclosed(last):
        return None
    _flush(raws, seps, buf, pending)
    return raws, seps


def _tokens(raws: list[str]) -> list[list[str]] | None:
    segments: list[list[str]] = []
    for raw in raws:
        try:
            tokens = shlex.split(raw)
        except ValueError:
            return None
        if not tokens or tokens[0] in _RESERVED:
            return None
        if tokens[0].startswith("(") or tokens[0].endswith(")"):
            return None
        segments.append(tokens)
    return segments


def tokenize(command: str) -> list[list[str]] | None:
    scanned = _scan(command)
    return None if scanned is None else _tokens(scanned[0])


class WorkerChain(NamedTuple):
    # O3: raws, seps and tokens align; segments drop the _SAFE_ENV prefix of each.
    raws: list[str]
    seps: list[str]
    tokens: list[list[str]]
    segments: list[list[str]]


def worker_parse(command: str) -> WorkerChain | None:
    scanned = _scan(command, redirects=True)
    tokens = None if scanned is None else _tokens(scanned[0])
    if scanned is None or tokens is None:
        return None
    segments = [list(itertools.dropwhile(_SAFE_ENV.match, s)) for s in tokens]
    return WorkerChain(scanned[0], scanned[1], tokens, segments)


def chain_bases(chain: WorkerChain, cwd: str, dir_cmds: frozenset[str]) -> list[str] | None:
    # O6: each segment's working folder; one absolute cd heading an && chain moves the rest.
    moves = [i for i, s in enumerate(chain.segments) if s and _base(s[0]) in dir_cmds]
    count = len(chain.segments)
    if not moves:
        return [cwd] * count
    head = chain.segments[0]
    if moves != [0] or len(head) != 2 or head[0] != "cd" or not os.path.isabs(head[1]):
        return None
    joins = {"&&", "|", REDIRECT_SEP}
    if chain.seps[:1] not in ([], ["&&"]) or not set(chain.seps) <= joins:
        return None
    return [cwd] + [os.path.normpath(head[1])] * (count - 1)


def declared_segments(commands: Iterable[str]) -> frozenset[tuple[str, ...]]:
    # B2: a declared stack command that parses to one segment runs verbatim.
    out: set[tuple[str, ...]] = set()
    for command in commands:
        chain = worker_parse(command)
        if chain is not None and len(chain.segments) == 1 and chain.segments[0]:
            out.add(tuple(chain.segments[0]))
    return frozenset(out)


def split_pipeline(command: str) -> list[str] | None:
    """Thin wrapper over the scanner: raw stages of a pure `|` pipeline, else None."""
    scanned = _scan(command)
    if scanned is None or tokenize(command) is None or any(sep != "|" for sep in scanned[1]):
        return None
    return [raw.strip() for raw in scanned[0]]


def worker_segments(command: str) -> list[list[str]] | None:
    # 0044, O3: the worker parse's segments; a write redirect is a tee segment.
    chain = worker_parse(command)
    return None if chain is None else chain.segments


def _base(token: str) -> str:
    return os.path.basename(token)


def _cmd_name(tokens: list[str]) -> str:
    first = tokens[0] if tokens else ""
    if not first or "$" in first or "'" in first or '"' in first:
        return ""
    if "/" in first:
        # 8.5: a path outside the system bin dirs could be an agent-written script.
        return _base(first) if os.path.dirname(first) in _TRUSTED_BIN else ""
    return first


def _short_flags(token: str) -> set[str]:
    if token.startswith("-") and not token.startswith("--") and len(token) > 1:
        return set(token[1:])
    return set()


def _long_matches(arg: str, canonical: str, min_chars: int = 4) -> bool:
    key = arg.split("=", 1)[0]
    return key.startswith("--") and len(key) - 2 >= min_chars and canonical.startswith(key)


def _git_split(tokens: list[str]) -> tuple[str | None, list[str], list[str]]:
    if not tokens or _base(tokens[0]) != "git":
        return None, [], []
    globals_: list[str] = []
    i = 1
    while i < len(tokens):
        token = tokens[i]
        if token in _GIT_GLOBAL_WITH_ARG:
            globals_.extend(tokens[i : i + 2])
            i += 2
            continue
        if token.startswith("-"):
            globals_.append(token)
            i += 1
            continue
        return token, tokens[i + 1 :], globals_
    return None, [], globals_


def _git_subcommand(tokens: list[str]) -> str | None:
    return _git_split(tokens)[0]


def _git_config_override(globals_: list[str]) -> bool:
    return any(
        token in {"-c", "--config-env"} or token.startswith(("--config-env=", "--exec-path"))
        for token in globals_
    )


def _config_settings(globals_: list[str]) -> list[tuple[str, str]]:
    settings: list[tuple[str, str]] = []
    for i, token in enumerate(globals_):
        if token in {"-c", "--config-env"} and i + 1 < len(globals_):
            setting = globals_[i + 1]
        elif token.startswith("--config-env="):
            setting = token.split("=", 1)[1]
        else:
            continue
        key, _, value = setting.partition("=")
        settings.append((key, value))
    return settings


def _gpgsign_override(globals_: list[str]) -> bool:
    return any(
        "gpgsign" in key.lower() and value.lower() not in _FALSE
        for key, value in _config_settings(globals_)
    )


def _config_key_denied(globals_: list[str]) -> bool:
    return any(_GIT_CONFIG_DENY.fullmatch(key) for key, _ in _config_settings(globals_))


def _push_parts(args: list[str]) -> tuple[bool, list[str], set[str]]:
    positional: list[str] = []
    flags: set[str] = set()
    forbidden = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            positional.extend(args[i + 1 :])
            break
        if arg in _PUSH_ARG_OPTS:
            i += 2
            continue
        if arg.startswith("--"):
            flags.add(arg.split("=", 1)[0])
            forbidden = forbidden or any(
                _long_matches(arg, c, _PUSH_MIN.get(c, 2)) for c in _PUSH_FORBIDDEN
            )
        elif _short_flags(arg):
            flags.update(f"-{c}" for c in _short_flags(arg))
            forbidden = forbidden or bool({"f", "d"} & _short_flags(arg))
        else:
            positional.append(arg)
        i += 1
    refspecs = positional[1:]
    forbidden = forbidden or any(ref.startswith(("+", ":")) for ref in refspecs)
    return forbidden, refspecs, flags


def _push_destination(refspec: str) -> str:
    dest = refspec.split(":")[-1].lstrip("+")
    return dest.removeprefix("refs/heads/")


def _push_to_default(refspecs: list[str], flags: set[str]) -> bool:
    if any(_long_matches(flag, c, 2) for flag in flags for c in _PUSH_ALL):
        return True
    for ref in refspecs:
        if "*" in ref or _push_destination(ref).split("/")[-1].casefold() in _DEFAULT_BRANCHES:
            return True
    return False


def _rm_target_dangerous(target: str) -> bool:
    if "{" in target:
        return True
    expanded = target.replace("${HOME}", _HOME).replace("$HOME", _HOME)
    if expanded.startswith("~"):
        expanded = os.path.expanduser(expanded)
    trimmed = expanded.rstrip("/") or "/"
    base = (trimmed[:-2] or "/") if trimmed.endswith("/*") else trimmed
    if base.startswith("/"):
        base = os.path.normpath(base)
        base = "/" if base == "//" else base
    # N4: the home dir or any ancestor of it (~/.. resolves to /home).
    return base == "/" or _HOME == base or _HOME.startswith(base + "/")


def _rm_reason(args: list[str]) -> str | None:
    recursive = False
    targets: list[str] = []
    options_done = False
    for arg in args:
        if not options_done and arg == "--":
            options_done = True
        elif not options_done and arg.startswith("--"):
            recursive = recursive or _long_matches(arg, "--recursive", 1)
        elif not options_done and _short_flags(arg):
            recursive = recursive or bool({"r", "R"} & _short_flags(arg))
        else:
            targets.append(arg)
    if recursive and any(_rm_target_dangerous(t) for t in targets):
        return R_DESTRUCTIVE
    if any("{" in a for a in args) or any(set("${}") & set(t) for t in targets):
        return _FALLBACK
    return None


def _quote_spans(text: str) -> str:
    # N3: each quoted span, its marks included, becomes one Q.
    return "".join(
        "Q" if lex.kind == OPEN else lex.text
        for lex in quote_walk(text)
        if not lex.quote or lex.kind == OPEN
    )


def _normalize(text: str, placeholder: bool) -> str:
    text = text.replace("${IFS}", " ").replace("$IFS", " ")
    text = text.replace("${HOME}", "~").replace("$HOME", "~")
    if placeholder:
        text = _quote_spans(text.replace("$'", "'").replace('$"', '"'))
    for token in ("$'", '$"', "${", "$(", ")", "'", '"', "\\"):
        text = text.replace(token, "")
    for char in "{},":
        text = text.replace(char, " ")
    return text


def _raw_segments(text: str) -> list[str]:
    segments: list[str] = []
    buf: list[str] = []
    for lex in quote_walk(text):
        if lex.kind == CHAR and not lex.quote and lex.text in ";&|\n\r()":
            segments.append("".join(buf))
            buf = []
        else:
            buf.append(lex.text)
    segments.append("".join(buf))
    return segments


def _word_parts(token: str) -> set[str]:
    return {_base(part) for part in re.split(r"[{},]", token)}


def _segment_views(raw: str) -> list[list[str]]:
    text = raw.replace("${HOME}", "~").replace("$HOME", "~")
    views: list[list[str]] = []
    for view in (text, _quote_spans(text.replace("$'", "'").replace('$"', '"'))):
        for token in ("$'", '$"', "${", "$(", "'", '"', "\\"):
            view = view.replace(token, "")
        tokens = view.split()
        with_arg: frozenset[str] = frozenset()
        wrapper: set[str] = set()
        while tokens and (
            _ASSIGN.match(tokens[0])
            or tokens[0] in _RESERVED
            or tokens[0].startswith("-")
            or _word_parts(tokens[0]) & WORKER_WRAPPERS
            or ("timeout" in wrapper and DURATION.fullmatch(tokens[0]))
        ):
            if _word_parts(tokens[0]) & WRAPPER_OPTS.keys():
                wrapper = _word_parts(tokens[0]) & WRAPPER_OPTS.keys()
                with_arg = WRAPPER_OPTS[min(wrapper)][1]
            tokens = tokens[2:] if tokens[0] in with_arg else tokens[1:]
        views.append(tokens)
    return views


_RM_RECURSIVE = re.compile(r"(?:^|[{,])(?:-[{},A-Za-z]*[rR]|--[{},]*r)")


def _raw_segment_reason(raw: str) -> str | None:
    for tokens in _segment_views(raw):
        if not tokens:
            continue
        words = _word_parts(tokens[0])
        rest = tokens[1:]
        if "rm" in words and any(_RM_RECURSIVE.search(t) for t in rest):
            targets = [t for t in rest if not t.startswith("-")]
            if "{" in raw or any(_rm_target_dangerous(t) for t in targets):
                return R_DESTRUCTIVE
        if "git" in words:
            i = 0
            while i < len(rest) and rest[i].startswith("-"):
                i += 2 if rest[i] in _GIT_GLOBAL_WITH_ARG else 1
            if i < len(rest) and "push" in _word_parts(rest[i]) and "{" in raw:
                return R_BRACE_PUSH
    return None


def _regex_tripwire(command: str) -> str | None:
    text = command.replace("\\\r\n", "").replace("\\\n", "")
    # Round 5: braces and ~/.. are judged on raw segments before normalization erases them.
    for raw in _raw_segments(text):
        reason = _raw_segment_reason(raw)
        if reason:
            return reason
    # N3: quotes deleted (catches split words) and quoted spans as one char (keeps segments whole).
    for normalized in (_normalize(text, False), _normalize(text, True)):
        for pattern, reason in _REGEX_TRIPWIRES:
            if pattern.search(normalized):
                return reason
    return None


class WrapperOption(NamedTuple):
    # issue 76: a one-argument wrapper option; its value is tokens[at][len(prefix):].
    wrapper: str
    option: str
    at: int
    prefix: str


def unwrap(tokens: list[str]) -> tuple[list[str], list[WrapperOption]] | None:
    # issue 76: strip_wrappers plus the one-argument options it passed, in order.
    options: list[WrapperOption] = []
    rest = _strip_wrappers(tokens, [], options)
    return None if rest is None else (rest, options)


def _long_option(spelled: str, row: frozenset[str]) -> str:
    # issue 76: getopt_long takes a unique prefix (--ch for --chdir); else it stays as spelled.
    if not spelled.startswith("--") or spelled == "--" or spelled in row:
        return spelled
    hits = [option for option in row if option.startswith(spelled)]
    return hits[0] if len(hits) == 1 else spelled


def _cluster(
    token: str, no_arg: frozenset[str], with_arg: frozenset[str]
) -> tuple[str, int] | None:
    # issue 76, audit round 1: getopt reads -iC/x as -i, then -C taking the rest of the word.
    # Returns (one-argument letter or "", index its value starts at); None at a letter off the row.
    for cut in range(2, len(token) + 1):
        letter = "-" + token[cut - 1]
        if letter in with_arg:
            return letter, cut
        if letter not in no_arg:
            return None
    return "", len(token)


def strip_wrappers(tokens: list[str]) -> list[str] | None:
    # issue 76: the tokens from the wrapped command on; None when an option is off WRAPPER_OPTS.
    return _strip_wrappers(tokens, [])


def _strip_wrappers(
    tokens: list[str], assigns: list[str], options: list[WrapperOption] | None = None
) -> list[str] | None:
    total = len(tokens)
    found: list[WrapperOption] = [] if options is None else options
    while tokens:
        while tokens and _ASSIGN.match(tokens[0]):
            assigns.append(tokens[0])
            tokens = tokens[1:]
        if not tokens or _base(tokens[0]) not in WRAPPER_OPTS:
            return tokens
        name = _base(tokens[0])
        no_arg, with_arg = WRAPPER_OPTS[name]
        offset = total - len(tokens)
        i = 1
        while i < len(tokens):
            token = tokens[i]
            spelled = token.split("=", 1)[0]
            key = _long_option(spelled, no_arg | with_arg)
            if token == "--":
                i += 1
                break
            if name == "env" and _ASSIGN.match(token):
                assigns.append(token)
            elif not token.startswith("-") or token == "-" and name != "env":
                break
            elif key in no_arg and ("=" not in token or key.startswith("--")):
                pass
            elif key in with_arg and "=" in token and key.startswith("--"):
                # audit round 2: only getopt_long strips = (--chdir=v); a short -C=v keeps it,
                # so it falls through to _cluster, which reads its value as =v.
                found.append(WrapperOption(name, key, offset + i, spelled + "="))
            elif key in with_arg and key.startswith("--") or token in with_arg:
                if i + 1 < len(tokens):
                    found.append(WrapperOption(name, key, offset + i + 1, ""))
                i += 1
            elif name == "nice" and re.fullmatch(r"-\d+", token):
                pass
            elif name == "command" and token in {"-v", "-V"}:
                return []
            elif not token.startswith("--") and (cluster := _cluster(token, no_arg, with_arg)):
                letter, cut = cluster
                if letter and cut < len(token):
                    found.append(WrapperOption(name, letter, offset + i, token[:cut]))
                elif letter:
                    if i + 1 < len(tokens):
                        found.append(WrapperOption(name, letter, offset + i + 1, ""))
                    i += 1
            else:
                return None
            i += 1
        if name in WRAPPER_OPERAND:
            # issue 76, 82: an operand off its pattern leaves the command unknown.
            operand = WRAPPER_OPERAND[name]
            if i >= len(tokens) or operand is None or not operand.fullmatch(tokens[i]):
                return None
            i += 1
            if name == "flock" and tokens[i : i + 1] and tokens[i].split("=")[0] in FLOCK_BODY:
                return None
        tokens = tokens[i:]
    return tokens


def env_split_values(tokens: list[str]) -> list[str]:
    # issue 80: the value of each env -S or --split-string, in clusters and long prefixes too.
    return [
        v
        for at, word in enumerate(tokens)
        if _base(word) == "env"
        for v in _env_split(tokens[at + 1 :])
    ]


def _env_split(args: list[str]) -> list[str]:
    # issue 80: getopt order; an unknown letter or option is read past, so -S behind it is found.
    with_arg = WRAPPER_OPTS["env"][1]
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] not in {"-", "--"}:
        token = args[i]
        later = args[i + 1 : i + 2] or [""]
        if token.startswith("--"):
            key, eq, value = token.partition("=")
            if "--split-string".startswith(key):
                return [value if eq else later[0]]
            i += 2 if not eq and _long_option(key, with_arg) in with_arg else 1
            continue
        for cut, letter in enumerate(token[1:], start=2):
            if letter == "S":
                return [token[cut:] or later[0]]
            if "-" + letter in with_arg:
                i += 0 if token[cut:] else 1
                break
        i += 1
    return []


def _inline_code(tokens: list[str], letters: str, longs: frozenset[str]) -> str | None:
    i = 1
    while i < len(tokens):
        token = tokens[i]
        if token == "--":
            i += 1
            break
        if token.split("=", 1)[0] in longs:
            return token.split("=", 1)[1] if "=" in token else (tokens[i + 1 : i + 2] or [""])[0]
        if token.startswith("--"):
            i += 1
            continue
        if token.startswith("-") and len(token) > 1:
            group = token[1:]
            hit = next((idx for idx, ch in enumerate(group) if ch in letters), None)
            if hit is not None:
                rest = group[hit + 1 :]
                return rest or (tokens[i + 1 : i + 2] or [""])[0]
            if "m" in group and letters == "c":
                return None
            i += 1
            continue
        break
    return None


def _shell_code(tokens: list[str]) -> str | None:
    i = 1
    has_c = False
    while i < len(tokens):
        token = tokens[i]
        if token == "--":
            i += 1
            break
        if token in _SHELL_ARG_OPTS:
            i += 2
            continue
        if token.startswith("--"):
            if token not in _SHELL_LONG_FLAGS:
                return _FALLBACK
            i += 1
            continue
        if token[:1] in {"-", "+"} and len(token) > 1:
            has_c = has_c or "c" in token[1:]
            i += 1
            continue
        break
    if not has_c:
        return None
    return tokens[i] if i < len(tokens) else ""


def _segment_reason(segment: list[str], depth: int, main: bool) -> str | None:
    if depth > 3:
        return R_UNSUPPORTED
    if any(_base(t) == "xargs" for t in segment):
        rest = segment[[_base(t) for t in segment].index("xargs") + 1 :]
        if any(_base(t) == "git" for t in rest) and {"push", "commit", "tag", "clean"} & set(rest):
            return R_XARGS
    if not main and env_split_values(segment):
        # issue 80: workers only, main stays exempt from construct limits; a tripwire names itself.
        return _regex_tripwire(" ".join(segment)) or R_ENV_SPLIT
    assigns: list[str] = []
    tokens = _strip_wrappers(segment, assigns)
    if tokens is None:
        return _FALLBACK
    if not tokens:
        return None
    name = _base(tokens[0])
    if set("${") & set(tokens[0]):
        return _FALLBACK if main else R_VARIABLE
    if name in _SHELLS:
        code = _shell_code(tokens)
        if code == _FALLBACK:
            return _FALLBACK
        return _command_reason(code, depth + 1, main) if code else None
    if name.startswith("python"):
        code = _inline_code(tokens, "c", frozenset())
        return _command_reason(code, depth + 1, main) if code else None
    if name in {"perl", "ruby", "node"}:
        letters = "ep" if name == "node" else "eE"
        code = _inline_code(tokens, letters, frozenset({"--eval", "--print"}))
        return _command_reason(code, depth + 1, main) if code else None
    if name == "eval":
        return _command_reason(" ".join(tokens[1:]), depth + 1, main)
    if name == "git":
        return _git_reason(tokens, assigns, main)
    if name == "rm":
        return _rm_reason(tokens[1:])
    if name.startswith("mkfs") or (name == "dd" and any(t.startswith("if=") for t in tokens)):
        return R_DESTRUCTIVE
    if name in {"gpg", "gpg2"}:
        return R_SIGN
    if name == "ssh-keygen" and any(t.startswith("-Y") for t in tokens):
        if "sign" in tokens or "-Ysign" in tokens:
            return R_SIGN
    return None


def _git_reason(tokens: list[str], assigns: list[str], main: bool) -> str | None:
    sub, args, globals_ = _git_split(tokens)
    if _gpgsign_override(globals_):
        return R_SIGN
    if _config_key_denied(globals_):
        return R_GIT_CONFIG_KEY
    if any(a.split("=", 1)[0].startswith("GIT_CONFIG_") and "sign" in a.lower() for a in assigns):
        return R_SIGN
    if sub is not None and set("${") & set(sub):
        return _FALLBACK if main else R_VARIABLE
    if sub in {"push", "commit", "tag", "clean"} and any(
        set("${}") & set(arg) for arg in args + globals_
    ):
        return _FALLBACK
    if sub in GIT_PLUMBING_REMOTE:
        return R_GIT_PLUMBING
    if sub in {"add", "stage", "commit", "update-index"}:
        reason = _git_data_dir_reason(sub, args, globals_)
        if reason:
            return reason
    if sub == "push":
        forbidden, refspecs, flags = _push_parts(args)
        if forbidden:
            return R_FORCE_PUSH
        if _push_to_default(refspecs, flags):
            return R_DEFAULT_BRANCH
    if sub == "clean":
        return R_CLEAN
    if sub == "stash" and _stash_untracked(args):
        return R_STASH_UNTRACKED
    if sub in _SIGNABLE_GIT and any(
        _long_matches(arg, "--gpg-sign", 2) or "S" in _short_flags(arg) for arg in args
    ):
        return R_SIGN
    if sub == "tag" and any(
        _long_matches(arg, "--sign", 2)
        or _long_matches(arg, "--local-user", 2)
        or {"s", "u"} & _short_flags(arg)
        for arg in args
    ):
        return R_SIGN
    return None


def _command_reason(command: str, depth: int = 0, main: bool = True) -> str | None:
    if depth > 3:
        return R_UNSUPPORTED
    segments = tokenize(command)
    if segments is None:
        return _regex_tripwire(command)
    for segment in segments:
        reason = _segment_reason(segment, depth, main)
        if reason == _FALLBACK:
            return _regex_tripwire(command)
        if reason:
            return reason
    return None


def _stash_untracked(args: list[str]) -> bool:
    if args and not args[0].startswith("-") and args[0] not in {"push", "save"}:
        return False
    skip = False
    for arg in args:
        if skip:
            skip = False
        elif arg in _STASH_WITH_ARG:
            skip = True
        elif arg == "--":
            return False
        elif _long_matches(arg, "--include-untracked", 1) or _long_matches(arg, "--all", 1):
            return True
        elif not arg.startswith("--") and {"a", "u"} & _short_flags(arg):
            return True
    return False


def _names_project_data(path: str) -> bool:
    parts = os.path.normpath(path).split(os.sep)
    return any(parts[i : i + 2] == [".claude", "daedalus"] for i in range(len(parts) - 1))


def _force_add(args: list[str]) -> bool:
    return any(
        _long_matches(a, "--force", 3) or (not a.startswith("--") and "f" in _short_flags(a))
        for a in args
    )


_COMMIT_WITH_ARG = frozenset(
    {"-m", "-am", "-F", "-C", "-c", "-t", "--author", "--date", "--message", "--file"}
    | {"--template", "--fixup", "--squash", "--trailer", "--cleanup", "--reuse-message"}
)


def _pathspecs(sub: str, args: list[str]) -> list[str]:
    out: list[str] = []
    skip = False
    after_dashes = False
    for arg in args:
        if skip:
            skip = False
        elif after_dashes or not arg.startswith("-"):
            out.append(arg)
        elif arg == "--":
            after_dashes = True
        elif sub == "commit" and arg in _COMMIT_WITH_ARG:
            skip = True
    return out


def _git_data_dir_reason(sub: str, args: list[str], globals_: list[str]) -> str | None:
    base = "."
    for i, flag in enumerate(globals_[:-1]):
        if flag == "-C":
            base = os.path.join(base, globals_[i + 1])
    if _PROJECT_DATA in base or _names_project_data(base):
        return R_DATA_DIR_GIT
    if sub == "update-index":
        # 0010: --stdin/--index-info hide paths; --cacheinfo=mode,sha,path is a single arg.
        if "--index-info" in args or ("--stdin" in args and {"--add", "--force-add"} & set(args)):
            return R_DATA_DIR_GIT
        paths = list(args)
    else:
        paths = _pathspecs(sub, args)
    for arg in paths:
        if _PROJECT_DATA in arg or _names_project_data(os.path.join(base, arg)):
            return R_DATA_DIR_GIT
    # 0010: a forced add overrides the * marker; block forced adds of ancestors and globs.
    if _force_add(args):
        for arg in paths:
            norm = os.path.normpath(os.path.join(base, arg))
            if norm in {".", ".claude"} or norm.endswith("/.claude") or arg.startswith(":"):
                return R_DATA_DIR_GIT
            if _GLOB_CHARS & set(arg):
                return R_DATA_DIR_GIT
    return None


def _is_plugin_script(tokens: list[str], name: str) -> bool:
    # 8.5, F1: `python3 <absolute path>` whose real file is the plugin's own scripts/<name>.
    if len(tokens) < 2 or tokens[0] != "python3":
        return False
    script = tokens[1]
    if not script.startswith("/") or ".." in script.split("/"):
        return False
    return os.path.realpath(script) == os.path.join(_REPO_SCRIPTS, name)


def _is_append_ledger(tokens: list[str]) -> bool:
    return _is_plugin_script(tokens, "append_ledger.py")


def _is_cite(tokens: list[str], own_script: Callable[[str], bool]) -> bool:
    # RCP: `python3 <plugin root>/scripts/cite.py <file> <pattern>`, the file in the unit worktree.
    return len(tokens) == 4 and _is_plugin_script(tokens, "cite.py") and own_script(tokens[2])


_SED_ADDR = r"(?:\d+|\$|/[^/\\]*/)"
_SED_PRINT = re.compile(
    rf"(?:{_SED_ADDR}(?:,{_SED_ADDR})?)?p(?:;(?:{_SED_ADDR}(?:,{_SED_ADDR})?)?p)*"
)
_READ_PATH_DENY = frozenset("*?[]{}$~\\")


def _unquoted_expansion(raw: str) -> bool:
    # 0084: an unquoted glob, brace, tilde or $ can split into operands the jail never saw.
    return any(
        lex.kind == CHAR and not lex.quote and lex.text in "*?[{~$" for lex in quote_walk(raw)
    )


def _docs_read_split(name: str, args: list[str]) -> tuple[set[str], list[str], list[str]] | None:
    plain, valued = DOCS_READS[name]
    seen: set[str] = set()
    scripts: list[str] = []
    operands: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            operands += args[i + 1 :]
            break
        if not arg.startswith("-") or arg == "-":
            operands.append(arg)
            i += 1
            continue
        if arg.startswith("--"):
            return None
        for j, char in enumerate(arg[1:], start=2):
            if char in valued:
                if not arg[j:] and i + 1 >= len(args):
                    return None
                value = arg[j:] or args[i + 1]
                i += 0 if arg[j:] else 1
                if char == "e":
                    scripts.append(value)
                break
            if char not in plain:
                return None
            seen.add(char)
        i += 1
    return seen, scripts, operands


def docs_read_ok(tokens: list[str], raw: str, roots: list[str], cwd: str, base: str) -> bool:
    # 0084: a relative operand must land under a root from the project root and from cwd.
    name = _cmd_name(tokens)
    if name not in DOCS_READS or _unquoted_expansion(raw):
        return False
    split = _docs_read_split(name, tokens[1:])
    if split is None:
        return False
    seen, scripts, paths = split
    if name in {"grep", "sed"} and not scripts:
        scripts, paths = paths[:1], paths[1:]
    if name == "sed" and ("n" not in seen or not all(_SED_PRINT.fullmatch(s) for s in scripts)):
        return False
    if name == "ls" and not paths:
        paths = [cwd]
    if not paths or (name in {"grep", "sed"} and not scripts):
        return False
    if name == "diff" and len(paths) != 2:
        return False
    for path in paths:
        if _READ_PATH_DENY & set(path):
            return False
        places = [path] if os.path.isabs(path) else [_abs(path, base), _abs(path, cwd)]
        if not all(any(_under(p, root) for root in roots) for p in places):
            return False
    return True


# B2 narrowed by audit finding (c), Build Train 20261019-124612: -m runs these modules only.
RUNNER_MODULES = frozenset({"pytest", "mypy", "ruff", "unittest", "coverage"})
# 0048, issue 91, 0164: runners the confine check wraps, each with the leading forms it admits;
# () admits any. Apart from WRAPPER_OPTS (pin H1 -> H2); node, a WORKER_WRAPPERS name, is --test.
TEST_RUNNERS: dict[str, tuple[tuple[str, ...], ...]] = {
    "pytest": ((),),
    "make": ((),),
    "tox": ((),),
    "nox": ((),),
    "just": ((),),
    "npx": ((),),
    "uv": (("run",),),
    "go": (("test",),),
    "cargo": (("test",),),
    "node": (("--test",),),
    # 0164: pnpm wraps like npm; every script, exec and fallback bin runs under the wrapper.
    "pnpm": ((),),
    "vitest": (("run",),),
    "tsc": (("--noEmit",),),
    "vite": (("build",),),
    "terraform": (("validate",), ("fmt", "-check"), ("fmt", "-recursive", "-check")),
}
# 0164: package scripts that start a dev server; npm's run and test verbs with their aliases.
DEV_SCRIPTS = frozenset({"dev", "start", "serve", "preview"})
NPM_RUN = frozenset({"run", "run-script", "rum", "urn"})
NPM_TEST = frozenset({"test", "t", "tst"})
# 0158, 0164: terraform subcommands that change state; refused bare and under the wrapper.
TERRAFORM_MUTATE = frozenset(
    {"apply", "destroy", "import", "state", "taint", "untaint", "force-unlock", "refresh"}
)
TERRAFORM_FMT_FLAGS = frozenset({"-check", "-recursive"})
_JS_TOOLS = frozenset({"vite", "vitest", "tsc", "node"})
# 0164: package managers that run a project script or a bin, and their exec verbs.
JS_LAUNCHERS = frozenset({"pnpm", "npm", "npx", "yarn", "bun"})
_JS_EXEC = frozenset({"exec", "x", "dlx"})
# 0164: package manager options whose value is the next word, never the command.
_JS_VALUED = frozenset({"-C", "--dir", "-F", "--filter", "--prefix", "--cwd", "--workspace"})
R_DEV_SERVER = (
    "a coder never starts a dev server: the operator hosts the dev server and the verify step "
    "names the URL and the check (0164). Next: run `vite build` for a build, or yield the URL "
    "and the check for the operator."
)
R_VITEST_WATCH = (
    "vitest runs only as `vitest run` with no watch option; any other form starts watch mode, "
    "which never exits (0164). Next: run `vitest run`, under the kernel wrapper."
)
R_TSC = (
    "tsc runs only as the type check `tsc --noEmit`, never with --watch or -w and never "
    "emitting files (0164). Next: run `tsc --noEmit`, under the kernel wrapper."
)
R_TERRAFORM_MUTATE = (
    "terraform apply, destroy, import, state, taint, untaint, force-unlock and refresh change "
    "infrastructure or state and stay with the operator, bare or under the kernel wrapper "
    "(0158). Next: run `terraform validate` or `terraform fmt -check`, or yield the change to "
    "the operator."
)
R_TERRAFORM_OPERATOR = (
    "a coder runs only `terraform validate` and `terraform fmt -check`, the latter with "
    "-recursive and one folder inside your unit worktree at most, each under the kernel "
    "wrapper; init, plan and every other subcommand or fmt form stay with the operator "
    "(0158, 0164). Next: send one of those two forms, or yield the command to the operator."
)
R_WATCH = (
    "a watch option keeps the command running and never exits (0164). "
    "Next: drop the watch option and run the command once, under the kernel wrapper."
)


def _watch(arg: str) -> bool:
    # 0164: -w and every --watch spelling, with a value or a suffix (--watch=true, --watch-path).
    return arg == "-w" or arg.startswith("--watch")


def _tsc_option(arg: str) -> str:
    # 0164: tsc reads -watch, --watch and --Watch alike; the bare lowercase name, or "".
    return arg.lstrip("-").lower() if arg.startswith("-") else ""


def _first_positional(args: list[str], valued: frozenset[str] = frozenset()) -> int | None:
    # 0164: the first word that is not an option, nor the value of an option in valued.
    skip = False
    for idx, arg in enumerate(args):
        if skip:
            skip = False
        elif arg.startswith("-"):
            skip = arg in valued
        else:
            return idx
    return None


def js_inner(tokens: list[str]) -> list[str] | None:
    # 0164: the command a package manager runs as a bin (pnpm exec node, npx node, pnpm node).
    if not tokens or _base(tokens[0]) not in JS_LAUNCHERS:
        return None
    while tokens and _base(tokens[0]) in JS_LAUNCHERS:
        name, args = _base(tokens[0]), tokens[1:]
        first = _first_positional(args, _JS_VALUED)
        if first is None:
            return None
        if args[first] in _JS_EXEC:
            rest = [arg for arg in args[first + 1 :] if arg != "--"]
            start = _first_positional(rest)
            tokens = rest[start:] if start is not None else []
        elif name == "npm":
            return None
        else:
            tokens = args[first:]
    return tokens or None


def terraform_check(args: list[str]) -> tuple[str, ...] | None:
    # 0158, 0164: the coder's terraform allowlist; the fmt folder operands, or None when refused.
    rest = args[1:] if args[:1] and args[0].startswith("-chdir=") else args
    if rest == ["validate"]:
        return ()
    if rest[:1] != ["fmt"]:
        return None
    flags = [arg for arg in rest[1:] if arg.startswith("-")]
    paths = tuple(arg for arg in rest[1:] if not arg.startswith("-"))
    exact = len(flags) == len(set(flags)) and set(flags) <= TERRAFORM_FMT_FLAGS
    return paths if exact and "-check" in flags and len(paths) <= 1 else None


def python_script(tokens: list[str]) -> str | None:
    # B2: the script operand of `python3 <path> ...`; None for -m, -c, flags or no operand.
    if not tokens or _base(tokens[0]) not in {"python", "python3"}:
        return None
    args = tokens[1:]
    return args[0] if args and not args[0].startswith("-") else None


def confine_split(tokens: list[str]) -> tuple[str, list[str]] | None:
    # 0048: <wrapper> --unit <worktree> -- <command...>, the one form; None for any other.
    if len(tokens) < 5 or tokens[1] != "--unit" or tokens[3] != "--":
        return None
    return tokens[2], tokens[4:]


def confine_wrapper(word: str, base: str) -> bool:
    # 0048: the plugin's own wrapper by its real file; a copy in a worktree is not it.
    return _base(word) == CONFINE and command_path(word, base) == CONFINE_PATH


def _tester_runner_ok(
    name: str, tokens: list[str], own_script: Callable[[str], bool] | None = None
) -> bool:
    args = tokens[1:]
    if any(arg.startswith("--basetemp") for arg in args):
        return False
    if name in TEST_RUNNERS:
        # issue 91: an option before the lead (cargo +nightly test) fails closed as a test, bar
        # a WORKER_WRAPPERS name, where a match admits the command (node -e stays refused).
        forms = TEST_RUNNERS[name]
        if all(forms) and args and args[0][:1] in {"-", "+"} and name not in WORKER_WRAPPERS:
            return True
        return any(tuple(args[: len(form)]) == form for form in forms)
    if name == "npm":
        return bool(args) and (args[0] in NPM_TEST or (args[0] in NPM_RUN and len(args) > 1))
    if name in {"python", "python3"}:
        # B2, finding (c): a runner module, or a script own_script places in the coder's worktree.
        if args[:1] == ["-m"]:
            return len(args) > 1 and args[1] in RUNNER_MODULES
        script = python_script(tokens)
        return script is not None and own_script is not None and own_script(script)
    return False


def runner_row(tokens: list[str]) -> bool:
    # 0164: a TEST_RUNNERS form, after any wrapper; the kernel wrapper's read roots attach to it.
    inner = strip_wrappers(tokens) or tokens
    name = _base(inner[0]) if inner else ""
    return name in TEST_RUNNERS and _tester_runner_ok(name, inner)


def runner_refusal(tokens: list[str]) -> str | None:
    # 0164, 0158: a dev server, a watch mode or a terraform state change, bare or wrapped.
    inner = strip_wrappers(tokens) or tokens
    if not inner:
        return None
    name, args = _base(inner[0]), inner[1:]
    if name in {"pnpm", "npm", "npx"}:
        # 0164: a dev script anywhere, -- included; a tool it runs; a watch flag after the verb.
        if name != "npx" and DEV_SCRIPTS & set(args):
            return R_DEV_SERVER
        tool = next((i for i, arg in enumerate(args) if _base(arg) in _JS_TOOLS), None)
        refused = None if tool is None else runner_refusal(args[tool:])
        first = _first_positional(args, _JS_VALUED)
        if refused is None and name != "npx" and first is not None:
            refused = R_WATCH if any(_watch(arg) for arg in args[first + 1 :]) else None
        return refused
    head = args[: args.index("--")] if "--" in args else args
    watch = any(_watch(arg) for arg in head)
    if name == "node":
        return R_WATCH if watch else None
    if name == "vite":
        return None if head[:1] == ["build"] and not watch else R_DEV_SERVER
    if name == "vitest":
        return None if head[:1] == ["run"] and not watch else R_VITEST_WATCH
    if name == "tsc":
        options = [_tsc_option(arg) for arg in head]
        emit = "noemit" not in options or head[options.index("noemit") + 1 :][:1] == ["false"]
        watching = any(opt == "w" or opt.startswith("watch") for opt in options)
        return R_TSC if emit or watching else None
    if name == "terraform":
        if terraform_check(args) is not None:
            return None
        verbs = [arg for arg in args if not arg.startswith("-")]
        return (
            R_TERRAFORM_MUTATE
            if verbs[:1] and verbs[0] in TERRAFORM_MUTATE
            else (R_TERRAFORM_OPERATOR)
        )
    return None


def _exempt_indices(tokens: list[str]) -> set[int]:
    name = _base(tokens[0])
    if name in {"jq", "rg", "grep"}:
        return set(range(1, len(tokens)))
    exempt: set[int] = set()
    if name == "git":
        sub, args, _ = _git_split(tokens)
        offset = len(tokens) - len(args)
        if sub == "commit":
            exempt.update(offset + j + 1 for j, a in enumerate(args) if a in {"-m", "-am"})
    if name == "gh":
        # I7: file operands (--body-file, -F) are paths, so hygiene judges them.
        for j, token in enumerate(tokens):
            if token in {"--body", "--title", "-b", "-t"}:
                exempt.add(j + 1)
            if token.startswith(("--body=", "--title=")):
                exempt.add(j)
    return exempt


def _rsync_remote(args: list[str]) -> bool:
    # 0022: host:path and rsync:// are remote operands; -e/--rsh picks the program that runs.
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            return any(re.match(r"[^/]*:", a) for a in args[i + 1 :])
        if arg in _VALUE_LONG_NEXT or arg == "-f":
            i += 2
            continue
        if arg.startswith("--"):
            if arg.split("=", 1)[0] in {"--rsh", "--rsync-path"}:
                return True
        elif arg.startswith("-"):
            if "e" in arg.split("f", 1)[0]:
                return True
        elif re.match(r"[^/]*:", arg):
            return True
        i += 1
    return False


def _raw_words(raw: str) -> list[str]:
    # O4: the shell words of one raw segment with their quotes kept, aligned with shlex.split.
    words: list[str] = []
    buf: list[str] = []
    for lex in quote_walk(raw):
        if lex.kind == CHAR and not lex.quote and lex.text in " \t":
            if buf:
                words.append("".join(buf))
                buf = []
        else:
            buf.append(lex.text)
    if buf:
        words.append("".join(buf))
    return words


def _unsingled(word: str) -> str:
    # O4: the characters of a raw word the shell may still expand; single-quoted spans drop out.
    return "".join(
        lex.text for lex in quote_walk(word) if lex.quote != "'" and lex.kind not in {OPEN, CLOSE}
    )


def _unquoted(word: str) -> str:
    return "".join(
        lex.text[1:] if lex.kind == ESCAPE else lex.text
        for lex in quote_walk(word)
        if lex.kind not in {OPEN, CLOSE}
    )


def opaque_word(word: str) -> bool:
    # prepush2-2026-10-27: bash rewrites the word ($'-uu', $X, {-u,}, a leading glob) unseen.
    if set("$`") & set(_unsingled(word)):
        return True
    bare = [lex for lex in quote_walk(word) if lex.kind == CHAR and not lex.quote]
    if any(lex.text in "{}" for lex in bare):
        return True
    if not any(lex.text in _GLOB_CHARS for lex in bare):
        return False
    # prepush2-2026-10-27: a glob can expand to a planted file named like a flag.
    lead = next((lex for lex in quote_walk(word) if lex.kind not in {OPEN, CLOSE}), None)
    leading = lead is not None and lead in bare and lead.text in _GLOB_CHARS
    return _unquoted(word).startswith("-") or leading


SEARCH_CMDS = frozenset({"rg", "grep", "egrep", "fgrep"})


def search_opaque(command: str) -> bool:
    # prepush2-2026-10-27: a search segment holding a word bash rewrites may hide a reach flag.
    for raw in _raw_segments(command):
        words = _raw_words(raw)
        if any(_base(_unquoted(w)) in SEARCH_CMDS for w in words) and any(
            opaque_word(w) for w in words
        ):
            return True
    return False


def _hygiene_bad(token: str, word: str | None) -> bool:
    # O4: judge the raw span when it is known, else the shlex token as before.
    text = token if word is None else _unsingled(word)
    lead = token if word is None else word
    return bool(_HYGIENE_CHARS & set(text)) or lead.startswith("~")


def command_path(word: str, base: str) -> str:
    # issue 55: the real file a command word runs; a bare name resolves through PATH.
    if "/" in word:
        return os.path.realpath(_abs(word, base))
    return os.path.realpath(shutil.which(word) or word)


@lru_cache(maxsize=4)
def _claude_real(search_path: str) -> str | None:
    found = shutil.which("claude", path=search_path)
    return os.path.realpath(found) if found else None


def runs_claude(tokens: list[str], base: str) -> bool:
    # issue 55: the command word, the word past wrappers or node's script, by name or real file.
    stripped = strip_wrappers(tokens) or []
    words = tokens[:1] + stripped[:1]
    if stripped and _base(stripped[0]) == "node":
        words += [a for a in stripped[1:] if not a.startswith("-")][:1]
    real = _claude_real(os.environ.get("PATH", os.defpath))
    return any(
        _base(w) == "claude" or (real is not None and command_path(w, base) == real) for w in words
    )


def _path_trusted(
    word: str, base: str, own_script: Callable[[str], bool], tools: frozenset[str]
) -> bool:
    # issue 55: a path command word sits in a system bin folder, a unit worktree or the manifest.
    if "/" not in word:
        return True
    full = os.path.normpath(_abs(word, base))
    trusted_bin = os.path.isabs(full) and os.path.dirname(full) in _TRUSTED_BIN
    return trusted_bin or own_script(word) or os.path.realpath(full) in tools


def _worker_hygiene(
    tokens: list[str],
    agent: str,
    words: list[str] | None = None,
    own_script: Callable[[str], bool] | None = None,
    base: str = "",
    tools: frozenset[str] = frozenset(),
) -> str | None:
    if _ASSIGN.match(tokens[0]):
        return R_ENV
    if runs_claude(tokens, base):
        return R_CLAUDE_PATH
    wraps = own_script is not None or agent == "terraform-reviewer"
    if wraps and _base(tokens[0]) == CONFINE:
        # 0048, 0158: a coder's or the terraform reviewer's wrapped command is judged as if bare.
        split = confine_split(tokens)
        if split is None or not confine_wrapper(tokens[0], base):
            return R_CONFINE_FORM
        cut = len(tokens) - len(split[1])
        aligned = list(words) if words and len(words) == len(tokens) else []
        if _hygiene_bad(tokens[2], aligned[2] if aligned else None):
            return R_HYGIENE
        inner = aligned[cut:] if aligned else None
        return _worker_hygiene(split[1], agent, inner, own_script, base, tools)
    # issue 55: own_script marks the coder, the one worker whose path commands are judged here.
    if own_script is not None and not _path_trusted(tokens[0], base, own_script, tools):
        return R_UNTRUSTED_PATH
    name = _base(tokens[0])
    inner = strip_wrappers(tokens) or tokens
    if {name, _base(inner[0])} & ARCHIVE_CMDS:
        return R_ARCHIVE
    allexport = any(re.fullmatch(r"-[a-zA-Z]*a[a-zA-Z]*|allexport", t) for t in tokens[1:])
    if name in SHELL_VAR_CMDS or (name == "set" and allexport):
        return R_SHELL_VARS
    if name in SHELL_STATE_CMDS or (name == "printf" and any(t.startswith("-v") for t in tokens)):
        return R_SHELL_STATE
    if name == "rsync" and _rsync_remote(tokens[1:]):
        return R_RSYNC_REMOTE
    if name == "find" and any(a in _FIND_DENY or a.startswith("-fprint") for a in tokens[1:]):
        return R_FIND_WRITE
    exempt = _exempt_indices(tokens)
    ledger = agent == "charter-docs" and _is_append_ledger(tokens)
    if ledger:
        exempt.add(1)
    if agent == "orchestrator" and name == "python3":  # 0060, pin B6 -> B4: security exception.
        from checks.command_allowlist import train_script_ok

        ledger = train_script_ok(tokens)
    if agent == "coder" and own_script is not None and _is_cite(tokens, own_script):
        ledger = True  # RCP, 0128: the coder's citation helper; its hygiene check still runs.
    is_wrapper = name in WORKER_WRAPPERS or name.startswith("python")
    if (
        agent == "charter-docs"
        and name == "python3"
        and "CLAUDE_PLUGIN_ROOT" in (tokens[1] if len(tokens) > 1 else "")
    ):
        return R_LEDGER_LITERAL
    if is_wrapper and not ledger and not _tester_runner_ok(name, tokens, own_script):
        return R_INLINE
    # 0164: pnpm exec node -e, npx node <file> and the like meet the interpreter rule too.
    bin_run = js_inner(tokens)
    if bin_run and _base(bin_run[0]) in WORKER_WRAPPERS:
        if not _tester_runner_ok(_base(bin_run[0]), bin_run, own_script):
            return R_INLINE
    spans: list[str | None] = list(words) if words and len(words) == len(tokens) else []
    for idx, token in enumerate(tokens):
        word = spans[idx] if spans else None
        if idx not in exempt and _hygiene_bad(token, word):
            return R_HYGIENE
    sub, args, globals_ = _git_split(tokens)
    if _git_config_override(globals_):
        return R_GIT_CONFIG
    if sub == "config":
        flags = [a for a in args if a.startswith("-")]
        if flags not in (["--get"], ["--list"]):
            return R_GIT_CONFIG
    return None

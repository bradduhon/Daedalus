# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import fnmatch
import itertools
import os
import re
import shlex
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from lib.audit import _git_env, project_data_dir, project_root
from lib.config import Config
from lib.ledger import LedgerError, resolve_ledger
from lib.workspace import train_marker

KNOWN_AGENTS = frozenset(
    {
        "main",
        "repo-coder",
        "contract-spec",
        "charter-docs",
        "security-auditor",
        "nist-specialist",
        "cis-specialist",
        "pr-train-conductor",
        "web-researcher",
        "standards-rules-specialist",
        "boundary-tester",
    }
)
WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})
WEB_TOOLS = frozenset({"WebFetch", "WebSearch"})
# 5.5: all routing is through Fable; workers never message each other.
WORKER_DENIED_TOOLS = frozenset({"Task", "Agent", "SendMessage"})
# spec 8, 0020: credential stores refused to every agent, main included; denyRead is layer two.
CREDENTIAL_DENY = (".ssh", ".aws", ".gnupg", ".config/gh", ".claude/.credentials.json")
# 0023: these tools carry only the credential deny, for every agent known or not.
CREDENTIAL_TOOLS = frozenset({"Read", "Glob", "Grep"})

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
READ_ONLY_GIT = frozenset({"diff", "log", "show", "status", "rev-parse", "ls-files", "branch"})
SPECIALIST_GIT = frozenset({"diff", "show", "log"})
# M1: charter-docs git is add/commit/status/log/diff only (4.2); no merge, no worktree.
CHARTER_DOCS_GIT = frozenset({"add", "commit", "status", "log", "diff"})
CONDUCTOR_GIT = frozenset({"push", "status", "log", "rev-parse", "branch", "diff", "add", "commit"})
TESTER_GIT = frozenset({"add", "commit", "status", "diff"})
# Final review I1: transport plumbing and credential helpers reach remotes without push.
GIT_PLUMBING_REMOTE = frozenset(
    {"send-pack", "http-push", "receive-pack", "upload-pack", "fetch-pack"}
    | {"credential", "credential-store", "credential-cache"}
)
REMOTE_GIT = (
    frozenset({"push", "remote", "fetch", "pull", "clone", "ls-remote", "submodule"})
    | GIT_PLUMBING_REMOTE
)
# Final review I3a: repo-coder git is an allowlist; everything else blocks.
CODER_GIT = frozenset(
    {"add", "commit", "status", "diff", "log", "show", "rev-parse", "ls-files", "branch"}
    | {"stash", "restore", "checkout", "worktree", "config"}
)
# Final review I3b: commands whose operands are write targets for repo-coder.
CODER_WRITE_CMDS = frozenset(
    {"cp", "mv", "tee", "install", "ln", "truncate", "rsync", "dd"}
    | {"mkdir", "touch", "rm", "rmdir", "unlink", "chmod", "chown", "chgrp"}
)
# 0022: options whose value is not a path; every other non-option operand is a path.
_VALUE_OPTS: dict[str, frozenset[str]] = {
    "install": frozenset({"-m", "-o", "-g", "-S"}),
    "mkdir": frozenset({"-m"}),
    "truncate": frozenset({"-s"}),
    "touch": frozenset({"-d", "-t"}),
    "cp": frozenset({"-S"}),
    "mv": frozenset({"-S"}),
    "ln": frozenset({"-S"}),
    "rsync": frozenset({"-f"}),
}
# 0022: short options whose attached or following value is a path operand (-t<dir>).
_PATH_OPTS: dict[str, frozenset[str]] = {
    "cp": frozenset({"-t"}),
    "mv": frozenset({"-t"}),
    "install": frozenset({"-t"}),
    "ln": frozenset({"-t"}),
    "touch": frozenset({"-r"}),
    "truncate": frozenset({"-r"}),
}
# 0022: long options whose =x or next-token value is not a path; --preserve takes =x only.
_VALUE_LONG_NEXT = frozenset(
    {"--mode", "--owner", "--group", "--suffix", "--size", "--date", "--from", "--chmod"}
    | {"--exclude", "--include", "--filter", "--exclude-from", "--include-from"}
)
_VALUE_LONG = _VALUE_LONG_NEXT | {"--preserve"}
_MODE = re.compile(r"(?:[0-7]{3,4}|[ugoa]*[-+=][rwxXstugo]*)(?:,[ugoa]*[-+=][rwxXstugo]*)*")
# 0022: shell state a worker could carry into a later segment (GIT_WORK_TREE and kin).
SHELL_VAR_CMDS = frozenset({"export", "declare", "typeset", "readonly", "local"})
# 0022: builtins that rebind what a later segment runs (hash pytest=/bin/rm).
SHELL_STATE_CMDS = frozenset(
    {"hash", "alias", "unalias", "unset", "shopt", "enable", "setopt", "unsetopt"}
    | {"trap", "getopts"}
)
DIR_CHANGE_CMDS = frozenset({"cd", "pushd", "popd"})
NETWORK_TOOLS = frozenset({"curl", "wget", "ssh", "scp", "nc", "ncat", "telnet", "aws", "gh"})
GH_ALLOWED = {
    "pr": frozenset({"create", "edit", "view", "checks", "status", "list", "comment", "diff"}),
    "run": frozenset({"list", "view", "watch"}),
}
# 8.5 ruling A: first tokens a worker may never run, bar the allowlisted test runner forms.
WORKER_WRAPPERS = frozenset(
    {"env", "nice", "nohup", "stdbuf", "timeout", "exec", "eval", "xargs", "command"}
    | {"builtin", "source", ".", "sh", "bash", "zsh", "dash", "ksh", "python", "python3"}
    | {"node", "perl", "ruby", "sudo", "doas", "time"}
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
# (no-argument options, options taking one argument) per wrapper; anything else falls back.
_WRAPPER_OPTS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
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
_BRANCH_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")
_DEFAULT_BRANCHES = frozenset({"main", "master"})
# 8.5, F1: the plugin's scripts dir; append_ledger.py runs only by this absolute path.
_REPO_SCRIPTS = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
_FALLBACK = "\x00fallback"
# F1: the variable is empty in agent Bash, so the literal form never reaches the script.
R_LEDGER_LITERAL = (
    "${CLAUDE_PLUGIN_ROOT} is empty in agent Bash. "
    f"Next: run python3 {os.path.join(_REPO_SCRIPTS, 'append_ledger.py')} with the same arguments."
)
# Plugin agents arrive as <plugin>:<agent>; only these prefixes unwrap.
AGENT_NAMESPACES = ("daedalus",)
# tests/fixtures/live-agent namespace; accepted only when DAEDALUS_LIVE_TEST=1.
TEST_NAMESPACE = "daedalus-probe"
R_NAMESPACED_MAIN = "a namespaced agent may not claim the orchestrator role. Next: name the agent."

R_UNSUPPORTED = (
    "command uses an unsupported shell construct (newline, background &, ||, substitution, "
    "redirect, grouping, or |&). Next: send one plain command, or pipe read-only filters only."
)
R_PIPE = "pipes are not permitted for this agent. Next: send one plain command."
R_NO_CWD = "hook received no absolute cwd; failing closed. Next: report to the operator."
R_TOOL = "workers use only their allowlisted tools. Next: ask Fable."
R_DOTGIT = "writes into .git/ are never permitted. Next: change the repository through git."
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
R_CODER_UNIT_GIT = (
    "repo-coder git add and commit run only inside your unit worktree. "
    "Next: use git -C <your unit worktree> add/commit."
)
R_CD_RELATIVE = (
    "a chain that changes directory may not use relative write paths or pathspecs: {}. "
    "Next: use absolute paths (or an absolute git -C) after cd."
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
R_CLEAN = "git clean is never run by any Fable component. Next: remove files by name."
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
R_CONDUCTOR_PUSH = (
    "the conductor pushes one named branch to origin, nothing else (0001). "
    "Next: `git push -u origin <branch>`."
)
R_GIT_PLUMBING = (
    "git transport plumbing and credential helpers are not run from a session. "
    "Next: use git push or git fetch by name."
)
R_CODER_GIT = (
    "repo-coder git is limited to add, commit, status, diff, log, show, rev-parse, ls-files, "
    "branch listing, stash list/push/pop/show, "
    "restore/checkout -- <unit worktree src|tests paths>, "
    "worktree list. Next: use those only; the trains handle the rest."
)
R_DATA_DIR = (
    "the plugin data directory is written by hooks only. "
    "Next: edit <repo>/.claude/daedalus/config.json from your own shell."
)
R_DATA_DIR_GIT = (
    "the plugin data directory is never committed. Next: leave .claude/daedalus out of git."
)
R_SUBAGENT_MAIN = "a subagent may not run as main. Next: name the agent."
R_CONDUCTOR_REPO = "the conductor works in the current repo only. Next: cd to the repo and omit -R."
R_BODY_FILE = (
    "gh --body-file/-F must name a file under docs/.tmp/ or /tmp. "
    "Next: write the body to docs/.tmp/ and pass that path."
)
R_BODY_INLINE = (
    "gh pr create/edit/comment take the body only from --body-file, never --body or -b. "
    "Next: write the body to docs/.tmp/ and pass --body-file <path>."
)
R_EDIT_BASE = (
    "gh pr edit may not change the base branch. "
    "Next: report the base mismatch; the operator retargets the pull request."
)
R_GITLEAKS = (
    "conductor gitleaks runs only as gitleaks detect --redact, any report path under /tmp. "
    "Next: rerun it as gitleaks detect --redact --log-opts=<base>..<branch>."
)
R_LEDGER_DIRECT = (
    "the ledger is written only through append_ledger.py. "
    "Next: write the entry to docs/.tmp/ and run append_ledger.py."
)
R_DOCS_BASH = (
    "charter-docs Bash is limited to append_ledger.py, git add <path>, git commit -m, "
    "git status, git log and git diff. Next: use those only; the main session runs the rest."
)
R_CREDENTIAL = (
    "{path} is a credential path. "
    "Next: Daedalus never reads credentials; use the tool that needs them from your own shell"
)
R_UNKNOWN = (
    "unknown agent_type '{agent}', fail closed. Next: add the agent to the jail before using it."
)
_CREDENTIAL_SPLIT = re.compile(r"[\s;&|()<>`]+")
_CREDENTIAL_PART = re.compile(r"[=:,]")
_GLOB_START = re.compile(r"[*?\[{]")
_BRACE = re.compile(r"\{[^}]*\}")
_BARE_CD = re.compile(r"(?:^|[;&|(\s])(?:cd|pushd)\s*(?:$|[;&|)])")
_DATA_DIR_DEFAULT = "/.claude/plugins/data/daedalus"
_PROJECT_DATA = ".claude/daedalus"
UNIT_WORKTREES = ".claude/worktrees"
_GLOB_CHARS = frozenset("*?[")
_DATA_DIR_WRITE = re.compile(
    r">|(?:^|[\s;&|(/])(?:tee|rm|mv|cp|truncate|touch|ln|mkdir|chmod|chown|install|rmdir)"
    r"(?=[\s;&|)]|$)"
    r"|\bsed\b[^;&|\n]*\s(?:-[a-zA-Z]*i|--in-place)|\bpython[\d.]*\b[^;&|\n]*\s-[a-zA-Z]*c"
)
_DEVNULL = re.compile(r"\d?>&\d|&?\d?>>?\s*/dev/null")
_CD_TARGET = re.compile(r"(?:^|[;&|(\s])(?:cd|pushd)\s+([^\s;&|)]+)")
_DAEDALUS_WORD = re.compile(r"(?<![\w.-])daedalus(?![\w-])")
_GIT_INDEX_WRITE = re.compile(r"\bgit\b[^;&|]*\b(?:add|stage|commit|update-index)\b")
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


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str | None = None
    agent: str | None = None


def _allow() -> Decision:
    return Decision(True, None)


def _block(reason: str) -> Decision:
    return Decision(False, reason)


def _under(path: str, root: str) -> bool:
    real_path = os.path.realpath(path)
    real_root = os.path.realpath(root)
    return real_path == real_root or real_path.startswith(real_root + os.sep)


def _abs(path: str, cwd: str) -> str:
    return path if os.path.isabs(path) else os.path.join(cwd, path)


def _scan(command: str) -> tuple[list[str], list[str]] | None:
    raws: list[str] = []
    seps: list[str] = []
    buf: list[str] = []
    quote = ""
    i = 0
    while i < len(command):
        char = command[i]
        if quote == "'":
            buf.append(char)
            quote = "" if char == "'" else quote
            i += 1
            continue
        if char == "\\":
            if command[i + 1 : i + 2] in {"\n", "\r"}:
                return None
            buf.append(command[i : i + 2])
            i += 2
            continue
        if quote == '"':
            if char == "`" or command.startswith("$(", i):
                return None
            buf.append(char)
            quote = "" if char == '"' else quote
            i += 1
            continue
        if char in "'\"":
            quote = char
            buf.append(char)
            i += 1
            continue
        if char in "\n\r`<>()" or command.startswith("$(", i) or command.startswith("|&", i):
            return None
        pair = command[i : i + 2]
        if pair in {"&&", "||"}:
            seps.append(pair)
            raws.append("".join(buf))
            buf = []
            i += 2
            continue
        if char == "&":
            return None
        if char in "|;":
            seps.append(char)
            raws.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(char)
        i += 1
    if quote:
        return None
    raws.append("".join(buf))
    return raws, seps


def tokenize(command: str) -> list[list[str]] | None:
    scanned = _scan(command)
    if scanned is None:
        return None
    segments: list[list[str]] = []
    for raw in scanned[0]:
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


def split_pipeline(command: str) -> list[str] | None:
    """Thin wrapper over the scanner: raw stages of a pure `|` pipeline, else None."""
    scanned = _scan(command)
    if scanned is None or tokenize(command) is None or any(sep != "|" for sep in scanned[1]):
        return None
    return [raw.strip() for raw in scanned[0]]


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
    out: list[str] = []
    i = 0
    while i < len(text):
        char = text[i]
        if char == "\\":
            out.append(text[i : i + 2])
            i += 2
            continue
        if char not in "'\"":
            out.append(char)
            i += 1
            continue
        j = i + 1
        while j < len(text) and text[j] != char:
            j += 2 if char == '"' and text[j] == "\\" else 1
        out.append("Q")
        i = j + 1
    return "".join(out)


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
    quote = ""
    i = 0
    while i < len(text):
        char = text[i]
        if char == "\\" and quote != "'":
            buf.append(text[i : i + 2])
            i += 2
            continue
        if quote:
            quote = "" if char == quote else quote
        elif char in "'\"":
            quote = char
        elif char in ";&|\n\r()":
            segments.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(char)
        i += 1
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
            or ("timeout" in wrapper and re.fullmatch(r"[\d.]+[smhd]?", tokens[0]))
        ):
            if _word_parts(tokens[0]) & _WRAPPER_OPTS.keys():
                wrapper = _word_parts(tokens[0]) & _WRAPPER_OPTS.keys()
                with_arg = _WRAPPER_OPTS[min(wrapper)][1]
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


def _strip_wrappers(tokens: list[str], assigns: list[str]) -> list[str] | None:
    while tokens:
        while tokens and _ASSIGN.match(tokens[0]):
            assigns.append(tokens[0])
            tokens = tokens[1:]
        if not tokens or _base(tokens[0]) not in _WRAPPER_OPTS:
            return tokens
        name = _base(tokens[0])
        no_arg, with_arg = _WRAPPER_OPTS[name]
        i = 1
        while i < len(tokens):
            token = tokens[i]
            key = token.split("=", 1)[0]
            if token == "--":
                i += 1
                break
            if name == "env" and _ASSIGN.match(token):
                assigns.append(token)
            elif not token.startswith("-") or token == "-" and name != "env":
                break
            elif key in no_arg or (key in with_arg and "=" in token):
                pass
            elif token in with_arg:
                i += 1
            elif token[:2] in with_arg or (name == "nice" and re.fullmatch(r"-\d+", token)):
                pass
            elif name == "command" and token in {"-v", "-V"}:
                return []
            else:
                return None
            i += 1
        if name == "timeout" and i < len(tokens):
            i += 1
        tokens = tokens[i:]
    return tokens


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


def _flags_ok(
    args: list[str],
    plain: frozenset[str] = frozenset(),
    prefixes: tuple[str, ...] = (),
    patterns: tuple[str, ...] = (),
    with_arg: frozenset[str] = frozenset(),
    positional: bool = True,
) -> bool:
    i = 0
    after_dashes = False
    while i < len(args):
        arg = args[i]
        if after_dashes or not arg.startswith("-") or arg == "-":
            if not positional:
                return False
        elif arg == "--":
            after_dashes = True
        elif arg in with_arg and i + 1 < len(args):
            i += 1
        elif not (
            arg in plain
            or (prefixes and arg.startswith(prefixes))
            or any(re.fullmatch(p, arg) for p in patterns)
        ):
            return False
        i += 1
    return True


def _commit_ok(args: list[str], cwd: str) -> bool:
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in {"-q", "--quiet", "-a"}:
            i += 1
        elif arg == "--":
            return not _has_magic(args[i + 1 :])
        elif arg in {"-m", "-am"} and i + 1 < len(args):
            i += 2
        elif (
            arg == "-F" and i + 1 < len(args) and _under(_abs(args[i + 1], cwd), f"{cwd}/docs/.tmp")
        ):
            i += 2
        else:
            return False
    return True


@lru_cache(maxsize=32)
def _registered_worktrees(repo: str) -> frozenset[str]:
    cmd = ["git", "-C", repo, "worktree", "list", "--porcelain"]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=2, env=_git_env(), check=False
        )
    except (OSError, subprocess.SubprocessError):
        return frozenset()
    if out.returncode != 0:
        return frozenset()
    lines = out.stdout.splitlines()
    return frozenset(os.path.realpath(x[9:]) for x in lines if x.startswith("worktree "))


def _unit_parts(target: str, cwd: str) -> list[str] | None:
    # 0022: train-made unit worktrees sit at <repo>/.claude/worktrees/<name>, git-registered.
    repo = os.path.realpath(str(project_root(cwd)))
    base = os.path.join(repo, UNIT_WORKTREES)
    parts = os.path.relpath(os.path.realpath(target), base).split(os.sep)
    if parts[0] in {os.curdir, os.pardir}:
        return None
    return parts if os.path.join(base, parts[0]) in _registered_worktrees(repo) else None


def _in_unit_worktree_code(target: str, cwd: str) -> bool:
    parts = _unit_parts(target, cwd)
    return parts is not None and len(parts) >= 2 and parts[1] in {"src", "tests"}


def _in_code_dirs(arg: str, cwd: str) -> bool:
    target = _abs(arg, cwd)
    return (
        _under(target, f"{cwd}/src")
        or _under(target, f"{cwd}/tests")
        or _in_unit_worktree_code(target, cwd)
    )


def _pathspec_ok(args: list[str], cwd: str, base: str | None = None) -> bool:
    # I3a, 0022 P3: `-- <unit worktree src|tests paths>`; relative ones resolve against -C (base).
    root = cwd if base is None else base
    return (
        len(args) > 1
        and args[0] == "--"
        and not _has_magic(args[1:])
        and all(_in_unit_worktree_code(_abs(a, root), cwd) for a in args[1:])
    )


def _has_magic(pathspecs: list[str]) -> bool:
    # 0022: :/ and :(top) are worktree-top relative, so the jail refuses every magic form.
    return any(p.startswith(":") for p in pathspecs)


def _stash_ok(args: list[str]) -> bool:
    if args[:1] == ["list"]:
        return len(args) == 1
    if args[:1] in (["pop"], ["show"]):
        return len(args) <= 2 and not any(a.startswith("-") for a in args[1:])
    if args[:1] == ["push"]:
        rest = args[1:]
        return rest == [] or (len(rest) == 2 and rest[0] == "-m")
    return False


def _config_read_ok(args: list[str]) -> bool:
    return args[:1] in (["--get"], ["--list"]) and not any(a.startswith("-") for a in args[1:])


_FORMAT = ("--format=", "--pretty=")
# F3b: read-only status forms; -sb style bundles match the pattern in the grammar.
_STATUS_FLAGS = frozenset(
    {"--short", "--branch", "--porcelain", "--porcelain=v1", "--porcelain=v2", "--show-stash"}
)
_GIT_GRAMMAR: dict[str, Callable[[list[str], str], bool]] = {
    "status": lambda a, _: _flags_ok(a, _STATUS_FLAGS, (), (r"-[sb]+",)),
    "log": lambda a, _: _flags_ok(
        a,
        frozenset({"--oneline", "--stat", "--name-only", "-p", "--no-merges", "--all"}),
        (*_FORMAT, "--grep=", "--author="),
        (r"-\d+", r"-n\d+"),
        frozenset({"-n", "-S", "-G"}),
    ),
    "diff": lambda a, _: _flags_ok(
        a,
        frozenset(
            {"--stat", "--name-only", "--name-status", "--cached", "--word-diff", "--color=never"}
        ),
        (),
        (r"-U\d+",),
    ),
    "show": lambda a, _: _flags_ok(a, frozenset({"--stat", "--name-only"}), _FORMAT),
    "rev-parse": lambda a, _: _flags_ok(
        a,
        frozenset({"--short", "--abbrev-ref", "--is-inside-work-tree", "--show-toplevel"}),
        ("--short=",),
    ),
    "ls-files": lambda a, _: _flags_ok(a, frozenset({"-z"})),
    "branch": lambda a, _: _flags_ok(
        a, frozenset({"-a", "-r", "-v", "--list", "--show-current"}), positional=False
    ),
    "add": lambda a, _: _flags_ok(a, frozenset({"-A", "-u", "--all"})) and not _has_magic(a),
    "commit": lambda a, cwd: _commit_ok(a, cwd),
    "merge": lambda a, _: _flags_ok(a, frozenset({"--no-ff"}), with_arg=frozenset({"-m"})),
    "worktree": lambda a, _: a[:1] == ["list"] and all(x == "--porcelain" for x in a[1:]),
    "stash": lambda a, _: _stash_ok(a),
    "restore": _pathspec_ok,
    "checkout": _pathspec_ok,
    "config": lambda a, _: _config_read_ok(a),
}


def _git_grammar_ok(
    tokens: list[str],
    subs: frozenset[str],
    cwd: str,
    charter: str | None,
    grammar: dict[str, Callable[[list[str], str], bool]] | None = None,
) -> bool:
    grammar = _GIT_GRAMMAR if grammar is None else grammar
    sub, args, globals_ = _git_split(tokens)
    if sub not in subs or sub not in grammar:
        return False
    i = 0
    while i < len(globals_):
        flag = globals_[i]
        if flag == "--no-pager":
            i += 1
            continue
        if flag == "-C" and i + 1 < len(globals_):
            target = _abs(globals_[i + 1], cwd)
            if _under(target, cwd) or (charter is not None and _under(target, charter)):
                i += 2
                continue
        return False
    if grammar[sub] is _pathspec_ok:
        return _pathspec_ok(args, cwd, _git_dir(globals_, cwd))
    return grammar[sub](args, cwd)


def _git_dir(globals_: list[str], cwd: str) -> str:
    # 0022 P3: git chains each -C onto the previous one.
    base = cwd
    for i in range(len(globals_) - 1):
        if globals_[i] == "-C":
            base = _abs(globals_[i + 1], base)
    return base


def _docs_add_ok(args: list[str], _: str) -> bool:
    # M1: explicit paths only; no -A, no ".", no globs or pathspec magic.
    paths = args[1:] if args[:1] == ["--"] else args
    return bool(paths) and all(
        not p.startswith(("-", ":"))
        and not _GLOB_CHARS & set(p)
        and not {".", ".."} & set(p.split("/"))
        and not p.endswith("/")
        for p in paths
    )


_DOCS_GRAMMAR: dict[str, Callable[[list[str], str], bool]] = {
    "add": _docs_add_ok,
    "commit": lambda a, _: len(a) == 2 and a[0] == "-m",
    "status": _GIT_GRAMMAR["status"],
    "log": _GIT_GRAMMAR["log"],
    "diff": _GIT_GRAMMAR["diff"],
}


def _conductor_push_ok(tokens: list[str]) -> bool:
    sub, args, globals_ = _git_split(tokens)
    if sub != "push" or globals_:
        return False
    if args[:1] in (["-u"], ["--set-upstream"]):
        args = args[1:]
    return (
        len(args) == 2
        and args[0] == "origin"
        and bool(_BRANCH_NAME.fullmatch(args[1]))
        and args[1].casefold() not in _DEFAULT_BRANCHES
    )


def _read_only_segment(
    tokens: list[str], git_subcommands: frozenset[str], cwd: str, charter: str | None
) -> bool:
    name = _cmd_name(tokens)
    args = tokens[1:]
    if name == "git":
        return _git_grammar_ok(tokens, git_subcommands, cwd, charter)
    if name not in READ_ONLY_CMDS:
        return False
    if name == "find":
        return not any(arg in _FIND_DENY or arg.startswith("-fprint") for arg in args)
    if name == "sort":
        return not any(
            _long_matches(arg, "--output", 1)
            or _long_matches(arg, "--compress-program", 2)
            or _long_matches(arg, "--temporary-directory", 1)
            or {"o", "T"} & _short_flags(arg)
            for arg in args
        )
    if name == "rg":
        return not any(arg.split("=", 1)[0] in {"--pre", "--pre-glob"} for arg in args)
    if name == "uniq":
        # 8.5: uniq writes its second positional operand.
        return len([arg for arg in args if not arg.startswith("-")]) <= 1
    if name == "file":
        return not any(arg == "--compile" or "C" in _short_flags(arg) for arg in args)
    return True


R_LEDGER_ARGS = (
    "append_ledger takes only --probe, or --expected-seq, --entry-file, --repo and --type "
    "once each with a value. Next: run append_ledger from the repo whose ledger you are "
    "appending to; --cwd is for operators."
)
_LEDGER_VALUE_FLAGS = frozenset({"--expected-seq", "--entry-file", "--repo", "--type"})
_LEDGER_SHELL_CHARS = frozenset("*?[{$`")


def _ledger_args_ok(tokens: list[str]) -> bool:
    # 0004: allowlist, not a denylist; a glob like --cw? expands to --cwd after the jail.
    args = tokens[2:]
    if any(_LEDGER_SHELL_CHARS & set(arg) for arg in args):
        return False
    if args == ["--probe"]:
        return True
    seen: set[str] = set()
    i = 0
    while i < len(args):
        flag, eq, value = args[i].partition("=")
        if not eq:
            if i + 1 >= len(args):
                return False
            value = args[i + 1]
            i += 1
        i += 1
        if flag not in _LEDGER_VALUE_FLAGS or flag in seen or not value or value.startswith("-"):
            return False
        seen.add(flag)
    return seen == _LEDGER_VALUE_FLAGS


def _is_append_ledger(tokens: list[str]) -> bool:
    if len(tokens) < 2 or tokens[0] != "python3":
        return False
    script = tokens[1]
    if not script.startswith("/") or ".." in script.split("/"):
        return False
    return os.path.realpath(script) == os.path.join(_REPO_SCRIPTS, "append_ledger.py")


def _gh_allowed(tokens: list[str]) -> bool:
    words = _gh_words(tokens)
    return len(words) == 2 and words[1] in GH_ALLOWED.get(words[0], frozenset())


_GH_PR_WRITES = frozenset({"create", "edit", "comment"})


def _gh_words(tokens: list[str]) -> list[str]:
    words: list[str] = []
    i = 1
    while i < len(tokens) and len(words) < 2:
        token = tokens[i]
        if token in {"-R", "--repo"}:
            i += 2
            continue
        if not token.startswith(("--repo=", "-R")):
            words.append(token)
        i += 1
    return words


def _gh_pr_write(tokens: list[str]) -> bool:
    words = _gh_words(tokens)
    return words[:1] == ["pr"] and words[1:2] != [] and words[1] in _GH_PR_WRITES


def _gh_repo_flag(tokens: list[str]) -> bool:
    # I7: reads may name another repo; pr writes stay in the current one.
    return _gh_pr_write(tokens) and any(
        t in {"-R", "--repo"} or t.startswith(("--repo=", "-R")) for t in tokens[1:]
    )


def _gh_body_file_ok(tokens: list[str], cwd: str) -> bool:
    if not _gh_pr_write(tokens):
        return True
    for i, token in enumerate(tokens):
        if token in {"--body-file", "-F"}:
            value = tokens[i + 1] if i + 1 < len(tokens) else ""
        elif token.startswith("--body-file="):
            value = token.split("=", 1)[1]
        elif token.startswith("-F") and len(token) > 2:
            value = token[2:]
        else:
            continue
        # I7: stdin (-) and relative-to-elsewhere paths fail; realpath under the two homes only.
        if value in {"", "-"} or not (
            _under(_abs(value, cwd), f"{cwd}/docs/.tmp") or _under(_abs(value, cwd), "/tmp")
        ):
            return False
    return True


def _gh_has_body_file(tokens: list[str]) -> bool:
    return any(
        t in {"--body-file", "-F"} or t.startswith(("--body-file=", "-F")) for t in tokens[1:]
    )


def _gh_short_has(token: str, letter: str) -> bool:
    # I3: a pflag short bundle (-db x) carries the flag too; an -F value is a path, not a bundle.
    if not re.match(r"-[A-Za-z]", token) or token.startswith("-F"):
        return False
    return letter in token[1:]


def _gh_write_reason(tokens: list[str]) -> str | None:
    if not _gh_pr_write(tokens):
        return None
    for token in tokens[1:]:
        if token in {"--body", "-b"} or token.startswith("--body=") or _gh_short_has(token, "b"):
            return R_BODY_INLINE
    if not _gh_has_body_file(tokens):
        return R_BODY_INLINE
    if _gh_words(tokens)[1] == "edit" and any(
        t == "--base" or t.startswith("--base=") or _gh_short_has(t, "B") for t in tokens[1:]
    ):
        return R_EDIT_BASE
    return None


def _ledger_write_reason(path: str, cwd: str, config: Config) -> str | None:
    # I1: protect the ledger append_ledger resolves (manifest, config, probe); fail closed.
    try:
        resolved = resolve_ledger(cwd, config)
    except LedgerError as exc:
        return f"the ledger could not be resolved, so charter-docs writes fail closed: {exc}"
    default = project_root(cwd) / "docs" / "decisions.md"
    protected = {str(resolved.path)} if resolved is not None else set()
    if default.is_file():
        protected.add(str(default))
    return R_LEDGER_DIRECT if any(_same_path(path, p) for p in protected) else None


def _same_path(target: str, protected: str) -> bool:
    # FW-I1: case-insensitive mounts are in scope; samefile if it exists, else casefolded realpath.
    if os.path.exists(target):
        try:
            return os.path.samefile(target, protected)
        except OSError:
            return False
    return os.path.realpath(target).casefold() == os.path.realpath(protected).casefold()


def _in_place(name: str, args: list[str]) -> bool:
    for arg in args:
        if name == "sed" and (arg == "--in-place" or arg.startswith("--in-place=")):
            return True
        if arg.startswith("-") and not arg.startswith("--"):
            group = arg[1:]
            if name == "sed" and "i" in group.split("e")[0]:
                return True
            if name == "perl" and "i" in group:
                return True
    return False


def _short_taker(arg: str, opts: frozenset[str]) -> tuple[str, str] | None:
    # 0022: in a short group (-pm, -rt<dir>) the first value-taking letter consumes the rest.
    if len(arg) < 2 or arg[0] != "-" or arg[1] == "-":
        return None
    for idx, char in enumerate(arg[1:], start=2):
        if f"-{char}" in opts:
            return f"-{char}", arg[idx:]
    return None


def _write_operands(name: str, args: list[str]) -> list[str]:
    if name == "dd":
        return [a.split("=", 1)[1] for a in args if a.startswith("of=")]
    values = _VALUE_OPTS.get(name, frozenset())
    paths = _PATH_OPTS.get(name, frozenset())
    operands: list[str] = []
    script_given = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            operands += args[i + 1 :]
            break
        if name in {"sed", "perl"} and arg in {"-e", "-E", "-f"}:
            script_given = True
            i += 2
            continue
        taker = _short_taker(arg, values | paths)
        if taker is not None:
            flag, attached = taker
            value = attached or (args[i + 1] if i + 1 < len(args) else "")
            if flag in paths and value:
                operands.append(value)
            i += 1 if attached else 2
            continue
        if arg in _VALUE_LONG_NEXT:
            i += 2
            continue
        if arg.startswith("--") and "=" in arg:
            key, value = arg.split("=", 1)
            if name not in {"sed", "perl"} and key not in _VALUE_LONG:
                operands.append(value)
        elif not arg.startswith("-") or arg == "-":
            operands.append(arg)
        i += 1
    if not operands:
        return operands
    if name in {"sed", "perl"} and not script_given:
        return operands[1:]
    # 0022: the leading mode or owner is not a path; --reference replaces it.
    if any(a.startswith("--reference") for a in args):
        return operands
    if (name == "chmod" and _MODE.fullmatch(operands[0])) or name in {"chown", "chgrp"}:
        return operands[1:]
    return operands


def _coder_write_target(segment: list[str], cwd: str) -> str | None:
    name = _base(segment[0])
    args = segment[1:]
    if name not in CODER_WRITE_CMDS and not (name in {"sed", "perl"} and _in_place(name, args)):
        return None
    for arg in _write_operands(name, args):
        if arg != "-" and not _in_unit_worktree_code(_abs(arg, cwd), cwd):
            return arg
    return None


def _cd_relative_target(segment: list[str], cwd: str) -> str | None:
    # 0022: after cd, relative operands resolve against the hook cwd, not the shell's.
    name = _base(segment[0])
    args = segment[1:]
    if name == "git":
        sub, git_args, globals_ = _git_split(segment)
        dirs = [globals_[i + 1] for i in range(len(globals_) - 1) if globals_[i] == "-C"]
        if sub in {"add", "commit"} and not dirs:
            return f"git {sub} without -C"
        if sub in {"restore", "checkout"} and not dirs:
            dirs = [a for a in git_args if a != "--"]
        return next((d for d in dirs if not os.path.isabs(d)), None)
    if name not in CODER_WRITE_CMDS and not (name in {"sed", "perl"} and _in_place(name, args)):
        return None
    operands = [a for a in _write_operands(name, args) if a != "-"]
    return next((a for a in operands if not os.path.isabs(a)), None)


def _data_dir_markers() -> list[str]:
    markers = [f"~{_DATA_DIR_DEFAULT}", f"{_HOME}{_DATA_DIR_DEFAULT}"]
    markers += [f"$HOME{_DATA_DIR_DEFAULT}", f"${{HOME}}{_DATA_DIR_DEFAULT}"]
    markers += ["$CLAUDE_PLUGIN_DATA", "${CLAUDE_PLUGIN_DATA}", _PROJECT_DATA]
    env = os.environ.get("CLAUDE_PLUGIN_DATA")
    if env:
        markers.append(os.path.normpath(env))
    return markers


def _normalize_paths(command: str) -> str:
    # 0010: `.claude//daedalus` and `./.claude/./daedalus` must match the marker too.
    text = re.sub(r"/{2,}", "/", command)
    prev = None
    while prev != text:
        prev, text = text, re.sub(r"(^|[\s/'\"=])\./", r"\1", text)
    return text


def _cd_into_claude(command: str) -> bool:
    for target in _CD_TARGET.findall(command):
        norm = os.path.normpath(target.strip("'\""))
        # 0010: cd into the data dir itself (or below it) needs no further daedalus mention.
        if _names_project_data(norm):
            return True
        if os.path.basename(norm) == ".claude" and _DAEDALUS_WORD.search(command):
            return True
    return False


def _cd_data_dir_git(command: str) -> bool:
    return _cd_into_claude(command) and bool(_GIT_INDEX_WRITE.search(command))


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


def _data_dir_write(command: str) -> bool:
    normalized = _normalize_paths(command)
    named = any(marker in normalized for marker in _data_dir_markers())
    if not (named or _cd_into_claude(normalized)):
        return False
    # I4: quoted spans collapse first so a jq filter's `>` reads as data, not a redirect.
    unquoted = _quote_spans(normalized.replace("$'", "'").replace('$"', '"'))
    return bool(_DATA_DIR_WRITE.search(_DEVNULL.sub(" ", unquoted)))


def _names_project_data(path: str) -> bool:
    parts = os.path.normpath(path).split(os.sep)
    return any(parts[i : i + 2] == [".claude", "daedalus"] for i in range(len(parts) - 1))


def _data_dir_path(path: str, cwd: str) -> bool:
    env = os.environ.get("CLAUDE_PLUGIN_DATA")
    if env and os.path.isabs(env) and _under(path, env):
        return True
    # 0010: the project data dir for this cwd, plus any .claude/daedalus in another worktree.
    return _names_project_data(path) or _under(path, str(project_data_dir(cwd)))


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


def _gitleaks_ok(tokens: list[str]) -> bool:
    if tokens[1:2] != ["detect"]:
        return False
    redacted = False
    i = 2
    while i < len(tokens):
        token = tokens[i]
        key, has_value, value = token.partition("=")
        if token.startswith("-r") and len(token) > 2 and token[2] != "=":
            key, has_value, value = "-r", "=", token[2:]
        elif re.match(r"-[A-Za-z]+r", token):
            # N6: a bundled short group carrying -r hides the report path; fail closed.
            return False
        if key in {"--report-path", "-r"}:
            if not has_value:
                value = tokens[i + 1] if i + 1 < len(tokens) else ""
                i += 1
            if not value.startswith("/") or not _under(value, "/tmp"):
                return False
        elif key == "--log-opts":
            if not has_value:
                value = tokens[i + 1] if i + 1 < len(tokens) else ""
                i += 1
            if "--output" in value or "--ext-diff" in value:
                return False
        elif token in {"--redact", "--redact=100"}:
            redacted = True
        i += 1
    # I4: an unredacted finding would put the secret into the audit chain.
    return redacted


def _tester_runner_ok(name: str, tokens: list[str]) -> bool:
    args = tokens[1:]
    if any(arg.startswith("--basetemp") for arg in args):
        return False
    if name == "pytest":
        return True
    if name == "npm":
        return bool(args) and (
            args[0] in {"test", "t"} or (args[0] in {"run", "run-script"} and len(args) > 1)
        )
    if name == "uv":
        return args[:2] == ["run", "pytest"]
    if name in {"python", "python3"}:
        # F3c: mypy takes path operands only; flags and @argfiles stay out.
        mypy = args[:2] == ["-m", "mypy"] and not any(a.startswith(("-", "@")) for a in args[2:])
        return args[:2] == ["-m", "pytest"] or mypy
    if name == "node":
        return bool(args) and not args[0].startswith("-")
    if name in {"go", "cargo"}:
        return args[:1] == ["test"]
    return False


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


def _worker_hygiene(tokens: list[str], agent: str) -> str | None:
    if _ASSIGN.match(tokens[0]):
        return R_ENV
    name = _base(tokens[0])
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
    is_wrapper = name in WORKER_WRAPPERS or name.startswith("python")
    if (
        agent == "charter-docs"
        and name == "python3"
        and "CLAUDE_PLUGIN_ROOT" in (tokens[1] if len(tokens) > 1 else "")
    ):
        return R_LEDGER_LITERAL
    if is_wrapper and not ledger and not _tester_runner_ok(name, tokens):
        return R_INLINE
    for idx, token in enumerate(tokens):
        if idx not in exempt and (_HYGIENE_CHARS & set(token) or token.startswith("~")):
            return R_HYGIENE
    sub, args, globals_ = _git_split(tokens)
    if _git_config_override(globals_):
        return R_GIT_CONFIG
    if sub == "config":
        flags = [a for a in args if a.startswith("-")]
        if flags not in (["--get"], ["--list"]):
            return R_GIT_CONFIG
    return None


def _credential_roots() -> list[str]:
    home = Path.home()
    return [os.path.realpath(home / rel) for rel in CREDENTIAL_DENY]


def _expand_home(token: str, cwd: str) -> str | None:
    # spec 8: quotes are dropped, so "$HOME"/.ssh and '~'/.ssh are checked as expanded.
    token = token.replace('"', "").replace("'", "")
    home = str(Path.home())
    if token == "~" or token.startswith("~/"):
        token = home + token[1:]
    elif token.startswith("~"):
        token = os.path.expanduser(token)
    for var in ("${HOME}", "$HOME"):
        if token.startswith(var):
            token = home + token[len(var) :]
            break
    if not token:
        return None
    if os.path.isabs(token):
        return token
    return os.path.join(cwd, token) if os.path.isabs(cwd) else None


def _credential_candidates(tool: str, tool_input: dict[str, Any], cwd: str) -> list[str]:
    if tool == "Bash":
        command = str(tool_input.get("command") or "")
        tokens = [t for t in _CREDENTIAL_SPLIT.split(command) if t]
        return tokens + [p for t in tokens for p in _CREDENTIAL_PART.split(t)[1:] if p]
    if tool not in CREDENTIAL_TOOLS and tool not in WRITE_TOOLS:
        return []
    values = [str(tool_input.get(k) or "") for k in ("file_path", "notebook_path", "path")]
    pattern = str(tool_input.get("pattern") or "")
    if tool == "Glob" and pattern:
        values.append(pattern if pattern.startswith(("/", "~", "$HOME", "${HOME}")) else "")
        base = str(tool_input.get("path") or cwd)
        values.append(os.path.join(base, pattern))
    elif tool == "Grep" and pattern.startswith(("/", "~", "$HOME", "${HOME}")):
        # spec 8: a Grep pattern is a regex; only an absolute or home-rooted one names a path.
        values.append(pattern)
    return [v for v in values if v]


def _glob_reaches(parts: list[str], root: list[str], dotglob: bool) -> bool:
    for i, name in enumerate(root):
        if i >= len(parts):
            return False
        pat = _BRACE.sub("*", parts[i])
        if "**" in pat:
            return True
        # spec 8: a shell wildcard skips a leading dot unless dotglob is set.
        if not dotglob and name.startswith(".") and not pat.startswith("."):
            return False
        if not fnmatch.fnmatchcase(name, pat):
            return False
    return True


def _credential_hit(target: str, roots: list[str], glob: bool, dotglob: bool = True) -> bool:
    if not glob or not _GLOB_START.search(target):
        return any(_under(target, root) for root in roots)
    # spec 8: realpath the literal prefix, then match each glob component against each store.
    parts = os.path.normpath(target).split(os.sep)
    first = next(i for i, part in enumerate(parts) if _GLOB_START.search(part))
    base = os.path.realpath(os.sep.join(parts[:first]) or os.sep)
    if any(_under(base, root) for root in roots):
        return True
    pattern = [p for p in base.split(os.sep) if p] + parts[first:]
    return any(_glob_reaches(pattern, [p for p in r.split(os.sep) if p], dotglob) for r in roots)


def _bash_bases(command: str, cwd: str) -> list[str]:
    # spec 8: a relative token is also checked against every cd target, so cd ~ is modeled.
    bases = [cwd] if os.path.isabs(cwd) else []
    for target in _CD_TARGET.findall(command):
        expanded = _expand_home(target, cwd)
        if expanded:
            bases.append(expanded)
    if _BARE_CD.search(command):
        bases.append(str(Path.home()))
    return bases


def _credential_reason(tool: str, tool_input: dict[str, Any], cwd: str) -> str | None:
    roots = _credential_roots()
    glob = tool in {"Bash", "Glob"}
    bases, dotglob = [cwd], True
    if tool == "Bash":
        command = str(tool_input.get("command") or "")
        bases = _bash_bases(command, cwd)
        dotglob = "dotglob" in command or "GLOBIGNORE" in command
    for raw in _credential_candidates(tool, tool_input, cwd):
        for base in bases or [cwd]:
            target = _expand_home(raw, base)
            if target is not None and _credential_hit(target, roots, glob, dotglob):
                return R_CREDENTIAL.format(path=raw)
    return None


def _train_active(cwd: str) -> bool:
    # 0023: existence only; a symlinked or unreadable marker still counts as an active train.
    return os.path.lexists(train_marker(project_root(cwd)))


def _ours(raw_agent: str) -> bool:
    prefix, sep, _ = raw_agent.partition(":")
    return bool(sep) and prefix in (*AGENT_NAMESPACES, TEST_NAMESPACE)


def _unknown_decision(raw_agent: str, agent: str, cwd: str) -> Decision:
    # 0023: a foreign agent is refused only while a train is active; a daedalus name always is.
    if _ours(raw_agent):
        return _block(R_UNKNOWN.format(agent=agent))
    if not os.path.isabs(cwd):
        return _block(R_NO_CWD)
    return _block(R_UNKNOWN.format(agent=agent)) if _train_active(cwd) else _allow()


def normalize_agent(agent_type: str) -> str:
    prefix, sep, name = agent_type.partition(":")
    test_ns = prefix == TEST_NAMESPACE and os.environ.get("DAEDALUS_LIVE_TEST") == "1"
    if sep and (prefix in AGENT_NAMESPACES or test_ns) and name:
        return name
    return agent_type


def decide(hook_input: dict[str, Any], config: Config) -> Decision:
    raw_agent = str(hook_input.get("agent_type") or "main")
    agent = normalize_agent(raw_agent)
    tool = str(hook_input.get("tool_name") or "")
    cwd = str(hook_input.get("cwd") or "")
    tool_input = hook_input.get("tool_input")
    credential = _credential_reason(tool, tool_input if isinstance(tool_input, dict) else {}, cwd)
    if credential:
        return Decision(False, credential, agent)
    if tool in CREDENTIAL_TOOLS:
        return Decision(True, None, agent)
    if agent == "main" and raw_agent != "main":
        return Decision(False, R_NAMESPACED_MAIN, agent)
    # m4: only the orchestrator thread arrives without an agent_id.
    if agent == "main" and hook_input.get("agent_id"):
        return Decision(False, R_SUBAGENT_MAIN, agent)
    if agent in KNOWN_AGENTS:
        decision = _decide(hook_input, config, agent)
    else:
        decision = _unknown_decision(raw_agent, agent, cwd)
    return Decision(decision.allow, decision.reason, agent)


def _decide(hook_input: dict[str, Any], config: Config, agent: str) -> Decision:
    tool = str(hook_input.get("tool_name") or "")
    cwd = str(hook_input.get("cwd") or "")
    tool_input = hook_input.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    command = str(tool_input.get("command") or "")
    raw_path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
    is_write = tool in WRITE_TOOLS
    if (is_write or tool == "Bash") and not os.path.isabs(cwd):
        return _block(R_NO_CWD)
    path = _abs(raw_path, cwd)
    if is_write and (
        ".git" in path.split(os.sep) or ".git" in os.path.normpath(path).split(os.sep)
    ):
        return _block(R_DOTGIT)
    if is_write and _data_dir_path(path, cwd):
        return _block(R_DATA_DIR)
    charter = str(config.charter_root) if config.charter_root else None

    if tool == "Bash" and agent == "main":
        # 8.5: main is bound only by the tripwires; regex fallback when tokenize refuses.
        if _data_dir_write(command):
            return _block(R_DATA_DIR)
        if _cd_data_dir_git(command):
            return _block(R_DATA_DIR_GIT)
        reason = _command_reason(command)
        return _block(reason) if reason else _allow()
    segments: list[list[str]] = []
    piped = False
    if tool == "Bash":
        scanned = _scan(command)
        parsed = tokenize(command)
        # 8.5: || is a fallback chain the jail does not reason about, blocked for workers.
        if parsed is None or scanned is None or "||" in scanned[1]:
            return _block(R_UNSUPPORTED)
        segments = parsed
        piped = "|" in scanned[1]
        for segment in segments:
            reason = _segment_reason(segment, 0, main=False)
            if reason == _FALLBACK:
                reason = _regex_tripwire(command)
            if reason:
                return _block(reason)
    if agent != "main" and (tool in WORKER_DENIED_TOOLS or tool.startswith("mcp__")):
        return _block(R_TOOL)
    if tool == "Bash" and agent != "main":
        # Env prefix ruling: only the fixed _SAFE_ENV names may precede a worker command.
        segments = [list(itertools.dropwhile(_SAFE_ENV.match, s)) for s in segments]
        if not all(segments):
            return _block(R_ENV)
        for segment in segments:
            reason = _worker_hygiene(segment, agent)
            if reason:
                return _block(reason)

    if agent == "main":
        if is_write and _in_code_dirs(path, cwd):
            return _block(
                "Fable does not write application code. "
                "Next: dispatch a repo-coder for this change."
            )
        return _allow()

    if agent == "repo-coder":
        if is_write and not _in_unit_worktree_code(_abs(path, cwd), cwd):
            return _block(
                f"write outside src/ or tests/ of your unit worktree: {path}. "
                "Next: ask Fable to route this to contract-spec or charter-docs."
            )
        if tool == "Bash":
            if piped:
                return _block(R_PIPE)
            moved = any(_base(s[0]) in DIR_CHANGE_CMDS for s in segments)
            for segment in segments:
                relative = _cd_relative_target(segment, cwd) if moved else None
                if relative is not None:
                    return _block(R_CD_RELATIVE.format(relative))
                exempt = _exempt_indices(segment)
                words = [_base(t) for i, t in enumerate(segment) if i not in exempt]
                sub = _git_subcommand(segment) if _base(segment[0]) == "git" else None
                # I3a: a local subcommand's operands (stash push) go to the git allowlist below.
                if sub in REMOTE_GIT or (
                    sub not in CODER_GIT and "git" in words and REMOTE_GIT & set(words)
                ):
                    return _block(
                        "no remote git operations in the Build Train. "
                        "Next: commit locally; the Push Train pushes."
                    )
                if NETWORK_TOOLS & set(words):
                    return _block(
                        "network or remote tooling is not permitted (tripwire). "
                        "Next: return [STATUS: YIELD_WEB] with your question."
                    )
                if any(t.startswith("--basetemp") for t in segment):
                    return _block("pytest --basetemp is not permitted. Next: use the default.")
                if _base(segment[0]) == "git" and not _git_grammar_ok(
                    segment, CODER_GIT, cwd, None
                ):
                    return _block(R_CODER_GIT)
                if sub in {"add", "commit"}:
                    git_dir = _git_dir(_git_split(segment)[2], cwd)
                    if _unit_parts(git_dir, cwd) is None:
                        return _block(R_CODER_UNIT_GIT)
                target = _coder_write_target(segment, cwd)
                if target is not None:
                    return _block(
                        f"Bash write outside src/ or tests/: {target}. "
                        "Next: write under your unit worktree src/ or tests/, "
                        "or ask Fable to route the change."
                    )
        if tool in WEB_TOOLS:
            return _block(
                "no web access for coders. Next: return [STATUS: YIELD_WEB] with your question."
            )
        return _allow()

    if agent == "contract-spec":
        if is_write:
            ok = _under(path, f"{cwd}/contracts") or (
                charter is not None and _under(path, f"{charter}/specs")
            )
            if not ok:
                return _block(
                    "contract-spec may write only contracts/ or the charter specs/ directory. "
                    "Next: put schema changes there."
                )
        if tool == "Bash":
            return _block("contract-spec has no shell. Next: use Read, Grep, Glob, Write, Edit.")
        if tool in WEB_TOOLS:
            return _block(
                "contract-spec has no web access. Next: ask Fable to dispatch web-researcher."
            )
        return _allow()

    if agent == "charter-docs":
        if is_write:
            reason = _ledger_write_reason(path, cwd, config)
            if reason:
                return _block(reason)
            ok = (charter is not None and _under(path, charter)) or _under(path, f"{cwd}/docs")
            if not ok:
                return _block(
                    "charter-docs may write only the charter repo or docs/. "
                    "Next: keep documentation there."
                )
        if tool == "Bash":
            if piped:
                return _block(R_PIPE)
            for segment in segments:
                if _is_append_ledger(segment):
                    if not _ledger_args_ok(segment):
                        return _block(R_LEDGER_ARGS)
                    continue
                name = _cmd_name(segment)
                if name == "git" and _git_grammar_ok(
                    segment, CHARTER_DOCS_GIT, cwd, charter, _DOCS_GRAMMAR
                ):
                    continue
                return _block(R_DOCS_BASH)
        if tool in WEB_TOOLS:
            return _block(
                "charter-docs has no web access. Next: ask Fable to dispatch web-researcher."
            )
        return _allow()

    if agent == "security-auditor":
        if is_write:
            return _block(
                "the auditor is read-only. "
                "Next: return findings in [VERDICT: REJECTED]; the coder fixes them."
            )
        if tool == "Bash" and not all(
            _read_only_segment(s, READ_ONLY_GIT, cwd, charter) for s in segments
        ):
            return _block(
                "auditor Bash is limited to read-only git and inspection commands, piped only. "
                "Next: use git diff/log/show or rg/cat/jq with | head."
            )
        if tool in WEB_TOOLS:
            return _block(
                "the auditor has no web access. Next: judge from the diff and the packets."
            )
        return _allow()

    if agent in {"nist-specialist", "cis-specialist"}:
        if is_write:
            return _block(
                "specialist caches are operator-pinned; no writes. "
                "Next: report [STATUS: CACHE_INVALID] if the cache is wrong."
            )
        if tool == "Bash" and not all(
            _read_only_segment(s, SPECIALIST_GIT, cwd, charter) for s in segments
        ):
            return _block(
                "specialist Bash is limited to read-only inspection. "
                "Next: use sha256sum, cat, jq, rg, git diff."
            )
        if tool in WEB_TOOLS:
            return _block(
                "specialists never fetch; the cache is operator-pinned. "
                "Next: use the pinned catalog."
            )
        return _allow()

    if agent == "pr-train-conductor":
        if is_write:
            return _block(
                "the conductor is read-only for source. "
                "Next: report and stop; the Build Train edits."
            )
        if tool == "Bash":
            if piped:
                return _block(R_PIPE)
            for segment in segments:
                name = _cmd_name(segment)
                if name == "git" and _git_subcommand(segment) == "push":
                    if not _conductor_push_ok(segment):
                        return _block(R_CONDUCTOR_PUSH)
                    continue
                if name == "git" and _git_grammar_ok(segment, CONDUCTOR_GIT, cwd, None):
                    continue
                if name == "gh":
                    if _gh_repo_flag(segment):
                        return _block(R_CONDUCTOR_REPO)
                    if not _gh_body_file_ok(segment, cwd):
                        return _block(R_BODY_FILE)
                    reason = _gh_write_reason(segment)
                    if reason:
                        return _block(reason)
                    if not _gh_allowed(segment):
                        return _block(
                            "conductor gh is limited to pr create/edit/view/checks/status/list/"
                            "comment/diff and run list/view/watch; the operator is the merge "
                            "gate (0001). Next: report the PR URL."
                        )
                    continue
                if name == "gitleaks":
                    if not _gitleaks_ok(segment):
                        return _block(R_GITLEAKS)
                    continue
                return _block(
                    "conductor Bash is limited to git push/status/log/rev-parse/branch/diff/"
                    "add/commit, "
                    "gh pr/run, gitleaks detect. Next: use those only."
                )
        if tool in WEB_TOOLS:
            return _block("the conductor has no web access. Next: use gh.")
        return _allow()

    if agent in {"web-researcher", "standards-rules-specialist"}:
        if is_write:
            return _block(f"{agent} is read-only. Next: return your findings as text.")
        if tool == "Bash":
            return _block(f"{agent} has no shell. Next: use Read, Grep, Glob.")
        if tool in WEB_TOOLS and agent != "web-researcher":
            return _block(
                "only web-researcher may fetch. Next: ask Fable to dispatch web-researcher."
            )
        return _allow()

    if agent == "boundary-tester":
        if is_write and not _under(path, f"{cwd}/tests/adversarial"):
            return _block(
                f"boundary-tester writes only under tests/adversarial/: {path}. "
                "Next: put the test there."
            )
        if tool == "Bash":
            if piped:
                return _block(R_PIPE)
            for segment in segments:
                name = _cmd_name(segment)
                if name == "git" and _git_grammar_ok(segment, TESTER_GIT, cwd, None):
                    continue
                if _tester_runner_ok(name, segment):
                    continue
                if name in READ_ONLY_CMDS and _read_only_segment(segment, frozenset(), cwd, None):
                    continue
                if {"install", "i", "add", "ci", "get"} & set(segment[1:3]):
                    return _block(
                        "boundary-tester may not install packages. "
                        "Next: return [STATUS: YIELD_DEPENDENCY]."
                    )
                return _block(
                    "boundary-tester Bash is limited to the test runner, local git, "
                    "and inspection. Next: use those only."
                )
        if tool in WEB_TOOLS:
            return _block("boundary-tester has no web access. Next: return [STATUS: YIELD_WEB].")
        return _allow()

    return _block(
        f"no policy for agent_type '{agent}', fail closed. Next: add a case to lib/jail.py."
    )

# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from lib import dispatch_binding, hook_io, shell
from lib.audit import _git_env, project_data_dir, project_root
from lib.audit_proof import SUMMARY_DIR
from lib.config import (
    Config,
    ConfigError,
    ExcludedRoot,
    resolve_excluded_roots,
    root_ignored,
)
from lib.credential_paths import (
    CREDENTIAL_TOOLS,
    IGNORE_FILES,
    R_BRACE_UNJUDGED,
    R_CREDENTIAL,
    R_CREDENTIAL_TREE,
    R_IGNORE_WHITELIST,
    R_REPLY_KEY,
    R_REPLY_KEY_TREE,
    REPLY_KEY_NAME,
    glob_patterns,
    glob_reaches,
    ignore_whitelist,
    key_roots,
    path_reason,
    reply_key_hit,
)
from lib.credential_paths import CUT as _CUT
from lib.credential_paths import LIT as _LIT
from lib.credential_paths import REDIRECT as _REDIRECT
from lib.credential_paths import anchor as _anchor
from lib.credential_paths import clean as _clean
from lib.credential_paths import credential_hit as _credential_hit
from lib.credential_paths import credential_roots as _credential_roots
from lib.credential_paths import dotglob_on as _dotglob_on
from lib.credential_paths import expand_word as _expand_word
from lib.credential_paths import store_rest as _store_rest
from lib.credential_paths import tilde as _tilde
from lib.credential_paths import unjudged_root as _unjudged_root
from lib.gh_policy import CONDUCTOR_GH, GhFlag, _push_reason, allowlist_applies, gh_args, gh_reason
from lib.ledger import LedgerError, resolve_ledger
from lib.manifest import Manifest, ManifestError, extension_hit, path_hit
from lib.manifest import load as load_manifest
from lib.repo_root import git_root
from lib.shell import (
    _ASSIGN,
    _DEFAULT_BRANCHES,
    _FALLBACK,
    _FIND_DENY,
    _GLOB_CHARS,
    _HOME,
    _PROJECT_DATA,
    _REPO_SCRIPTS,
    _SHELLS,
    _VALUE_LONG_NEXT,
    FLOCK_BODY,
    GIT_PLUMBING_REMOTE,
    R_CLEAN,
    R_DATA_DIR_GIT,
    R_DEFAULT_BRANCH,
    R_DESTRUCTIVE,
    R_ENV_SPLIT,
    R_FORCE_PUSH,
    R_STASH_UNTRACKED,
    READ_ONLY_CMDS,
    READ_ONLY_GIT,
    WRAPPER_CHDIR,
    WRAPPER_WRITES,
    WrapperOption,
    _abs,
    _base,
    _cmd_name,
    _command_reason,
    _git_split,
    _long_matches,
    _names_project_data,
    _pathspecs,
    _quote_spans,
    _shell_code,
    _short_flags,
    _under,
    chain_bases,
    env_split_values,
    runs_claude,
    strip_wrappers,
    tokenize,
    unwrap,
    worker_parse,
)
from lib.train_scope import (
    AGENT_NAMESPACES,
    KNOWN_AGENTS,
    TEST_NAMESPACE,
    policed_outside_train,
)
from lib.train_state import active_train
from lib.workspace import UNMARK_NEXT, train_marker

WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})
WEB_TOOLS = frozenset({"WebFetch", "WebSearch"})
# 5.5: all routing is through the orchestrating session; workers never message each other.
WORKER_DENIED_TOOLS = frozenset({"Task", "Agent", "SendMessage"})

REMOTE_GIT = (
    frozenset({"push", "remote", "fetch", "pull", "clone", "ls-remote", "submodule"})
    | GIT_PLUMBING_REMOTE
)
# Final review I3b, issue 75: commands whose operands are write targets for repo-coder.
CODER_WRITE_CMDS = frozenset(
    {"cp", "mv", "tee", "install", "ln", "truncate", "rsync", "dd"}
    | {"mkdir", "touch", "rm", "rmdir", "unlink", "chmod", "chown", "chgrp"}
    | {"mkfifo", "mknod", "shred"}
)
# 0022: options whose value is not a path; every other non-option operand is a path.
_VALUE_OPTS: dict[str, frozenset[str]] = {
    "install": frozenset({"-m", "-o", "-g", "-S"}),
    "mkdir": frozenset({"-m"}),
    "mkfifo": frozenset({"-m"}),
    "mknod": frozenset({"-m"}),
    "shred": frozenset({"-n", "-s"}),
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
    "rsync": frozenset({"-T"}),
}
_VALUE_LONG = _VALUE_LONG_NEXT | {"--preserve"}
_MODE = re.compile(r"(?:[0-7]{3,4}|[ugoa]*[-+=][rwxXstugo]*)(?:,[ugoa]*[-+=][rwxXstugo]*)*")
DIR_CHANGE_CMDS = frozenset({"cd", "pushd", "popd"})
# audit A7-1: claude starts a nested session with no agent_id, which the jail would judge as main.
NETWORK_TOOLS = frozenset(
    {"curl", "wget", "ssh", "scp", "nc", "ncat", "telnet", "aws", "gh", "claude"}
)
R_NESTED_CLAUDE = (
    "claude starts a nested session the jail cannot attribute to an agent (audit A7-1). "
    "Next: run it from your own shell."
)
_CLAUDE_WORD = re.compile(r"(?:^|[\s;&|(/'\"`])claude(?=[\s;&|)'\"`]|$)")
# 0028: the conductor's gh set lives in lib.gh_policy.
GH_ALLOWED = {cmd: frozenset(sub for c, sub in CONDUCTOR_GH if c == cmd) for cmd, _ in CONDUCTOR_GH}
_BRANCH_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")
R_NAMESPACED_MAIN = "a namespaced agent may not claim the orchestrator role. Next: name the agent."

R_PIPE = "pipes are not permitted for this agent. Next: send one plain command."
R_NO_CWD = "hook received no absolute cwd; failing closed. Next: report to the operator."
R_TOOL = "workers use only their allowlisted tools. Next: ask the orchestrating session."
R_DOTGIT = "writes into .git/ are never permitted. Next: change the repository through git."
R_CODER_UNIT_GIT = (
    "repo-coder git add and commit run only inside your unit worktree. "
    "Next: use git -C <your unit worktree> add/commit."
)
# 0054: a coder's protected paths, relative to its unit worktree root.
BUILTIN_PROTECTED = Manifest(("contracts/", ".github/", ".claude/", "service-manifest.json"))
R_BASH_OUTSIDE = (
    "Bash write outside your unit worktree: {}. "
    "Next: write inside your unit worktree, or ask the orchestrating session to route the change."
)
R_ROUTE_NEXT = (
    "Next: ask the orchestrating session to route this change to contract-spec or charter-docs."
)
R_PROTECTED_BUILTIN = "protected path (built in): {}. " + R_ROUTE_NEXT
R_PROTECTED_PATH = "protected path (service-manifest.json jail_narrowing): {}. " + R_ROUTE_NEXT
R_PROTECTED_EXT = "protected extension (service-manifest.json jail_narrowing): {}. " + R_ROUTE_NEXT
R_CD_RELATIVE = (
    "a chain that changes directory may not use relative write paths or pathspecs: {}. "
    "Next: use absolute paths (or an absolute git -C) after cd."
)
R_CONDUCTOR_PUSH = (
    "the conductor pushes one named branch to origin, nothing else (0001). "
    "Next: `git push -u origin daedalus/<train-id>`."
)
R_CONDUCTOR_PUSH_HEAD = (
    "the conductor never pushes HEAD; it names this train's branch (issue 11). "
    "Next: `git push -u origin daedalus/<train-id>`."
)
R_CONDUCTOR_PUSH_BRANCH = (
    "the conductor pushes only this train's branch, {branch} (issue 11). "
    "Next: `git push -u origin {branch}`."
)
R_CONDUCTOR_NO_TRAIN = (
    "no active train names the branch to push (issue 11). "
    "Next: run /daedalus:push-train, which marks the train before the push."
)
R_CONDUCTOR_CHARTER = (
    "git -C reaches only the charter root .claude/daedalus/config.json declares, and only for "
    "the push of this train's branch (0078). "
    "Next: run the command in this repo without -C, or `git -C <charter_root> push -u origin "
    "daedalus/<train-id>`."
)
R_CODER_GIT = (
    "repo-coder git is limited to add, commit, status, diff (--check included), log (-S and -G "
    "included), show, grep, blame, merge-base, rev-parse, ls-files, "
    "branch listing, stash list/push/pop/show, "
    "restore/checkout -- <unit worktree paths>, "
    "worktree list; --output is refused on every subcommand. "
    "Next: use those only; the trains handle the rest."
)
R_DATA_DIR = (
    "the plugin data directory is written by hooks only. "
    "Next: edit <repo>/.claude/daedalus/config.json from your own shell."
)
R_SUBAGENT_MAIN = "a subagent may not run as main. Next: name the agent."
R_CONDUCTOR_REPO = (
    "the conductor's gh pr writes target this repo; -R/--repo is admitted only on gh pr create "
    "naming the declared charter root's origin, with --head on this train's branch (0078). "
    "Next: omit -R, or pass --repo <charter slug> --head daedalus/<train-id>."
)
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
    "git status, git log and git diff, plus the reads cat, grep, head, tail, wc, ls, diff and "
    "sed -n on literal paths under the charter root or docs/. "
    "Next: use those only; the main session runs the rest."
)
# 0044: reason literals the hook scripts under scripts/checks return.
R_UNIT_OUTSIDE = (
    "write outside your unit worktree: {}. "
    "Next: ask the orchestrating session to route this to contract-spec or "
    "charter-docs."
)
R_REMOTE_GIT = (
    "no remote git operations in the Build Train. Next: commit locally; the Push Train pushes."
)
R_NETWORK = (
    "network or remote tooling is not permitted (tripwire). "
    "Next: return [STATUS: YIELD_WEB] with your question."
)
# issue 56: the refusal names the flag, the agent and the next action in every grammar.
R_BASETEMP_AGENT = (
    "pytest --basetemp is refused for {agent}: the temp folder it names lies outside the "
    "write checks (issue 56). Next: drop --basetemp and rerun; pytest's default temp folder works."
)
R_BASETEMP = R_BASETEMP_AGENT.format(agent="repo-coder")
R_CONTRACT_SPEC_WRITE = (
    "contract-spec may write only contracts/ or the charter specs/ directory. "
    "Next: put schema changes there."
)
R_CHARTER_DOCS_WRITE = (
    "charter-docs may write only the charter repo or docs/. Next: keep documentation there."
)
R_AUDITOR_BASH = (
    "auditor Bash is limited to read-only git and inspection commands, piped only. "
    "Next: use git diff/log/show or rg/cat/jq with | head."
)
R_SPECIALIST_BASH = (
    "specialist Bash is limited to read-only inspection. "
    "Next: use sha256sum, cat, jq, rg, git diff."
)
R_CONDUCTOR_BASH = (
    "conductor Bash is limited to git push/status/log/rev-parse/branch/diff/"
    "add/commit, "
    "gh pr/run, gitleaks detect. Next: use those only."
)
R_CONDUCTOR_COMMIT_ALL = (
    "the conductor commits only what is already staged; git commit -a, --all or any prefix "
    "of it, a short option group holding a, and paths on the commit line are refused "
    "(issue 2). Next: stage each file by path with git add <path>, then run "
    "git commit -m <message>."
)
R_CONDUCTOR_WEB = "the conductor has no web access. Next: use gh."
R_WEB_RESEARCHER_ONLY = (
    "only web-researcher may fetch. Next: ask the orchestrating session to dispatch web-researcher."
)
R_UNKNOWN = (
    "unknown agent_type '{agent}', fail closed. Next: add the agent to the jail before using it."
)
# 0100: one line of rule, then the unmark line for a marker a dead train left.
R_UNKNOWN_TRAIN = (
    "unknown agent_type '{agent}' is read-only while {marker} exists: Bash runs read-only "
    "inspection and git reads, pipes allowed; Write, Edit, dispatch and web tools are refused "
    "(0100).\n" + UNMARK_NEXT
)
# Main never prompted (amends 0106): the plain-words warnings sent into the main session's context.
WARN_DOTGIT = (
    "Writing {path} edits the repository's own metadata; a wrong write corrupts the clone."
)
WARN_DATA_DIR = (
    "This touches the plugin data folder. It holds the audit log, train state and coder "
    "bindings; a hand edit breaks the hash chain that proves the audit happened."
)
WARN_CREDENTIAL = (
    "This path holds credentials; reading it puts the secret into the session transcript."
)
WARN_CREDENTIAL_WRITE = (
    "This path holds credentials; writing it can replace a key or leave a secret behind."
)
WARN_FORCE_PUSH = (
    "A force, delete or mirror push rewrites the remote branch; commits that exist only there "
    "are lost."
)
WARN_DEFAULT_BRANCH = "Pushing to the default branch skips the pull request the operator merges."
WARN_DELETE = (
    "This recursive or raw-device delete removes files that neither git nor the plugin can restore."
)
WARN_CLEAN = (
    "git clean deletes untracked files, the plugin data folder included; nothing restores them."
)
WARN_TRAIN_PUSH = "Pushing during a train publishes a branch before the audit approves its tip."
WARN_COMMAND = "This command matches a pattern the plugin guards against."
WARN_NESTED_CLAUDE = (
    "This starts a nested Claude session; the jail judges its calls as yours, with no agent's "
    "limits."
)
WARN_DISPATCH = (
    "This dispatch skips a train invariant ({reason}). The agent starts without it; "
    "the audit log records the warning."
)
WARN_NO_CWD = (
    "The hook received no working folder, so the plugin cannot tell which repository this "
    "call touches."
)
# 0106: tripwire findings with their own consequence; any other finding gets WARN_COMMAND.
_TRIPWIRE_WARNINGS = {
    R_FORCE_PUSH: WARN_FORCE_PUSH,
    R_DEFAULT_BRANCH: WARN_DEFAULT_BRANCH,
    R_DESTRUCTIVE: WARN_DELETE,
    R_CLEAN: WARN_CLEAN,
    R_DATA_DIR_GIT: WARN_DATA_DIR,
    R_STASH_UNTRACKED: WARN_DATA_DIR,
    R_NESTED_CLAUDE: WARN_NESTED_CLAUDE,
}
# Main never prompted (amends 0105, 0106): allow with context, never ask, for the main session.
R_MAIN_TRAIN_WARN = (
    "Build Train {train} is active in this repository and works in unit worktrees. "
    "Writing {path} here can leave a dirty tree that finish refuses, conflict with a unit "
    "branch, or land on the integration branch."
)
R_ROUTED = (
    "{agent} is judged by the router, not lib.jail.decide. "
    "Next: route the call through scripts/enforce_agent_jail.py."
)
_CREDENTIAL_PART = re.compile(r"[=:,]")
R_CREDENTIAL_PARAM = (
    "{path} could be a credential path; the jail cannot resolve its variable. "
    "Next: spell the path out"
)
# issue 76: time is not here; its WRAPPER_OPTS row reads its options.
_CONTROL_WORDS = frozenset({"!", "do", "then", "else", "elif", "while", "until", "if"})
_BINDERS = frozenset({"read", "mapfile", "readarray", "getopts", "select"})
# issue 76: _command_at's answer when a wrapper option is off shell.WRAPPER_OPTS.
_OPAQUE = -1
_GREPS = frozenset({"grep", "egrep", "fgrep"})
# spec 8: short options whose value is the next word (or the rest of the cluster).
_SEARCH_VALUES: dict[str, frozenset[str]] = {
    "grep": frozenset("efmABCdD"),
    "rg": frozenset("efmABCgtTjMrE"),
}
_SEARCH_LONGS = frozenset(
    {"--regexp", "--file", "--max-count", "--context", "--after-context", "--before-context"}
    | {"--glob", "--type", "--type-not", "--threads", "--replace", "--encoding"}
)
_PATH_CMDS = (
    READ_ONLY_CMDS
    | CODER_WRITE_CMDS
    | {"cd", "pushd", "source", ".", "less", "more", "base64", "xxd", "od", "strings"}
    | {"tar", "zip", "unzip", "scp", "gzip", "gunzip", "zcat", "openssl", "ssh-keygen", "gpg"}
    | {"egrep", "fgrep", "nl", "tac", "diff", "cmp"}
    | {"bsdtar", "7z", "7za", "7zr", "7zz", "pax"}
)
_PATH_OPTION = re.compile(r"--?[\w-]*(?:dir|file|path|target|output|input|config|key|root)", re.I)
_DATA_DIR_DEFAULT = "/.claude/plugins/data/daedalus"
UNIT_WORKTREES = ".claude/worktrees"
_DATA_DIR_WRITE = re.compile(
    r">|(?:^|[\s;&|(/])(?:tee|rm|mv|cp|truncate|touch|ln|mkdir|chmod|chown|install|rmdir"
    r"|mkfifo|mknod|shred)"
    r"(?=[\s;&|)]|$)"
    r"|\bsed\b[^;&|\n]*\s(?:-[a-zA-Z]*i|--in-place)|\bpython[\d.]*\b[^;&|\n]*\s-[a-zA-Z]*c"
    r"|\bgit\b[^;&|\n]*\s(?:init|clone)\b"
)
_DEVNULL = re.compile(r"\d?>&\d|&?\d?>>?\s*/dev/null")
_CD_TARGET = re.compile(r"(?:^|[;&|(\s])(?:cd|pushd)\s+([^\s;&|)]+)")
_DAEDALUS_WORD = re.compile(r"(?<![\w.-])daedalus(?![\w-])")
_GIT_INDEX_WRITE = re.compile(r"\bgit\b[^;&|]*\b(?:add|stage|commit|update-index)\b")


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str | None = None
    agent: str | None = None
    # Main never prompted (amends 0105, 0106): a main-session finding the hook allows with context.
    warn: bool = False


def _allow() -> Decision:
    return Decision(True, None)


def _block(reason: str) -> Decision:
    return Decision(False, reason)


def _warn(reason: str) -> Decision:
    # Main never prompted (amends 0105, 0106): allow with context, never ask, for the main session.
    return Decision(False, reason, warn=True)


def _main_warn(warning: str, finding: str) -> Decision:
    # Main never prompted (amends 0106): allow with context, never ask, for the main session.
    # The warning first, then the jail's finding verbatim so the audit log keeps it whole.
    return _warn(f"{warning} The jail's finding: {finding}")


def _tripwire_warn(finding: str) -> Decision:
    # Main never prompted (amends 0106): allow with context, never ask, for the main session.
    # Git push during a train carries the gh policy's push finding.
    warning = _TRIPWIRE_WARNINGS.get(finding, WARN_COMMAND)
    if finding == _push_reason("main"):
        warning = WARN_TRAIN_PUSH
    return _main_warn(warning, finding)


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


def _commits_work_tree(args: list[str]) -> bool:
    # issue 2: -a, --all or a prefix, a cluster holding a, or a pathspec commits past the index.
    # Every word is read, option values included, so no value reading decides it.
    return bool(_pathspecs("commit", args)) or any(
        _long_matches(arg, "--all", 1) or (not arg.startswith("--") and "a" in _short_flags(arg))
        for arg in args
    )


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


def _in_unit_worktree(target: str, cwd: str) -> bool:
    parts = _unit_parts(target, cwd)
    return parts is not None and len(parts) >= 2


def _main_write_train(path: str, cwd: str) -> str | None:
    # 0105, 0104: the train id when the path is in a marked repo outside its scratch, else None.
    target = os.path.realpath(_abs(path, cwd))
    root = project_root(cwd)
    if not (_under(target, str(root)) and _train_scoped(cwd, "", {})):
        root = project_root(os.path.dirname(target))
        if not os.path.lexists(train_marker(root)):
            return None
    if _under(target, str(root / SUMMARY_DIR)):
        return None
    branch = _train_branch(str(root)) or ""
    return branch.removeprefix("daedalus/") or "(id unreadable)"


@dataclass(frozen=True)
class CoderBoundary:
    manifest: Manifest
    ledger_rel: str | None


@lru_cache(maxsize=8)
def _manifest_at(repo: str) -> Manifest | str:
    # 0054: read once per process from the main checkout; an error string fails closed.
    try:
        return load_manifest(Path(repo)) or Manifest()
    except ManifestError as exc:
        return f"service-manifest.json is unusable, so coder writes fail closed: {exc}"


def _coder_boundary(cwd: str, config: Config) -> CoderBoundary | str:
    repo = os.path.realpath(str(project_root(cwd)))
    manifest = _manifest_at(repo)
    if isinstance(manifest, str):
        return manifest
    try:
        resolved = resolve_ledger(cwd, config)
    except LedgerError as exc:
        return f"the ledger could not be resolved, so coder writes fail closed: {exc}"
    ledger_rel = None
    if resolved is not None:
        rel = os.path.relpath(os.path.realpath(resolved.path), repo)
        if rel.split(os.sep)[0] != os.pardir:
            ledger_rel = rel.replace(os.sep, "/")
    return CoderBoundary(manifest, ledger_rel)


def _coder_write_reason(target: str, cwd: str, boundary: CoderBoundary | str) -> str | None:
    # 0054: inside the unit worktree a write is refused only on a protected path.
    rel = "/".join((_unit_parts(target, cwd) or [])[1:])
    return protected_reason(rel, target, boundary)


def protected_reason(rel: str, target: str, boundary: CoderBoundary | str) -> str | None:
    # 0054: the one protected-path rule; rel is relative to the tree root, an ancestor hits too.
    if isinstance(boundary, str):
        return boundary
    folded = rel.casefold()
    ledger = boundary.ledger_rel
    if ".git" in folded.split("/") or path_hit(BUILTIN_PROTECTED, rel):
        return R_PROTECTED_BUILTIN.format(target)
    # prepush-2026-10-27: a `!` line in either file lets rg read the reply key.
    if folded.rsplit("/", 1)[-1] in IGNORE_FILES:
        return R_PROTECTED_BUILTIN.format(target)
    if ledger is not None and path_hit(Manifest((ledger,)), rel):
        return R_PROTECTED_BUILTIN.format(target)
    if path_hit(boundary.manifest, rel):
        return R_PROTECTED_PATH.format(target)
    if extension_hit(boundary.manifest, rel):
        return R_PROTECTED_EXT.format(target)
    return None


def _pathspec_ok(args: list[str], cwd: str, base: str | None = None) -> bool:
    # I3a, 0022: `-- <unit worktree paths>`; relative ones resolve against -C (base).
    root = cwd if base is None else base
    return (
        len(args) > 1
        and args[0] == "--"
        and not _has_magic(args[1:])
        and all(_in_unit_worktree(_abs(a, root), cwd) for a in args[1:])
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
        frozenset({"--oneline", "--stat", "--name-only", "-p", "--no-merges", "--all"})
        | {"--pickaxe-regex", "--pickaxe-all"},
        (*_FORMAT, "--grep=", "--author="),
        (r"-\d+", r"-n\d+", r"-[SG].+"),
        frozenset({"-n", "-S", "-G"}),
    ),
    "diff": lambda a, _: _flags_ok(
        a,
        frozenset(
            {"--stat", "--name-only", "--name-status", "--cached", "--word-diff", "--color=never"}
            | {"--check"}
        ),
        (),
        (r"-U\d+",),
    ),
    "show": lambda a, _: _flags_ok(
        a, frozenset({"--stat", "--name-only", "--name-status", "--oneline", "-s"}), _FORMAT
    ),
    # O5: history reads; -O (pager), -f, --no-index and --contents stay out.
    "grep": lambda a, _: _flags_ok(
        a,
        frozenset({"--cached", "--untracked", "--heading", "--break"}),
        (),
        (r"-[nilLwvcEFIhH]+", r"-[ABC]\d+"),
        frozenset({"-e", "-A", "-B", "-C", "--max-depth"}),
    ),
    "blame": lambda a, _: _flags_ok(
        a,
        frozenset({"-w", "-s", "-e", "-l", "--porcelain", "--line-porcelain"}),
        (),
        (r"-[CM]\d*", r"-L.+"),
        frozenset({"-L"}),
    ),
    "merge-base": lambda a, _: _flags_ok(
        a, frozenset({"--is-ancestor", "--all", "--octopus", "--independent", "--fork-point"})
    ),
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
    # O5: --output and its abbreviations, even where an option value would swallow it.
    if any(_long_matches(arg, "--output", 1) for arg in args):
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
    # 0022: git chains each -C onto the previous one.
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
# issue 2: the conductor commits the index as staged; the coder's commit grammar is unchanged.
_CONDUCTOR_GRAMMAR: dict[str, Callable[[list[str], str], bool]] = {
    **_GIT_GRAMMAR,
    "commit": lambda a, cwd: not _commits_work_tree(a) and _commit_ok(a, cwd),
}


def _train_branch(cwd: str) -> str | None:
    # issue 11: the active train's integration branch, named by the train marker.
    train = active_train(project_root(cwd))
    return f"daedalus/{train}" if train else None


def _conductor_push_reason(tokens: list[str], cwd: str, charter: str | None) -> str | None:
    sub, args, globals_ = _git_split(tokens)
    if sub != "push":
        return R_CONDUCTOR_PUSH
    # 0078: the one global admitted is -C naming the declared charter root exactly.
    if globals_ and not (
        charter is not None
        and len(globals_) == 2
        and globals_[0] == "-C"
        and os.path.realpath(_abs(globals_[1], cwd)) == os.path.realpath(_abs(charter, cwd))
    ):
        return R_CONDUCTOR_CHARTER
    if args[:1] in (["-u"], ["--set-upstream"]):
        args = args[1:]
    if len(args) == 2 and args[1].casefold() == "head":
        return R_CONDUCTOR_PUSH_HEAD
    if not (
        len(args) == 2
        and args[0] == "origin"
        and _BRANCH_NAME.fullmatch(args[1])
        and args[1].casefold() not in _DEFAULT_BRANCHES
    ):
        return R_CONDUCTOR_PUSH
    branch = _train_branch(cwd)
    if branch is None:
        return R_CONDUCTOR_NO_TRAIN
    return None if args[1] == branch else R_CONDUCTOR_PUSH_BRANCH.format(branch=branch)


def _reaches_charter(tokens: list[str], cwd: str, charter: str | None) -> bool:
    # 0078: a git -C into the charter root; only the train branch push may do that.
    globals_ = _git_split(tokens)[2]
    return (
        charter is not None
        and "-C" in globals_
        and _under(_git_dir(globals_, cwd), _abs(charter, cwd))
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


def _gh_allowed(tokens: list[str]) -> bool:
    words = _gh_words(tokens)
    return len(words) == 2 and words[1] in GH_ALLOWED.get(words[0], frozenset())


_GH_PR_WRITES = frozenset({"create", "edit", "comment"})


def _gh_words(tokens: list[str]) -> list[str]:
    # issue 76: gh_policy's parse; a segment it refuses has no command path, so nothing is allowed.
    parsed = gh_args(tokens[1:])
    return [] if parsed is None else parsed.words[:2]


def _gh_flags(tokens: list[str], *names: str) -> list[GhFlag]:
    parsed = gh_args(tokens[1:])
    return [] if parsed is None else [f for f in parsed.flags if f.name in names]


def _gh_pr_write(tokens: list[str]) -> bool:
    words = _gh_words(tokens)
    return words[:1] == ["pr"] and words[1:2] != [] and words[1] in _GH_PR_WRITES


def _gh_repo_flag(tokens: list[str]) -> bool:
    # I7: reads may name another repo; pr writes stay in the current one.
    return _gh_pr_write(tokens) and bool(_gh_flags(tokens, "-R", "--repo"))


# 0078: gh's [HOST/]OWNER/REPO from an https, ssh or scp-form origin URL.
_REMOTE_URL = re.compile(
    r"(?:(?:https?|ssh|git)://(?:[^@/]+@)?(?P<host>[^/:@]+)(?::\d+)?/"
    r"|(?:[^@/:]+@)?(?P<scp>[^/:@]+):)"
    r"(?P<path>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?"
)


def _remote_slug(url: str) -> str | None:
    match = _REMOTE_URL.fullmatch(url.strip())
    if match is None:
        return None
    host = (match["host"] or match["scp"]).casefold()
    return match["path"] if host == "github.com" else f"{host}/{match['path']}"


def _charter_slug(charter: str) -> str | None:
    # 0078: a local read of the charter root's origin; the URL never reaches a reason.
    cmd = ["git", "-C", charter, "remote", "get-url", "origin"]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=2, env=_git_env(), check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return _remote_slug(out.stdout) if out.returncode == 0 else None


def _gh_flag_values(tokens: list[str], long: str, short: str) -> list[str] | None:
    # 0078: `--x v`, `--x=v` and `-X v` only; an attached or bundled short form fails closed.
    if gh_args(tokens[1:]) is None:
        return None
    found = _gh_flags(tokens, long, f"-{short}")
    return None if any(f.attached for f in found) else [f.value or "" for f in found]


def _charter_pr_create_ok(tokens: list[str], cwd: str, charter: str | None) -> bool:
    # 0078: one gh pr create on the declared charter root's origin, for this train's branch.
    if charter is None or _gh_words(tokens) != ["pr", "create"]:
        return False
    repos = _gh_flag_values(tokens, "--repo", "R")
    heads = _gh_flag_values(tokens, "--head", "H")
    if repos is None or heads is None or len(repos) != 1 or len(heads) != 1:
        return False
    branch = _train_branch(cwd)
    if branch is None or heads[0] != branch:
        return False
    return repos[0] == _charter_slug(_abs(charter, cwd))


def _gh_body_file_ok(tokens: list[str], cwd: str) -> bool:
    if not _gh_pr_write(tokens):
        return True
    for flag in _gh_flags(tokens, "--body-file", "-F"):
        value = flag.value or ""
        # I7: stdin (-) and relative-to-elsewhere paths fail; realpath under the two homes only.
        if value in {"", "-"} or not (
            _under(_abs(value, cwd), f"{cwd}/docs/.tmp") or _under(_abs(value, cwd), "/tmp")
        ):
            return False
    return True


def _gh_write_reason(tokens: list[str]) -> str | None:
    if not _gh_pr_write(tokens):
        return None
    if _gh_flags(tokens, "--body", "-b") or not _gh_flags(tokens, "--body-file", "-F"):
        return R_BODY_INLINE
    if _gh_words(tokens)[1] == "edit" and _gh_flags(tokens, "--base", "-B"):
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
    if name == "mknod":
        # issue 75: NAME TYPE [MAJOR MINOR]; only NAME is a path.
        return _write_operands("mkfifo", args)[:1]
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


def _backup_suffix(name: str, args: list[str]) -> str | None:
    # issue 30: a backup suffix with a slash places the backup outside the target's directory.
    if name not in {"cp", "mv", "install", "ln"}:
        return None
    for i, arg in enumerate(args):
        value = None
        if arg.startswith("--suffix="):
            value = arg.split("=", 1)[1]
        elif arg in {"--suffix", "-S"}:
            value = args[i + 1] if i + 1 < len(args) else ""
        elif arg.startswith("-S") and not arg.startswith("--"):
            value = arg[2:]
        if value is not None and "/" in value:
            return f"backup suffix {value}"
    return None


def _coder_write_targets(segment: list[str], cwd: str) -> list[str]:
    # 0054: file operands of a write command, and git restore or checkout pathspecs.
    name = _base(segment[0])
    args = segment[1:]
    if name == "git":
        sub, git_args, globals_ = _git_split(segment)
        if sub not in {"restore", "checkout"} or git_args[:1] != ["--"]:
            return []
        base = _git_dir(globals_, cwd)
        return [_abs(a, base) for a in git_args[1:]]
    if name not in CODER_WRITE_CMDS and not (name in {"sed", "perl"} and _in_place(name, args)):
        return []
    return [_abs(a, cwd) for a in _write_operands(name, args) if a != "-"]


def _coder_bash_reason(
    segment: list[str], cwd: str, boundary: Callable[[], CoderBoundary | str]
) -> str | None:
    name = _base(segment[0])
    args = segment[1:]
    if name in CODER_WRITE_CMDS or (name in {"sed", "perl"} and _in_place(name, args)):
        suffix = _backup_suffix(name, args)
        if suffix is not None:
            return R_BASH_OUTSIDE.format(suffix)
    for target in _coder_write_targets(segment, cwd):
        if not _in_unit_worktree(target, cwd):
            return R_BASH_OUTSIDE.format(target)
        reason = _coder_write_reason(target, cwd, boundary())
        if reason:
            return reason
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


def _data_dir_write(command: str) -> bool:
    normalized = _normalize_paths(command)
    named = any(marker in normalized for marker in _data_dir_markers())
    if not (named or _cd_into_claude(normalized)):
        return False
    # I4: quoted spans collapse first so a jq filter's `>` reads as data, not a redirect.
    unquoted = _quote_spans(normalized.replace("$'", "'").replace('$"', '"'))
    return bool(_DATA_DIR_WRITE.search(_DEVNULL.sub(" ", unquoted)))


def _data_dir_path(path: str, cwd: str) -> bool:
    env = os.environ.get("CLAUDE_PLUGIN_DATA")
    if env and os.path.isabs(env) and _under(path, env):
        return True
    # 0010: the project data dir for this cwd, plus any .claude/daedalus in another worktree.
    return _names_project_data(path) or _under(path, str(project_data_dir(cwd)))


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


def _shell_words(command: str) -> list[list[str]]:
    # spec 8: single-quoted or escaped $ is literal; quote edges end a variable name.
    segments: list[list[str]] = []
    words: list[str] = []
    cur: list[str] = []
    started, redirect, quote = False, False, ""
    i, n = 0, len(command)

    def end_word() -> None:
        nonlocal cur, started, redirect
        if cur or started:
            words.append((_REDIRECT if redirect else "") + "".join(cur))
            redirect = False
        cur, started = [], False

    while i < n:
        c = command[i]
        if quote == "'":
            if c == "'":
                quote = ""
                cur.append(_CUT)
            else:
                cur.append(_LIT if c == "$" else c)
        elif quote == '"':
            if c == '"':
                quote = ""
                cur.append(_CUT)
            elif c == "\\" and i + 1 < n:
                i += 1
                cur.append(_LIT if command[i] == "$" else command[i])
            else:
                cur.append(c)
        elif c in "'\"":
            quote, started = c, True
            cur.append(_CUT)
        elif c == "\\" and i + 1 < n:
            i += 1
            cur.append(_LIT if command[i] == "$" else command[i])
            started = True
        elif c in "<>":
            end_word()
            redirect = True
            while i + 1 < n and command[i + 1] in "&>":
                i += 1
        elif c.isspace() or c in ";&|()`":
            end_word()
            if c not in " \t" and words:
                segments.append(list(words))
                words.clear()
        else:
            cur.append(c)
            started = True
        i += 1
    end_word()
    if words:
        segments.append(words)
    return segments


def _bash_env(segments: list[list[str]]) -> list[dict[str, list[str]]]:
    # spec 8: assignments and for-loops bind, read and friends unbind, HOME stays real.
    env = {k: [v] for k, v in os.environ.items()}
    env["HOME"] = [str(Path.home())]
    env.setdefault("CLAUDE_PLUGIN_ROOT", [os.path.dirname(_REPO_SCRIPTS)])
    env.setdefault("CLAUDE_PLUGIN_DATA", [env["HOME"][0] + _DATA_DIR_DEFAULT])
    envs: list[dict[str, list[str]]] = []
    changes: list[dict[str, list[str] | None]] = []
    for words in segments:
        clean = [_clean(w) for w in words]
        changed: dict[str, list[str] | None] = {}
        for i, word in enumerate(words):
            name, eq, value = word.partition("=")
            if eq and _ASSIGN.match(word) and name != "HOME":
                bound = _expand_word(value, env)
                unknown = any(u for _, u in bound)
                changed[name] = None if unknown else [t for t, _ in bound]
            if clean[i] == "for" and i + 1 < len(words):
                loop = [x for w in words[i + 3 :] for x in _expand_word(w, env)]
                listed = i + 2 < len(words) and clean[i + 2] == "in"
                ok = listed and not any(u for _, u in loop)
                changed[clean[i + 1]] = [t for t, _ in loop] if ok else None
            if clean[i] in _BINDERS:
                for later in clean[i + 1 :]:
                    if not later.startswith("-"):
                        changed[later] = None
            for key, values in changed.items():
                if values is None:
                    env.pop(key, None)
                else:
                    env[key] = values
        # spec 8: a binding applies from its own segment onward, never to earlier segments.
        envs.append(dict(env))
        changes.append(changed)
    _loop_union(segments, envs, changes)
    return envs


def _loop_union(
    segments: list[list[str]],
    envs: list[dict[str, list[str]]],
    changes: list[dict[str, list[str] | None]],
) -> None:
    # spec 8: a later iteration sees every binding in its loop, header included.
    opened: list[int] = []
    for k, words in enumerate(segments):
        first = _clean(words[0])
        if first == "do":
            head = k - 1 if k and _clean(segments[k - 1][0]) in {"for", "while", "until"} else k
            opened.append(head)
        if first != "done" or not opened:
            continue
        span = range(opened.pop(), k + 1)
        merged: dict[str, list[str] | None] = {}
        for j in span:
            for key, values in changes[j].items():
                prior = merged.get(key, [])
                merged[key] = None if values is None or prior is None else [*prior, *values]
        for j in span:
            for key, values in merged.items():
                if values is None:
                    envs[j].pop(key, None)
                else:
                    envs[j][key] = list(dict.fromkeys([*envs[j].get(key, []), *values]))


def _command_at(
    clean: list[str], skip: set[int], options: list[WrapperOption] | None = None
) -> int | None:
    # spec 8, issue 76: past control words and assignments, then shell.unwrap; options collects.
    places = [i for i, word in enumerate(clean) if word and i not in skip]
    k = 0
    while k < len(places):
        word = clean[places[k]]
        if word in _CONTROL_WORDS or _ASSIGN.match(word):
            k += 1
            continue
        unwrapped = unwrap([clean[i] for i in places[k:]])
        if unwrapped is None:
            return _OPAQUE
        rest, found = unwrapped
        if options is not None:
            options += [o._replace(at=places[k + o.at]) for o in found]
        if not rest:
            return None
        if len(places) - len(rest) == k:
            return places[k]
        k = len(places) - len(rest)
    return None


def _opaque_words(clean: list[str], skip: set[int]) -> set[int]:
    # issue 76: past an unknown wrapper option the command word is unknown; these words remain.
    return {i for i, word in enumerate(clean) if word and i not in skip}


def _opaque_values(texts: list[str], indices: set[int]) -> list[str]:
    # issue 76: each plain word, plus an option word's value (--x=v, -X=v), as a path.
    # audit round 1: a short cluster's value may start at any letter (-iC/x), so every suffix.
    values: list[str] = []
    for i in sorted(indices):
        word = texts[i]
        if not word.startswith("-"):
            values.append(word)
            continue
        if "=" in word:
            values.append(word.split("=", 1)[1])
        if not word.startswith("--"):
            values += [word[k:] for k in range(2, len(word))]
    return list(dict.fromkeys(v for v in values if v))


def _opaque_targets(texts: list[str], indices: set[int], cwd: str) -> list[str]:
    # issue 76: any value may be a folder the command moves to, so each is also a base.
    values = _opaque_values(texts, indices)
    bases = [cwd, *(b for b in (_anchor(v, cwd) for v in values) if b)]
    found = (_anchor(v, base) for v in values for base in dict.fromkeys(bases))
    return list(dict.fromkeys(t for t in found if t))


def _option_values(
    texts: list[str], options: list[WrapperOption], kinds: frozenset[tuple[str, str]]
) -> list[str]:
    return [texts[o.at][len(o.prefix) :] for o in options if (o.wrapper, o.option) in kinds]


def _moved_base(texts: list[str], options: list[WrapperOption], cwd: str) -> str | None:
    # issue 76: env -C, env --chdir and sudo -D move the command's folder, each from the last.
    base: str | None = cwd
    for value in _option_values(texts, options, WRAPPER_CHDIR):
        base = _anchor(value, base) if base is not None else None
    return base


def _search_paths(name: str, clean: list[str], args: list[int]) -> set[int]:
    # spec 8: grep and rg take the first operand as the pattern unless -e or -f names it.
    letters = _SEARCH_VALUES["rg" if name == "rg" else "grep"] if name != "jq" else frozenset()
    paths: set[int] = set()
    operands: list[int] = []
    explicit, pending = False, ""
    for i in args:
        word = clean[i]
        if pending:
            if pending in {"f", "--file"}:
                paths.add(i)
            pending = ""
        elif word.startswith("--"):
            opt = word.split("=", 1)[0]
            explicit = explicit or opt in {"--regexp", "--file"}
            if opt == "--file" and "=" in word:
                paths.add(i)
            elif "=" not in word and opt in _SEARCH_LONGS:
                pending = opt
        elif word.startswith("-") and len(word) > 1:
            for j, ch in enumerate(word[1:]):
                if ch in letters:
                    explicit = explicit or ch in "ef"
                    if j == len(word) - 2:
                        pending = ch
                    elif ch == "f":
                        paths.add(i)
                    break
        else:
            operands.append(i)
    return paths | set(operands if explicit else operands[1:])


def _path_positions(words: list[str]) -> tuple[str, int, set[int]]:
    # spec 8: where an unresolved variable could name a file for a modeled reader or writer.
    clean = [_clean(w) for w in words]
    paths = {i for i, w in enumerate(words) if w.startswith(_REDIRECT)}
    at = _command_at(clean, paths)
    if at == _OPAQUE:
        return "", -1, paths | _opaque_words(clean, paths)
    if at is None:
        return "", -1, paths
    name = _base(clean[at])
    args = [i for i in range(at + 1, len(clean)) if i not in paths]
    if name in _GREPS or name in {"rg", "jq"}:
        return name, at, paths | _search_paths(name, clean, args)
    if name == "find":
        for i in args:
            if clean[i].startswith(("-", "(", "!")):
                break
            paths.add(i)
        return name, at, paths
    if name in _PATH_CMDS:
        paths |= {i for i in args if not clean[i].startswith("-") or _PATH_OPTION.match(clean[i])}
    return name, at, paths


def _tree_reader(
    name: str, clean: list[str], at: int, ops: list[int], command: str
) -> tuple[bool, list[int], bool] | None:
    # spec 8: (sees hidden dirs, operand indices, reads the cwd when no operand is given).
    args = clean[at + 1 :]
    longs = {a.split("=", 1)[0] for a in args if a.startswith("--")}
    short = {c for a in args if a.startswith("-") and not a.startswith("--") for c in a[1:]}
    if name in _GREPS:
        on = bool({"r", "R"} & short or {"--recursive", "--dereference-recursive"} & longs)
        on = on or any(a.startswith("--directories=recurse") for a in args)
        return (True, ops, not ops) if on else None
    if name == "rg":
        return rg_reaches_hidden(args, command), ops, not ops
    if name == "find":
        on = bool({"-exec", "-execdir", "-ok", "-okdir"} & set(args)) or "xargs" in command
        return (True, ops, not ops) if on else None
    if name in {"tar", "rsync", "bsdtar", "7z", "7za", "7zr", "7zz", "pax"}:
        return True, ops, False
    if name == "scp" and "r" in short:
        return True, ops, False
    if name == "cp" and ({"r", "R", "a"} & short or {"--recursive", "--archive"} & longs):
        return True, ops, False
    if name == "zip" and ({"r", "R"} & short or "--recurse-paths" in longs):
        return True, ops, False
    return None


_RG_GLOBS = frozenset({"--glob", "--iglob"})
# 113, prepush-2026-10-27: each reads hidden or ignored files, or follows a link out of the tree.
_RG_REACH_LONGS = frozenset(
    {"--hidden", "--no-ignore", "--unrestricted", "--ignore-file", "--follow"}
)
_RG_REACH_SHORT = frozenset("u.L")
_RG_CONFIG_ENV = "RIPGREP_CONFIG_PATH"
R_RG_REACH = (
    "rg with --hidden, -u, --no-ignore, --ignore-file, -L, --follow or RIPGREP_CONFIG_PATH reads "
    "hidden or ignored files (113). Next: drop the flag and search the tree as rg skips it"
)
R_RG_ONE = "a verify is one plain rg search with no wrapper, prefix, pipe or chain (113)"


def rg_reaches_hidden(args: list[str], command: str) -> bool:
    # 113: a config file can add any flag, so its variable anywhere in the command fails closed.
    longs = {a.split("=", 1)[0] for a in args if a.startswith("--")}
    short = {c for a in args if a.startswith("-") and not a.startswith("--") for c in a[1:]}
    return bool(_RG_REACH_SHORT & short or _RG_REACH_LONGS & longs) or _RG_CONFIG_ENV in command


def _rg_globs(args: list[str]) -> list[str]:
    # SC-12: each -g, --glob or --iglob whitelist; a negated glob only hides, a $ value is *.
    raws: list[str] = []
    letters = _SEARCH_VALUES["rg"]
    i = 0
    while i < len(args) and args[i] != "--":
        arg, later = args[i], (args[i + 1 : i + 2] or [""])[0]
        key, eq, value = arg.partition("=")
        if arg.startswith("--") and (key in _RG_GLOBS or key in _SEARCH_LONGS) and not eq:
            raws += [later] if key in _RG_GLOBS else []
            i += 1
        elif arg.startswith("--"):
            raws += [value] if key in _RG_GLOBS else []
        elif arg.startswith("-"):
            hit = next((k for k, c in enumerate(arg[1:], 2) if c in letters), None)
            if hit is not None:
                # SC-12: -g=x may reach rg as x or =x, so both are judged.
                value = arg[hit:] or later
                raws += [value, value.removeprefix("=")] if arg[hit - 1] == "g" else []
                i += 0 if arg[hit:] else 1
        i += 1
    raws = ["*" if set("$`") & set(r) else r for r in dict.fromkeys(raws) if not r.startswith("!")]
    return [p for raw in raws for p in glob_patterns(raw)]


def _tree_reason(
    parsed: list[tuple[list[str], tuple[str, int, set[int]]]],
    envs: list[dict[str, list[str]]],
    bases: list[str],
    roots: list[str],
    command: str,
    keys: tuple[str, ...] = (),
) -> str | None:
    dotglob = _dotglob_on(command)
    # SC-12: reply key roots let a dot folder hide them from **; credential stores do not.
    pairs = [(root, False) for root in roots] + [(key, True) for key in keys]
    for k, (words, (name, at, paths)) in enumerate(parsed):
        if at < 0:
            continue
        ops = [i for i in sorted(paths) if not words[i].startswith(_REDIRECT)]
        found = _tree_reader(name, [_clean(w) for w in words], at, ops, command)
        if found is None:
            continue
        hidden, ops, implicit = found
        globs = _rg_globs([_clean(w) for w in words[at + 1 :]]) if name == "rg" else []
        targets = list(bases) if implicit else []
        for i in ops:
            for text, _ in _expand_word(words[i], envs[k]):
                targets += [t for t in (_anchor(text, b) for b in bases or [""]) if t]
        for target in targets:
            for root, dots_hide in pairs:
                rest = _store_rest(target, root, True, dotglob, dots_hide)
                # spec 8, SC-12: rg skips hidden dirs unless a flag or a whitelist glob reaches one.
                shown = hidden or glob_reaches(globs, rest or [])
                if rest is not None and (shown or not any(p.startswith(".") for p in rest)):
                    return R_CREDENTIAL_TREE.format(path=target)
                if rest is not None and name == "rg" and ignore_whitelist(root):
                    return R_IGNORE_WHITELIST.format(path=target)
    return None


def rg_reason(command: str, cwd: str) -> str | None:
    # 113: the specialist's rg judgement as one call; packs.py judges each pack verify by it.
    chain = shell.worker_parse(command)
    if chain is None or len(chain.tokens) != 1 or chain.tokens[0][:1] != ["rg"]:
        return R_RG_ONE
    tokens = chain.tokens[0]
    if not _read_only_segment(tokens, frozenset(), cwd, None):
        return R_SPECIALIST_BASH
    if rg_reaches_hidden(tokens[1:], command):
        return R_RG_REACH
    # 113: judged against the reply key's fixed place, whether or not one exists yet.
    if glob_reaches(_rg_globs(tokens[1:]), [".claude", "daedalus", REPLY_KEY_NAME]):
        return R_REPLY_KEY_TREE.format(path=cwd)
    return _credential_reason("Bash", {"command": command}, cwd)


def _bash_credential_reason(
    command: str, cwd: str, roots: list[str], keys: tuple[str, ...] = ()
) -> str | None:
    segments = _shell_words(command)
    envs = _bash_env(segments)
    dotglob = _dotglob_on(command)
    parsed = [(words, _path_positions(words)) for words in segments]
    bases = [cwd] if os.path.isabs(cwd) else []
    for k, (words, (name, at, _)) in enumerate(parsed):
        # issue 76: a wrapper that changes folder is a base for relative paths, like cd.
        moves: list[WrapperOption] = []
        clean = [_clean(w) for w in words]
        redirects = {i for i, w in enumerate(words) if w.startswith(_REDIRECT)}
        found_at = _command_at(clean, redirects, moves)
        texts = [(_expand_word(w, envs[k]) or [("", False)])[0][0] for w in words]
        moved = [_moved_base(texts, moves, cwd)] if os.path.isabs(cwd) else []
        if found_at == _OPAQUE and os.path.isabs(cwd):
            values = _opaque_values(texts, _opaque_words(clean, redirects))
            moved += [_anchor(v, cwd) for v in values]
        bases += [b for b in dict.fromkeys(moved) if b is not None and b not in bases]
        if name not in {"cd", "pushd"}:
            continue
        # spec 8: the first non-option argument is the target; a bare cd goes home.
        target, options = None, True
        for word in words[at + 1 :]:
            if options and _clean(word) == "--":
                options = False
            elif not (options and _clean(word).startswith("-")):
                target = word
                break
        texts = [t for t, _ in _expand_word(target, envs[k])] if target else envs[k]["HOME"]
        bases += [b for b in (_anchor(t, cwd) for t in texts) if b]
    absolute: list[str] = []
    relative: list[str] = []
    unresolved = ""
    for k, (words, (_, _, paths)) in enumerate(parsed):
        env = envs[k]
        for i, word in enumerate(words):
            for text, unknown in _expand_word(word, env):
                if unknown and i in paths and not unresolved:
                    unresolved = _clean(word)
                parts = [_tilde(p, env["HOME"][0]) for p in _CREDENTIAL_PART.split(text)[1:] if p]
                for cand in [text, *parts]:
                    (absolute if os.path.isabs(cand) else relative).append(cand)

    def hit(target: str) -> str | None:
        if reply_key_hit(target) or _credential_hit(target, list(keys), True, dotglob, True):
            return R_REPLY_KEY.format(path=target)
        if _credential_hit(target, roots, True, dotglob):
            return R_CREDENTIAL.format(path=target)
        return None

    # spec 8: spelled-out paths first, so the message names the path the command wrote.
    for cand in absolute:
        reason = hit(os.path.normpath(cand))
        if reason:
            return reason
    if unresolved:
        return R_CREDENTIAL_PARAM.format(path=unresolved)
    # audit B4 round 3: an unexpanded brace word whose alternative starts its own path.
    unjudged = next((w for s in segments for w in map(_clean, s) if _unjudged_root(w)), "")
    if unjudged:
        return R_BRACE_UNJUDGED.format(path=unjudged)
    for cand in relative:
        for base in bases:
            reason = hit(os.path.normpath(os.path.join(base, cand)))
            if reason:
                return reason
    return _tree_reason(parsed, envs, bases, roots, command, keys)


def _credential_reason(tool: str, tool_input: dict[str, object], cwd: str) -> str | None:
    if tool == "Bash":
        command = str(tool_input.get("command") or "")
        # SC-12: the reply key joins as its own roots, so globs and folder reads of it refuse.
        keys = tuple(key_roots(cwd))
        return _bash_credential_reason(command, cwd, _credential_roots(), keys)
    if tool not in CREDENTIAL_TOOLS and tool not in WRITE_TOOLS:
        return None
    return path_reason(tool, tool_input, cwd)


def _policy_segments(command: str, depth: int = 0) -> list[list[str]] | None:
    # 0028: see gh and git push through wrappers and shell -c bodies; None means regex fallback.
    if depth > 3:
        return None
    parsed = tokenize(command)
    if parsed is None:
        return None
    flat: list[list[str]] = []
    for segment in parsed:
        tokens = strip_wrappers(segment)
        if tokens is None:
            return None
        if not tokens:
            continue
        name = _base(tokens[0])
        if name in _SHELLS or name == "eval":
            code = " ".join(tokens[1:]) if name == "eval" else _shell_code(tokens)
            if code == _FALLBACK:
                return None
            inner = _policy_segments(code, depth + 1) if code else []
            if inner is None:
                return None
            flat += inner
            continue
        inline = name.startswith("python") or name in {"perl", "ruby", "node"}
        if name not in {"gh", "git"} and (inline or {"gh", "git"} & {_base(t) for t in tokens}):
            return None
        flat.append(tokens)
    return flat


def _gh_gate(agent: str, cwd: str, command: str) -> str | None:
    # 0035: outside a train, main and unknown agents skip the whole gate, deny classes included.
    if not allowlist_applies(agent, cwd, command):
        return None
    return gh_reason(agent, command, _policy_segments(command))


def _train_active(cwd: str) -> bool:
    # 0023: existence only; a symlinked or unreadable marker still counts as an active train.
    return os.path.lexists(train_marker(project_root(cwd)))


_TARGET_CAP = 8
_GIT_DIR_OPTS = ("--git-dir=", "--work-tree=")
R_SHELL_BODY = (
    "a shell -c body is one command string the jail does not walk for what it writes "
    "(issue 81). Next: run the command directly, without bash -c, sh -c or flock -c."
)
_BODY_DEPTH = 3


def _shell_body(words: list[str]) -> str | None:
    # issue 81: the -c body of a shell; past an unknown long flag, the word after a c flag.
    code = _shell_code(words)
    if code != _FALLBACK:
        return code
    flags = [k for k, w in enumerate(words) if w[:1] in "-+" and w[1:2] != "-" and "c" in w[1:]]
    return (words[flags[0] + 1 : flags[0] + 2] or [""])[0] if flags else None


def _hidden_bodies(words: list[str]) -> list[tuple[str, str]]:
    # issue 80, 81: (finding, command string) for each env -S value and shell or flock -c body.
    found = [(R_ENV_SPLIT, value) for value in env_split_values(words)]
    for at, word in enumerate(words):
        name = _base(word)
        body = _shell_body(words[at:]) if name in _SHELLS else None
        if name == "flock" and (
            hits := [k for k in range(at + 1, len(words)) if words[k].split("=")[0] in FLOCK_BODY]
        ):
            _, eq, value = words[hits[0]].partition("=")
            body = value if eq else (words[hits[0] + 1 : hits[0] + 2] or [""])[0]
        if body is not None:
            found.append((R_SHELL_BODY, body))
    return found


def _hidden_reason(command: str) -> str | None:
    # issue 80, 81: the first env -S or -c body in any segment, refused while a train runs.
    for words in _shell_words(command):
        hidden = _hidden_bodies([_clean(w) for w in words if not w.startswith(_REDIRECT)])
        if hidden:
            return hidden[0][0]
    return None


def _body_past_cap(command: str, depth: int = 0) -> bool:
    # issue 81: a body nested past _BODY_DEPTH is never walked, so the call is judged in a train.
    for words in _shell_words(command):
        for _, body in _hidden_bodies([_clean(w) for w in words if not w.startswith(_REDIRECT)]):
            if depth >= _BODY_DEPTH or _body_past_cap(body, depth + 1):
                return True
    return False


def _bash_write_dirs(command: str, cwd: str, depth: int = 0) -> list[str]:
    # issue 30: redirects, write operands, cd targets and git -C name the repos a command acts on.
    segments = _shell_words(command)
    envs = _bash_env(segments)
    found: list[str] = []
    for k, words in enumerate(segments):
        clean = [_clean(w) for w in words]
        texts = [(_expand_word(w, envs[k]) or [("", False)])[0][0] for w in words]
        redirects = {i for i, w in enumerate(words) if w.startswith(_REDIRECT)}
        options: list[WrapperOption] = []
        at = _command_at(clean, redirects, options)
        # issue 76: redirects and the wrapper's own output open in cwd; the command's in base.
        picks = [texts[i] for i in sorted(redirects)] + _option_values(
            texts, options, WRAPPER_WRITES
        )
        base = _moved_base(texts, options, cwd)
        acts = [base] if base is not None and base != cwd else []
        if at == _OPAQUE or base is None:
            picks += _opaque_targets(texts, _opaque_words(clean, redirects), cwd)
        elif at is not None:
            name = _base(clean[at])
            args = [texts[i] for i in range(at + 1, len(words)) if i not in redirects]
            if name in {"cd", "pushd"}:
                acts += [a for a in args if not a.startswith("-")][:1]
            elif name == "git":
                sub, _, globals_ = _git_split(["git", *args])
                # spec 6: worktree reads by name only after its grammar; add and remove act on -C.
                if sub not in READ_ONLY_GIT or sub == "worktree":
                    pairs = zip(globals_, globals_[1:], strict=False)
                    acts += [value for flag, value in pairs if flag == "-C"]
                    acts += [g.split("=", 1)[1] for g in globals_ if g.startswith(_GIT_DIR_OPTS)]
            elif name in CODER_WRITE_CMDS or (name in {"sed", "perl"} and _in_place(name, args)):
                acts += [a for a in _write_operands(name, args) if a != "-"]
        found += [t for t in (_anchor(p, cwd) for p in picks) if t]
        found += [t for t in (_anchor(p, base or cwd) for p in acts) if t]
        if depth < _BODY_DEPTH:
            # issue 80, 81: a hidden body's own targets name the repo, so a train scopes the call.
            plain = [texts[i] for i in range(len(words)) if i not in redirects]
            for _, body in _hidden_bodies(plain):
                found += _bash_write_dirs(body, base or cwd, depth + 1)
    return found


def _write_dirs(tool: str, tool_input: dict[str, object], cwd: str) -> list[str]:
    if tool in WRITE_TOOLS:
        raw = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        return [_abs(raw, cwd)] if raw else []
    if tool == "Bash":
        return _bash_write_dirs(str(tool_input.get("command") or ""), cwd)
    return []


def _marked_repo(cwd: str, tool: str, tool_input: dict[str, object]) -> Path | None:
    # 0023, issue 30: a train in the cwd repo or in any repo the call writes into counts.
    seen: set[str] = set()
    for path in [cwd, *_write_dirs(tool, tool_input, cwd)]:
        while path and not os.path.isdir(path) and os.path.dirname(path) != path:
            path = os.path.dirname(path)
        if not os.path.isabs(path) or path in seen:
            continue
        seen.add(path)
        if len(seen) > _TARGET_CAP:
            break
        root = project_root(path)
        if os.path.lexists(train_marker(root)):
            return root
    return None


def _train_scoped(cwd: str, tool: str, tool_input: dict[str, object]) -> bool:
    # 0035: an unknown repo (no absolute cwd) is judged as if a train runs there.
    return (
        not os.path.isabs(cwd)
        or _marked_repo(cwd, tool, tool_input) is not None
        or (tool == "Bash" and _body_past_cap(str(tool_input.get("command") or "")))
    )


def _ours(raw_agent: str) -> bool:
    prefix, sep, _ = raw_agent.partition(":")
    return bool(sep) and prefix in (*AGENT_NAMESPACES, TEST_NAMESPACE)


def _foreign_read_ok(command: str, cwd: str, charter: str | None) -> bool:
    # 0100: the auditor's per-segment read-only class, pipes included; no env-prefix strip.
    segments = tokenize(command)
    if not segments:
        return False
    return all(_read_only_segment(s, READ_ONLY_GIT, cwd, charter) for s in segments)


def _unknown_decision(
    raw_agent: str,
    agent: str,
    cwd: str,
    tool: str,
    tool_input: dict[str, object],
    charter: str | None = None,
) -> Decision:
    # 0023, 0100: a foreign agent reads only while a train is active; a daedalus name never acts.
    if _ours(raw_agent):
        return _block(R_UNKNOWN.format(agent=agent))
    if not os.path.isabs(cwd):
        return _block(R_NO_CWD)
    # 0010: the data dir is Daedalus's own integrity, refused to every agent train or not.
    raw_path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
    if tool in WRITE_TOOLS and _data_dir_path(_abs(raw_path, cwd), cwd):
        return _block(R_DATA_DIR)
    command = str(tool_input.get("command") or "") if tool == "Bash" else ""
    if command and (_data_dir_write(command) or _cd_data_dir_git(command)):
        return _block(R_DATA_DIR)
    repo = _marked_repo(cwd, tool, tool_input)
    # issue 81: a body past the walk's cap may name any repo, so it fails closed.
    if repo is None and not (command and _body_past_cap(command)):
        return _allow()
    hidden = _hidden_reason(command) if command else None
    if hidden is not None or repo is None:
        return _block(hidden or R_SHELL_BODY)
    if tool == "Bash" and _foreign_read_ok(command, cwd, charter):
        return _allow()
    return _block(R_UNKNOWN_TRAIN.format(agent=agent, marker=train_marker(repo), repo=repo))


def normalize_agent(agent_type: str) -> str:
    prefix, sep, name = agent_type.partition(":")
    test_ns = prefix == TEST_NAMESPACE and os.environ.get("DAEDALUS_LIVE_TEST") == "1"
    if sep and (prefix in AGENT_NAMESPACES or test_ns) and name:
        return name
    return agent_type


def decide(hook_input: dict[str, object], config: Config) -> Decision:
    raw_agent = hook_io.raw_agent(hook_input)
    agent = hook_io.agent(hook_input)
    tool = str(hook_input.get("tool_name") or "")
    cwd = str(hook_input.get("cwd") or "")
    raw_input = hook_input.get("tool_input")
    tool_input: dict[str, object] = raw_input if isinstance(raw_input, dict) else {}
    # m4, 0106: the operator's own session is bare main with no agent_id; it is never denied.
    operator = raw_agent == "main" and not hook_input.get("agent_id")
    if tool in CREDENTIAL_TOOLS:
        reason = path_reason(tool, tool_input, cwd)
        if reason and operator:
            # Main never prompted (amends 0106): allow with context, never ask, for main.
            return _with_agent(_main_warn(WARN_CREDENTIAL, reason), agent)
        return Decision(reason is None, reason, agent)
    # 0035: outside a train, main and foreign agents carry only the read deny above.
    if not policed_outside_train(raw_agent) and not _train_scoped(cwd, tool, tool_input):
        # 0130, D.5: main is warned here only when the hook calls the jail, during a train.
        roots = _main_excluded(tool, tool_input, cwd, config) if operator else _allow()
        return _with_agent(roots, agent)
    credential = _credential_reason(tool, tool_input, cwd)
    if credential and operator:
        warning = WARN_CREDENTIAL_WRITE if tool in WRITE_TOOLS else WARN_CREDENTIAL
        # Main never prompted (amends 0106): allow with context, never ask, for the main session.
        return _with_agent(_main_warn(warning, credential), agent)
    if credential:
        return Decision(False, credential, agent)
    if agent == "main" and raw_agent != "main":
        return Decision(False, R_NAMESPACED_MAIN, agent)
    # m4: only the orchestrator thread arrives without an agent_id.
    if agent == "main" and hook_input.get("agent_id"):
        return Decision(False, R_SUBAGENT_MAIN, agent)
    if agent == "main":
        decision = _decide_main(tool, cwd, tool_input)
        if decision.allow and operator:
            decision = _main_excluded(tool, tool_input, cwd, config)
    elif agent in KNOWN_AGENTS:
        # 0044: a Daedalus agent's calls run its agent file's hooks, never this function.
        decision = _block(R_ROUTED.format(agent=agent))
    elif tool == "Bash" and (gh := _gh_gate(agent, cwd, str(tool_input.get("command") or ""))):
        decision = _block(gh)
    else:
        charter = str(config.charter_root) if config.charter_root else None
        decision = _unknown_decision(raw_agent, agent, cwd, tool, tool_input, charter)
    return _with_agent(decision, agent)


def _with_agent(decision: Decision, agent: str) -> Decision:
    return Decision(decision.allow, decision.reason, agent, decision.warn)


def integrity_reason(tool: str, tool_input: dict[str, object], cwd: str) -> str | None:
    # 0053, issue 75: no absolute cwd, a write into .git or the data folder, Bash included.
    is_write = tool in WRITE_TOOLS
    if not (is_write or tool == "Bash"):
        return None
    if not os.path.isabs(cwd):
        return R_NO_CWD
    if not is_write:
        command = str(tool_input.get("command") or "")
        if _data_dir_write(command):
            return R_DATA_DIR
        return R_DATA_DIR_GIT if _cd_data_dir_git(command) else None
    path = _abs(str(tool_input.get("file_path") or tool_input.get("notebook_path") or ""), cwd)
    if ".git" in path.split(os.sep) or ".git" in os.path.normpath(path).split(os.sep):
        return R_DOTGIT
    return R_DATA_DIR if _data_dir_path(path, cwd) else None


def _decide_main(tool: str, cwd: str, tool_input: dict[str, object]) -> Decision:
    # Main never prompted (amends 0105, 0106): allow with context, never ask, for the main session.
    command = str(tool_input.get("command") or "")
    raw_path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
    is_write = tool in WRITE_TOOLS
    path = _abs(raw_path, cwd)
    integrity = integrity_reason(tool, tool_input, cwd)
    if integrity == R_NO_CWD:
        return _main_warn(WARN_NO_CWD, R_NO_CWD)
    if integrity == R_DOTGIT:
        return _main_warn(WARN_DOTGIT.format(path=path), R_DOTGIT)
    if integrity is not None:
        return _main_warn(WARN_DATA_DIR, integrity)
    if tool == "Bash":
        # 8.5, 0106: main meets only the tripwires, as warnings; regex fallback if tokenize refuses.
        reason = _command_reason(command) or _gh_gate("main", cwd, command)
        reason = reason or (R_NESTED_CLAUDE if _nested_claude(command, cwd) else None)
        return _tripwire_warn(reason) if reason else _allow()
    train = _main_write_train(path, cwd) if is_write else None
    if train is not None:
        return _warn(R_MAIN_TRAIN_WARN.format(train=train, path=path))
    if tool in dispatch_binding.DISPATCH_TOOLS:
        reason = dispatch_binding._dispatch_reason(tool_input, cwd)
        if reason:
            # Main never prompted (amends 0106): the dispatch runs with the skipped invariant named.
            return _warn(WARN_DISPATCH.format(reason=reason))
    return _allow()


def _nested_claude(command: str, cwd: str) -> bool:
    # audit A7-1, issue 55: through wrappers, shell -c bodies and links; the regex on a parse fail.
    segments = _policy_segments(command)
    if segments is None:
        return bool(_CLAUDE_WORD.search(command))
    return any(seg and runs_claude(seg, cwd) for seg in segments)


# 0136, D.5: the excluded roots rule; checks/excluded_roots.py and the main session share it.
R_EXCLUDED_PATH = (
    "{what} names {path}, inside the excluded root {root} (D.2.1). "
    "Next: keep files under that root out of git, gh and redirects."
)
R_EXCLUDED_TREE = (
    "{what} would take in the excluded root {root}, which git does not ignore (D.5). "
    "Next: name the paths to stage, or add the root to .gitignore."
)
R_EXCLUDED_TEXT = (
    "a command the jail cannot parse mentions the excluded root {root} beside git, gh or a "
    "redirect (D.5). Next: send one plain command that names its paths."
)
WARN_EXCLUDED = (
    "This command would put a file from a folder the project excludes into git, GitHub or a "
    "file write."
)
R_EXCLUDED_ICASE = (
    "{spec} makes git match paths in any letter case, so it can name a file in an excluded "
    "root under another spelling (issue 97). Next: spell each path in its exact case, without "
    ":(icase), the short :i: form, --icase-pathspecs or GIT_ICASE_PATHSPECS."
)
# issue 97: the icase spellings an unparsed command may carry.
_ICASE_TEXT = re.compile(
    r":\([^)]*\bicase\b|(?:^|[\s'\"=]):[^\s:(]*i[^\s:]*:|--icase-pathspecs|GIT_ICASE_PATHSPECS",
    re.I,
)
WARN_EXCLUDED_FAILED = "The excluded folders could not be resolved, so this command went unchecked."
_EXCLUDED_GIT = frozenset({"add", "stage", "commit", "update-index", "stash"})
_STASH_READS = frozenset({"list", "show", "pop", "apply", "drop", "clear", "branch", "create"})
_EXCLUDED_WORDS = re.compile(r"\bgit\b[^;&|]*\b(?:add|stage|commit|update-index|stash)\b|\bgh\b")
_EXCLUDED_WRITES = re.compile(r">|\btee\b")
ExcludedRoots = Callable[[], tuple[ExcludedRoot, ...]]


def excluded_roots_for(cwd: str, load: Callable[[], Config]) -> ExcludedRoots:
    # D.2.1: resolved once per call and only when a command reaches git, gh or a redirect.
    cache: list[tuple[ExcludedRoot, ...]] = []

    def roots() -> tuple[ExcludedRoot, ...]:
        if not cache:
            cache.append(resolve_excluded_roots(load(), project_root(cwd)))
        return cache[0]

    return roots


def _work_tree(path: str) -> str:
    for folder in (Path(path), *Path(path).parents):
        if (folder / ".git").exists():
            return str(folder)
    return path


def _active_roots(roots: tuple[ExcludedRoot, ...], tree: str) -> list[ExcludedRoot]:
    # D.5: a repository inside a root is another repo; a linked worktree gets each root again.
    main = git_root(tree)
    out = [r for r in roots if not _under(tree, r.path)]
    if main is not None and os.path.normpath(main) != os.path.normpath(tree):
        for root in roots:
            rel = os.path.relpath(root.path, main)
            if rel != "." and not rel.startswith(".." + os.sep) and rel != "..":
                out.append(ExcludedRoot(os.path.join(tree, rel), root.ignored))
    return out


def _root_of(path: str, roots: list[ExcludedRoot]) -> ExcludedRoot | None:
    return next((r for r in roots if _under(path, r.path)), None)


def _candidates(raw: str) -> list[str]:
    # D.5: an option value, a gh @file and an update-index cacheinfo path each name a path.
    out = [raw, raw.split("=", 1)[1] if "=" in raw else "", raw.rsplit(",", 1)[-1]]
    out += [c[1:] for c in out if c.startswith("@")]
    return [c for c in dict.fromkeys(out) if c and not c.startswith("-")]


def _pathspec(spec: str, base: str, tree: str) -> tuple[str, bool] | None:
    # D.5: pathspec magic; top reads from the work tree, exclude names nothing, a glob is a folder.
    if spec.startswith((":!", ":^")):
        return None
    if spec.startswith(":/"):
        base, spec = tree, spec[2:]
    elif spec.startswith(":(") and ")" in spec:
        words, spec = spec[2:].split(")", 1)
        magic = set(words.split(","))
        if "exclude" in magic:
            return None
        base = tree if "top" in magic else base
    cut = min((spec.index(c) for c in _GLOB_CHARS if c in spec), default=-1)
    if cut < 0:
        return os.path.normpath(_abs(spec, base)), False
    folder = spec[:cut].rsplit("/", 1)[0] if "/" in spec[:cut] else ""
    return os.path.normpath(_abs(folder or ".", base)), True


def _git_parts(sub: str, args: list[str]) -> tuple[list[str], set[str]]:
    # D.5: pathspecs and option values, and the short and long flags; a message is not a path.
    paths: list[str] = []
    flags: set[str] = set()
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--":
            paths += args[i:]
            break
        if not arg.startswith("-") or arg == "-":
            paths.append(arg)
        elif arg.startswith("--"):
            key, eq, value = arg.partition("=")
            flags.add(key)
            if key == "--message" and not eq:
                i += 1
            elif eq and key != "--message":
                paths.append(value)
        else:
            cluster = arg[1:]
            taker = next((n for n, c in enumerate(cluster) if c in "mFC"), None)
            flags |= set(cluster if taker is None else cluster[: taker + 1])
            if taker is not None:
                value = cluster[taker + 1 :] or (args[i] if i < len(args) else "")
                i += 0 if cluster[taker + 1 :] else 1
                paths += [value] if cluster[taker] == "F" else []
    if sub == "stash" and paths[:1] and paths[0] in {"push", "save", *_STASH_READS}:
        verb = paths.pop(0)
        paths = [] if verb != "push" else paths
    return paths, flags


def _whole_tree(sub: str, flags: set[str]) -> tuple[bool, bool]:
    # D.5: (takes the whole work tree, takes ignored files too) for add -A, commit -a, stash -u.
    if sub in {"add", "stage"}:
        whole = bool({"A", "--all", "--no-ignore-removal", "--pathspec-from-file"} & flags)
        return whole, bool({"f", "--force"} & flags)
    if sub == "commit":
        return bool({"a", "--all", "--pathspec-from-file"} & flags), False
    if sub == "stash":
        every = bool({"a", "--all"} & flags)
        return every or bool({"u", "--include-untracked", "--pathspec-from-file"} & flags), every
    return False, False


def _icase_spec(spec: str) -> bool:
    # issue 97: the long :(icase) magic, or the short : form with i among its flag letters.
    if spec.startswith(":("):
        words = spec[2:].split(")", 1)[0].split(",")
        return any(word.strip().lower() == "icase" for word in words)
    return spec.startswith(":") and ":" in spec[1:] and "i" in spec[1:].split(":", 1)[0].lower()


def _icase_git(segment: list[str], tokens: list[str]) -> str | None:
    # issue 97: the icase pathspec, global option or environment variable a git call carries.
    sub, args, globals_ = _git_split(tokens)
    env = [w for w in segment if w.split("=", 1)[0] == "GIT_ICASE_PATHSPECS" and "=" in w]
    spellings = env + [g for g in globals_ if g == "--icase-pathspecs"]
    paths = _git_parts(sub or "", args)[0]
    spellings += [p for p in paths for c in _candidates(p) if _icase_spec(c)]
    return spellings[0] if spellings else None


def _excluded_git(tokens: list[str], base: str, roots: ExcludedRoots) -> str | None:
    sub, args, globals_ = _git_split(tokens)
    if sub not in _EXCLUDED_GIT or (sub == "stash" and args[:1] and args[0] in _STASH_READS):
        return None
    where = _git_dir(globals_, base)
    tree = _work_tree(where)
    active = _active_roots(roots(), tree)
    if not active:
        return None
    what = f"git {sub}"
    hit = _root_of(where, active)
    if hit is not None:
        return R_EXCLUDED_PATH.format(what=what, path=where, root=hit.path)
    paths, flags = _git_parts(sub, args)
    whole, force = _whole_tree(sub, flags)
    stages = sub in {"add", "stage", "stash"}
    spans = [tree] if whole else []
    for raw in paths:
        for cand in _candidates(raw):
            spec = _pathspec(cand, where, tree)
            if spec is None:
                continue
            target, glob = spec
            hit = _root_of(target, active)
            if hit is not None:
                return R_EXCLUDED_PATH.format(what=what, path=target, root=hit.path)
            if stages or glob:
                spans.append(target)
    for span in spans:
        for root in active:
            if _under(root.path, span) and (force or not root_ignored(root, Path(tree))):
                return R_EXCLUDED_TREE.format(what=what, root=root.path)
    return None


def _named_paths(tokens: list[str], base: str, every: bool) -> list[str]:
    # D.5: every tee operand is a path; a gh word is one when absolute, with a slash, or on disk.
    out: list[str] = []
    for raw in tokens:
        for cand in [raw] if every and not raw.startswith("-") else _candidates(raw):
            path = os.path.normpath(_abs(cand, base))
            if every or os.path.isabs(cand) or "/" in cand or os.path.lexists(path):
                out.append(path)
    return out


def _excluded_named(what: str, tokens: list[str], base: str, roots: ExcludedRoots) -> str | None:
    tree = _work_tree(base) if what == "gh" else base
    active = _active_roots(roots(), tree) if what == "gh" else list(roots())
    for path in _named_paths(tokens, base, what == "tee"):
        hit = _root_of(path, active)
        if hit is not None:
            return R_EXCLUDED_PATH.format(what=what, path=path, root=hit.path)
    return None


def _excluded_text(command: str, cwd: str, roots: ExcludedRoots, writes: bool) -> str | None:
    # D.5: an unparsed command is judged on its text, the roots named as written or from cwd.
    if not (_EXCLUDED_WORDS.search(command) or (writes and _EXCLUDED_WRITES.search(command))):
        return None
    icase = _ICASE_TEXT.search(command)
    if icase and re.search(r"\bgit\b", command) and roots():
        return R_EXCLUDED_ICASE.format(spec=icase.group(0).strip(" \t'\"="))
    for root in _active_roots(roots(), _work_tree(cwd)):
        rel = os.path.relpath(root.path, cwd)
        names = [root.path] + ([rel] if not rel.startswith("..") and rel != "." else [])
        if any(name in command for name in names):
            return R_EXCLUDED_TEXT.format(root=root.path)
    return None


def excluded_root_reason(
    command: str, cwd: str, roots: ExcludedRoots, writes: bool = True
) -> str | None:
    # 0136, D.5: git staging, commit, update-index and stash, gh and redirects into a root.
    chain = worker_parse(command)
    bases = None if chain is None else chain_bases(chain, cwd, DIR_CHANGE_CMDS)
    if chain is None or bases is None:
        return _excluded_text(command, cwd, roots, writes)
    for segment, base in zip(chain.segments, bases, strict=True):
        tokens = strip_wrappers(segment) if segment else []
        if tokens is None:
            return _excluded_text(command, cwd, roots, writes)
        name = _base(tokens[0]) if tokens else ""
        icase = _icase_git(segment, tokens) if name == "git" else None
        reason: str | None = None
        if icase is not None and roots():
            reason = R_EXCLUDED_ICASE.format(spec=icase)
        elif name == "git":
            reason = _excluded_git(tokens, base, roots)
        elif name == "gh" or (name == "tee" and writes):
            reason = _excluded_named(name, tokens[1:], base, roots)
        elif name in _SHELLS or {"git", "gh"} & {_base(t) for t in tokens}:
            reason = _excluded_text(" ".join(tokens), base, roots, writes)
        if reason is not None:
            return reason
    return None


def _main_excluded(tool: str, tool_input: dict[str, object], cwd: str, config: Config) -> Decision:
    # 0130, D.5: main meets the excluded roots rule as a warning in context, never a refusal.
    command = str(tool_input.get("command") or "")
    if tool != "Bash" or not command or not os.path.isabs(cwd):
        return _allow()
    try:
        reason = excluded_root_reason(command, cwd, excluded_roots_for(cwd, lambda: config))
    except (ConfigError, OSError, subprocess.SubprocessError) as exc:
        return _main_warn(WARN_EXCLUDED_FAILED, str(exc))
    return _main_warn(WARN_EXCLUDED, reason) if reason else _allow()

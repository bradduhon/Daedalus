# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0259: the note reading of a main-session command its grammar could not type. It reads the
# parsed words of every command, nested bodies included, for the note classes alone; a
# command it finds nothing in runs with no note. Never a refusal, never an agent's rule.
from __future__ import annotations

import os
import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from lib import credential_paths, gh_policy, shell, shparse
from lib import session_notes as notes
from lib.audit import project_data_dir
from lib.config import ExcludedRoot
from lib.shparse import (
    Assignment,
    BraceList,
    Command,
    Glob,
    Literal,
    Opaque,
    Param,
    Tilde,
    Word,
)

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
_PLUGIN_PARAM = "CLAUDE_PLUGIN_ROOT"
# 0259: the plugin data folder's variable, resolved from the hook's own environment.
_DATA_PARAM = "CLAUDE_PLUGIN_DATA"
_NEST_LIMIT = 4
_UNREAD = "\0"
_WRITE_OPS = frozenset({">", ">>", ">|", "&>", "&>>"})
# 262, 0259: builtins whose operand names a variable they set from input or an option.
_VAR_BUILTINS = frozenset({"unset", "printf", "read", "mapfile", "readarray", "getopts"})
# 0259: builtins whose NAME=value operands set a shell variable later words may name.
_DECLARES = frozenset({"export", "declare", "typeset", "local", "readonly"})
# 0259: git subcommands that publish; push or merge outside the release phase earns a note.
_GIT_PUBLISH = frozenset({"push", "merge", "send-pack", "http-push"})
# 0259: git's own subcommands that never publish; an alias or any other word earns a note.
_GIT_LOCAL = frozenset(
    {"add", "am", "annotate", "apply", "archive", "blame", "branch", "bundle", "cat-file"}
    | {"check-attr", "check-ignore", "check-ref-format", "checkout", "cherry", "cherry-pick"}
    | {"clean", "clone", "commit", "commit-tree", "config", "count-objects", "describe"}
    | {"diff", "diff-files", "diff-index", "diff-tree", "fetch", "for-each-ref"}
    | {"format-patch", "fsck", "gc", "grep", "hash-object", "help", "init", "log", "ls-files"}
    | {"ls-remote", "ls-tree", "maintenance", "merge-base", "merge-file", "merge-tree", "mktag"}
    | {"mktree", "mv", "name-rev", "notes", "prune", "pull", "range-diff", "read-tree"}
    | {"rebase", "reflog", "remote", "repack", "replace", "reset", "restore", "rev-list"}
    | {"rev-parse", "revert", "rm", "shortlog", "show", "show-branch", "show-ref"}
    | {"sparse-checkout", "stash", "status", "stripspace", "switch", "symbolic-ref", "tag"}
    | {"update-index", "update-ref", "var", "verify-commit", "verify-tag", "version"}
    | {"whatchanged", "worktree", "write-tree"}
)
# 0259, 0239: git subcommands that print file content, which can show a tracked secret.
_GIT_CONTENT = frozenset(
    {"log", "show", "diff", "grep", "blame", "annotate", "cat-file", "archive", "stash"}
    | {"whatchanged", "format-patch", "bundle", "range-diff"}
)
# 0259: each git tripwire's note class and the words that open its note.
_GIT_TRIPWIRES: dict[str, tuple[notes.NoteClass, str]] = {
    shell.R_FORCE_PUSH: (
        notes.PUSH_OR_MERGE,
        "This force, delete or mirror push rewrites a remote branch",
    ),
    shell.R_DEFAULT_BRANCH: (notes.PUSH_OR_MERGE, "This push goes to the default branch"),
    shell.R_CLEAN: (notes.PROTECTED_WRITE, "This git clean can delete files in"),
    shell.R_STASH_UNTRACKED: (notes.PROTECTED_WRITE, "This stash of untracked files can remove"),
    shell.R_DATA_DIR_GIT: (notes.PROTECTED_WRITE, "This git command stages files from"),
    shell.R_SIGN: (notes.SIGNING, "This git command"),
    shell.R_GIT_CONFIG_KEY: (notes.GIT_CONFIG_KEY, "This git command"),
}
_GIT_CREDENTIAL = frozenset({"credential", "credential-store", "credential-cache"})
# 0277: GitHub API writes that put commits or branches on the remote, a push by another route.
_GH_PUSH_PATH = re.compile(r"(?:^|/)(?:git/(?:refs|commits|trees|blobs|tags)|contents)(?:/|$)")
_GH_PUSH_MUTATION = re.compile(r"\b(?:createCommitOnBranch|createRef|updateRefs?)\b")
# 0277: gh's own top-level commands and help topics (gh 2.97 `gh help`); any other word is an
# alias or an extension, which may push or merge.
_GH_KNOWN = frozenset(
    {"accessibility", "actions", "agent-task", "alias", "api", "attestation", "auth", "browse"}
    | {"cache", "codespace", "completion", "config", "copilot", "discussion", "environment"}
    | {"exit-codes", "extension", "formatting", "gist", "gpg-key", "help", "issue", "label"}
    | {"licenses", "mintty", "org", "pr", "preview", "project", "reference", "release", "repo"}
    | {"ruleset", "run", "search", "secret", "skill", "ssh-key", "status", "telemetry"}
    | {"variable", "version", "workflow"}
)
# 0136, 0259: git subcommands the excluded roots rule skips as reads.
_GIT_READS = frozenset(
    {"log", "show", "diff", "status", "ls-files", "grep", "blame", "rev-parse", "branch"}
    | {"merge-base", "worktree", "describe", "shortlog", "reflog", "cat-file", "ls-tree"}
)
# 0259: commands that remove, move or re-own a folder; naming one above the data folder reaches it.
_REMOVE_FAMILIES = frozenset({"rm", "rmdir", "mv", "shred", "unlink", "chmod", "chown", "chgrp"})
# 0259: copiers that write a whole folder when recursive, which can overwrite the data folder.
_COPIERS = frozenset({"cp", "rsync"})
# 0259: commands that walk a folder; naming a folder above a credential store reads it.
_TREE_FAMILIES = frozenset(
    {"grep", "egrep", "fgrep", "rg", "ag", "ack", "find", "fd", "tar", "zip", "cp", "rsync"}
    | {"scp", "tree"}
)
Released = Callable[[], bool]
ExcludedRoots = Callable[[], tuple[ExcludedRoot, ...]]


@dataclass(frozen=True)
class _Path:
    text: str
    glob: bool
    # 0259: a brace the reading could not expand reads as a * that also matches dot names.
    dots: bool = False


def tripwire_note(finding: str, sub: str, released: Released) -> notes.Note | None:
    # 0259: one git tripwire as its note class; a push or merge in the release phase is silent.
    if finding == shell.R_GIT_PLUMBING:
        if sub in _GIT_CREDENTIAL:
            return notes.note(notes.CREDENTIAL_READ, "This git credential helper", finding)
        klass, lead = notes.PUSH_OR_MERGE, "This git transport command can push"
    elif finding in _GIT_TRIPWIRES:
        klass, lead = _GIT_TRIPWIRES[finding]
    else:
        return None
    if klass is notes.PUSH_OR_MERGE and released():
        return None
    return notes.note(klass, lead, finding)


def gh_note(parsed: gh_policy.GhArgs | None, released: Released) -> notes.Note | None:
    # 0259, 0277: a gh push or merge is class 3; every other gh write runs with no note.
    what = _gh_publish(parsed)
    if what is None or released():
        return None
    finding = gh_policy.class_reason("main", parsed) if parsed else gh_policy.R_GH_BUNDLE
    return notes.note(notes.PUSH_OR_MERGE, what, finding or "")


def _gh_publish(parsed: gh_policy.GhArgs | None) -> str | None:
    # 0277: the gh routes that merge or write commits and branches on GitHub; unread is noted.
    if parsed is None:
        return "This gh command may push or merge: the plugin could not read its flags"
    words = parsed.words
    if any(_UNREAD in w for w in words[:2]):
        return "This gh command may push or merge: the plugin could not read its subcommand"
    klass, detail = gh_policy.classify(parsed)
    if klass == "merge":
        return f"This gh {detail} merges on GitHub"
    # 0277: an alias or an extension runs a command the plugin cannot see, as git's do.
    if (words and words[0] not in _GH_KNOWN) or words[:2] == ["extension", "exec"]:
        return f"This gh {' '.join(words[:3])} may push or merge: it runs an alias or an extension"
    flags = {flag.name for flag in parsed.flags}
    if words[:2] == ["repo", "sync"] and len(words) > 2:
        return "This gh repo sync updates a branch on GitHub"
    if words[:2] == ["repo", "create"] and "--push" in flags:
        return "This gh repo create --push pushes work to GitHub"
    if words[:2] == ["pr", "close"] and flags & {"-d", "--delete-branch"}:
        return "This gh pr close --delete-branch deletes a branch on GitHub"
    if words[:1] != ["api"]:
        return None
    explicit, fields, body, raw = gh_policy._api_parts(parsed)
    query = " ".join(f.partition("=")[2] for f in fields if f.partition("=")[0] == "query")
    if any(_UNREAD in part for part in (explicit or "", raw, query)):
        return "This gh api call may push or merge: the plugin could not read its target"
    path = gh_policy._endpoint(raw)
    writes = f"This gh {detail} writes commits or branches on GitHub"
    if path == "graphql":
        if body or query.startswith("@"):
            return "This gh api call may push or merge: the plugin could not read its query"
        return writes if _GH_PUSH_MUTATION.search(query) else None
    method = explicit or ("POST" if fields or body else "GET")
    return writes if method != "GET" and _GH_PUSH_PATH.search(path) else None


def push_note(sub: str) -> notes.Note:
    # 0259: the push rule's own finding rides the audit row beside the note.
    detail = gh_policy._push_reason("main") or ""
    return notes.note(notes.PUSH_OR_MERGE, f"This git {sub} publishes work", detail)


def unread_note(command: str, cwd: str, released: Released) -> notes.Note | None:
    return _Reader(command, cwd, cwd, released, {}, 0).script(shparse.parse(command))


def excluded_reason(command: str, cwd: str, roots: ExcludedRoots) -> str | None:
    # 0136, 0259: the excluded roots rule over a command main's grammar could not type.
    return _Excluded(command, cwd, roots).script(shparse.parse(command), cwd, 0)


class _Excluded:
    def __init__(self, text: str, cwd: str, roots: ExcludedRoots) -> None:
        self.reader = _Reader(text, cwd, cwd, lambda: True, {}, 0)
        self.roots = roots
        # 97, 0259: GIT_ICASE_PATHSPECS set, or a variable set whose name could not be read.
        self.icase = False

    def script(self, script: shparse.Script, base: str, depth: int) -> str | None:
        from lib.jail import _ICASE_ENV  # 0259: jail imports this module.

        reader = self.reader
        reader.base = base
        for cmd, _ in shparse.walk(script):
            words = list(cmd.words)
            head = _head(words)
            name = words[head].literal if head < len(words) else None
            family = shell.command_family(name) if name else ""
            named = [w for w in words[:head] if "=" in w.raw]
            if family in _DECLARES or family in _VAR_BUILTINS:
                named += words[head + 1 :]
            set_names = [a.name for a in cmd.assignments]
            set_names += [reader.name(w) if reader.paths(w) else "\0" for w in named]
            for word in words:
                nodes = shparse.nodes(word)
                set_names += [n.name for n in nodes if isinstance(n, Param) and "=" in n.op]
            if head < len(words) and not family and "=" in words[head].raw:
                set_names.append("\0")
            self.icase = self.icase or any(n in (_ICASE_ENV, "\0") for n in set_names)
            if family == "cd" and head + 1 < len(words):
                moved = reader.paths(words[head + 1])
                reader.base = _join(reader.base, moved[0].text) if len(moved) == 1 else reader.base
                continue
            found = self.command(cmd, words, head, family)
            body = _body(cmd, head, family) if found is None and depth < _NEST_LIMIT else None
            if body is not None:
                found = self.script(shparse.parse(body), reader.base, depth + 1)
                reader.base = base
            if found is not None:
                return found
        return None

    def command(self, cmd: Command, words: list[Word], head: int, family: str) -> str | None:
        from lib.jail import (  # 0259: jail imports this module.
            _ICASE_ENV,
            R_EXCLUDED_ICASE,
            R_EXCLUDED_PATH,
            R_EXCLUDED_UNSEEN,
            _active_roots,
            _root_of,
            _work_tree,
        )

        reader = self.reader
        active = _active_roots(self.roots(), _work_tree(reader.base))
        if not active:
            return None
        rest = words[head:]
        toks = reader.tokens(rest)
        if not family and head < len(words):
            # 0259: a command word the reading cannot see, or a brace naming git, reads as git.
            seen = [shell.command_family(p.text) for p in reader.paths(words[head])]
            family = "git" if not seen or "git" in seen else family
            toks = ["git", *toks[1:]]
        if family == "git":
            sub, _, _ = shell._git_split(["git", *toks[1:]])
            if sub is None or sub in _GIT_READS:
                return None
            if self.icase or any("icase" in t for t in toks):
                return R_EXCLUDED_ICASE.format(spec=_ICASE_ENV)
            if any(t.startswith(("--pathspec-from-file", "--stdin")) for t in toks):
                return R_EXCLUDED_UNSEEN.format(source="a file or stdin")
        elif family != "gh":
            toks = []
        for word in [*([] if not toks else rest[1:]), *shparse.redirect_targets(cmd)]:
            for path in reader.paths(word):
                for candidate in _candidates(path.text):
                    full = _join(reader.base, candidate)
                    hit = _root_of(full, active)
                    if hit is not None:
                        return R_EXCLUDED_PATH.format(
                            what=family or "git", path=full, root=hit.path
                        )
        return None


class _Reader:
    def __init__(
        self, text: str, cwd: str, base: str, released: Released, env: dict[str, str], depth: int
    ) -> None:
        self.text = text
        self.cwd = cwd
        self.base = base
        self.released = released
        # 0259: shell variables a literal assignment earlier in the command set.
        self.env = env
        self.depth = depth
        self.fed = False

    def script(self, script: shparse.Script) -> notes.Note | None:
        for cmd, _ in shparse.walk(script):
            found = self.command(cmd)
            if found is not None:
                return found
        return None

    def command(self, cmd: Command) -> notes.Note | None:
        words = list(cmd.words)
        head = _head(words)
        name = words[head].literal if head < len(words) else None
        family = shell.command_family(name) if name else ""
        # 0259: xargs feeds the command operands the reading cannot see.
        self.fed = any(shell.command_family(w.literal or "") == "xargs" for w in words[:head])
        found = self.credential(cmd, family)
        if found is not None or not words:
            self.assign(cmd.assignments)
            return found
        if family == "cd" and head + 1 < len(words):
            moved = self.paths(words[head + 1])
            self.base = _join(self.base, moved[0].text) if len(moved) == 1 else self.base
            return None
        if family in _DECLARES:
            self.declare(words[head + 1 :])
        found = self.family(cmd, words, head, family) or self.protected(cmd, words, head, family)
        if found is None and self.depth < _NEST_LIMIT:
            body = _body(cmd, head, family)
            if body is not None:
                inner = _Reader(body, self.cwd, self.base, self.released, self.env, self.depth + 1)
                found = inner.script(shparse.parse(body))
        return found

    def credential(self, cmd: Command, family: str) -> notes.Note | None:
        # 0259: a word naming a credential store, a .env file or the reply key; a folder
        # holding a store counts for a command that walks folders.
        walks = family in _TREE_FAMILIES
        named = [*cmd.words, *shparse.redirect_targets(cmd), *(a.value for a in cmd.assignments)]
        for word in named:
            raw = self.raw(word)
            if _braced(word, raw) and credential_paths.unjudged_root(raw):
                found = credential_paths.R_BRACE_UNJUDGED.format(path=raw)
                return notes.note(notes.CREDENTIAL_READ, "This command", found)
            for path in self.paths(word):
                for candidate in _candidates(path.text):
                    hit = self.store(candidate, path, walks)
                    if hit is not None:
                        return notes.note(notes.CREDENTIAL_READ, "This command", hit)
        return None

    def store(self, raw: str, path: _Path, walks: bool) -> str | None:
        # 0259: the credential check's own finding text for the store a path reaches.
        full = _join(self.base, raw)
        if credential_paths.reply_key_hit(full):
            return credential_paths.R_REPLY_KEY.format(path=full)
        if credential_paths.env_file_hit(full):
            return credential_paths.R_ENV_FILE.format(path=full)
        for root in credential_paths.credential_roots():
            rest = credential_paths.store_rest(full, root, path.glob, path.dots)
            if rest == []:
                return credential_paths.R_CREDENTIAL.format(path=full)
            if rest and walks:
                return credential_paths.R_CREDENTIAL_TREE.format(path=full)
        return None

    def family(self, cmd: Command, words: list[Word], head: int, family: str) -> notes.Note | None:
        # 0259: git, gh and rm by their words; a command word the reading cannot see is read as
        # git and as rm, and noted only where that reading finds a tripwire or a publish.
        rest = words[head:]
        prefix = [w.literal for w in words[:head] if w.literal and "=" in w.literal]
        assigns = [a.name + a.op + a.value.raw for a in cmd.assignments] + prefix
        if family == "git":
            return self.git(self.tokens(rest), assigns, True)
        if family == "gh":
            return self.gh(rest)
        if family == "rm":
            return _rm_note(self.tokens(rest))
        if family == "":
            toks = ["git", *self.tokens(rest[1:])]
            return self.git(toks, assigns, False) or _rm_note(["rm", *toks[1:]])
        return None

    def git(self, toks: list[str], assigns: list[str], named: bool) -> notes.Note | None:
        sub, _, _ = shell._git_split(toks)
        if sub is None:
            return None if not self.fed else self.unread_git()
        tripwire = shell._git_reason([t.replace(_UNREAD, "") for t in toks], assigns)
        if tripwire is not None:
            found = tripwire_note(tripwire, sub, self.released)
            if found is not None or tripwire in _GIT_TRIPWIRES or tripwire == shell.R_GIT_PLUMBING:
                return found
        if named and sub in _GIT_CONTENT and self.tracks_secret():
            what = "This git command may print a .env or credential file the repository tracks"
            return notes.note(notes.CREDENTIAL_READ, what)
        if self.released() or sub in _GIT_LOCAL or (not named and sub not in _GIT_PUBLISH):
            return None
        if _UNREAD in sub:
            return self.unread_git()
        elif sub in _GIT_PUBLISH:
            return push_note(sub)
        else:
            what = f"This git {sub} may push or merge: it is not a git command the plugin knows"
        return notes.note(notes.PUSH_OR_MERGE, what)

    def unread_git(self) -> notes.Note | None:
        if self.released():
            return None
        what = "This git command may push or merge: the plugin could not read its subcommand"
        return notes.note(notes.PUSH_OR_MERGE, what)

    def tracks_secret(self) -> bool:
        # 0239, 0259: the checkout's tracked files hold a secret, or cannot be listed.
        from lib.jail import tracked_secrets  # 0259: jail imports this module.

        roots = credential_paths.credential_roots()

        def hit(path: str) -> str | None:
            return self.store(path, _Path(path, False), False)

        found = tracked_secrets(self.base, [], hit, roots)
        return found is None or bool(found)

    def gh(self, words: list[Word]) -> notes.Note | None:
        # 0277: an unread word keeps its marker, so only an unread subcommand or target is noted.
        return gh_note(gh_policy.gh_args(self.tokens(words[1:])), self.released)

    def protected(
        self, cmd: Command, words: list[Word], head: int, family: str
    ) -> notes.Note | None:
        rest = words[head:]
        targets = shparse.redirect_targets(cmd)
        writes = {r.target.span for r in cmd.redirects if r.op in _WRITE_OPS}
        remover = family in _REMOVE_FAMILIES or (family in _COPIERS and _recursive(rest))
        plugin = self.plugin_script(rest, family)
        values = [a.value for a in cmd.assignments]
        for word in [*words[:head], *values, *rest[1:], *targets]:
            written = word.span in writes
            for path in self.paths(word):
                if self.in_data(path) and (written or not plugin):
                    what = "This command writes into" if written else "This command may write into"
                    return notes.note(notes.PROTECTED_WRITE, what)
                if remover and _holds_protected(_join(self.base, path.text), self.cwd):
                    what = "This command may remove, move or overwrite a folder holding"
                    return notes.note(notes.PROTECTED_WRITE, what)
        return None

    def name(self, word: Word) -> str:
        # 0259: the variable a NAME=value, NAME+=value or bare NAME operand sets.
        paths = self.paths(word)
        text = paths[0].text if len(paths) == 1 else word.raw
        return text.split("=", 1)[0].removesuffix("+").strip("'\"")

    def in_data(self, path: _Path) -> bool:
        # 0259: the typed check's own tests: a data folder path or a link to one, or a glob.
        from lib.jail import _data_dir_reach, _data_dir_target  # 0259: jail imports this.

        if path.glob:
            return _data_dir_reach(path.text, self.base, self.cwd)
        return _data_dir_target(_join(self.base, path.text), self.cwd)

    def plugin_script(self, words: list[Word], family: str) -> bool:
        # 0259: the plugin's own scripts keep the run state; their path words earn no note.
        if family != "python" or len(words) < 2:
            return False
        paths = self.paths(words[1])
        scripts = str(PLUGIN_ROOT / "scripts") + os.sep
        return len(paths) == 1 and _join(self.base, paths[0].text).startswith(scripts)

    def assign(self, assignments: list[Assignment]) -> None:
        for item in assignments:
            paths = self.paths(item.value)
            if len(paths) == 1:
                self.env[item.name] = paths[0].text
            else:
                self.env.pop(item.name, None)

    def declare(self, words: list[Word]) -> None:
        for word in words:
            paths = self.paths(word)
            name, eq, value = paths[0].text.partition("=") if len(paths) == 1 else ("", "", "")
            if eq and name.isidentifier():
                self.env[name] = credential_paths._expand_home(value)

    def tokens(self, words: list[Word]) -> list[str]:
        # 0259: each word as its readable values, brace alternatives side by side; unread marked.
        out: list[str] = []
        for word in words:
            paths = self.paths(word)
            out += [p.text for p in paths] if paths else [_UNREAD + self.raw(word)]
        return out

    def paths(self, word: Word) -> list[_Path]:
        # 0259: literal text, ~, known or earlier-set variables and brace alternatives; any
        # other expansion leaves the word unread.
        if _braced(word, self.raw(word)):
            alts = credential_paths.expand_braces(self.raw(word))
            if alts is None:
                # 0259: a sequence or a long list reads as a glob, as the typed check reads it.
                return [_Path(credential_paths._expand_home(self.raw(word)), True, True)]
            glob = any(isinstance(p, Glob) for p in word.parts)
            return [_Path(credential_paths._expand_home(a), glob) for a in alts if a]
        out: list[str] = []
        glob = False
        for pos, part in enumerate(word.parts):
            if isinstance(part, Literal):
                out.append(part.text)
            elif isinstance(part, Tilde) and (pos == 0 or "".join(out).endswith(("=", ":"))):
                out.append(os.path.expanduser("~" + part.user) if part.user else _home())
            elif isinstance(part, Param) and part.op == "" and self.param(part.name):
                out.append(self.param(part.name))
            elif isinstance(part, Glob):
                out.append(self.text[part.span[0] : part.span[1]])
                glob = True
            else:
                return []
        joined = "".join(out)
        return [_Path(joined, glob)] if joined else []

    def param(self, name: str) -> str:
        if name in self.env:
            return self.env[name]
        if name == _DATA_PARAM:
            value = os.environ.get(_DATA_PARAM) or ""
            return value if os.path.isabs(value) else ""
        if name == "HOME":
            return _home()
        return str(PLUGIN_ROOT) if name == _PLUGIN_PARAM else ""

    def raw(self, word: Word) -> str:
        return word.literal if word.literal is not None else self.text[word.span[0] : word.span[1]]


def _candidates(text: str) -> list[str]:
    # 0259: the path itself, an option's =value, and the path in a git <rev>:<path> or pathspec.
    out = [text]
    head, eq, tail = text.partition("=")
    if eq and tail and head.startswith("-"):
        out.append(tail)
    if ":" in text and "://" not in text:
        if text.startswith(":(") and ")" in text:
            after = text.split(")", 1)[1]
        else:
            after = text.split(":", 1)[1]
        out.append(after.lstrip("/") if text.startswith(":/") else after)
    return [c for c in out if c]


def _braced(word: Word, raw: str) -> bool:
    # 0259: a brace list, or a part the parser left opaque around a brace, read by alternative.
    return "{" in raw and any(isinstance(p, BraceList | Opaque) for p in word.parts)


def _recursive(words: list[Word]) -> bool:
    lits = [w.literal or "" for w in words[1:]]
    longs = {"--recursive", "--archive"}
    return any(
        x in longs or (x[:1] == "-" and x[1:2] != "-" and set(x[1:]) & set("rRa")) for x in lits
    )


def _rm_note(toks: list[str]) -> notes.Note | None:
    found = shell._rm_reason([t for t in toks[1:] if _UNREAD not in t])
    return notes.note(notes.DESTRUCTIVE_DELETE, "This command", found) if found else None


def _head(words: list[Word]) -> int:
    # 0259: the index of the command word past wrappers, their options and their operands.
    i = 0
    while i < len(words):
        name = words[i].literal
        family = shell.command_family(name) if name else ""
        if name is not None and shell._ASSIGN.match(name):
            i += 1  # 0259: a quoted NAME=value word bash runs as a command; read past it.
            continue
        if family not in shell.WRAPPER_OPTS:
            return i
        _, valued = shell.WRAPPER_OPTS[family]
        i += 1
        while i < len(words):
            lit = words[i].literal or ""
            if lit == "--":
                i += 1
                break
            if not lit.startswith("-") or lit == "-":
                break
            i += 2 if lit in valued else 1
        while family == "env" and i < len(words) and "=" in (words[i].literal or ""):
            i += 1
        if family in shell.WRAPPER_OPERAND and i < len(words):
            i += 1
    return i


def _body(cmd: Command, head: int, family: str) -> str | None:
    # 0259: the literal script a shell -c or stdin text, an eval, an env -S, a find -exec or a
    # git rebase --exec runs.
    words = list(cmd.words)
    lits = [w.literal for w in words]
    if family == "find":
        return _find_exec(lits[head + 1 :])
    if family == "git":
        return _rebase_exec(lits[head + 1 :])
    if family == "eval":
        rest = lits[head + 1 :]
        return " ".join(lit for lit in rest if lit is not None) if None not in rest else None
    for i, lit in enumerate(lits[:head]):
        if lit in ("-S", "--split-string") and i + 1 < len(lits) and lits[i + 1] is not None:
            tail = [x for x in lits[i + 2 :] if x is not None]
            return " ".join([str(lits[i + 1]), *tail])
    if family not in shell._SHELLS:
        return None
    for i, lit in enumerate(lits[head + 1 : -1], start=head + 1):
        if lit and lit.startswith("-") and not lit.startswith("--") and "c" in lit[1:]:
            at = i + 2 if lits[i + 1] == "--" else i + 1
            return lits[at] if at < len(lits) else None
    return _stdin_script(cmd)


def _stdin_script(cmd: Command) -> str | None:
    # 0259: a shell reading its script from a literal heredoc or here-string.
    for redirect in cmd.redirects:
        doc = redirect.heredoc
        if redirect.op in ("<<", "<<-") and isinstance(doc, shparse.Heredoc):
            return doc.body
        if redirect.op == "<<<":
            return redirect.target.literal
    return None


def _rebase_exec(lits: list[str | None]) -> str | None:
    # 0259: the command a git rebase -x or --exec runs after each commit.
    runs: list[str] = []
    for i, lit in enumerate(lits):
        if lit in ("-x", "--exec") and i + 1 < len(lits) and lits[i + 1] is not None:
            runs.append(str(lits[i + 1]))
        elif lit is not None and lit.startswith("--exec="):
            runs.append(lit.split("=", 1)[1])
    return "\n".join(runs) if runs else None


def _find_exec(lits: list[str | None]) -> str | None:
    # 0259: the command a find -exec, -execdir, -ok or -okdir runs, up to its ; or +.
    for i, lit in enumerate(lits):
        if lit in ("-exec", "-execdir", "-ok", "-okdir"):
            run: list[str] = []
            for word in lits[i + 1 :]:
                if word is None or word in (";", "+"):
                    break
                run.append(word)
            return shlex.join(run) if run else None
    return None


def _home() -> str:
    # 0259: read per call, as the credential roots are, so both name the same home.
    return str(Path.home())


def _join(base: str, path: str) -> str:
    return os.path.normpath(os.path.join(base, path))


def _holds_protected(path: str, cwd: str) -> bool:
    # 0259: removing or moving a folder above the project's data folder reaches it too.
    data = str(project_data_dir(cwd))
    return path == os.sep or data.startswith(path.rstrip(os.sep) + os.sep)

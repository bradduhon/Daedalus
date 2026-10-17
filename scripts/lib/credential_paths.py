# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0023: the credential-path deny, the one rule every agent meets in or out of a train.
# Standard library only: the jail's entry script imports this before the rest of lib.
from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path
from typing import Any

# spec 8, 0023: credential stores refused to every agent, main included.
CREDENTIAL_DENY = (".ssh", ".aws", ".gnupg", ".config/gh", ".claude/.credentials.json")
# 0023: these tools carry only the credential deny, for every agent known or not.
CREDENTIAL_TOOLS = frozenset({"Read", "Glob", "Grep"})
R_CREDENTIAL = (
    "{path} is a credential path. "
    "Next: Daedalus never reads credentials; use the tool that needs them from your own shell"
)
R_CREDENTIAL_TREE = (
    "{path} contains a credential path. "
    "Next: Daedalus never reads credentials; point the read at a directory without them"
)
_GLOB_START = re.compile(r"[*?\[{]")
_BRACE = re.compile(r"\{[^}]*\}")
VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*|[0-9]+)[^}]*\}|\$([A-Za-z_][A-Za-z0-9_]*|[0-9])")
_UNQUOTE = re.compile(r"[\"'\\]")
# spec 8: lexer marks for a literal $, a quote edge that ends a name, and a redirect target.
LIT, CUT, REDIRECT = "\x00", "\x01", "\x02"
_EXPANSION_CAP = 16
_HOME_ROOTED = ("/", "~", "$HOME", "${HOME")


def credential_roots() -> list[str]:
    home = Path.home()
    return [os.path.realpath(home / rel) for rel in CREDENTIAL_DENY]


def clean(word: str) -> str:
    return word.replace(CUT, "").replace(REDIRECT, "").replace(LIT, "$")


def tilde(text: str, home: str) -> str:
    if text == "~" or text.startswith("~/"):
        return home + text[1:]
    return os.path.expanduser(text) if text.startswith("~") else text


def expand_word(word: str, env: dict[str, list[str]]) -> list[tuple[str, bool]]:
    # spec 8: $name and ${name...} alike; each expansion carries whether a name was unknown.
    results: list[tuple[str, bool]] = [("", False)]
    pos = 0
    for match in VAR.finditer(word):
        values = env.get(match.group(1) or match.group(2))
        alts = [(v, False) for v in values] if values else [("", True)]
        lit = word[pos : match.start()]
        results = [(t + lit + v, u or w) for t, u in results for v, w in alts]
        results = results[:_EXPANSION_CAP]
        pos = match.end()
    home = env["HOME"][0]
    out: list[tuple[str, bool]] = []
    for text, unresolved in results:
        text += word[pos:]
        unresolved = unresolved or "${" in text
        text = clean(text)
        out.append((tilde(text, home), unresolved))
    return out


def anchor(text: str, base: str) -> str | None:
    if not text:
        return None
    if os.path.isabs(text):
        return os.path.normpath(text)
    return os.path.normpath(os.path.join(base, text)) if os.path.isabs(base) else None


def _expand_home(token: str, cwd: str) -> str | None:
    # spec 8: quotes and backslashes are dropped; ~, $HOME and ${HOME...} expand to home.
    text = expand_word(_UNQUOTE.sub("", token), {"HOME": [str(Path.home())]})[0][0]
    return anchor(text, cwd)


def _candidates(tool: str, tool_input: dict[str, Any], cwd: str) -> list[str]:
    values = [str(tool_input.get(k) or "") for k in ("file_path", "notebook_path", "path")]
    pattern = str(tool_input.get("pattern") or "")
    if tool == "Glob" and pattern:
        values.append(pattern if pattern.startswith(_HOME_ROOTED) else "")
        base = str(tool_input.get("path") or cwd)
        values.append(os.path.join(base, pattern))
    elif tool == "Grep" and pattern.startswith(_HOME_ROOTED):
        # spec 8: a Grep pattern is a regex; only an absolute or home-rooted one names a path.
        values.append(pattern)
    return [v for v in values if v]


def _glob_rest(parts: list[str], root: list[str], dotglob: bool) -> list[str] | None:
    for i, name in enumerate(root):
        if i >= len(parts):
            return root[i:]
        pat = _BRACE.sub("*", parts[i])
        if "**" in pat:
            return []
        # spec 8: a shell wildcard skips a leading dot unless dotglob is set.
        if not dotglob and name.startswith(".") and not pat.startswith("."):
            return None
        if not fnmatch.fnmatchcase(name, pat):
            return None
    return []


def _contains(parent: str, child: str) -> bool:
    # spec 8: a plain prefix test misses the filesystem root, so ancestry is checked here.
    real_parent, real_child = os.path.realpath(parent), os.path.realpath(child)
    return real_child == real_parent or real_child.startswith(real_parent.rstrip(os.sep) + os.sep)


def store_rest(target: str, root: str, glob: bool, dotglob: bool) -> list[str] | None:
    # spec 8: [] means target is in the store; a list is the store's components below target.
    if glob and _GLOB_START.search(target):
        parts = os.path.normpath(target).split(os.sep)
        first = next(i for i, part in enumerate(parts) if _GLOB_START.search(part))
        base = os.path.realpath(os.sep.join(parts[:first]) or os.sep)
        if _contains(root, base):
            return []
        pattern = [p for p in base.split(os.sep) if p] + parts[first:]
        return _glob_rest(pattern, [p for p in root.split(os.sep) if p], dotglob)
    real = os.path.realpath(target)
    if _contains(root, real):
        return []
    if _contains(real, root):
        return [p for p in root[len(real) :].split(os.sep) if p]
    return None


def credential_hit(target: str, roots: list[str], glob: bool, dotglob: bool = True) -> bool:
    return any(store_rest(target, root, glob, dotglob) == [] for root in roots)


def path_reason(tool: str, tool_input: dict[str, Any], cwd: str) -> str | None:
    # 0023: path-argument tools; the jail judges Bash commands with its own shell model.
    roots = credential_roots()
    for raw in _candidates(tool, tool_input, cwd):
        target = _expand_home(raw, cwd)
        if target is not None and credential_hit(target, roots, tool == "Glob"):
            return R_CREDENTIAL.format(path=target)
    if tool == "Grep":
        # spec 8: the Grep tool searches hidden dirs, so a root above a store reads it.
        target = _expand_home(str(tool_input.get("path") or cwd), cwd)
        if target and any(store_rest(target, root, False, True) is not None for root in roots):
            return R_CREDENTIAL_TREE.format(path=target)
    return None

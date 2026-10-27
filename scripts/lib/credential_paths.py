# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0023: the credential-path deny, the one rule every agent meets in or out of a train.
# Standard library and the fast-path lib.project_root only: the jail's entry script imports
# this before the rest of lib.
from __future__ import annotations

import fnmatch
import os
import re
import string
from pathlib import Path

from lib.project_root import project_root

# spec 8, 0023: credential stores refused to every agent, main included.
# 0048: the last two are git's credential-store files, the default and the XDG one.
CREDENTIAL_DENY = (
    ".ssh",
    ".aws",
    ".gnupg",
    ".config/gh",
    ".claude/.credentials.json",
    ".git-credentials",
    ".config/git/credentials",
)
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
# SC-12: the one name of the reply key file; lib.audit imports it.
REPLY_KEY_NAME = "reply-hmac.key"
R_REPLY_KEY = (
    "{path} is the train's reply key. "
    "Next: no agent reads the reply key; check-reply reads it for the train"
)
R_REPLY_KEY_TREE = (
    "{path} contains the train's reply key. "
    "Next: search a folder outside .claude/daedalus, or name the files you need"
)
# prepush-2026-10-27: rg ranks these above .gitignore, so a `!` line beats the data folder marker.
IGNORE_FILES = (".rgignore", ".ignore")
IGNORE_READ_MAX = 1024 * 1024
R_IGNORE_WHITELIST = (
    "{path} holds the train's reply key or a credential path, and a .rgignore or .ignore file "
    "on the way to it holds a `!` line that makes rg read hidden folders. "
    "Next: search a folder that holds neither, or name the files you need"
)
_GLOB_START = re.compile(r"[*?\[{]")
VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*|[0-9]+)[^}]*\}|\$([A-Za-z_][A-Za-z0-9_]*|[0-9])")
_UNQUOTE = re.compile(r"[\"'\\]")
# spec 8: lexer marks for a literal $, a quote edge that ends a name, and a redirect target.
LIT, CUT, REDIRECT = "\x00", "\x01", "\x02"
_EXPANSION_CAP = 16
_HOME_ROOTED = ("/", "~", "$HOME", "${HOME")
# issue 53: zsh's (D) qualifier; option names fold case and underscores (GLOB_DOTS, globdots).
_DOTS_QUALIFIER = re.compile(r"\([^()\s]*D[^()\s]*\)")
_DOTGLOB_WORDS = ("dotglob", "globignore", "globdots")
_ROOTED_ALT = re.compile(r"[{,][/~$]")
R_BRACE_UNJUDGED = (
    "{path} has a brace group the jail does not expand (a sequence or more than 16 "
    "alternatives) and an alternative that starts its own path. Next: name each path you need"
)


def dotglob_on(command: str) -> bool:
    # issue 53: bash dotglob or GLOBIGNORE, zsh globdots or (D); any one lets a wildcard match dots.
    folded = command.replace("_", "").lower()
    return any(w in folded for w in _DOTGLOB_WORDS) or bool(_DOTS_QUALIFIER.search(command))


def _brace_group(text: str) -> tuple[str, list[str], str] | None:
    # issue 53: the first {a,b} group as (prefix, alternatives, suffix); {x} opens as x, as rg
    # and glob tools read it, so a shell's literal {x} over-refuses; {} stays literal.
    depth, start, param = 0, 0, 0
    cuts: list[int] = []
    for i, char in enumerate(text):
        # audit B4 round 3: ${...} is a parameter, never a brace group, as in bash.
        if param:
            param += {"{": 1, "}": -1}.get(char, 0)
        elif char == "{" and depth == 0 and text[i - 1 : i] == "$":
            param = 1
        elif char == "{":
            if depth == 0:
                start, cuts = i, []
            depth += 1
        elif char == "," and depth == 1:
            cuts.append(i)
        elif char == "}" and depth:
            depth -= 1
            if depth == 0 and (cuts or i > start + 1):
                edges = [start, *cuts, i]
                alts = [text[a + 1 : b] for a, b in zip(edges, edges[1:], strict=False)]
                return text[:start], alts, text[i + 1 :]
    return None


def _braces_to_star(text: str) -> str:
    # audit B4 round 2: every top-level balanced {...} group, nested ones inside it, becomes *.
    out: list[str] = []
    depth, start = 0, 0
    for i, char in enumerate(text):
        if char == "{":
            if depth == 0:
                start = i
            depth += 1
        elif char == "}" and depth:
            depth -= 1
            if depth == 0:
                out.append("*")
        elif depth == 0:
            out.append(char)
    # audit B4 round 2: an unclosed { stays literal, as the shell keeps it.
    return "".join(out) + (text[start:] if depth else "")


def expand_braces(text: str) -> list[str] | None:
    # issue 53: the shell's brace alternatives, nested groups included; None past the cap.
    done: list[str] = []
    pending = [text]
    while pending:
        group = _brace_group(pending[0])
        if group is None:
            done.append(pending.pop(0))
        else:
            head, alts, tail = group
            # audit B4 round 1: a {a..z} sequence is not modeled, so the caller reads it as *.
            if len(alts) == 1 and ".." in alts[0]:
                return None
            pending = [head + alt + tail for alt in alts] + pending[1:]
        if len(done) + len(pending) > _EXPANSION_CAP:
            return None
    return done


def unjudged_root(text: str) -> bool:
    # audit B4 round 3: a brace word the jail leaves unexpanded, one of whose alternatives
    # starts its own path, so no anchor of the raw word reaches the store it names.
    return expand_braces(text) is None and bool(_ROOTED_ALT.search(text))


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
    # audit B4 round 3: bash order, braces first, then tilde and parameters per alternative;
    # an unexpanded brace word stays whole for the store match's * fallback.
    return [x for alt in expand_braces(word) or [word] for x in _expand_alt(alt, env)]


def _expand_alt(word: str, env: dict[str, list[str]]) -> list[tuple[str, bool]]:
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
    # issue 83: the existing prefix resolves through its links before a later .. applies.
    if not text or not (os.path.isabs(text) or os.path.isabs(base)):
        return None
    path = os.path.join(base, text)
    try:
        return os.path.realpath(path)
    except ValueError:
        return os.path.normpath(path)


def _expand_home(token: str) -> str:
    # spec 8: quotes and backslashes are dropped; ~, $HOME and ${HOME...} expand to home.
    # audit B4 round 3: a path argument is literal; only a Glob pattern's braces expand.
    return _expand_alt(_UNQUOTE.sub("", token), {"HOME": [str(Path.home())]})[0][0]


def _candidates(tool: str, tool_input: dict[str, object], cwd: str) -> list[str]:
    values = [str(tool_input.get(k) or "") for k in ("file_path", "notebook_path", "path")]
    pattern = str(tool_input.get("pattern") or "")
    if tool == "Glob" and pattern:
        base = str(tool_input.get("path") or cwd)
        # audit B4 round 3: each brace alternative is rooted or joined under base on its own.
        for alt in expand_braces(pattern) or [pattern]:
            values.append(alt if alt.startswith(_HOME_ROOTED) else "")
            values.append(os.path.join(base, alt))
    elif tool == "Grep" and pattern.startswith(_HOME_ROOTED):
        # spec 8: a Grep pattern is a regex; only an absolute or home-rooted one names a path.
        values.append(pattern)
    return [v for v in values if v]


def _glob_rest(
    parts: list[str], root: list[str], dotglob: bool, dots_hide: bool = False
) -> list[str] | None:
    for i, name in enumerate(root):
        if i >= len(parts):
            return root[i:]
        pat = parts[i]
        hidden = not dotglob and name.startswith(".") and not pat.startswith(".")
        # SC-12: for the reply key a dot folder stops ** too; a credential store stays strict.
        if dots_hide and hidden:
            return None
        if "**" in pat:
            return []
        # spec 8: a shell wildcard skips a leading dot unless dotglob is set.
        if hidden:
            return None
        if not fnmatch.fnmatchcase(name, pat):
            return None
    return []


def _contains(parent: str, child: str) -> bool:
    # spec 8: a plain prefix test misses the filesystem root, so ancestry is checked here.
    real_parent, real_child = os.path.realpath(parent), os.path.realpath(child)
    return real_child == real_parent or real_child.startswith(real_parent.rstrip(os.sep) + os.sep)


def _widest(rests: list[list[str] | None]) -> list[str] | None:
    # issue 53: the alternative that exposes most: inside the store, then no dot folder between.
    found = [r for r in rests if r is not None]
    found.sort(key=lambda r: (bool(r), any(p.startswith(".") for p in r)))
    return found[0] if found else None


def store_rest(
    target: str, root: str, glob: bool, dotglob: bool, dots_hide: bool = False
) -> list[str] | None:
    # spec 8: [] means target is in the store; a list is the store's components below target.
    if glob and _GLOB_START.search(target):
        alts = expand_braces(target)
        if alts is None:
            # issue 53: past the cap or on a sequence, a brace reads as a * that matches dot names.
            return store_rest(_braces_to_star(target), root, glob, True, dots_hide)
        if alts != [target]:
            return _widest([store_rest(a, root, glob, dotglob, dots_hide) for a in alts])
        parts = os.path.normpath(target).split(os.sep)
        first = next(i for i, part in enumerate(parts) if _GLOB_START.search(part))
        base = os.path.realpath(os.sep.join(parts[:first]) or os.sep)
        if _contains(root, base):
            return []
        pattern = [p for p in base.split(os.sep) if p] + parts[first:]
        root_parts = [p for p in root.split(os.sep) if p]
        return _glob_rest(pattern, root_parts, dotglob, dots_hide)
    real = os.path.realpath(target)
    if _contains(root, real):
        return []
    if _contains(real, root):
        return [p for p in root[len(real) :].split(os.sep) if p]
    return None


def credential_hit(
    target: str, roots: list[str], glob: bool, dotglob: bool = True, dots_hide: bool = False
) -> bool:
    return any(store_rest(target, root, glob, dotglob, dots_hide) == [] for root in roots)


def reply_key_hit(target: str) -> bool:
    # SC-12: the train's reply key, found by its real path, is unreadable to every agent.
    real = Path(os.path.realpath(target))
    return (
        real.name == REPLY_KEY_NAME
        and real.parent.name == "daedalus"
        and real.parent.parent.name == ".claude"
    )


def key_roots(*paths: str) -> list[str]:
    # SC-12: the existing reply key of each named path's project, as one more store root.
    keys = {project_root(Path(p)) / ".claude" / "daedalus" / REPLY_KEY_NAME for p in paths if p}
    return sorted(os.path.realpath(k) for k in keys if k.is_absolute() and os.path.lexists(k))


def glob_patterns(raw: str) -> list[str]:
    # issue 53: each brace alternative is its own glob; past the cap or on a sequence, a brace is *.
    pats = (expand_braces(raw) or [_braces_to_star(raw)]) if raw else []
    # SC-12: a leading / anchors an rg glob to the search root; the match ignores it.
    return [p.lstrip("/") for p in pats if p.lstrip("/")]


# SC-12: the glob characters glob_reaches models; any other (\, [, {, ,) fails closed.
GLOB_MODELLED = frozenset(string.ascii_letters + string.digits + "._-*?/")


def glob_reaches(pats: list[str], rest: list[str]) -> bool:
    # SC-12: a whitelist glob naming any run of components below the search root, case folded.
    # SC-12: fnmatch's * crosses /, and the / edges let a gitignore **/ match zero folders.
    pats = [p for p in pats if not p.startswith("!")]
    if any(set(p) - GLOB_MODELLED for p in pats):
        return True
    runs = {"/".join(rest[i:j]) for i in range(len(rest)) for j in range(i + 1, len(rest) + 1)}
    names = {edge.format(run.casefold()) for run in runs for edge in ("{}", "/{}", "{}/", "/{}/")}
    folded = {p.casefold() for pat in pats for p in (pat, pat.rstrip("/")) if p}
    return any(fnmatch.fnmatchcase(name, pat) for name in names for pat in folded)


def _negates(path: Path) -> bool:
    # prepush-2026-10-27: an unreadable or oversized ignore file fails closed.
    try:
        if not path.is_file():
            return False
        with path.open("rb") as handle:
            data = handle.read(IGNORE_READ_MAX + 1)
    except OSError:
        return True
    if len(data) > IGNORE_READ_MAX:
        return True
    return any(line.lstrip().startswith(b"!") for line in data.splitlines())


def ignore_whitelist(store: str) -> bool:
    # prepush-2026-10-27: rg reads the ignore files of every parent, so walk / down to the store.
    return any(
        _negates(folder / name)
        for folder in Path(os.path.realpath(store)).parents
        for name in IGNORE_FILES
    )


def _grep_key_reason(target: str, keys: list[str], glob: object) -> str | None:
    # SC-12: the Grep tool honors the data folder's `*` marker from above, so only a search
    # rooted inside .claude, or a glob that overrides the marker, can read the key.
    pats = glob_patterns(glob if isinstance(glob, str) else "")
    for key in keys:
        if _contains(os.path.dirname(os.path.dirname(key)), target):
            return R_REPLY_KEY_TREE.format(path=target)
        if _contains(target, key) and ignore_whitelist(key):
            return R_IGNORE_WHITELIST.format(path=target)
        if not pats:
            continue
        rest = [os.path.basename(key)]
        if _contains(target, key):
            rest = os.path.relpath(key, os.path.realpath(target)).split(os.sep)
        if glob_reaches(pats, rest):
            return R_REPLY_KEY_TREE.format(path=target)
    return None


def path_reason(tool: str, tool_input: dict[str, object], cwd: str) -> str | None:
    # 0023: path-argument tools; the jail judges Bash commands with its own shell model.
    roots = credential_roots()
    pattern = str(tool_input.get("pattern") or "")
    if tool == "Glob" and unjudged_root(pattern):
        return R_BRACE_UNJUDGED.format(path=pattern)
    for raw in _candidates(tool, tool_input, cwd):
        text = _expand_home(raw)
        target = anchor(text, cwd)
        if target is None:
            continue
        # issue 83: judged on the resolved path, named as the caller spelled it.
        shown = os.path.normpath(os.path.join(cwd, text))
        # SC-12: Read names one file and Glob lists names only, so the key's own path is enough.
        if reply_key_hit(target):
            return R_REPLY_KEY.format(path=shown)
        if credential_hit(target, roots, tool == "Glob"):
            return R_CREDENTIAL.format(path=shown)
    if tool == "Grep":
        # spec 8: the Grep tool searches hidden dirs, so a root above a store reads it.
        target = anchor(_expand_home(str(tool_input.get("path") or cwd)), cwd)
        if target and any(store_rest(target, root, False, True) is not None for root in roots):
            return R_CREDENTIAL_TREE.format(path=target)
        if target:
            return _grep_key_reason(target, key_roots(cwd, target), tool_input.get("glob"))
    return None

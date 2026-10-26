#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# Pins MAP -> REQ, MAP -> VER: daedalus_map.py --repo <repo> --out <dir> [--plan <plan>] [--check]
# writes <dir>/map.md and <dir>/map.json: imports with fan-in, test coverage, readers and writers
# of shared records, plan ownership and near-duplicate blocks. Stdlib only and deterministic: no
# clock, no absolute path, every list sorted. --check rebuilds and exits 1 when either file differs.
from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import keyword
import os
import re
import sys
import tokenize
from array import array
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TypedDict

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import atomic  # noqa: E402
from lib.plan_record import PlanError, _covers, load  # noqa: E402
from lib.project_keys import config_keys, manifest_keys  # noqa: E402

MAP_JSON = "map.json"
MAP_MD = "map.md"
SKIP_DIRS = frozenset({"__pycache__", "node_modules", "venv", "site-packages"})
TEXT_SUFFIXES = frozenset({".md", ".json", ".toml", ".yml", ".yaml", ".sh", ".txt", ".cfg"})
MAX_BYTES = 1_000_000
# Train C duplication audit method: a window of normalized tokens, reported from six lines up.
WINDOW = 60
MIN_LINES = 6
STATUS = re.compile(r"\[(?:STATUS|VERDICT|STANDARDS): [A-Z][A-Z_]*[A-Z]\]")
ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{2,}")
EVENTS = (
    "Notification",
    "PostToolUse",
    "PostToolUseFailure",
    "PreCompact",
    "PreToolUse",
    "SessionEnd",
    "SessionStart",
    "Stop",
    "SubagentStart",
    "SubagentStop",
    "UserPromptSubmit",
)
# A record is security-relevant when it is a hook event or its name carries one of these words.
SECURITY = re.compile(
    r"verdict|compliance|audit|secret|token|key|password|credential|auth|hmac|session|ledger"
    r"|approv|reject|narrow|protect|jail|exception|exempt",
    re.IGNORECASE,
)
READ_CALLS = frozenset(
    {"get", "pop", "startswith", "endswith", "find", "rfind", "index", "count", "match"}
    | {"search", "fullmatch", "compile", "findall", "finditer", "getenv", "partition"}
    | {"removeprefix", "removesuffix", "split"}
)
WRITE_CALLS = frozenset({"setdefault", "setenv", "putenv", "delenv", "unsetenv"})
_KEYWORDS = frozenset(keyword.kwlist)
R_OUT = (
    "The map output folder {out} is not inside the repository {repo}, so nothing was written. "
    "Next: pass an --out folder inside the repository."
)
R_STALE = (
    "STALE map: {path} no longer matches the files in the tree. "
    "Next: rerun the same map command without --check to rebuild it."
)
R_MISSING = (
    "STALE map: {path} does not exist yet, so there is nothing to check. "
    "Next: run the map command without --check first."
)
R_PLAN = (
    "The map could not read the plan it was given: {error}\n"
    "Next: pass the plan file the train recorded as --plan."
)


class ImportRow(TypedDict):
    fan_in: list[str]
    imports: list[str]
    symbols: dict[str, list[str]]


class RecordRow(TypedDict):
    kind: str
    mentions: list[str]
    readers: list[str]
    security: bool
    writers: list[str]


class MapTables(TypedDict):
    # Pin MAP -> VER: exactly these five top-level keys.
    coverage: dict[str, list[str]]
    duplicates: list[list[str]]
    imports: dict[str, ImportRow]
    ownership: dict[str, list[str]]
    readers: dict[str, RecordRow]


@dataclass(frozen=True)
class Scan:
    files: list[str]
    texts: dict[str, str]
    py: frozenset[str]
    tests: frozenset[str]


def _is_test(rel: str) -> bool:
    parts = rel.split("/")
    name = parts[-1]
    return (
        any(p in ("tests", "test") for p in parts[:-1])
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name == "conftest.py"
    )


def _walk(repo: Path, out: Path) -> list[str]:
    # Hidden folders hold worktrees, caches and train scratch; links are never followed.
    found: list[str] = []
    for top, dirs, names in os.walk(repo):
        here = Path(top)
        dirs[:] = sorted(
            d for d in dirs if not d.startswith(".") and d not in SKIP_DIRS and here / d != out
        )
        for name in names:
            path = here / name
            if path.suffix in TEXT_SUFFIXES | {".py"} and not path.is_symlink():
                found.append(path.relative_to(repo).as_posix())
    return sorted(found)


def scan_tree(repo: Path, out: Path) -> Scan:
    texts: dict[str, str] = {}
    for rel in _walk(repo, out):
        path = repo / rel
        try:
            if path.stat().st_size <= MAX_BYTES:
                texts[rel] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
    files = sorted(texts)
    py = frozenset(f for f in files if f.endswith(".py"))
    return Scan(files, texts, py, frozenset(f for f in py if _is_test(f)))


def _parse(scan: Scan) -> dict[str, ast.Module]:
    trees: dict[str, ast.Module] = {}
    for rel in sorted(scan.py):
        try:
            trees[rel] = ast.parse(scan.texts[rel], filename=rel)
        except (SyntaxError, ValueError):
            continue
    return trees


# Import graph


def _candidate(base: str, dotted: str, py: frozenset[str]) -> str | None:
    stem = "/".join(p for p in (base, *dotted.split(".")) if p)
    for cand in (f"{stem}.py", f"{stem}/__init__.py"):
        if cand in py:
            return cand
    return None


def _fallback(py: frozenset[str]) -> dict[str, str | None]:
    # A dotted name found once in the tree; an ambiguous one maps to None, a stdlib one is left out.
    names: dict[str, str | None] = {}
    for rel in sorted(py):
        parts = rel[:-3].split("/")
        parts = parts[:-1] if parts[-1] == "__init__" else parts
        for i in range(len(parts)):
            dotted = ".".join(parts[i:])
            if "." not in dotted and dotted in sys.stdlib_module_names:
                continue
            names[dotted] = None if dotted in names and names[dotted] != rel else rel
    return names


class Resolver:
    def __init__(self, py: frozenset[str]) -> None:
        self.py = py
        self.fallback = _fallback(py)

    def resolve(self, importer: str, dotted: str, level: int) -> str | None:
        # The importer's own folder and its parents first, as a script run sees them.
        parts = importer.split("/")[:-1]
        if level:
            if level - 1 > len(parts):
                return None
            base = "/".join(parts[: len(parts) - (level - 1)])
            if not dotted:
                init = f"{base}/__init__.py" if base else "__init__.py"
                return init if init in self.py else None
            return _candidate(base, dotted, self.py)
        for i in range(len(parts), -1, -1):
            found = _candidate("/".join(parts[:i]), dotted, self.py)
            if found:
                return found
        return self.fallback.get(dotted)


@dataclass
class ModuleUse:
    imports: set[str] = field(default_factory=set)
    symbols: dict[str, set[str]] = field(default_factory=dict)

    def use(self, module: str, name: str | None = None) -> None:
        self.imports.add(module)
        if name:
            self.symbols.setdefault(module, set()).add(name)


def _uses(rel: str, tree: ast.Module, resolver: Resolver) -> ModuleUse:
    use = ModuleUse()
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                target = resolver.resolve(rel, alias.name, 0)
                if target:
                    use.use(target)
                    if alias.asname or "." not in alias.name:
                        aliases[alias.asname or alias.name] = target
        elif isinstance(node, ast.ImportFrom):
            dotted = node.module or ""
            package = resolver.resolve(rel, dotted, node.level)
            for alias in node.names:
                sub = ".".join(p for p in (dotted, alias.name) if p)
                target = resolver.resolve(rel, sub, node.level) if alias.name != "*" else None
                if target:
                    use.use(target)
                    aliases[alias.asname or alias.name] = target
                elif package:
                    use.use(package, alias.name if alias.name != "*" else None)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            target = aliases.get(node.value.id)
            if target:
                use.use(target, node.attr)
    use.imports.discard(rel)
    use.symbols.pop(rel, None)
    return use


def imports_table(scan: Scan, trees: dict[str, ast.Module]) -> dict[str, ImportRow]:
    # Pin MAP -> VER: imports.<module>.fan_in lists the non-test modules that import it.
    resolver = Resolver(scan.py)
    sources = sorted(scan.py - scan.tests)
    uses = {rel: _uses(rel, trees[rel], resolver) for rel in sources if rel in trees}
    fan_in: dict[str, set[str]] = {rel: set() for rel in sources}
    symbols: dict[str, dict[str, set[str]]] = {rel: {} for rel in sources}
    for importer, use in uses.items():
        for target in use.imports - scan.tests:
            fan_in[target].add(importer)
        for target, names in use.symbols.items():
            for name in names:
                symbols.setdefault(target, {}).setdefault(name, set()).add(importer)
    empty = ModuleUse()
    return {
        rel: {
            "fan_in": sorted(fan_in[rel]),
            "imports": sorted(uses.get(rel, empty).imports - scan.tests),
            "symbols": {k: sorted(v) for k, v in sorted(symbols[rel].items())},
        }
        for rel in sources
    }


# Test-to-module coverage


def _named(value: str, by_name: dict[str, set[str]], sources: list[str]) -> set[str]:
    if "/" in value and value.endswith(".py"):
        tail = value.lstrip("/")
        return {rel for rel in sources if rel == tail or rel.endswith(f"/{tail}")}
    found = by_name.get(value, set())
    return set(found) if len(found) == 1 else set()


def coverage_table(scan: Scan, trees: dict[str, ast.Module]) -> dict[str, list[str]]:
    # A test covers a module it imports or names as `x.py`, a path, or a unique snake-case stem.
    resolver = Resolver(scan.py)
    sources = sorted(scan.py - scan.tests)
    by_name: dict[str, set[str]] = {}
    for rel in sources:
        name = rel.rsplit("/", 1)[-1]
        by_name.setdefault(name, set()).add(rel)
        if "_" in name[:-3].strip("_"):
            by_name.setdefault(name[:-3], set()).add(rel)
    covered: dict[str, set[str]] = {rel: set() for rel in sources}
    for test in sorted(scan.tests & set(trees)):
        hits = set(_uses(test, trees[test], resolver).imports)
        for node in ast.walk(trees[test]):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                hits |= _named(node.value, by_name, sources)
        for target in hits & set(covered):
            covered[target].add(test)
    return {rel: sorted(tests) for rel, tests in covered.items()}


# Readers and writers of shared records


@dataclass
class Occurrences:
    readers: set[str] = field(default_factory=set)
    writers: set[str] = field(default_factory=set)
    mentions: set[str] = field(default_factory=set)


@dataclass
class Records:
    kinds: dict[str, str] = field(default_factory=dict)
    found: dict[str, Occurrences] = field(default_factory=dict)

    def add(self, name: str, kind: str, role: str, where: str) -> None:
        self.kinds.setdefault(name, kind)
        occ = self.found.setdefault(name, Occurrences())
        {"reader": occ.readers, "writer": occ.writers}.get(role, occ.mentions).add(where)


# How a literal's use counts per record kind; a use the kind does not list is a mention.
_LINE_ROLE = {"reader": "reader", "writer": "writer", "emit": "writer", "value": "writer"}
_KEY_ROLE = {"reader": "reader", "writer": "writer"}


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _call_name(call: ast.Call) -> tuple[str, str]:
    func = call.func
    if isinstance(func, ast.Attribute):
        owner = func.value
        if isinstance(owner, ast.Attribute):
            return owner.attr, func.attr
        return (owner.id if isinstance(owner, ast.Name) else ""), func.attr
    return "", func.id if isinstance(func, ast.Name) else ""


def _role(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    # reader or writer by the literal's use; value in a dict, emit when it leaves as output.
    parent = parents.get(node)
    while isinstance(parent, ast.Tuple | ast.List | ast.Set | ast.JoinedStr | ast.BinOp):
        node, parent = parent, parents.get(parent)
    if isinstance(parent, ast.Compare):
        return "reader"
    if isinstance(parent, ast.Subscript) and parent.slice is node:
        return "reader" if isinstance(parent.ctx, ast.Load) else "writer"
    if isinstance(parent, ast.Dict):
        return "writer" if node in parent.keys else "value"
    if isinstance(parent, ast.Call):
        name = _call_name(parent)[1]
        first = bool(parent.args) and parent.args[0] is node
        if first and name in READ_CALLS:
            return "reader"
        if first and name in WRITE_CALLS:
            return "writer"
        return "emit"
    if isinstance(parent, ast.Return | ast.keyword | ast.FormattedValue):
        return "emit"
    return "other"


def _env_role(node: ast.expr, parents: dict[ast.AST, ast.AST]) -> str | None:
    # An environment name read through os.environ or getenv, or set through env= or setenv.
    parent = parents.get(node)
    if isinstance(parent, ast.Subscript) and parent.slice is node:
        value = parent.value
        name = value.attr if isinstance(value, ast.Attribute) else ""
        name = value.id if isinstance(value, ast.Name) else name
        if name == "environ":
            return "reader" if isinstance(parent.ctx, ast.Load) else "writer"
    if isinstance(parent, ast.Call) and parent.args and parent.args[0] is node:
        owner, name = _call_name(parent)
        if name == "getenv" or (owner == "environ" and name in READ_CALLS):
            return "reader"
        if name in WRITE_CALLS:
            return "writer"
    if isinstance(parent, ast.Dict) and node in parent.keys:
        holder = parents.get(parent)
        if isinstance(holder, ast.keyword) and holder.arg == "env":
            return "writer"
        if isinstance(holder, ast.Call) and _call_name(holder) == ("environ", "update"):
            return "writer"
    return None


def _key_leaves() -> dict[str, set[str]]:
    # 0076 vocabulary: a top-level manifest or config key, or a nested one with a snake-case leaf.
    leaves: dict[str, set[str]] = {}
    for key in (*manifest_keys(), *config_keys()):
        leaf = key.rsplit(".", 1)[-1].removesuffix("[]")
        if "." not in key or "_" in leaf:
            leaves.setdefault(leaf, set()).add(key)
    return leaves


def _module_strings(tree: ast.Module) -> dict[str, str]:
    # A module-level NAME = "literal" stands for its literal wherever the module loads NAME.
    found: dict[str, str] = {}
    for stmt in tree.body:
        value = stmt.value if isinstance(stmt, ast.Assign | ast.AnnAssign) else None
        targets = stmt.targets if isinstance(stmt, ast.Assign) else []
        targets = [stmt.target] if isinstance(stmt, ast.AnnAssign) else targets
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            found.update((t.id, value.value) for t in targets if isinstance(t, ast.Name))
    return found


def _strings(tree: ast.Module) -> list[tuple[ast.expr, str]]:
    named = _module_strings(tree)
    found: list[tuple[ast.expr, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.append((node, node.value))
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in named:
            found.append((node, named[node.id]))
    return found


def _python_records(
    rel: str, tree: ast.Module, records: Records, leaves: dict[str, set[str]]
) -> None:
    parents = _parents(tree)
    for node, text in _strings(tree):
        where = f"{rel}:{node.lineno}"
        role = _role(node, parents)
        for token in sorted(set(STATUS.findall(text))):
            records.add(token, "status", _LINE_ROLE.get(role, "mention"), where)
        if text in EVENTS:
            records.add(text, "event", _LINE_ROLE.get(role, "mention"), where)
        for key in sorted(leaves.get(text, ())):
            records.add(key, "key", _KEY_ROLE.get(role, "mention"), where)
        env = _env_role(node, parents) if ENV_NAME.fullmatch(text) else None
        if env is not None:
            records.add(text, "env", env, where)


def _python_env_mentions(rel: str, tree: ast.Module, records: Records) -> None:
    for node, text in _strings(tree):
        if records.kinds.get(text) == "env":
            occ = records.found[text]
            where = f"{rel}:{node.lineno}"
            if where not in occ.readers | occ.writers:
                occ.mentions.add(where)


def _alternation(words: Iterable[str]) -> str:
    return "|".join(re.escape(w) for w in sorted(words, key=lambda w: (-len(w), w)))


def _text_records(scan: Scan, records: Records, leaves: dict[str, set[str]]) -> None:
    # Prose and config files are mentions only: a backticked key, a quoted event, a ${NAME}.
    envs = [name for name, kind in records.kinds.items() if kind == "env"]
    patterns: list[tuple[re.Pattern[str], str]] = [
        (re.compile(r"[`\"'](" + _alternation(EVENTS) + r")[`\"']"), "event"),
    ]
    if leaves:
        patterns.append((re.compile(r"`(" + _alternation(leaves) + r")`"), "key"))
    if envs:
        patterns.append((re.compile(r"\$\{?(" + _alternation(envs) + r")\b"), "env"))
    for rel in scan.files:
        if rel.endswith(".py"):
            continue
        for number, line in enumerate(scan.texts[rel].splitlines(), 1):
            where = f"{rel}:{number}"
            for token in STATUS.findall(line):
                records.add(token, "status", "mention", where)
            for pattern, kind in patterns:
                for word in pattern.findall(line):
                    for name in sorted(leaves[word]) if kind == "key" else (word,):
                        records.add(name, kind, "mention", where)


def _line_key(where: str) -> tuple[str, int]:
    path, _, line = where.rpartition(":")
    return path, int(line)


def readers_table(scan: Scan, trees: dict[str, ast.Module]) -> dict[str, RecordRow]:
    records = Records()
    leaves = _key_leaves()
    for rel in sorted(trees):
        _python_records(rel, trees[rel], records, leaves)
    for rel in sorted(trees):
        _python_env_mentions(rel, trees[rel], records)
    _text_records(scan, records, leaves)
    return {
        name: {
            "kind": records.kinds[name],
            "mentions": sorted(occ.mentions, key=_line_key),
            "readers": sorted(occ.readers, key=_line_key),
            "security": records.kinds[name] == "event" or bool(SECURITY.search(name)),
            "writers": sorted(occ.writers, key=_line_key),
        }
        for name, occ in sorted(records.found.items())
    }


# File ownership by plan unit


def ownership_table(plan_path: Path | None, files: Iterable[str]) -> dict[str, list[str]]:
    # Pin MAP -> REQ: each listed path, and each tree file a folder or glob covers, to its units.
    if plan_path is None:
        return {}
    plan = load(plan_path)
    listed = {entry for unit in plan.units for entry in unit.files}
    wide = [e for e in listed if e.endswith("/") or any(c in e for c in "*?[")]
    paths = listed | {f for f in files for e in wide if _covers(e, f)}
    return {
        path: sorted(
            {u.id for u in plan.units for e in u.files if _covers(e, path) or _covers(path, e)}
        )
        for path in sorted(paths)
    }


# Near-duplicate blocks


def _norm_tokens(text: str) -> tuple[list[str], list[int]]:
    # Names and literals normalized; keywords, operators and attribute names kept; imports dropped.
    skip = {tokenize.NL, tokenize.COMMENT, tokenize.INDENT, tokenize.DEDENT, tokenize.ENCODING}
    skip |= {tokenize.ENDMARKER, tokenize.FSTRING_MIDDLE, tokenize.FSTRING_END}
    words: list[str] = []
    lines: list[int] = []
    prev = ";"
    importing = False
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type in skip:
                continue
            if prev == ";" and tok.string in ("import", "from"):
                importing = True
            if importing:
                importing = tok.type != tokenize.NEWLINE
                prev = ";" if not importing else tok.string
                continue
            if tok.type == tokenize.NAME:
                word = tok.string if tok.string in _KEYWORDS or prev == "." else "N"
            elif tok.type in (tokenize.STRING, tokenize.FSTRING_START):
                word = "S"
            elif tok.type == tokenize.NUMBER:
                word = "0"
            elif tok.type == tokenize.NEWLINE:
                word = ";"
            else:
                word = tok.string
            words.append(word)
            lines.append(tok.start[0])
            prev = word
    except (tokenize.TokenError, SyntaxError):
        return [], []
    return words, lines


class _Union:
    def __init__(self) -> None:
        self.up: dict[int, int] = {}

    def find(self, x: int) -> int:
        self.up.setdefault(x, x)
        while self.up[x] != x:
            self.up[x] = self.up[self.up[x]]
            x = self.up[x]
        return x

    def join(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.up[max(ra, rb)] = min(ra, rb)


def _merge(ranges: list[tuple[str, int, int]]) -> list[tuple[str, int, int]]:
    merged: list[tuple[str, int, int]] = []
    for path, a, b in ranges:
        if merged and merged[-1][0] == path and a <= merged[-1][2]:
            merged[-1] = (path, merged[-1][1], max(b, merged[-1][2]))
        else:
            merged.append((path, a, b))
    return merged


def _windows(
    scan: Scan, files: list[str]
) -> tuple[list[list[int]], dict[int, list[tuple[int, int]]]]:
    # Each window of normalized tokens by a 64-bit digest; only digests seen twice keep their spots.
    vocab: dict[str, int] = {}
    lines_of: list[list[int]] = []
    first: dict[int, tuple[int, int]] = {}
    spots: dict[int, list[tuple[int, int]]] = {}
    for fid, rel in enumerate(files):
        words, lines = _norm_tokens(scan.texts[rel])
        ids = array("I", (vocab.setdefault(w, len(vocab)) for w in words))
        lines_of.append(lines)
        for i in range(len(ids) - WINDOW + 1):
            raw = hashlib.blake2b(ids[i : i + WINDOW].tobytes(), digest_size=8).digest()
            key = int.from_bytes(raw, "big")
            if key in spots:
                spots[key].append((fid, i))
            elif key in first:
                spots[key] = [first.pop(key), (fid, i)]
            else:
                first[key] = (fid, i)
    return lines_of, spots


def duplicates_table(scan: Scan) -> list[list[str]]:
    # Pin MAP -> VER: each entry lists the file:line ranges of one near-duplicate block.
    files = sorted(scan.py)
    lines_of, spots = _windows(scan, files)
    runs: list[tuple[int, int, int]] = []
    run_of: dict[tuple[int, int], int] = {}
    for fid, i in sorted({pos for found in spots.values() for pos in found}):
        if runs and runs[-1][0] == fid and runs[-1][2] == i - 1:
            runs[-1] = (fid, runs[-1][1], i)
        else:
            runs.append((fid, i, i))
        run_of[(fid, i)] = len(runs) - 1
    union = _Union()
    for found in spots.values():
        for pos in found[1:]:
            union.join(run_of[found[0]], run_of[pos])
    groups: dict[int, list[tuple[str, int, int]]] = {}
    for rid, (fid, start, end) in enumerate(runs):
        top, bottom = lines_of[fid][start], lines_of[fid][end + WINDOW - 1]
        if bottom - top + 1 >= MIN_LINES:
            groups.setdefault(union.find(rid), []).append((files[fid], top, bottom))
    blocks = [_merge(sorted(ranges)) for ranges in groups.values()]
    return sorted([f"{p}:{a}-{b}" for p, a, b in block] for block in blocks if len(block) > 1)


# Output


def build(repo: Path, out: Path, plan_path: Path | None) -> MapTables:
    scan = scan_tree(repo, out)
    trees = _parse(scan)
    return {
        "coverage": coverage_table(scan, trees),
        "duplicates": duplicates_table(scan),
        "imports": imports_table(scan, trees),
        "ownership": ownership_table(plan_path, scan.files),
        "readers": readers_table(scan, trees),
    }


def render_json(data: MapTables) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _cell(items: Iterable[str]) -> str:
    return ", ".join(items).replace("|", "\\|") or "none"


def _files(spots: list[str]) -> list[str]:
    return sorted({_line_key(s)[0] for s in spots})


def render_md(data: MapTables, plan_given: bool) -> str:
    imports = data["imports"]
    out = [
        "# Dependency map",
        "",
        "Built by `scripts/daedalus_map.py` from the tree; regenerate it after every merge.",
        "`map.json` beside this file holds the same tables with line numbers.",
        "",
        "## Import graph and fan-in",
        "",
        "| Module | Fan-in | Imported by | Imports |",
        "|---|---|---|---|",
    ]
    for mod in sorted(imports, key=lambda m: (-len(imports[m]["fan_in"]), m)):
        row = imports[mod]
        fan = row["fan_in"]
        out.append(f"| {mod} | {len(fan)} | {_cell(fan)} | {_cell(row['imports'])} |")
    out += ["", "## Test-to-module coverage", "", "| Module | Tests |", "|---|---|"]
    out += [f"| {mod} | {_cell(tests)} |" for mod, tests in data["coverage"].items()]
    out += [
        "",
        "## Readers and writers of shared records",
        "",
        "| Record | Kind | Security | Readers | Writers | Mentions |",
        "|---|---|---|---|---|---|",
    ]
    for name, rec in data["readers"].items():
        out.append(
            f"| {_cell([name])} | {rec['kind']} | {'yes' if rec['security'] else 'no'} | "
            f"{_cell(_files(rec['readers']))} | {_cell(_files(rec['writers']))} | "
            f"{len(rec['mentions'])} |"
        )
    out += ["", "## File ownership by plan unit", ""]
    if plan_given:
        out += ["| Path | Units |", "|---|---|"]
        out += [f"| {_cell([p])} | {_cell(units)} |" for p, units in data["ownership"].items()]
    else:
        out.append("No plan given (`--plan`).")
    out += ["", "## Near-duplicate blocks", "", "| Block | Ranges |", "|---|---|"]
    out += [f"| {n} | {_cell(ranges)} |" for n, ranges in enumerate(data["duplicates"], 1)]
    return "\n".join(out) + "\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="daedalus_map.py", allow_abbrev=False)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--check", action="store_true")
    return parser


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _check(out: Path, texts: dict[str, str]) -> int:
    for name, text in texts.items():
        path = out / name
        if not path.is_file():
            print(R_MISSING.format(path=path))
            return 1
        if path.read_text(encoding="utf-8") != text:
            print(R_STALE.format(path=path))
            return 1
    print(f"OK map: {out / MAP_JSON} is current sha256={_sha256(texts[MAP_JSON])}")
    return 0


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    repo = args.repo.resolve()
    out = (repo / args.out).resolve()
    if out == repo or not out.is_relative_to(repo):
        print(R_OUT.format(out=args.out, repo=args.repo))
        return 2
    try:
        data = build(repo, out, args.plan)
    except PlanError as exc:
        print(R_PLAN.format(error=exc))
        return 2
    texts = {MAP_JSON: render_json(data), MAP_MD: render_md(data, args.plan is not None)}
    if args.check:
        return _check(out, texts)
    out.mkdir(parents=True, exist_ok=True)
    for name, text in texts.items():
        atomic.write_atomic(out / name, text)
    print(f"OK map: {out / MAP_MD}")
    print(f"OK map: {out / MAP_JSON} sha256={_sha256(texts[MAP_JSON])}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

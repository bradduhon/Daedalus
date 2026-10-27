# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# Plan 10 spec 3.2 item 3: every write site under scripts/ maps to a FILES writer, both ways.
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from lib import inventory

from tests.conftest import SCRIPTS_DIR

PRIMITIVES = frozenset({"write_atomic", "create_once", "open_lock", "locked"})
ANY_RECEIVER = frozenset({"write_text", "write_bytes", "mkdir", "touch"})
DOTTED = frozenset(
    {
        "os.mkdir",
        "os.makedirs",
        "os.replace",
        "os.rename",
        "shutil.move",
        "tempfile.mkstemp",
        "tempfile.mkdtemp",
        # Spec 3.2: the two tempfile creators beyond mkstemp and mkdtemp, so fetch._temp counts.
        "tempfile.NamedTemporaryFile",
        "tempfile.TemporaryDirectory",
    }
)
WRITER = re.compile(r"scripts/[A-Za-z0-9_/]+\.py:[A-Za-z_][A-Za-z0-9_.]*")
Slots = dict[str, int]


def _imports(tree: ast.Module) -> dict[str, str]:
    # Spec 3.2: `from shutil import copy2` and `import x as y` resolve to the dotted name.
    names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names[alias.asname or alias.name.split(".")[0]] = alias.name
    return names


def _dotted(func: ast.expr, names: dict[str, str]) -> str:
    if isinstance(func, ast.Name):
        return names.get(func.id, func.id)
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            return f"{names.get(func.value.id, func.value.id)}.{func.attr}"
        return f"?.{func.attr}"
    return "?"


def _mode(call: ast.Call, index: int) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == "mode":
            return kw.value
    return call.args[index] if len(call.args) > index else None


def _writes_mode(mode: ast.expr | None) -> bool:
    # Spec 3.2: a mode holding w, a, x or +; a mode not written as a literal counts, fail closed.
    if mode is None:
        return False
    if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
        return bool(set(mode.value) & set("wax+"))
    return True


def _names_creat(node: ast.AST) -> bool:
    return any(
        (isinstance(n, ast.Attribute) and n.attr == "O_CREAT")
        or (isinstance(n, ast.Name) and n.id == "O_CREAT")
        for n in ast.walk(node)
    )


def _file_site(call: ast.Call, names: dict[str, str]) -> bool:
    dotted = _dotted(call.func, names)
    if dotted.rsplit(".", 1)[-1] in PRIMITIVES:
        return True
    if isinstance(call.func, ast.Attribute) and call.func.attr in ANY_RECEIVER:
        return True
    if dotted in DOTTED or dotted.startswith("shutil.copy"):
        return True
    if dotted == "os.open":
        return any(_names_creat(arg) for arg in call.args[1:])
    if isinstance(call.func, ast.Name) and call.func.id == "open" and "open" not in names:
        return _writes_mode(_mode(call, 1))
    if isinstance(call.func, ast.Attribute) and call.func.attr == "open":
        # Spec 3.2: Path.open with a literal write mode; a URL opener's open is no file write.
        mode = _mode(call, 0)
        return isinstance(mode, ast.Constant) and _writes_mode(mode)
    return False


def _git_write(args: list[str | None]) -> bool:
    # Spec 3.2: worktree add, branch, switch -c, commit, merge or tag; -C and -c take a value.
    i = 0
    while i < len(args) and args[i] in {"-C", "-c"}:
        i += 2
    rest = args[i:]
    if not rest:
        return False
    if rest[0] == "worktree":
        return rest[1:2] == ["add"]
    if rest[0] == "switch":
        return "-c" in rest[1:]
    return rest[0] in {"branch", "commit", "merge", "tag"}


def _flat(nodes: list[ast.expr]) -> list[str | None]:
    out: list[str | None] = []
    for node in nodes:
        if isinstance(node, ast.List | ast.Tuple):
            out.extend(_flat(list(node.elts)))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            out.append(node.value)
        else:
            out.append(None)
    return out


class _Module:
    def __init__(self, path: Path, base: Path, runners: dict[str, Slots]) -> None:
        self.key = path.relative_to(base).as_posix()
        self.tree = ast.parse(path.read_text(encoding="utf-8"))
        self.names = _imports(self.tree)
        self.local = runners[path.stem]
        self.remote = {
            name: runners[dotted.rsplit(".", 1)[-1]]
            for name, dotted in self.names.items()
            if dotted.rsplit(".", 1)[-1] in runners
        }
        self.fns = [n for n in self.tree.body if isinstance(n, ast.FunctionDef)]

    def slot(self, call: ast.Call) -> int | None:
        # Spec 3.2: the position where a git runner's git arguments start, else None.
        if isinstance(call.func, ast.Name):
            return self.local.get(call.func.id)
        if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
            return self.remote.get(call.func.value.id, {}).get(call.func.attr)
        return None


def _param_slot(fn: ast.FunctionDef, node: ast.expr) -> int | None:
    target = node.value if isinstance(node, ast.Starred) else node
    if not isinstance(target, ast.Name):
        return None
    params = [a.arg for a in fn.args.posonlyargs + fn.args.args]
    if fn.args.vararg is not None and target.id == fn.args.vararg.arg:
        return len(params)
    return params.index(target.id) if target.id in params else None


def _runner_slot(module: _Module, fn: ast.FunctionDef) -> int | None:
    # Spec 3.2: a runner builds ["git", ..., *param] or hands a param to another runner's slot.
    for node in ast.walk(fn):
        if isinstance(node, ast.List) and _flat(node.elts[:1]) == ["git"]:
            for elt in node.elts[1:]:
                if isinstance(elt, ast.Starred) and (found := _param_slot(fn, elt)) is not None:
                    return found
        elif isinstance(node, ast.Call):
            slot = module.slot(node)
            if slot is not None and len(node.args) > slot:
                if (found := _param_slot(fn, node.args[slot])) is not None:
                    return found
    return None


class _Walker(ast.NodeVisitor):
    def __init__(self, module: _Module) -> None:
        self.module = module
        self.scope: list[str] = []
        self.sites: dict[str, list[int]] = {}

    def _add(self, node: ast.Call | ast.List) -> None:
        writer = f"{self.module.key}:{'.'.join(self.scope) or '<module>'}"
        self.sites.setdefault(writer, []).append(node.lineno)

    def _scoped(self, node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    visit_ClassDef = _scoped
    visit_FunctionDef = _scoped
    visit_AsyncFunctionDef = _scoped

    def visit_Call(self, node: ast.Call) -> None:
        slot = self.module.slot(node)
        git_write = slot is not None and _git_write(_flat(node.args[slot:]))
        if git_write or _file_site(node, self.module.names):
            self._add(node)
        self.generic_visit(node)

    def visit_List(self, node: ast.List) -> None:
        flat = _flat(list(node.elts))
        if flat[:1] == ["git"] and _git_write(flat[1:]):
            self._add(node)
        self.generic_visit(node)


def write_sites(root: Path = SCRIPTS_DIR) -> dict[str, list[int]]:
    """Every write site under root, `scripts/<file>.py:<function>` to its line numbers."""
    paths = sorted(root.rglob("*.py"))
    runners: dict[str, Slots] = {path.stem: {} for path in paths}
    modules = [_Module(path, root.parent, runners) for path in paths]
    grew = True
    while grew:
        grew = False
        for module in modules:
            for fn in module.fns:
                if fn.name not in module.local:
                    found = _runner_slot(module, fn)
                    if found is not None:
                        module.local[fn.name] = found
                        grew = True
    sites: dict[str, list[int]] = {}
    for module in modules:
        walker = _Walker(module)
        walker.visit(module.tree)
        for writer, lines in walker.sites.items():
            sites.setdefault(writer, []).extend(lines)
    return sites


def test_every_write_site_has_a_files_row() -> None:
    listed = {e.writer for e in inventory.FILES}
    unlisted = {w: n for w, n in write_sites().items() if w not in listed}
    assert not unlisted, f"write sites with no FILES row in scripts/lib/inventory.py: {unlisted}"


def test_every_files_row_names_a_live_write_site() -> None:
    stale = {e.writer for e in inventory.FILES} - set(write_sites())
    assert not stale, f"FILES rows whose writer has no write site: {sorted(stale)}"


def test_every_writer_reads_script_file_and_function() -> None:
    bad = [e.writer for e in inventory.FILES if not WRITER.fullmatch(e.writer)]
    assert not bad, bad


def test_rows_are_unique_and_filled() -> None:
    assert len(set(inventory.FILES)) == len(inventory.FILES)
    assert all(e.pattern and e.when and "|" not in e.pattern + e.when for e in inventory.FILES)


def test_git_refs_and_worktrees_are_rows() -> None:
    patterns = {e.pattern for e in inventory.FILES}
    assert "refs/heads/daedalus/<train-id>" in patterns
    assert any(p.endswith(".claude/worktrees/<train-id>-<unit-slug>") for p in patterns)


def test_lines_match_rows() -> None:
    assert inventory.lines() == [f"{e.pattern} | {e.writer} | {e.when}" for e in inventory.FILES]


def _sites_of(tmp_path: Path, files: dict[str, str]) -> dict[str, list[int]]:
    for name, body in files.items():
        path = tmp_path / "scripts" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return write_sites(tmp_path / "scripts")


@pytest.mark.parametrize(
    "line",
    [
        "atomic.write_atomic(p, 'x')",
        "create_once(p, 'x', 0o600)",
        "locks.open_lock(p)",
        "locked(p)",
        "os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)",
        "open(p, 'w')",
        "open(p, mode='a')",
        "open(p, 'r+')",
        "open(p, flags)",
        "p.open('x')",
        "p.write_text('x')",
        "p.write_bytes(b'x')",
        "p.mkdir()",
        "p.touch()",
        "os.mkdir(p)",
        "os.makedirs(p)",
        "os.replace(a, b)",
        "os.rename(a, b)",
        "shutil.copy2(a, b)",
        "shutil.copytree(a, b)",
        "shutil.move(a, b)",
        "tempfile.mkstemp()",
        "tempfile.mkdtemp()",
        "mkdtemp()",
        "subprocess.run(['git', '-C', r, 'worktree', 'add', p])",
        "subprocess.run(['git', 'branch', '-d', b])",
        "subprocess.run(['git', 'switch', '-q', '-c', b])",
        "subprocess.run(['git', 'commit', '-m', m])",
        "subprocess.run(['git', 'merge', b])",
        "subprocess.run(['git', 'tag', t])",
    ],
)
def test_scanner_finds_each_write_kind(tmp_path: Path, line: str) -> None:
    # Spec 3.2 item 3: each listed write kind maps to its enclosing module:function.
    head = "import os, shutil, subprocess, tempfile\nfrom tempfile import mkdtemp\n"
    body = f"{head}class K:\n    def f(self, p, a, b, r, t, m, flags):\n        {line}\n"
    assert _sites_of(tmp_path, {"mod.py": body}) == {"scripts/mod.py:K.f": [5]}


@pytest.mark.parametrize(
    "line",
    [
        "open(p)",
        "open(p, 'rb')",
        "os.open(p, os.O_RDONLY)",
        "text.replace('a', 'b')",
        "opener.open(req, timeout=5)",
        "_text(u, 'branch')",
        "u.get('merge')",
        "subprocess.run(['git', 'worktree', 'list'])",
        "subprocess.run(['git', 'switch', '-q', b])",
        "subprocess.run(['git', 'merge-base', a, b])",
    ],
)
def test_scanner_skips_reads(tmp_path: Path, line: str) -> None:
    # Spec 3.2 item 3: a read, a string method or a read-only git list is no write site.
    body = f"import os, subprocess\ndef f(p, text, opener, req, u, a, b, _text):\n    {line}\n"
    assert _sites_of(tmp_path, {"mod.py": body}) == {}


def test_scanner_follows_git_runners_across_modules(tmp_path: Path) -> None:
    # Spec 3.2 item 3: a wrapper chain into the one git runner still names the caller.
    runner = "import subprocess\ndef run(args, cwd):\n    cmd = ['git', '-C', cwd, *args]\n"
    wrap = (
        "from lib import git\n"
        "def _run(repo, *args):\n    return git.run(args, repo)\n"
        "def _git(repo, *args):\n    _run(repo, *args)\n"
        "def save(repo):\n    _git(repo, 'commit', '-m', 'x')\n"
        "def look(repo):\n    _git(repo, 'status')\n"
        "def direct(repo):\n    git.run(['tag', 'v1'], repo)\n"
    )
    found = _sites_of(tmp_path, {"lib/git.py": runner, "lib/wrap.py": wrap})
    assert found == {"scripts/lib/wrap.py:save": [7], "scripts/lib/wrap.py:direct": [11]}


def test_module_level_write_is_named_module(tmp_path: Path) -> None:
    found = _sites_of(tmp_path, {"mod.py": "from pathlib import Path\nPath('x').touch()\n"})
    assert found == {"scripts/mod.py:<module>": [2]}

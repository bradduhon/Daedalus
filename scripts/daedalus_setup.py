#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0076: writes whichever starter project file is missing, behind /daedalus:setup.
# 0242: also describes the three settings files, creates the personal file and sets one key.
from __future__ import annotations

import argparse
import json
import os
import sys
import tomllib
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import atomic, settings_edit  # noqa: E402
from lib.audit import DataDirError, check_project_data_dir, ensure_project_data_dir  # noqa: E402
from lib.config import ConfigError, parse_config  # noqa: E402
from lib.ledger import LedgerError  # noqa: E402
from lib.manifest import MANIFEST_NAME, ManifestError  # noqa: E402
from lib.manifest import parse as parse_manifest  # noqa: E402
from lib.operator_file import MAX_BYTES as OPERATOR_MAX_BYTES  # noqa: E402
from lib.operator_file import OPERATOR_FILE, OperatorError  # noqa: E402
from lib.operator_file import validate as validate_operator  # noqa: E402
from lib.project_keys import (  # noqa: E402
    BLOCKS,
    GROUPS,
    KEY_ROWS,
    LITERACY_EXAMPLES,
    OVERLAPS,
    SETTINGS_FILES,
    Block,
    SettingsFile,
    starter_config,
    starter_manifest,
    starter_operator,
)
from lib.project_root import in_git_work_tree, project_root  # noqa: E402

CONFIG_NAME = "config.json"
# 0077: how far below the setup folder, and through how many folders, the repository scan looks.
SCAN_DEPTH = 3
SCAN_LIMIT = 2000
FORMS = tuple(f.form for f in SETTINGS_FILES)
_BY_FORM = {f.form: f for f in SETTINGS_FILES}
_LIMITS = {
    "manifest": settings_edit.MAX_BYTES,
    "config": settings_edit.MAX_BYTES,
    "operator": OPERATOR_MAX_BYTES,
}
# 0242: the Terraform walk's own bounds; a capped walk leaves the Terraform questions asked.
TERRAFORM_DEPTH = 6
TERRAFORM_ENDINGS = (".tf", ".tfvars")
_SKIPPED_FOLDERS = frozenset({"node_modules"})
SET_NEXT = "Next: correct the command as the line above says, then run it again."
FILE_NEXT = "Next: write the value file again as one JSON value, then run the same command again."
VALUE_NEXT = "Next: choose a value the key reference in the README allows, then set it again."


class SetupStop(Exception):
    pass


@dataclass(frozen=True)
class Marker:
    key: str
    file: str
    section: tuple[str, ...]
    proposal: str


# 0242: the marker files the stack proposals read; no command is run to detect anything.
STACK_MARKERS: tuple[Marker, ...] = (
    Marker(
        "commands.unit_test",
        "pyproject.toml",
        ("tool", "pytest", "ini_options"),
        "python3 -m pytest -q",
    ),
    Marker("commands.typecheck", "pyproject.toml", ("tool", "mypy"), "python3 -m mypy ."),
    Marker("commands.lint", "pyproject.toml", ("tool", "ruff"), "python3 -m ruff check ."),
    Marker("commands.unit_test", "package.json", ("scripts", "test"), "{pm} test"),
    Marker("commands.typecheck", "package.json", ("scripts", "typecheck"), "{pm} run typecheck"),
    Marker("commands.lint", "package.json", ("scripts", "lint"), "{pm} run lint"),
    Marker("commands.unit_test", "go.mod", (), "go test ./..."),
    Marker("commands.lint", "go.mod", (), "go vet ./..."),
    Marker("commands.unit_test", "Cargo.toml", (), "cargo test"),
    Marker("commands.typecheck", "Cargo.toml", (), "cargo check"),
    Marker("commands.lint", "Cargo.toml", (), "cargo clippy"),
)
# 0242, 0245: the lockfile that picks the runner in a package.json proposal, first match wins.
LOCKFILES: tuple[tuple[str, str], ...] = (
    ("pnpm-lock.yaml", "pnpm"),
    ("yarn.lock", "yarn"),
    ("package-lock.json", "npm"),
    ("uv.lock", "uv"),
)
_NODE_MANAGERS = frozenset({"pnpm", "yarn", "npm"})


def _write_new(path: Path, doc: dict[str, object], mode: int) -> bool:
    # 0076: create-once, so an existing file or a symlink there is never written.
    try:
        atomic.create_once(path, json.dumps(doc, indent=2) + "\n", mode)
    except FileExistsError:
        return False
    return True


def _report(path: Path, written: bool) -> None:
    print(f"written: {path}" if written else f"kept: {path} (it already exists)")


def _nested_repo(root: Path) -> tuple[Path | None, bool]:
    # 0077: breadth-first and bounded; returns the first repository found and whether the cap hit.
    queue: deque[tuple[Path, int]] = deque([(root, 0)])
    seen = 0
    while queue:
        folder, depth = queue.popleft()
        try:
            children = sorted(folder.iterdir())
        except OSError:
            continue
        for child in children:
            if child.name.startswith("."):
                continue
            if child.is_symlink():
                # 0077: a linked repository is still re-rooted; a link is checked, never descended.
                if os.path.lexists(child / ".git"):
                    return child, False
                continue
            if not child.is_dir():
                continue
            seen += 1
            if seen > SCAN_LIMIT:
                return None, True
            if os.path.lexists(child / ".git"):
                return child, False
            if depth + 1 < SCAN_DEPTH:
                queue.append((child, depth + 1))
    return None, False


def setup(repo: Path) -> int:
    root = project_root(repo)
    # 0077: starter files above repositories would become each one's project root; refuse.
    found, capped = (None, False) if in_git_work_tree(root) else _nested_repo(root)
    if capped:
        # 0077: fail closed; a folder too large to scan may still hold a repository.
        print(
            f"setup stopped: {root} holds more than {SCAN_LIMIT} folders, too many to confirm "
            "it holds no repository. Next: run the Daedalus setup skill from inside the one "
            "repository you want to set up."
        )
        return 1
    if found is not None:
        print(
            f"setup stopped: {root} is not a git repository but holds the repository "
            f"{found.relative_to(root)}, so starter files here would become its project root. "
            "Next: run the Daedalus setup skill from inside the one repository you want to set up."
        )
        return 1
    try:
        # 0010: the data folder passes its checks before either file is written.
        data = check_project_data_dir(str(root))
        manifest = root / MANIFEST_NAME
        written = _write_new(manifest, starter_manifest(), 0o644)
        _report(manifest, written)
        if written:
            # 0134: JSON holds no comments, so the literacy examples are printed beside the file.
            print(f"docs.reading_level: null; examples: {', '.join(LITERACY_EXAMPLES)}")
        config = data / CONFIG_NAME
        if os.path.lexists(config):
            _report(config, False)
            return 0
        data = ensure_project_data_dir(str(root))
        # 0070: the config never leaves the machine, so only its owner reads it.
        _report(config, _write_new(data / CONFIG_NAME, starter_config(), 0o600))
    except DataDirError as exc:
        print(f"setup stopped, the project data folder failed a check: {exc}")
        return 1
    except OSError as exc:
        print(
            f"setup stopped, a starter file could not be written ({exc}). Next: make the "
            "project folder writable for you, then run the Daedalus setup skill again."
        )
        return 1
    return 0


def _home() -> Path:
    # 0242: Path.home falls back to the password file; the personal file follows HOME or nothing.
    raw = os.environ.get("HOME", "")
    if not raw or not os.path.isabs(raw):
        state = "not set" if not raw else f"the relative path {raw!r}"
        raise SetupStop(
            f"setup stopped: HOME is {state}, so the personal settings file has no safe place. "
            "Next: set HOME to the full path of your home folder, then run setup again."
        )
    return Path(raw)


def _path(form: str, root: Path) -> Path:
    if form == "manifest":
        return root / MANIFEST_NAME
    if form == "config":
        return check_project_data_dir(str(root)) / CONFIG_NAME
    return _home() / OPERATOR_FILE


def _check(form: str, doc: object, path: Path) -> None:
    # 0242: each file's own reader judges the whole document; its message is shown as it is.
    if form == "manifest":
        parse_manifest(doc, path)
    elif form == "config":
        parse_config(doc, path)
    else:
        validate_operator(doc, str(path))


def _refuse_links(path: Path) -> None:
    for part in (path.parent, path):
        if os.path.islink(part):
            raise SetupStop(
                f"setup stopped: {part} is a symlink, and setup never writes through a link. "
                "Next: replace the link with a real folder or file from your own shell, then "
                "run setup again."
            )


def create_operator() -> int:
    # 0242: created when missing, every setting at its off value; never overwritten.
    path = _home() / OPERATOR_FILE
    folder = path.parent
    _refuse_links(path)
    try:
        folder.parent.mkdir(mode=0o700, exist_ok=True)
        folder.mkdir(mode=0o700, exist_ok=True)
        _refuse_links(path)
        written = _write_new(path, starter_operator(), 0o600)
    except OSError as exc:
        raise SetupStop(
            f"setup stopped, the personal settings file could not be written ({exc}). "
            "Next: make your home folder's .claude folder writable for you, then run setup again."
        ) from exc
    _report(path, written)
    return 0


def _segments(key: str) -> tuple[str, ...]:
    return tuple(key.split("."))


def _addressable(key: str) -> bool:
    # 0242: a key inside a list entry or a named entry has no single place to set.
    return "[]" not in key and "<" not in key


def _form_of_name(name: str) -> str:
    return next(f.form for f in SETTINGS_FILES if f.name == name)


def block_of(name: str, key: str) -> Block | None:
    return next((b for b in BLOCKS if b.file == name and b.key == key), None)


def _block_refusal(info: SettingsFile, block: Block, value: object) -> str | None:
    # 0242: a block is set whole, as an object of its own members or as null to clear it.
    if value is None:
        return None
    if not isinstance(value, dict):
        return (
            f"set refused: {block.key} of the {info.form} file takes an object of its settings "
            "or null. Next: write the value as one JSON object, or null to clear the block."
        )
    unknown = sorted(str(k) for k in value if f"{block.key}.{k}" not in block.members)
    if unknown:
        known = ", ".join(m.removeprefix(block.key + ".") for m in block.members)
        return (
            f"set refused: {block.key} of the {info.form} file has no setting named "
            f"{', '.join(unknown)}. Next: use only the settings {known}."
        )
    return None


def _key_refusal(info: SettingsFile, key: str) -> str | None:
    if block_of(info.name, key) is not None:
        return None
    if (info.name, key) in KEY_ROWS:
        if _addressable(key):
            return None
        return (
            f"set refused: {key} sits inside a list or a named entry of {info.name}, so it "
            "cannot be set alone. Next: edit that block by hand, as the key reference in the "
            "README shows."
        )
    owners = sorted({_form_of_name(f) for f, k in KEY_ROWS if k == key})
    if owners:
        return (
            f"set refused: {key} is a setting of the {' and '.join(owners)} file, not the "
            f"{info.form} file. Next: name the file that holds it, as in --set {owners[0]} {key}."
        )
    under = [k for f, k in KEY_ROWS if f == info.name and k.startswith(key + ".")]
    detail = f"names a block of {len(under)} settings, not one" if under else "is not a setting"
    return (
        f"set refused: {key} {detail} of the {info.form} file. Next: name one setting from "
        "the key reference in the README."
    )


def _show(value: object) -> str:
    return json.dumps(value, ensure_ascii=False)


def set_key(form: str, key: str, raw: str, repo: Path) -> int:
    # 0242: one key of an existing file; the reader checks the whole result before the rename.
    info = _BY_FORM.get(form)
    if info is None:
        raise SetupStop(
            f"set refused: {form!r} is not one of the settings files. "
            f"Next: name one of {', '.join(FORMS)} as the file to change."
        )
    refusal = _key_refusal(info, key)
    if refusal is not None:
        raise SetupStop(refusal)
    try:
        value: object = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise SetupStop(
            f"set refused: the value {raw[:80]!r} is not JSON. Next: write the value as JSON, "
            'such as true, 3, "text" or ["one", "two"].'
        ) from exc
    block = block_of(info.name, key)
    refusal = _block_refusal(info, block, value) if block is not None else None
    if refusal is not None:
        raise SetupStop(refusal)
    try:
        path = _path(form, project_root(repo))
    except DataDirError as exc:
        raise SetupStop(f"set refused, the project data folder failed a check: {exc}") from exc
    _refuse_links(path)
    if not path.exists():
        raise SetupStop(
            f"set refused: {path} does not exist yet. Next: run the Daedalus setup skill "
            "to create the file first, then set the value."
        )
    limit = _LIMITS[form]
    try:
        before = settings_edit.read_text(path, limit)
        doc = settings_edit.parse(before)
        present, old = settings_edit.lookup(doc, _segments(key))
        if present and settings_edit.same(old, value):
            print(f"kept: {path} {key} already {_show(value)}")
            return 0
        text = settings_edit.splice(before, _segments(key), value)
        changed = settings_edit.parse(text)
        if not settings_edit.same(changed, settings_edit.with_value(doc, _segments(key), value)):
            raise settings_edit.EditError("could not be changed in place")
    except settings_edit.EditError as exc:
        raise SetupStop(
            f"set refused: {path} {exc}. Next: fix the file by hand so it is one valid JSON "
            "object, then run the same command again."
        ) from exc
    try:
        _check(form, changed, path)
    except (ManifestError, ConfigError, OperatorError, LedgerError) as exc:
        # 0242: the reader's own message, with a next step when the reader gave none.
        tail = "" if "Next:" in str(exc) else f" {VALUE_NEXT}"
        raise SetupStop(
            f"set refused, the file's own check refused the new value: {exc}{tail}"
        ) from exc
    try:
        settings_edit.write(path, before, text, limit)
    except settings_edit.EditError as exc:
        raise SetupStop(
            f"set refused: {path} {exc}. Next: run the same command again, so it reads the "
            "file as it is now."
        ) from exc
    except OSError as exc:
        raise SetupStop(
            f"set refused: {path} could not be written ({exc}). Next: make that folder "
            "writable for you, then run the same command again."
        ) from exc
    old_text = _show(old) if present else "absent"
    print(f"changed: {path} {key}: {old_text} -> {_show(value)}")
    return 0


def _read_marker(root: Path, name: str) -> str | None:
    try:
        return settings_edit.read_text(root / name)
    except (settings_edit.EditError, OSError):
        return None


def _section(doc: object, section: tuple[str, ...]) -> bool:
    present, _ = settings_edit.lookup(doc, section)
    return present


def _package_manager(root: Path) -> tuple[str, str] | None:
    for name, manager in LOCKFILES:
        if os.path.isfile(root / name) and not os.path.islink(root / name):
            return manager, name
    return None


_PARSERS: dict[str, Callable[[str], object]] = {
    "pyproject.toml": tomllib.loads,
    "package.json": json.loads,
}


def detect(root: Path) -> dict[str, dict[str, object]]:
    # 0242: a proposal per stack key, each grounded in a marker file read here.
    found: dict[str, dict[str, object]] = {}
    manager = _package_manager(root)
    runner = manager[0] if manager is not None and manager[0] in _NODE_MANAGERS else "npm"
    docs: dict[str, object] = {}
    commands: dict[str, list[str]] = {}
    sources: dict[str, list[str]] = {}
    for marker in STACK_MARKERS:
        if marker.file not in docs:
            docs[marker.file] = _marker_doc(root, marker.file)
        doc = docs[marker.file]
        if doc is None or not _section(doc, marker.section):
            continue
        commands.setdefault(marker.key, []).append(marker.proposal.replace("{pm}", runner))
        sources.setdefault(marker.key, []).append(" ".join((marker.file, *marker.section)))
    for key, listed in commands.items():
        found[key] = {"value": listed[0] if len(listed) == 1 else listed, "from": sources[key]}
    return found


def _marker_doc(root: Path, name: str) -> object:
    # 0242: None when the file is absent, unreadable or not valid in its own format.
    text = _read_marker(root, name)
    parser = _PARSERS.get(name)
    if text is None:
        return None
    if parser is None:
        return {}
    try:
        return parser(text)
    except (ValueError, RecursionError):
        return None


def _terraform_files(root: Path) -> bool | None:
    # 0242: bounded like the repository scan; None when the cap stops the walk.
    queue: deque[tuple[Path, int]] = deque([(root, 0)])
    seen = 0
    while queue:
        folder, depth = queue.popleft()
        try:
            children = sorted(folder.iterdir())
        except OSError:
            continue
        for child in children:
            if child.name.startswith(".") or child.is_symlink():
                continue
            if child.is_file() and child.name.endswith(TERRAFORM_ENDINGS):
                return True
            if not child.is_dir() or child.name in _SKIPPED_FOLDERS:
                continue
            seen += 1
            if seen > SCAN_LIMIT:
                return None
            if depth + 1 < TERRAFORM_DEPTH:
                queue.append((child, depth + 1))
    return False


def moot(root: Path) -> dict[str, str]:
    # 0242: a question the repository already answers is skipped, with the reason shown.
    if _terraform_files(root) is False:
        why = "the project holds no Terraform files, so the Terraform tools are not asked"
        return {"checks.terraform_format": why, "checks.terraform_validate": why}
    return {}


def _defaults(form: str) -> dict[str, object]:
    # 0242, 0245: the starter values; an override left out reads as absent, its reader default.
    if form == "operator":
        return starter_operator()
    if form == "config":
        return starter_config()
    return starter_manifest()


def _prefix(key: str) -> tuple[str, ...]:
    parts: list[str] = []
    for part in key.split("."):
        if part.endswith("[]"):
            parts.append(part.removesuffix("[]"))
            break
        if part.startswith("<"):
            break
        parts.append(part)
    return tuple(parts)


def _key_entry(
    info: SettingsFile, key: str, group: str, day_one: bool, doc: object, readable: bool
) -> dict[str, object]:
    row = KEY_ROWS[(info.name, key)]
    entry: dict[str, object] = {
        "file": info.form,
        "key": key,
        "group": group,
        "day_one": day_one,
        "override": row.override,
        "active": bool(row.readers),
        "settable": _addressable(key),
        "governs": row.governs,
        "affects": row.affects,
        "kind": row.kind,
        "values": row.values,
        "default": row.default,
        "example": row.example,
        "readers": list(row.readers),
        "block": next((b.key for b in BLOCKS if b.file == info.name and key in b.members), None),
    }
    has_default, default = settings_edit.lookup(_defaults(info.form), _segments(key))
    if has_default and _addressable(key):
        entry["default_value"] = default
    if not readable:
        entry["state"] = "unknown"
        return entry
    if not _addressable(key):
        present, value = settings_edit.lookup(doc, _prefix(key))
        entry["state"] = "set" if present and value is not None else "absent"
        return entry
    present, value = settings_edit.lookup(doc, _segments(key))
    if not present:
        entry["state"] = "absent"
        return entry
    entry["value"] = value
    entry["state"] = "default" if has_default and settings_edit.same(value, default) else "set"
    return entry


def _block_entry(
    info: SettingsFile, block: Block, doc: object, readable: bool
) -> dict[str, object]:
    # 0242: a block the skill asks member by member and writes once with the block form.
    entry: dict[str, object] = {
        "file": info.form,
        "key": block.key,
        "members": list(block.members),
        "required": list(block.required),
    }
    if not readable:
        entry["state"] = "unknown"
        return entry
    present, value = settings_edit.lookup(doc, (block.key,))
    entry["state"] = "set" if present and value is not None else "absent"
    if present and value is not None:
        entry["value"] = value
    return entry


def _load(form: str, root: Path) -> tuple[Path | None, bool, object, str | None]:
    # 0242: (path, exists, document, why it is unreadable); one bad file never stops the rest.
    try:
        path = _path(form, root)
    except (SetupStop, DataDirError) as exc:
        return None, False, None, str(exc)
    if not os.path.lexists(path):
        return path, False, {}, None
    try:
        if os.path.islink(path) or os.path.islink(path.parent):
            raise settings_edit.EditError("is a symlink")
        doc = settings_edit.parse(settings_edit.read_text(path, _LIMITS[form]))
        _check(form, doc, path)
    except (settings_edit.EditError, OSError) as exc:
        return path, True, None, f"{path} {exc}"
    except (ManifestError, ConfigError, OperatorError, LedgerError) as exc:
        return path, True, None, str(exc)
    return path, True, doc, None


def describe_data(repo: Path) -> dict[str, object]:
    root = project_root(repo)
    files: list[dict[str, object]] = []
    keys: list[dict[str, object]] = []
    blocks: list[dict[str, object]] = []
    for info in SETTINGS_FILES:
        path, exists, doc, error = _load(info.form, root)
        groups = sorted((g for g in GROUPS if g.file == info.name), key=lambda g: g.order)
        files.append(
            {
                "file": info.form,
                "name": info.name,
                "path": str(path) if path is not None else None,
                "where": info.where,
                "whose": info.whose,
                "shared": info.shared,
                "holds": info.holds,
                "exists": exists,
                "malformed": error,
                "groups": [
                    {
                        "id": g.id,
                        "title": g.title,
                        "order": g.order,
                        "keys": list(g.keys),
                        "day_one": list(g.day_one),
                    }
                    for g in groups
                ],
            }
        )
        for group in groups:
            for key in group.keys:
                day_one = key in group.day_one
                keys.append(_key_entry(info, key, group.id, day_one, doc, error is None))
        blocks.extend(
            _block_entry(info, b, doc, error is None) for b in BLOCKS if b.file == info.name
        )
    return {
        "files": files,
        "overlaps": [{"id": o.id, "text": o.text, "wins": o.wins} for o in OVERLAPS],
        "blocks": blocks,
        "keys": keys,
        "detected": detect(root),
        "moot": moot(root),
    }


def describe(repo: Path) -> int:
    print(json.dumps(describe_data(repo), indent=2, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Write the missing starter service-manifest.json and config.json, describe "
        "the three settings files, create the personal settings file, or set one key of one "
        "file. Never overwrites a whole file."
    )
    parser.add_argument(
        "--repo", default=".", help="target project folder (default: current directory)"
    )
    forms = parser.add_mutually_exclusive_group()
    forms.add_argument(
        "--describe", action="store_true", help="print the three files and every key as JSON"
    )
    forms.add_argument(
        "--create-operator",
        action="store_true",
        help="create ~/.claude/daedalus/operator.json when it is missing",
    )
    forms.add_argument(
        "--set",
        nargs=2,
        metavar=("FILE", "KEY"),
        help=f"change one key of an existing file; FILE is one of {', '.join(FORMS)}",
    )
    parser.add_argument("--value", help="the new value of the --set key, written as JSON")
    parser.add_argument(
        "--value-file", help="a file holding the new value of the --set key, written as JSON"
    )
    return parser


def _value_text(value: str | None, value_file: str | None) -> str:
    # 0242: a value file keeps the operator's text off the command line; exactly one form.
    if (value is None) == (value_file is None):
        raise SetupStop(
            f"set refused: --set needs exactly one of --value and --value-file. {SET_NEXT}"
        )
    if value is not None:
        return value
    path = Path(str(value_file))
    try:
        return settings_edit.read_text(path, settings_edit.MAX_BYTES)
    except atomic.LinkRefused as exc:
        detail = "is a symlink"
        raise SetupStop(f"set refused: the value file {path} {detail}. {FILE_NEXT}") from exc
    except settings_edit.EditError as exc:
        raise SetupStop(f"set refused: the value file {path} {exc}. {FILE_NEXT}") from exc


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    repo = Path(args.repo).resolve()
    try:
        if args.set is None and (args.value is not None or args.value_file is not None):
            raise SetupStop(
                f"setup stopped: --value and --value-file go only with --set. {SET_NEXT}"
            )
        if args.describe:
            return describe(repo)
        if args.create_operator:
            return create_operator()
        if args.set is not None:
            raw = _value_text(args.value, args.value_file)
            return set_key(args.set[0], args.set[1], raw, repo)
    except SetupStop as exc:
        print(exc)
        return 1
    return setup(repo)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

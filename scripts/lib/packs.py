# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0157, Plan 10 spec 2.3: the one loader and checker of framework control packs. A pack is a
# folder holding pack.json and controls.json; the doctor, the importers and the tests read
# packs only through load_pack, pack_problems and pack_folders.
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from lib.config import PACKS_DIR
from lib.manifest import load as load_manifest
from lib.project_root import project_root

PACK_FILE = "pack.json"
CONTROLS_FILE = "controls.json"
SCHEMA = "daedalus-controls/1"
FRAMEWORKS_DIR = PACKS_DIR / "frameworks"
NIST_IDS = PACKS_DIR.parent / "tests" / "fixtures" / "nist-control-ids.txt"
PACK_KEYS = ("id", "version", "source", "license", "pinned_on", "sha256")
CONTROLS_KEYS = ("schema", "controls")
CONTROL_KEYS = (
    "id",
    "service",
    "title",
    "statement",
    "look_for",
    "verify",
    "live_check",
    "refs",
    "maps_to",
)
REQUIRED = ("id", "service", "title", "refs")
# 2.3: an id-map control (maps_to set) needs none of these three.
REQUIRED_UNLESS_MAPPED = ("statement", "look_for", "verify")
REF_KEYS = ("nist", "cis", "asvs")
SERVICES = (
    "iam",
    "s3",
    "kms",
    "cloudtrail",
    "vpc",
    "lambda",
    "dynamodb",
    "apigateway",
    "ec2",
    "ecs",
    "ecr",
    "logs",
    "any",
)
SHIPPED_LICENSE = "GPL-3.0-or-later"
NIST_LICENSE = "public domain (17 U.S.C. 105)"
OPERATOR_LICENSED = "operator-licensed"
ID_MAP_LICENSE = f"{OPERATOR_LICENSED}, ids only"
# 2.3: a guard against pasted benchmark text in an operator-licensed pack.
LICENSED_STATEMENT_MAX = 400
TITLE_MAX, TEXT_MAX, LINE_MAX = 200, 4000, 1000
MAX_BYTES = 4 * 1024 * 1024
PACK_ID = re.compile(r"[a-z0-9-]{1,40}")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
SHA256 = re.compile(r"[0-9a-f]{64}")
CONTROL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._()-]{0,63}")
DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


class PackError(ValueError):
    def __init__(self, folder: Path, problems: list[str]) -> None:
        super().__init__(f"{folder}: {'; '.join(problems)}")
        self.problems = problems


@dataclass(frozen=True)
class Refs:
    nist: tuple[str, ...] = ()
    cis: tuple[str, ...] = ()
    asvs: tuple[str, ...] = ()


@dataclass(frozen=True)
class Control:
    id: str
    service: str
    title: str
    refs: Refs
    statement: str | None = None
    look_for: str | None = None
    verify: str | None = None
    live_check: str | None = None
    maps_to: str | None = None


@dataclass(frozen=True)
class Pack:
    folder: Path
    id: str
    version: str
    source: str
    license: str
    pinned_on: str
    sha256: str
    controls: tuple[Control, ...]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def controls_text(controls: list[dict[str, object]]) -> str:
    # 2.5: the importers' one serialisation, so the hash in pack.json is over these bytes.
    return json.dumps({"schema": SCHEMA, "controls": controls}, indent=2, ensure_ascii=False) + "\n"


def _no_repeats(pairs: list[tuple[str, object]]) -> dict[str, object]:
    # python.md:28: a repeated key would let a later value hide an earlier one.
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"repeats the key {key!r}")
        out[key] = value
    return out


def _read(path: Path) -> tuple[bytes | None, str | None]:
    # 0010: a link is never followed; a file over MAX_BYTES is refused unread.
    if path.is_symlink():
        return None, f"{path.name} is a symlink"
    if not path.is_file():
        return None, f"{path.name} is missing"
    try:
        if path.stat().st_size > MAX_BYTES:
            return None, f"{path.name} is larger than {MAX_BYTES} bytes"
        return path.read_bytes(), None
    except OSError as exc:
        return None, f"{path.name} could not be read ({exc.strerror or exc})"


def _parse(name: str, data: bytes) -> tuple[object, str | None]:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_no_repeats), None
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        return None, f"{name} is not valid UTF-8 JSON ({exc})"


def _keys(where: str, value: dict[str, object], allowed: Iterable[str]) -> list[str]:
    return [
        f"{where} has the key {key!r}, which is off the spec 2.3 tables"
        for key in sorted(set(value) - set(allowed))
    ]


def _line(value: object, limit: int) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= limit and value.isprintable()


def _nist_ids() -> frozenset[str] | None:
    try:
        return frozenset(NIST_IDS.read_text(encoding="utf-8").split())
    except OSError:
        return None


def _meta_problems(meta: object) -> list[str]:
    if not isinstance(meta, dict):
        return ["pack.json is not a JSON object"]
    out = _keys("pack.json", meta, PACK_KEYS)
    out += [f"pack.json lacks the key {key!r}" for key in PACK_KEYS if key not in meta]
    checks: tuple[tuple[str, Callable[[object], object], str], ...] = (
        ("id", lambda v: isinstance(v, str) and PACK_ID.fullmatch(v), "[a-z0-9-]{1,40}"),
        ("version", lambda v: isinstance(v, str) and VERSION.fullmatch(v), "x.y.z numbers"),
        ("source", lambda v: _line(v, LINE_MAX), "one printable line"),
        ("license", lambda v: _line(v, LINE_MAX), "one printable line"),
        ("pinned_on", _day, "a YYYY-MM-DD date"),
        ("sha256", lambda v: isinstance(v, str) and SHA256.fullmatch(v), "64 lowercase hex"),
    )
    for key, ok, shape in checks:
        if key in meta and not ok(meta[key]):
            out.append(f"pack.json {key} must be {shape}")
    return out


def _day(value: object) -> bool:
    if not isinstance(value, str) or not DAY.fullmatch(value):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _refs_problems(where: str, refs: object, nist: frozenset[str] | None) -> list[str]:
    if not isinstance(refs, dict):
        return [f"{where} refs must be an object with the lists {list(REF_KEYS)}"]
    out = _keys(f"{where} refs", refs, REF_KEYS)
    for key in REF_KEYS:
        ids = refs.get(key)
        if not isinstance(ids, list) or not all(
            isinstance(i, str) and CONTROL_ID.fullmatch(i) for i in ids
        ):
            out.append(f"{where} refs.{key} must be a list of ids")
    listed = refs.get("nist")
    if isinstance(listed, list):
        for ident in listed:
            if nist is None:
                out.append(f"{where} refs.nist cannot be checked: {NIST_IDS} is unreadable")
                break
            if ident not in nist:
                out.append(f"{where} refs.nist id {ident!r} is not in {NIST_IDS.name}")
    return out


def _control_problems(
    index: int, item: object, licensed: bool, nist: frozenset[str] | None
) -> list[str]:
    where = f"controls[{index}]"
    if not isinstance(item, dict):
        return [f"{where} is not a JSON object"]
    ident = item.get("id")
    if isinstance(ident, str) and CONTROL_ID.fullmatch(ident):
        where = f"control {ident}"
    out = _keys(where, item, CONTROL_KEYS)
    mapped = "maps_to" in item
    need = REQUIRED if mapped else REQUIRED + REQUIRED_UNLESS_MAPPED
    out += [f"{where} lacks the key {key!r}" for key in need if key not in item]
    if "id" in item and where.startswith("controls["):
        out.append(f"{where} id must match {CONTROL_ID.pattern}")
    if "service" in item and item["service"] not in SERVICES:
        out.append(f"{where} service must be one of {', '.join(SERVICES)}")
    if "title" in item and not _line(item["title"], TITLE_MAX):
        out.append(f"{where} title must be one printable line of 1 to {TITLE_MAX} characters")
    for key in ("statement", "look_for", "verify", "live_check"):
        limit = LINE_MAX if key in ("verify", "live_check") else TEXT_MAX
        if key in item and not _line(item[key], limit):
            out.append(f"{where} {key} must be one printable line of 1 to {limit} characters")
    if mapped and not (isinstance(item["maps_to"], str) and CONTROL_ID.fullmatch(item["maps_to"])):
        out.append(f"{where} maps_to must be a control id")
    statement = item.get("statement")
    if licensed and isinstance(statement, str) and len(statement) > LICENSED_STATEMENT_MAX:
        out.append(
            f"{where} statement is {len(statement)} characters, over {LICENSED_STATEMENT_MAX} in "
            "an operator-licensed pack"
        )
    if "refs" in item:
        out += _refs_problems(where, item["refs"], nist)
    return out


def content_problems(
    meta: object, controls_raw: bytes, known: Collection[str] | None = None
) -> list[str]:
    # 2.3: every problem kind on in-memory content; known None checks maps_to against
    # this pack's own ids only, so callers pass the ids of the other packs they read.
    out = _meta_problems(meta)
    declared = meta.get("sha256") if isinstance(meta, dict) else None
    actual = digest(controls_raw)
    if isinstance(declared, str) and SHA256.fullmatch(declared) and declared != actual:
        out.append(f"controls.json sha256 is {actual}, not the {declared} pack.json declares")
    doc, bad = _parse(CONTROLS_FILE, controls_raw)
    if bad is not None:
        return [*out, bad]
    if not isinstance(doc, dict):
        return [*out, "controls.json is not a JSON object"]
    out += _keys("controls.json", doc, CONTROLS_KEYS)
    if doc.get("schema") != SCHEMA:
        out.append(f"controls.json schema must be {SCHEMA!r}")
    controls = doc.get("controls")
    if not isinstance(controls, list):
        return [*out, "controls.json controls must be a list"]
    license_ = meta.get("license") if isinstance(meta, dict) else None
    licensed = isinstance(license_, str) and license_.startswith(OPERATOR_LICENSED)
    nist = _nist_ids()
    seen: set[str] = set()
    for index, item in enumerate(controls):
        out += _control_problems(index, item, licensed, nist)
        ident = item.get("id") if isinstance(item, dict) else None
        if isinstance(ident, str):
            if ident in seen:
                out.append(f"control {ident} is a duplicate id")
            seen.add(ident)
    names = seen | set(known or ())
    for item in controls:
        target = item.get("maps_to") if isinstance(item, dict) else None
        if isinstance(target, str) and target not in names:
            out.append(f"control {item.get('id')} maps_to {target!r}, which no loaded pack holds")
    return out


def _pack_parts(folder: Path) -> tuple[object, bytes | None, list[str]]:
    if folder.is_symlink() or not folder.is_dir():
        return None, None, [f"{folder} is not a folder"]
    meta_raw, meta_bad = _read(folder / PACK_FILE)
    controls_raw, controls_bad = _read(folder / CONTROLS_FILE)
    missing = [bad for bad in (meta_bad, controls_bad) if bad is not None]
    if meta_raw is None or controls_raw is None:
        return None, None, missing
    meta, bad = _parse(PACK_FILE, meta_raw)
    return (None, None, [bad]) if bad is not None else (meta, controls_raw, [])


def control_ids(folders: Iterable[Path]) -> set[str]:
    # 2.3: the ids a maps_to may name; an unreadable pack adds none and fails on its own.
    out: set[str] = set()
    for folder in folders:
        _, raw, problems = _pack_parts(folder)
        doc = _parse(CONTROLS_FILE, raw)[0] if raw is not None and not problems else None
        controls = doc.get("controls") if isinstance(doc, dict) else None
        for item in controls if isinstance(controls, list) else []:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                out.add(item["id"])
    return out


def _pack_subfolders(parent: Path) -> list[Path]:
    # 0010: a linked subfolder is not a pack; it could point outside the project.
    if parent.is_symlink() or not parent.is_dir():
        return []
    return sorted(
        child
        for child in parent.iterdir()
        if child.is_dir() and not child.is_symlink() and (child / PACK_FILE).is_file()
    )


def neighbour_ids(folder: Path) -> set[str]:
    # 2.3: the default maps_to scope; the packs beside folder plus the shipped packs.
    folders = {*_pack_subfolders(folder.parent), *_pack_subfolders(FRAMEWORKS_DIR)}
    return control_ids(sorted(folders - {folder}))


def pack_problems(folder: Path, known: Collection[str] | None = None) -> list[str]:
    # Pin F1 -> F3: an empty list means the pack loads; known None reads neighbour_ids(folder).
    meta, controls_raw, problems = _pack_parts(folder)
    if problems or controls_raw is None:
        return problems
    return content_problems(meta, controls_raw, neighbour_ids(folder) if known is None else known)


def _refs(raw: dict[str, list[str]]) -> Refs:
    return Refs(*(tuple(raw[key]) for key in REF_KEYS))


def load_pack(folder: Path, known: Collection[str] | None = None) -> Pack:
    # Pin F1 -> F3: a pack with any problem raises PackError naming every one.
    problems = pack_problems(folder, known)
    if problems:
        raise PackError(folder, problems)
    meta = json.loads((folder / PACK_FILE).read_text(encoding="utf-8"))
    doc = json.loads((folder / CONTROLS_FILE).read_text(encoding="utf-8"))
    controls = tuple(
        Control(
            item["id"],
            item["service"],
            item["title"],
            _refs(item["refs"]),
            item.get("statement"),
            item.get("look_for"),
            item.get("verify"),
            item.get("live_check"),
            item.get("maps_to"),
        )
        for item in doc["controls"]
    )
    return Pack(
        folder,
        meta["id"],
        meta["version"],
        meta["source"],
        meta["license"],
        meta["pinned_on"],
        meta["sha256"],
        controls,
    )


def pack_folders(repo: Path) -> list[Path]:
    # Pin F1 -> F3, 0157 (12.1): the declared packs, then the shipped ones unless turned off.
    manifest = load_manifest(repo)
    frameworks = manifest.frameworks if manifest is not None else None
    out: list[Path] = []
    if frameworks is not None and frameworks.pack_dir is not None:
        out += _pack_subfolders(project_root(repo) / frameworks.pack_dir)
    if frameworks is None or frameworks.default_packs:
        out += _pack_subfolders(FRAMEWORKS_DIR)
    return out

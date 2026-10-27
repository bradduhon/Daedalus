#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0157, Plan 10 spec 2.5: operator-run; writes a control pack from a NIST OSCAL catalog file
# (oscal) or from a CSV of CIS ids mapped to pack controls (cis-map). It reads only the files
# named on the command line, never fetches, and writes no pack lib/packs.py would refuse.
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import shlex
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import atomic, packs  # noqa: E402
from lib.audit import DataDirError  # noqa: E402
from lib.config import ConfigError, load_config, resolve_excluded_roots  # noqa: E402
from lib.project_root import project_root  # noqa: E402
from lib.shell import _under  # noqa: E402

DESCRIPTION = (
    "Write a framework control pack (Plan 10 spec 2.5). oscal: the named controls of an OSCAL "
    "catalog file, such as the one refresh_frameworks.py --only nist-800-53 wrote. cis-map: a CSV "
    "with exactly the columns cis_id,control_id, written as an id-map pack that carries no "
    "benchmark text. --out is the pack folder; its name is the pack id, and it must sit inside "
    "the project and under no excluded root. Exit 1: a refused input or --out."
)
CATALOG_MAX = 64 * 1024 * 1024
BENCHMARK_MAX = 80
CIS_COLUMNS = ["cis_id", "control_id"]
# 2.5: an OSCAL catalog carries no diff hint or command, so these two are the importer's own.
OSCAL_LOOK_FOR = "Code or configuration the statement governs; judge the diff against it."
# 113, prepush-2026-10-27: one rg search the specialist's jail admits, for code citing the id.
OSCAL_VERIFY = "rg -n -F {id} ."
_PARAM = re.compile(r"\{\{\s*insert:\s*param,\s*([A-Za-z0-9_.-]+)\s*\}\}")
R_OUTSIDE = (
    "--out {out} is outside the project {repo}. Next: name a pack folder inside the project, "
    "such as the folder frameworks.pack_dir names."
)
R_EXCLUDED = (
    "--out {out} is under the excluded root {root}, whose files never reach git. Next: name a "
    "pack folder outside every excluded root."
)


class PackImportError(Exception):
    pass


def _read(path: str, what: str, limit: int | None = None) -> bytes:
    # 2.5: the pack reader's own guards: no link followed, no file over the cap read.
    data, bad = packs.read_capped(Path(path), limit)
    if data is None:
        raise PackImportError(
            f"{what} {bad}. Next: name the real input file, readable to you and not a link."
        )
    return data


def out_folder(out: str, repo: Path) -> Path:
    # 2.5: inside the project, under no excluded root, and named as a pack id.
    path = Path(os.path.abspath(out))
    if not _under(str(path), str(repo)) or os.path.realpath(path) == os.path.realpath(repo):
        raise PackImportError(R_OUTSIDE.format(out=out, repo=repo))
    try:
        roots = resolve_excluded_roots(load_config(str(repo)), repo)
    except (ConfigError, DataDirError) as exc:
        raise PackImportError(f"excluded_roots could not be resolved: {exc}") from exc
    for root in roots:
        if _under(str(path), root.path):
            raise PackImportError(R_EXCLUDED.format(out=out, root=root.path))
    if not packs.PACK_ID.fullmatch(path.name):
        raise PackImportError(
            f"--out folder name {path.name!r} is the pack id and must match "
            f"{packs.PACK_ID.pattern}. Next: name the pack folder in lowercase letters, digits "
            "and dashes."
        )
    return path


def _version(value: str | None, flag: str) -> str:
    if value is None or not packs.VERSION.fullmatch(value):
        raise PackImportError(
            f"{flag} {value!r} is not three dot-separated numbers. Next: pass a version such "
            f"as {flag} 1.0.0."
        )
    return value


def write_pack(out: Path, meta: dict[str, object], controls: list[dict[str, object]]) -> None:
    # 2.5: checked in memory first; controls.json lands before pack.json marks the folder a pack.
    text = packs.controls_text(controls)
    meta = {**meta, "sha256": packs.digest(text.encode("utf-8"))}
    raw, known = text.encode("utf-8"), packs.neighbour_ids(out)
    problems = packs.content_problems(meta, raw, known, project_root(out))
    if problems:
        raise PackImportError(
            f"the pack would not load: {'; '.join(problems)}. Next: fix the input file, then "
            "run the importer again."
        )
    out.mkdir(parents=True, exist_ok=True)
    atomic.refuse_links(out)
    atomic.write_atomic(out / packs.CONTROLS_FILE, text, 0o644)
    atomic.write_atomic(out / packs.PACK_FILE, json.dumps(meta, indent=2) + "\n", 0o644)


def _meta(pack_id: str, version: str, source: str, license_: str) -> dict[str, object]:
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    return {
        "id": pack_id,
        "version": version,
        "source": source,
        "license": license_,
        "pinned_on": today,
    }


def _label(control: dict[str, object]) -> str | None:
    props = control.get("props")
    for prop in props if isinstance(props, list) else []:
        if isinstance(prop, dict) and prop.get("name") == "label":
            value = prop.get("value")
            return value if isinstance(value, str) else None
    return None


def _catalog_index(doc: object) -> dict[str, dict[str, object]]:
    # 2.5: each control and enhancement by upper-cased id and by label; no recursion.
    catalog = doc.get("catalog") if isinstance(doc, dict) else None
    if not isinstance(catalog, dict):
        raise PackImportError(
            "the catalog has no catalog object. Next: name an OSCAL catalog JSON file."
        )
    index: dict[str, dict[str, object]] = {}
    stack: list[object] = [catalog]
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        for key in ("groups", "controls"):
            children = node.get(key)
            stack.extend(children if isinstance(children, list) else [])
        ident = node.get("id")
        if node is not catalog and isinstance(ident, str) and "title" in node:
            label = _label(node)
            for name in (ident.upper(), label.upper() if label else None):
                if name is not None:
                    index.setdefault(name, node)
    return index


def _prose(part: object) -> str:
    # 2.5: the statement part's prose in reading order, item labels kept, params as [id].
    pieces: list[str] = []
    stack: list[object] = [part]
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        label, prose = _label(node), node.get("prose")
        text = " ".join(p for p in (label, prose if isinstance(prose, str) else None) if p)
        if text:
            pieces.append(text)
        children = node.get("parts")
        stack.extend(reversed(children) if isinstance(children, list) else [])
    return " ".join(_PARAM.sub(r"[\1]", " ".join(pieces)).split())


def _statement(control: dict[str, object]) -> str:
    parts = control.get("parts")
    for part in parts if isinstance(parts, list) else []:
        if isinstance(part, dict) and part.get("name") == "statement":
            return _prose(part)
    return ""


def oscal(args: argparse.Namespace, out: Path) -> int:
    raw = _read(args.catalog, "--catalog", CATALOG_MAX)
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise PackImportError(
            f"--catalog is not UTF-8 JSON ({exc}). Next: name an OSCAL catalog JSON file."
        ) from exc
    index = _catalog_index(doc)
    metadata = doc["catalog"].get("metadata") if isinstance(doc, dict) else None
    found = metadata.get("version") if isinstance(metadata, dict) else None
    version = _version(args.version or (found if isinstance(found, str) else None), "--version")
    wanted = list(dict.fromkeys(i.strip().upper() for i in args.ids.split(",") if i.strip()))
    if not wanted:
        raise PackImportError(
            "the --ids list names no control. Next: pass the control ids, such as --ids AC-2,AC-3."
        )
    controls: list[dict[str, object]] = []
    for ident in wanted:
        control = index.get(ident)
        if control is None:
            raise PackImportError(
                f"--ids {ident} is not in the catalog. Next: check the id against the catalog."
            )
        label = _label(control) or str(control["id"]).upper()
        title = " ".join(str(control["title"]).split())
        statement = _statement(control)
        if not statement:
            raise PackImportError(
                f"{label} has no statement prose. Next: pick a control whose catalog entry has a "
                "statement."
            )
        controls.append(
            {
                "id": label,
                "service": "any",
                "title": title,
                "statement": statement,
                "look_for": OSCAL_LOOK_FOR,
                "verify": OSCAL_VERIFY.format(id=shlex.quote(label)),
                "refs": {"nist": [label], "cis": [], "asvs": []},
            }
        )
    source = str(Path(os.path.abspath(args.catalog)))
    write_pack(out, _meta(out.name, version, source, packs.NIST_LICENSE), controls)
    return len(controls)


def cis_map(args: argparse.Namespace, out: Path) -> int:
    raw = _read(args.map, "--map")
    benchmark = args.benchmark
    if not (1 <= len(benchmark) <= BENCHMARK_MAX and benchmark.isprintable()):
        raise PackImportError(
            f"--benchmark must be one printable line of 1 to {BENCHMARK_MAX} characters. "
            "Next: pass the benchmark name the map was made from."
        )
    version = _version(args.version, "--version")
    try:
        rows = list(csv.reader(io.StringIO(raw.decode("utf-8-sig"), newline="")))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise PackImportError(
            f"--map is not a UTF-8 CSV ({exc}). Next: save the map as a UTF-8 CSV file."
        ) from exc
    if not rows or rows[0] != CIS_COLUMNS:
        raise PackImportError(
            f"--map header must be exactly {','.join(CIS_COLUMNS)}, so no benchmark text enters "
            "a pack. Next: drop every other column from the CSV file."
        )
    controls: list[dict[str, object]] = []
    for number, row in enumerate(rows[1:], start=2):
        if len(row) != len(CIS_COLUMNS):
            raise PackImportError(
                f"--map line {number} has {len(row)} cells, not 2. Next: keep only "
                f"{','.join(CIS_COLUMNS)} on every line."
            )
        cis_id, control_id = (cell.strip() for cell in row)
        controls.append(
            {
                "id": cis_id,
                "service": "any",
                "title": f"{benchmark} {cis_id}",
                "refs": {"nist": [], "cis": [cis_id], "asvs": []},
                "maps_to": control_id,
            }
        )
    if not controls:
        raise PackImportError(
            "the --map file holds no rows. Next: add one line per CIS id under the header."
        )
    source = str(Path(os.path.abspath(args.map)))
    write_pack(out, _meta(out.name, version, source, packs.ID_MAP_LICENSE), controls)
    return len(controls)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=DESCRIPTION, allow_abbrev=False)
    modes = parser.add_subparsers(dest="mode", required=True)
    one = modes.add_parser("oscal", allow_abbrev=False, help="pack from an OSCAL catalog file")
    one.add_argument("--catalog", required=True, help="the OSCAL catalog JSON file")
    one.add_argument("--ids", required=True, help="comma-separated control ids, such as AC-2")
    one.add_argument("--version", help="pack version x.y.z (default: the catalog's version)")
    one.add_argument("--out", required=True, help="the pack folder to write")
    two = modes.add_parser("cis-map", allow_abbrev=False, help="id-map pack from a CIS id CSV")
    two.add_argument("--map", required=True, help="CSV with exactly cis_id,control_id")
    two.add_argument("--benchmark", required=True, help="benchmark name for control titles")
    two.add_argument("--version", required=True, help="pack version x.y.z")
    two.add_argument("--out", required=True, help="the pack folder to write")
    return parser


def main(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    try:
        out = out_folder(args.out, project_root(Path.cwd()))
        count = oscal(args, out) if args.mode == "oscal" else cis_map(args, out)
    except (PackImportError, OSError) as exc:
        print(f"import_pack: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {out} ({count} controls)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

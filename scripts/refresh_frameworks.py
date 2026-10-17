#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
"""Operator-run: compile the pinned framework caches into the plugin's machine cache (0026).

Each adapter pins an upstream ref, writes its files under <cache>/frameworks/<family>/ and
replaces its own entries in that family's manifest.json. The specialists only read the cache.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import fetch  # noqa: E402
from lib.audit import cache_dir_or_probe  # noqa: E402
from lib.fetch import RefreshError, _safe  # noqa: E402

MANIFEST = "manifest.json"
NIST_REF = "v1.5.0"
NIST_RAW = f"https://raw.githubusercontent.com/usnistgov/oscal-content/{NIST_REF}/nist.gov/"
NIST_LICENSE = "public domain (17 U.S.C. 105)"
NOT_CATALOG_NEXT = "Next: check the source URL points at the OSCAL catalog JSON."
URL_NEXT = "Next: report this line; the adapter URLs are pinned in refresh_frameworks.py."


@dataclass(frozen=True)
class Adapter:
    name: str
    family: str
    ref: str
    files: tuple[tuple[str, str], ...]
    license: str
    version: Callable[[bytes], str]
    compile: Callable[[list[bytes]], bytes | None]


def _revision(raw: bytes) -> str:
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise RefreshError(f"catalog is not valid JSON. {NOT_CATALOG_NEXT}") from exc
    if not isinstance(data, dict):
        raise RefreshError(f"catalog is not a JSON object. {NOT_CATALOG_NEXT}")
    # M3: the top-level form applies only when there is no catalog key at all.
    if "catalog" in data:
        holder, key = data["catalog"], "catalog.metadata.version"
    else:
        holder, key = data, "metadata.version"
    meta = holder.get("metadata") if isinstance(holder, dict) else None
    if not isinstance(meta, dict) or "version" not in meta:
        raise RefreshError(f"catalog has no {key} key. {NOT_CATALOG_NEXT}")
    return _printable(meta["version"], key, NOT_CATALOG_NEXT)


def _printable(value: Any, key: str, nxt: str) -> str:
    # 8.8: untrusted text reaches the terminal and the manifest; refuse control characters.
    if isinstance(value, str) and value and len(value) <= 64 and value.isprintable():
        return value
    raise RefreshError(f"{key} is not a printable string of 64 characters or fewer. {nxt}")


def _as_is(raws: list[bytes]) -> bytes | None:
    return None


ADAPTERS: dict[str, Adapter] = {
    "nist-800-53": Adapter(
        name="nist-800-53",
        family="nist",
        ref=NIST_REF,
        files=((NIST_RAW + "SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json", "catalog.json"),),
        license=NIST_LICENSE,
        version=_revision,
        compile=_as_is,
    ),
    "nist-csf-2.0": Adapter(
        name="nist-csf-2.0",
        family="nist",
        ref=NIST_REF,
        files=((NIST_RAW + "CSF/v2.0/json/NIST_CSF_v2.0_catalog.json", "csf-2.0.json"),),
        license=NIST_LICENSE,
        version=_revision,
        compile=_as_is,
    ),
}


def _old_entries(path: Path, replaced: set[str]) -> list[dict[str, Any]]:
    # 0026: a legacy single-catalog dict manifest is dropped; list entries of other adapters stay.
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise RefreshError(
            f"{path} is not readable JSON. Next: delete it and run the script again for every "
            "adapter."
        ) from exc
    if not isinstance(data, list):
        return []
    return [e for e in data if isinstance(e, dict) and e.get("file") not in replaced]


def _write_bytes(dest: Path, prefix: str, body: bytes) -> str:
    out = fetch._temp(dest, prefix)
    with out:
        out.write(body)
    return out.name


def run_adapter(adapter: Adapter, root: Path) -> list[tuple[str, str, Path]]:
    for url, _ in adapter.files:
        if not fetch._allowed(url):
            raise RefreshError(
                "source URL must be ASCII https on github.com, raw.githubusercontent.com or "
                "api.github.com, with no user, query, fragment, dot segment, backslash or "
                f"encoded slash. {URL_NEXT}"
            )
    dest = root / "frameworks" / adapter.family
    names = tuple(local for _, local in adapter.files)
    fetch._prepare_dest(root, dest, (*names, MANIFEST))
    pinned_on = datetime.now(UTC).date().isoformat()
    temps: list[str] = []
    with fetch._locked(dest):
        try:
            raws: list[bytes] = []
            outputs: list[tuple[str, str, str, str]] = []
            for url, local in adapter.files:
                tmp = fetch._temp(dest, f".{local}-")
                temps.append(tmp.name)
                with tmp:
                    sha256 = fetch._download(url, tmp)
                raws.append(Path(tmp.name).read_bytes())
                outputs.append((local, tmp.name, sha256, url))
            version = adapter.version(raws[0])
            entries = _old_entries(dest / MANIFEST, {o[0] for o in outputs})
            for local, _, sha256, url in outputs:
                entries.append(
                    {
                        "file": local,
                        "license": adapter.license,
                        "pinned_on": pinned_on,
                        "sha256": sha256,
                        "source_url": url,
                        "upstream_ref": adapter.ref,
                        "version": version,
                    }
                )
            entries.sort(key=lambda e: str(e.get("file")))
            body = json.dumps(entries, indent=2, sort_keys=True) + "\n"
            temps.append(_write_bytes(dest, ".manifest-", body.encode("utf-8")))
            # 8.8: every download and check finishes before the first replace.
            for local, name, _, _ in outputs:
                os.replace(name, dest / local)
            os.replace(temps[-1], dest / MANIFEST)
        finally:
            for name in temps:
                Path(name).unlink(missing_ok=True)
    return [(version, sha256, dest / local) for local, _, sha256, _ in outputs]


def _message(exc: Exception) -> str:
    if isinstance(exc, (RefreshError, RuntimeError)):
        return _safe(exc)
    if isinstance(exc, OSError):
        return (
            f"cannot write the cache: {_safe(exc)}. "
            "Next: check the --cache-root directory permissions."
        )
    # I1: no failure path ends in a traceback.
    return (
        f"refresh failed: {_safe(type(exc).__name__)}: {_safe(exc)}. "
        "Next: run the script again; if it repeats, report this line."
    )


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(1, f"refresh_frameworks: {message}. Next: run with --help for the options.\n")


def _selected(only: str | None) -> list[Adapter]:
    if only is None:
        return list(ADAPTERS.values())
    names = [n.strip() for n in only.split(",") if n.strip()]
    for name in names:
        if name not in ADAPTERS:
            raise RefreshError(
                f"unknown adapter {_safe(name)}. Next: pick from {', '.join(ADAPTERS)}."
            )
    return [ADAPTERS[n] for n in dict.fromkeys(names)]


def main(argv: list[str]) -> int:
    parser = _Parser(
        description="Compile the pinned framework caches into the plugin cache (network).",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--only", help=f"comma-separated adapters (default: all of {list(ADAPTERS)})"
    )
    parser.add_argument("--cache-root", help="cache root (default: the plugin cache directory)")
    args = parser.parse_args(argv)
    try:
        adapters = _selected(args.only)
        root = Path(os.path.abspath(args.cache_root)) if args.cache_root else cache_dir_or_probe()
    except (RefreshError, RuntimeError) as exc:
        print(_safe(exc), file=sys.stderr)
        return 1
    failed = False
    for adapter in adapters:
        try:
            for version, sha256, path in run_adapter(adapter, root):
                print(f"pinned {adapter.name} {version} sha256={sha256} at {path}")
        except Exception as exc:
            # 0026: one failed adapter keeps its old files; the others still run.
            print(f"{adapter.name}: {_message(exc)}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

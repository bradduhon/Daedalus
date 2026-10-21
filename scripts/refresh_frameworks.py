#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0026: operator-run; compiles the pinned framework caches into the plugin's machine cache.
# Each adapter pins an upstream ref, writes its files under <cache>/frameworks/<family>/ and
# replaces its own entries in that family's manifest.json. The specialists only read the cache.
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
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
OWASP_LICENSE = "CC BY-SA 4.0"
ASVS_REF = "v5.0.0_release"
ASVS_URL = (
    f"https://raw.githubusercontent.com/OWASP/ASVS/{ASVS_REF}/5.0/docs_en/"
    "OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
)
ASVS_KEYS = ("Name", "ShortName", "Version", "Description", "Requirements")
ASVS_NEXT = "Next: check the source URL points at the ASVS JSON export."
TOP10_REF = "3a31f35346c3f4e90f350395124382fa53af2afe"
TOP10_RAW = f"https://raw.githubusercontent.com/OWASP/Top10/{TOP10_REF}/2025/docs/en/"
TOP10_FILES = (
    "A01_2025-Broken_Access_Control.md",
    "A02_2025-Security_Misconfiguration.md",
    "A03_2025-Software_Supply_Chain_Failures.md",
    "A04_2025-Cryptographic_Failures.md",
    "A05_2025-Injection.md",
    "A06_2025-Insecure_Design.md",
    "A07_2025-Authentication_Failures.md",
    "A08_2025-Software_or_Data_Integrity_Failures.md",
    "A09_2025-Security_Logging_and_Alerting_Failures.md",
    "A10_2025-Mishandling_of_Exceptional_Conditions.md",
)
TOP10_NEXT = "Next: check the pinned Top 10 commit still holds the 2025 English pages."
_H1 = re.compile(r"^# (.+)$", re.M)
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_MD_ATTRS = re.compile(r"\{:[^}]*\}")
_TITLE_LEAD = re.compile(r"^A[0-9]{2}:2025[\s:\-\u2013\u2014]*")


@dataclass(frozen=True)
class Adapter:
    name: str
    family: str
    ref: str
    files: tuple[tuple[str, str], ...]
    license: str
    version: Callable[[bytes], str]
    compile: Callable[[list[bytes]], bytes | None]
    output: str | None = None
    attribution: str | None = None


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


def _asvs_version(raw: bytes) -> str:
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise RefreshError(f"ASVS file is not valid JSON. {ASVS_NEXT}") from exc
    if not isinstance(data, dict):
        raise RefreshError(f"ASVS file is not a JSON object. {ASVS_NEXT}")
    missing = [k for k in ASVS_KEYS if k not in data]
    if "Requirements" in missing or not (
        isinstance(data.get("Requirements"), list) and data["Requirements"]
    ):
        raise RefreshError(f"ASVS file has no Requirements list. {ASVS_NEXT}")
    if missing:
        raise RefreshError(f"ASVS file lacks {', '.join(missing)}. {ASVS_NEXT}")
    return _printable(data["Version"], "Version", ASVS_NEXT)


def _top10_version(raw: bytes) -> str:
    return f"2025@{TOP10_REF[:7]}"


def _top10_title(raw: bytes, name: str) -> str:
    # 0026: id from the file name; title from the first H1, markup and id prefix stripped.
    text = raw.decode("utf-8", errors="replace")
    match = _H1.search(text)
    bare = " ".join(_MD_ATTRS.sub("", _MD_IMAGE.sub("", match[1])).split()) if match else ""
    title = _TITLE_LEAD.sub("", bare).strip()
    if not title:
        raise RefreshError(f"{name} has no level-one heading with a title. {TOP10_NEXT}")
    return _printable(title, f"{name} heading", TOP10_NEXT)


def _top10_compile(raws: list[bytes]) -> bytes | None:
    entries = [
        {"id": f"{name[:3]}:2025", "title": _top10_title(raw, name), "source_file": name}
        for name, raw in zip(TOP10_FILES, raws, strict=True)
    ]
    return (json.dumps(entries, indent=2) + "\n").encode("utf-8")


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
    "owasp-asvs": Adapter(
        name="owasp-asvs",
        family="owasp",
        ref=ASVS_REF,
        files=((ASVS_URL, "asvs-5.0.0.json"),),
        license=OWASP_LICENSE,
        version=_asvs_version,
        compile=_as_is,
        attribution="OWASP Foundation, OWASP Application Security Verification Standard",
    ),
    "owasp-top10": Adapter(
        name="owasp-top10",
        family="owasp",
        ref=TOP10_REF,
        files=tuple((TOP10_RAW + name, name) for name in TOP10_FILES),
        license=OWASP_LICENSE,
        version=_top10_version,
        compile=_top10_compile,
        output="top10-2025.json",
        attribution="OWASP Foundation, OWASP Top 10",
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
    names = (adapter.output,) if adapter.output else tuple(local for _, local in adapter.files)
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
            compiled = adapter.compile(raws)
            if compiled is not None and adapter.output:
                # 0026: a compiled adapter keeps only its output; the downloads are discarded.
                urls = [url for url, _ in adapter.files]
                source = os.path.commonprefix(urls).rpartition("/")[0] + "/"
                name = _write_bytes(dest, f".{adapter.output}-", compiled)
                temps.append(name)
                digest = hashlib.sha256(compiled).hexdigest()
                outputs = [(adapter.output, name, digest, source)]
            entries = _old_entries(dest / MANIFEST, {o[0] for o in outputs})
            for local, _, sha256, url in outputs:
                entry = {
                    "file": local,
                    "license": adapter.license,
                    "pinned_on": pinned_on,
                    "sha256": sha256,
                    "source_url": url,
                    "upstream_ref": adapter.ref,
                    "version": version,
                }
                if adapter.attribution:
                    # 0026: CC BY-SA 4.0 attribution rides in the manifest entry.
                    entry["attribution"] = f"{adapter.attribution}, {url}"
                entries.append(entry)
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
                f"unknown adapter {_safe(name)}. "
                f"Next: pick an adapter name from {', '.join(ADAPTERS)}."
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

# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0069: the declared scrub file's terms, one per line; blank and # lines are skipped.
from __future__ import annotations

from pathlib import Path

from lib import manifest


class ScrubError(RuntimeError):
    pass


def declared_terms(repo: Path) -> list[str] | None:
    # 0069: None when no scrub_file is declared; a declared but unreadable file fails closed.
    try:
        rel = manifest.features(repo).scrub_file
    except manifest.ManifestError as exc:
        raise ScrubError(str(exc)) from exc
    if rel is None:
        return None
    path = manifest.manifest_path(repo).parent / rel
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ScrubError(
            f"the declared scrub file {rel} could not be read ({type(exc).__name__}). "
            "Next: restore the scrub file or clear features.scrub_file in the service manifest."
        ) from exc
    return [t for t in (line.strip() for line in lines) if t and not t.startswith("#")]


def count_hits(text: str, terms: list[str]) -> int:
    # 0069: case-insensitive literal match; callers report the count, never a term.
    folded = text.casefold()
    return sum(1 for term in dict.fromkeys(terms) if term.casefold() in folded)

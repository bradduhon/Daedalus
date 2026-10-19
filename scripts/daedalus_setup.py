#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
"""Writes whichever starter project file is missing, behind /daedalus:setup (0076)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.audit import DataDirError, check_project_data_dir, ensure_project_data_dir  # noqa: E402
from lib.manifest import MANIFEST_NAME  # noqa: E402
from lib.project_keys import starter_config, starter_manifest  # noqa: E402
from lib.project_root import in_git_work_tree, project_root  # noqa: E402

CONFIG_NAME = "config.json"
# 0077: how far below the setup folder, and through how many folders, the repository scan looks.
SCAN_DEPTH = 3
SCAN_LIMIT = 2000


def _write_new(path: Path, doc: dict[str, object], mode: int) -> bool:
    # 0076: O_EXCL creates or fails, so an existing file or a symlink there is never written.
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(doc, indent=2) + "\n")
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
            if child.name.startswith(".") or child.is_symlink() or not child.is_dir():
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
        _report(manifest, _write_new(manifest, starter_manifest(), 0o644))
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


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Write the missing starter service-manifest.json and config.json. "
        "Never overwrites a file."
    )
    parser.add_argument(
        "--repo", default=".", help="target project folder (default: current directory)"
    )
    args = parser.parse_args(argv)
    return setup(Path(args.repo).resolve())


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

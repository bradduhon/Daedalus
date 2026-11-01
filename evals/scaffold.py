#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0186: stages one golden case's fixture into the eval workspace (the current directory).
# Copies fixtures/_base, then fixtures/<case> over it; fixture.json says whether a git repo
# with one commit on main is made and which origin URL it gets. Runs no model.
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"
BASE = "_base"
SPEC = "fixture.json"
DATA_DIR = Path(".claude/daedalus")
# 0186: stored under neutral names so no fixture folder reads as a project root in this repo.
RENAMES = {
    "manifest.json": Path("service-manifest.json"),
    "daedalus-config.json": DATA_DIR / "config.json",
    "gitignore": Path(".gitignore"),
}
# 0186: a fixed identity, so the commit never depends on the workspace HOME.
GIT_ID = ("-c", "user.name=Plugin Eval", "-c", "user.email=eval@example.invalid")


def load_spec(case: str) -> dict[str, object]:
    spec = json.loads((FIXTURES / case / SPEC).read_text(encoding="utf-8"))
    if not isinstance(spec, dict):
        raise SystemExit(f"{case}/{SPEC} is not a JSON object")
    return spec


def copy_tree(source: Path, target: Path) -> None:
    for path in sorted(source.rglob("*")):
        rel = path.relative_to(source)
        if rel.as_posix() == SPEC or "__pycache__" in rel.parts:
            continue
        dest = target / RENAMES.get(rel.as_posix(), rel)
        if path.is_dir():
            dest.mkdir(parents=True, exist_ok=True)
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)


def git(target: Path, *args: str) -> None:
    subprocess.run(["git", *GIT_ID, *args], cwd=target, check=True, capture_output=True)


def stage(case: str, target: Path) -> dict[str, object]:
    spec = load_spec(case)
    copy_tree(FIXTURES / BASE, target)
    copy_tree(FIXTURES / case, target)
    # 0035: the data dir carries its own ignore-all marker, so git never tracks run state.
    (target / DATA_DIR / ".gitignore").write_text("*\n", encoding="utf-8")
    if spec.get("git") is True:
        git(target, "init", "-q", "-b", "main")
        git(target, "add", "-A")
        git(target, "commit", "-q", "-m", f"Add the {case} fixture")
        origin = spec.get("origin")
        if isinstance(origin, str):
            git(target, "remote", "add", "origin", origin)
    return spec


def main(argv: list[str]) -> int:
    if len(argv) != 1 or not (FIXTURES / argv[0] / SPEC).is_file():
        print("usage: scaffold.py <case name with a fixtures/<case>/fixture.json>", file=sys.stderr)
        return 2
    stage(argv[0], Path.cwd())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0033: validate_train.py <path>; exit 0 prints the OK line, exit 1 prints each defect then Next.
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.train_definition import (  # noqa: E402
    DEFINITION_NEXT,
    DefinitionError,
    Origin,
    load,
    validate,
)

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
USAGE = "usage: validate_train.py <path to a train definition .json file>"
USAGE_NEXT = "Next: pass the path of one train definition file to check."


def _origin(path: Path) -> Origin:
    # spec 3.1: a definition inside the plugin is a plugin definition; any other is a project's.
    return "plugin" if path.resolve().is_relative_to(PLUGIN_ROOT) else "project"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(f"{USAGE}\n{USAGE_NEXT}", file=sys.stderr)
        return 1
    path = Path(argv[0])
    try:
        defn = load(path)
    except DefinitionError as exc:
        print(f"check 1: {exc}\n{DEFINITION_NEXT}")
        return 1
    defects = validate(defn, PLUGIN_ROOT, _origin(path))
    if defects:
        print("\n".join([*defects, DEFINITION_NEXT]))
        return 1
    print(f"OK train {defn.name} v{defn.version}: {len(defn.stages)} stages")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

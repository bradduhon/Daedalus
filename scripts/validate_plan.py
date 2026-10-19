#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0086, spec 3.2: validate_plan.py <path> [--max-concurrent N]; exit 0 prints OK, exit 1 defects.
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.config import DEFAULT_MAX_CONCURRENT_BUILDERS  # noqa: E402
from lib.plan_record import PlanError, graph_line, load, validate  # noqa: E402

USAGE = "usage: validate_plan.py <path to a plan.md file> [--max-concurrent N]"
USAGE_NEXT = "Next: pass one plan file path and, optionally, a coder count of 1 or more."
PLAN_NEXT = "Next: fix each defect above in the plan block, then rerun the validator."
READ_NEXT = "Next: check the path, then rerun the validator on the plan file the planner wrote."


def _args(argv: list[str]) -> tuple[Path, int] | None:
    rest = list(argv)
    limit = DEFAULT_MAX_CONCURRENT_BUILDERS
    if "--max-concurrent" in rest:
        at = rest.index("--max-concurrent")
        value = rest[at + 1] if at + 1 < len(rest) else ""
        if not value.isdigit() or int(value) < 1:
            return None
        limit = int(value)
        del rest[at : at + 2]
    if len(rest) != 1 or rest[0].startswith("--"):
        return None
    return Path(rest[0]), limit


def main(argv: list[str]) -> int:
    parsed = _args(argv)
    if parsed is None:
        print(f"{USAGE}\n{USAGE_NEXT}", file=sys.stderr)
        return 1
    path, limit = parsed
    try:
        plan = load(path)
    except PlanError as exc:
        print(f"{exc}\n{READ_NEXT}")
        return 1
    defects = validate(plan, limit)
    if defects:
        print("\n".join([*defects, PLAN_NEXT]))
        return 1
    print(f"OK plan: {graph_line(plan, limit)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

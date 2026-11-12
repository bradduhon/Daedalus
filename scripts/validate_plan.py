#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0086, spec 3.2: validate_plan.py <path> [--max-concurrent N]; exit 0 prints OK, exit 1 defects.
# Spec 3.4: a plan with a version line also prints an OK version line after the OK plan line.
# Pin MAP -> REQ: --map <map.json> adds one defect per path two unjoined units own.
# 0280: --repo names whose work classes apply; --classes prints them for the planner.
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import operator_file  # noqa: E402
from lib.config import DEFAULT_MAX_CONCURRENT_BUILDERS, ConfigError  # noqa: E402
from lib.operator_file import Operator, OperatorError  # noqa: E402
from lib.plan_record import (  # noqa: E402
    PlanError,
    graph_line,
    has_class_fields,
    load,
    ownership_defects,
    read_ownership,
    validate,
)
from lib.project_root import project_root  # noqa: E402
from lib.work_classes import above_middle  # noqa: E402

USAGE = (
    "usage: validate_plan.py <path to a plan.md file> [--max-concurrent N] [--map <map.json>] "
    "[--repo <path>], or validate_plan.py --classes [--repo <path>]"
)
USAGE_NEXT = (
    "Next: pass one plan file path and, optionally, a coder count of 1 or more, the "
    "map.json path daedalus_map.py wrote and the repository path; or --classes alone."
)
PLAN_NEXT = "Next: fix each defect above in the plan block, then rerun the validator."
READ_NEXT = "Next: check the path, then rerun the validator on the plan file the planner wrote."
MAP_NEXT = "Next: rerun daedalus_map.py with --plan on this plan, then rerun the validator."
SETTINGS_NEXT = (
    "Next: correct the work_classes or class_models setting named above, then rerun the validator."
)


def _option(rest: list[str], flag: str) -> str | None:
    # Pin MAP -> REQ: removes `flag <value>` from rest; "" means a flag with no usable value.
    if flag not in rest:
        return None
    at = rest.index(flag)
    value = rest[at + 1] if at + 1 < len(rest) else ""
    del rest[at : at + 2]
    return "" if value.startswith("--") else value


def _args(argv: list[str]) -> tuple[Path | None, int, Path | None, Path | None] | None:
    # 0280: a None plan path is the --classes form, which takes --repo only.
    rest = list(argv)
    classes = "--classes" in rest
    if classes:
        rest.remove("--classes")
    repo = _option(rest, "--repo")
    if repo == "":
        return None
    repo_path = Path(repo).resolve() if repo else None
    if classes:
        return (None, 0, None, repo_path) if not rest else None
    limit = DEFAULT_MAX_CONCURRENT_BUILDERS
    count = _option(rest, "--max-concurrent")
    if count is not None:
        if not count.isdigit() or int(count) < 1:
            return None
        limit = int(count)
    mapped = _option(rest, "--map")
    if mapped == "":
        return None
    if len(rest) != 1 or rest[0].startswith("--"):
        return None
    return Path(rest[0]), limit, Path(mapped) if mapped else None, repo_path


def _operator(repo: Path) -> Operator | str:
    # 0280: the personal settings with the project's override, as every reader sees them.
    try:
        return operator_file.load(repo)
    except (OperatorError, ConfigError) as exc:
        return f"{exc}\n{SETTINGS_NEXT}"


def _print_classes(repo: Path) -> int:
    # 0280: the planner's copy of the work classes; a required place means a class_reason too.
    operator = _operator(repo)
    if isinstance(operator, str):
        print(operator)
        return 1
    if not operator.work_classes:
        print("no work classes are set; write no class field, and every unit is Plumbing.")
        return 0
    for name, definition in operator.work_classes:
        place = "required" if above_middle(name, operator) else "not required"
        print(f"class: {name} | place: {place} | definition: {definition}")
    return 0


def main(argv: list[str]) -> int:
    parsed = _args(argv)
    if parsed is None:
        print(f"{USAGE}\n{USAGE_NEXT}", file=sys.stderr)
        return 1
    path, limit, map_path, repo = parsed
    if path is None:
        return _print_classes(repo or project_root(Path.cwd()))
    try:
        plan = load(path)
    except PlanError as exc:
        print(f"{exc}\n{READ_NEXT}")
        return 1
    operator = None
    if has_class_fields(plan):
        # 0280: a plan with no class field never reads the settings, so it validates as before.
        loaded = _operator(repo or project_root(path.resolve().parent))
        if isinstance(loaded, str):
            print(loaded)
            return 1
        operator = loaded
    defects = validate(plan, limit, operator)
    if map_path is not None:
        try:
            defects += ownership_defects(plan, read_ownership(map_path))
        except PlanError as exc:
            print("\n".join([*defects, str(exc), MAP_NEXT]))
            return 1
    if defects:
        print("\n".join([*defects, PLAN_NEXT]))
        return 1
    print(f"OK plan: {graph_line(plan, limit)}")
    if plan.version is not None:
        # Spec 3.4, pin D4 -> D5: printed only when the plan carries a version line.
        print(f"OK version: unit={plan.version.unit} {plan.version.summary_line}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0086, spec 3.2: the one loader and validator of plan records; the coder gate imports it too.
# load() reads the single fenced plan block; validate() returns one defect line per failed check.
# 0128, pin REQ -> VER: load() also reads each unit's requirement section outside the block.
from __future__ import annotations

import fnmatch
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from lib.train_state import DOCS_SUFFIX

INTEGRATION = "integration"
SERIAL = "serial"
OVERLAP = "overlap"
KINDS = (SERIAL, OVERLAP)
ARROWS = {SERIAL: "->", OVERLAP: "~"}
_FENCE_OPEN = "```plan"
_FENCE_CLOSE = "```"
_SEP = " | "
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
_PAIR = re.compile(r"(\S+) (->|~) (\S+)")
_MERGE = re.compile(r"(\S+) then (\S+)")
_GRAPH = re.compile(r"graph: units=(\d+) critical_path=(\d+) width=(\d+) overlap_only=(\S*)")
_SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_UNIT_KEYS = ("title", "files", "base", "needs")
_EDGE_KEYS = ("kind", "why", "files", "merge")
_VERSION_KEYS = ("class", "reason", "unit")
VERSION_CLASSES = ("X", "Y", "Z")
_GLOB_CHARS = "*?["
# 3.3, 0182: a unit touching one runs the adversarial corpus; skills/catalog/SKILL.md names it.
JAIL_CHECK_PATHS = (
    "scripts/checks/",
    "scripts/lib/jail.py",
    "scripts/lib/shell.py",
    "scripts/enforce_agent_jail.py",
)
# 0175, 0182: never a small change or a contract skip; agents/auditor.md names it.
CONTROL_PATHS = (*JAIL_CHECK_PATHS, "agents/", "skills/", "hooks/")
# 0182: the most files a one-unit plan may name and still skip the contract.
CONTRACT_SKIP_FILES = 3
# 0128: a need is a tool name or a repo-relative protected path; never a flag, never absolute.
_NEED = re.compile(r"(?!-)[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)*/?")
_HEADING = re.compile(r"### ([A-Za-z0-9][A-Za-z0-9_.-]*): (\S.*)")
_SECTION_END = re.compile(r"#{1,3} ")
REQUIREMENTS = "Requirements:"
_NUMBERED = re.compile(r"(\d+)\. (.*)")
_TWO_SENTENCES = re.compile(r"\. [A-Z]")
_BACKTICKED = re.compile(r"`[^`\s][^`]*`")
_SLASH_PATH = re.compile(r"[\w.*<>-]+/[\w./*<>-]*")
SECTION_SHAPE = "`### <unit id>: <title>`, then a `Requirements:` line and `1. <requirement>` lines"


class PlanError(ValueError):
    pass


@dataclass(frozen=True)
class Unit:
    id: str
    title: str
    files: tuple[str, ...]
    base: str
    needs: tuple[str, ...] = ()


@dataclass(frozen=True)
class Section:
    # Pin REQ -> VER: one unit's requirement section; the verifier counts one claim per line.
    unit: str
    title: str
    line: int
    listed: bool
    requirements: tuple[str, ...]
    stray: str | None = None


@dataclass(frozen=True)
class Edge:
    source: str
    arrow: str
    target: str
    kind: str
    why: str
    files: tuple[str, ...]
    merge: tuple[str, str] | None

    @property
    def label(self) -> str:
        return f"{self.source} {self.arrow} {self.target}"


@dataclass(frozen=True)
class Pin:
    source: str
    target: str
    shape: str


@dataclass(frozen=True)
class Version:
    version: str
    change_class: str
    reason: str
    unit: str

    @property
    def summary_line(self) -> str:
        # Pin D4 -> D5: the line the orchestrator copies into the summary for the release step.
        return f"Version class: {self.version} {self.change_class}: {self.reason}"


@dataclass(frozen=True)
class Plan:
    units: tuple[Unit, ...]
    edges: tuple[Edge, ...]
    pins: tuple[Pin, ...]
    graph: str | None
    defects: tuple[str, ...]
    version: Version | None = None
    sections: tuple[Section, ...] = ()

    def section(self, uid: str) -> Section | None:
        return next((s for s in self.sections if s.unit == uid), None)


@dataclass(frozen=True)
class _Graph:
    units: int
    critical_path: int
    width: int
    overlap_only: tuple[tuple[str, str], ...]


def _fields(parts: list[str], keys: tuple[str, ...], where: str, out: list[str]) -> dict[str, str]:
    found: dict[str, str] = {}
    for part in parts:
        key, colon, value = part.partition(":")
        key = key.strip()
        if not colon or key not in keys:
            out.append(f"{where} has a field it does not know: {part.strip()}")
        elif key in found:
            out.append(f"{where} names {key} twice.")
        else:
            found[key] = value.strip()
    return found


def _list(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _unit(line: str, number: int, out: list[str]) -> Unit | None:
    head, *parts = line.split(_SEP)
    uid = head.partition(":")[2].strip()
    if not _ID.fullmatch(uid):
        out.append(f"line {number} of the plan block names no usable unit id: {line}")
        return None
    fields = _fields(parts, _UNIT_KEYS, f"unit {uid}", out)
    for key in ("title", "base"):
        if not fields.get(key):
            out.append(f"unit {uid} names no {key}.")
    needs = _needs(uid, fields["needs"], out) if "needs" in fields else ()
    return Unit(
        uid,
        fields.get("title", ""),
        _list(fields.get("files", "")),
        fields.get("base", ""),
        needs,
    )


def is_need(name: str) -> bool:
    # 0128: the one shape check for a need, shared by the plan reader and doctor --check-tools.
    return bool(_NEED.fullmatch(name)) and ".." not in name.split("/") and name.strip("/") != "."


def _needs(uid: str, value: str, out: list[str]) -> tuple[str, ...]:
    items = [item.strip() for item in value.split(",")]
    shape = "write needs: <tool name or protected path>[, ...]"
    if not value or any(not item for item in items):
        out.append(f"unit {uid} has a needs field with an empty item; {shape}.")
    kept: list[str] = []
    for item in (i for i in items if i):
        if not is_need(item):
            out.append(
                f"unit {uid} needs {item}, which is neither a tool name nor a repo-relative "
                f"path; {shape}."
            )
        elif item in kept:
            out.append(f"unit {uid} names the need {item} twice.")
        else:
            kept.append(item)
    return tuple(kept)


def _edge(line: str, number: int, out: list[str]) -> Edge | None:
    head, *parts = line.split(_SEP)
    pair = _PAIR.fullmatch(head.partition(":")[2].strip())
    if pair is None:
        out.append(f"line {number} of the plan block is not written edge: A -> B or A ~ B: {line}")
        return None
    source, arrow, target = pair.groups()
    fields = _fields(parts, _EDGE_KEYS, f"edge {source} {arrow} {target}", out)
    merge = _MERGE.fullmatch(fields.get("merge", ""))
    return Edge(
        source,
        arrow,
        target,
        fields.get("kind", ""),
        fields.get("why", ""),
        _list(fields.get("files", "")),
        (merge.group(1), merge.group(2)) if merge else None,
    )


def _pin(line: str, number: int, out: list[str]) -> Pin | None:
    head, _, shape = line.partition(_SEP)
    pair = _PAIR.fullmatch(head.partition(":")[2].strip())
    if pair is None or pair.group(2) != "->":
        out.append(f"line {number} of the plan block is not written pin: A -> B | shape: {line}")
        return None
    return Pin(pair.group(1), pair.group(3), shape.strip())


def _version(line: str, out: list[str]) -> Version:
    # Spec 3.4: version: <x.y.z> | class: <X, Y or Z> | reason: <one line> | unit: <unit id>
    head, *parts = line.split(_SEP)
    fields = _fields(parts, _VERSION_KEYS, "the version line", out)
    return Version(
        head.partition(":")[2].strip(),
        fields.get("class", ""),
        fields.get("reason", ""),
        fields.get("unit", ""),
    )


def _parse(block: list[str]) -> Plan:
    units: list[Unit] = []
    edges: list[Edge] = []
    pins: list[Pin] = []
    graphs: list[str] = []
    versions: list[Version] = []
    out: list[str] = []
    for number, raw in enumerate(block, 1):
        line = raw.strip()
        kind = line.partition(":")[0]
        if not line:
            continue
        if kind == "unit":
            unit = _unit(line, number, out)
            if unit is not None and any(u.id == unit.id for u in units):
                out.append(f"unit {unit.id} is declared twice; keep one line per unit.")
            elif unit is not None:
                units.append(unit)
        elif kind == "edge":
            edge = _edge(line, number, out)
            edges.extend([edge] if edge is not None else [])
        elif kind == "pin":
            pin = _pin(line, number, out)
            pins.extend([pin] if pin is not None else [])
        elif kind == "graph":
            graphs.append(line)
        elif kind == "version":
            versions.append(_version(line, out))
        else:
            out.append(
                f"line {number} of the plan block is not a unit, edge, pin, version or graph "
                f"line: {line}"
            )
    if len(graphs) > 1:
        out.append(f"the plan block has {len(graphs)} graph lines; keep exactly one.")
    if len(versions) > 1:
        out.append(f"the plan block has {len(versions)} version lines; keep at most one.")
    return Plan(
        tuple(units),
        tuple(edges),
        tuple(pins),
        graphs[0] if graphs else None,
        tuple(out),
        versions[0] if versions else None,
    )


def _empty(defect: str) -> Plan:
    return Plan((), (), (), None, (defect,))


def _requirements(lines: list[str], at: int) -> tuple[list[str], str | None]:
    # Pin REQ -> VER: numbered from 1 up to the first unnumbered line; a skipped number is stray.
    found: list[str] = []
    for line in lines[at:]:
        numbered = _NUMBERED.fullmatch(line.rstrip())
        if numbered is None:
            break
        if int(numbered.group(1)) != len(found) + 1:
            return found, line.rstrip()
        found.append(numbered.group(2).strip())
    return found, None


def _sections(lines: list[str]) -> tuple[Section, ...]:
    # Pin REQ -> VER: headings inside any fenced block, the plan block included, are never sections.
    fenced = False
    heads: list[tuple[int, re.Match[str]]] = []
    ends: list[int] = []
    for i, line in enumerate(lines):
        if line.strip().startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            continue
        head = _HEADING.fullmatch(line.rstrip())
        if head is not None:
            heads.append((i, head))
        if _SECTION_END.match(line):
            ends.append(i)
    out: list[Section] = []
    for i, head in heads:
        stop = next((e for e in ends if e > i), len(lines))
        body = lines[i + 1 : stop]
        at = next((k for k, line in enumerate(body) if line.rstrip() == REQUIREMENTS), None)
        found, stray = _requirements(body, at + 1) if at is not None else ([], None)
        out.append(
            Section(head.group(1), head.group(2), i + 1, at is not None, tuple(found), stray)
        )
    return tuple(out)


def load(path: Path) -> Plan:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise PlanError(f"the plan file {path} could not be read ({exc}).") from exc
    lines = text.splitlines()
    opens = [i for i, line in enumerate(lines) if line.strip() == _FENCE_OPEN]
    if not opens:
        return _empty("the file has no fenced plan block.")
    if len(opens) > 1:
        return _empty(f"the file has {len(opens)} fenced plan blocks; keep exactly one.")
    start = opens[0] + 1
    end = next((i for i in range(start, len(lines)) if lines[i].strip() == _FENCE_CLOSE), None)
    if end is None:
        return _empty("the fenced plan block has no closing fence.")
    plan = _parse(lines[start:end])
    return Plan(
        plan.units, plan.edges, plan.pins, plan.graph, plan.defects, plan.version, _sections(lines)
    )


def _known(plan: Plan) -> set[str]:
    return {u.id for u in plan.units}


def _serial(plan: Plan) -> dict[str, list[str]]:
    # 0086: only a well-formed serial edge orders two units; a pin never does.
    known = _known(plan)
    after: dict[str, list[str]] = {u.id: [] for u in plan.units}
    for e in plan.edges:
        if e.kind == SERIAL and e.arrow == "->" and {e.source, e.target} <= known:
            if e.source != e.target and e.target not in after[e.source]:
                after[e.source].append(e.target)
    return after


def _overlaps(plan: Plan) -> tuple[tuple[str, str], ...]:
    known = _known(plan)
    seen: list[tuple[str, str]] = []
    for e in plan.edges:
        pair = (e.source, e.target)
        if e.kind == OVERLAP and {e.source, e.target} <= known and e.source != e.target:
            if pair not in seen and pair[::-1] not in seen:
                seen.append(pair)
    return tuple(seen)


def _reach(after: dict[str, list[str]]) -> dict[str, set[str]]:
    reach: dict[str, set[str]] = {}
    for start in after:
        seen: set[str] = set()
        todo = list(after[start])
        while todo:
            node = todo.pop()
            if node not in seen:
                seen.add(node)
                todo.extend(after[node])
        reach[start] = seen
    return reach


def _cycle(after: dict[str, list[str]]) -> list[str] | None:
    state: dict[str, int] = {}
    path: list[str] = []

    def visit(node: str) -> list[str] | None:
        state[node] = 1
        path.append(node)
        for nxt in after[node]:
            if state.get(nxt) == 1:
                return [*path[path.index(nxt) :], nxt]
            if nxt not in state:
                found = visit(nxt)
                if found:
                    return found
        state[node] = 2
        path.pop()
        return None

    for node in after:
        if node not in state:
            found = visit(node)
            if found:
                return found
    return None


def _critical_path(after: dict[str, list[str]]) -> int:
    # 0086: the longest serial chain counted in units, in topological order.
    indegree = {node: 0 for node in after}
    for targets in after.values():
        for target in targets:
            indegree[target] += 1
    longest = dict.fromkeys(after, 1)
    ready = [node for node, count in indegree.items() if count == 0]
    while ready:
        node = ready.pop()
        for target in after[node]:
            longest[target] = max(longest[target], longest[node] + 1)
            indegree[target] -= 1
            if indegree[target] == 0:
                ready.append(target)
    return max(longest.values(), default=0)


def _antichain(reach: dict[str, set[str]]) -> int:
    # Dilworth: the largest set with no serial path between members is n minus a maximum matching.
    match: dict[str, str] = {}

    def augment(node: str, tried: set[str]) -> bool:
        for target in reach[node]:
            if target not in tried:
                tried.add(target)
                if target not in match or augment(match[target], tried):
                    match[target] = node
                    return True
        return False

    return len(reach) - sum(1 for node in reach if augment(node, set()))


def _compute(plan: Plan, max_concurrent: int) -> _Graph:
    after = _serial(plan)
    width = min(_antichain(_reach(after)), max_concurrent)
    return _Graph(len(after), _critical_path(after), width, _overlaps(plan))


def _render_pairs(pairs: tuple[tuple[str, str], ...]) -> str:
    return ",".join(f"{a}~{b}" for a, b in pairs) or "none"


def graph_line(plan: Plan, max_concurrent: int) -> str:
    g = _compute(plan, max_concurrent)
    return (
        f"graph: units={g.units} critical_path={g.critical_path} width={g.width} "
        f"overlap_only={_render_pairs(g.overlap_only)}"
    )


def _covers(pattern: str, path: str) -> bool:
    # 0086: a trailing slash names a folder; a glob character names a pattern.
    if pattern.endswith("/"):
        return path.startswith(pattern)
    if any(c in pattern for c in _GLOB_CHARS):
        return fnmatch.fnmatchcase(path, pattern)
    return pattern == path


def _shared(a: Unit, b: Unit) -> str | None:
    for x in a.files:
        for y in b.files:
            if _covers(x, y):
                return y
            if _covers(y, x):
                return x
    return None


def _unit_defects(plan: Plan) -> list[str]:
    known = _known(plan)
    out: list[str] = []
    for u in plan.units:
        if not u.files:
            out.append(f"unit {u.id} lists no files; name the files or folders it changes.")
        # 0134: the docs stage worktree <train-id>-docstage is no plan unit's slug.
        if u.id.lower() == DOCS_SUFFIX.removeprefix("-"):
            out.append(
                f"unit {u.id} takes the slug of the reserved docs stage worktree "
                f"<train-id>{DOCS_SUFFIX}. Next: give that unit another id in the plan."
            )
        if u.base and u.base != INTEGRATION and u.base not in known:
            out.append(
                f"unit {u.id} starts from {u.base}, which is neither {INTEGRATION} "
                "nor a unit in this plan."
            )
    return out


def _edge_defects(plan: Plan) -> list[str]:
    known = _known(plan)
    out: list[str] = []
    for e in plan.edges:
        out.extend(
            f"edge {e.label} names unknown unit {name}."
            for name in dict.fromkeys((e.source, e.target))
            if name not in known
        )
        if e.source == e.target:
            out.append(f"edge {e.label} joins a unit to itself.")
        if not e.kind:
            out.append(f"edge {e.label} names no kind; add kind: {SERIAL} or kind: {OVERLAP}.")
            continue
        if e.kind not in KINDS:
            out.append(f"edge {e.label} has kind {e.kind}; use {SERIAL} or {OVERLAP}.")
            continue
        if e.arrow != ARROWS[e.kind]:
            right = f"{e.source} {ARROWS[e.kind]} {e.target}"
            out.append(f"edge {e.label} has kind {e.kind}, which is written {right}.")
        if e.kind == SERIAL and not e.why:
            out.append(f"serial edge {e.label} names no why; name the import or interface.")
        if e.kind == OVERLAP:
            out.extend(_overlap_defects(e))
    return out


def _overlap_defects(e: Edge) -> list[str]:
    out: list[str] = []
    if not e.files:
        out.append(f"overlap edge {e.label} names no files; list the files both units change.")
    order = f"merge: {e.source} then {e.target}"
    if e.merge is None:
        out.append(f"overlap edge {e.label} names no merge order; write {order}.")
    elif set(e.merge) != {e.source, e.target}:
        out.append(
            f"overlap edge {e.label}: the merge order must name {e.source} and {e.target}, "
            f"as {order}."
        )
    return out


def _pin_defects(plan: Plan) -> list[str]:
    known = _known(plan)
    out: list[str] = []
    for p in plan.pins:
        label = f"{p.source} -> {p.target}"
        out.extend(
            f"pin {label} names unknown unit {name}."
            for name in dict.fromkeys((p.source, p.target))
            if name not in known
        )
        if not p.shape:
            out.append(f"pin {label} names no shape; name the function, flag or line.")
    return out


def _version_defects(plan: Plan) -> list[str]:
    # Spec 3.4: no version line validates as before; a present one is checked field by field.
    v = plan.version
    if v is None:
        return []
    out: list[str] = []
    if not _SEMVER.fullmatch(v.version):
        out.append(
            f"the version line names version {v.version or '(none)'}; "
            "write three dot-separated numbers, such as 4.0.0."
        )
    if v.change_class not in VERSION_CLASSES:
        out.append(f"the version line names class {v.change_class or '(none)'}; use X, Y or Z.")
    if not v.reason:
        out.append("the version line names no reason; give the change in one line.")
    if not v.unit:
        out.append("the version line names no unit; name the unit that edits the version sites.")
    elif v.unit not in _known(plan):
        out.append(f"the version line names unknown unit {v.unit}.")
    return out


def requirement_problem(text: str) -> str | None:
    # Pin REQ -> VER: one sentence ending in a period, naming a backticked token or a slash path.
    if not text.endswith("."):
        return "does not end in a period"
    if _TWO_SENTENCES.search(text):
        return "holds more than one sentence (a period, a space and a capital letter)"
    if not (_BACKTICKED.search(text) or _SLASH_PATH.search(text)):
        return "names no backticked token and no path holding a slash"
    return None


def _section_defects(plan: Plan) -> list[str]:
    out: list[str] = []
    for u in plan.units:
        mine = [s for s in plan.sections if s.unit == u.id]
        if not mine:
            out.append(
                f"unit {u.id} has no requirement section; below the plan block write "
                f"{SECTION_SHAPE}."
            )
            continue
        if len(mine) > 1:
            lines = ", ".join(str(s.line) for s in mine)
            out.append(
                f"unit {u.id} has {len(mine)} requirement sections (lines {lines}); keep one."
            )
        s = mine[0]
        if not s.requirements:
            out.append(
                f"the requirement section of unit {u.id} (line {s.line}) lists no requirement; "
                f"under it write {SECTION_SHAPE}."
            )
        if s.stray is not None:
            out.append(
                f"the requirement list of unit {u.id} breaks its numbering at: {s.stray}; "
                "number the requirements 1, 2, 3 in order."
            )
        for n, text in enumerate(s.requirements, 1):
            problem = requirement_problem(text)
            if problem is not None:
                out.append(f"requirement {n} of unit {u.id} {problem}: {text}")
    return out


def read_ownership(path: Path) -> dict[str, tuple[str, ...]]:
    # Pin MAP -> REQ: map.json's ownership object maps a repo-relative path to sorted unit ids.
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise PlanError(f"the map file {path} could not be read ({exc}).") from exc
    owners = data.get("ownership") if isinstance(data, dict) else None
    if not isinstance(owners, dict):
        raise PlanError(f"the map file {path} holds no ownership object.")
    out: dict[str, tuple[str, ...]] = {}
    for key, ids in owners.items():
        if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
            raise PlanError(f"the ownership entry {key} in {path} is not a list of unit ids.")
        out[key] = tuple(ids)
    return out


def ownership_defects(plan: Plan, owners: Mapping[str, Sequence[str]]) -> list[str]:
    # 0128: a path two units own needs an overlap edge or a serial path, as in _shared_defects.
    known = _known(plan)
    joined = {frozenset(pair) for pair in _overlaps(plan)}
    reach = _reach(_serial(plan))
    out: list[str] = []
    for path in sorted(owners):
        ids = list(dict.fromkeys(owners[path]))
        out.extend(f"the map gives {path} to unknown unit {i}." for i in ids if i not in known)
        mine = [i for i in ids if i in known]
        pairs = [
            f"{a} and {b}"
            for k, a in enumerate(mine)
            for b in mine[k + 1 :]
            if frozenset((a, b)) not in joined and b not in reach[a] and a not in reach[b]
        ]
        if pairs:
            out.append(
                f"the map gives {path} to units {'; '.join(pairs)} with neither an overlap edge "
                "nor a serial path between them."
            )
    return out


def _shared_defects(plan: Plan, reach: dict[str, set[str]]) -> list[str]:
    # 0086: a shared file needs an overlap edge, unless a serial path already orders the two units.
    joined = {frozenset(pair) for pair in _overlaps(plan)}
    out: list[str] = []
    units = plan.units
    for i, a in enumerate(units):
        for b in units[i + 1 :]:
            if frozenset((a.id, b.id)) in joined or b.id in reach[a.id] or a.id in reach[b.id]:
                continue
            path = _shared(a, b)
            if path is not None:
                out.append(
                    f"units {a.id} and {b.id} both change {path} but no overlap edge joins them."
                )
    return out


def _pair_set(value: str) -> set[frozenset[str]] | None:
    if value in ("", "none"):
        return set()
    pairs: set[frozenset[str]] = set()
    for item in value.split(","):
        a, tilde, b = item.partition("~")
        if not tilde or not a or not b:
            return None
        pairs.add(frozenset((a, b)))
    return pairs


def _graph_defects(plan: Plan, max_concurrent: int) -> list[str]:
    computed = _compute(plan, max_concurrent)
    line = graph_line(plan, max_concurrent)
    if plan.graph is None:
        return [f"the plan block has no graph line; add: {line}"]
    declared = _GRAPH.fullmatch(plan.graph)
    if declared is None:
        return [f"the graph line is not in the graph line shape; the plan computes: {line}"]
    out: list[str] = []
    keys = ("units", "critical_path", "width")
    numbers = (computed.units, computed.critical_path, computed.width)
    for key, said, real in zip(keys, declared.groups()[:3], numbers, strict=True):
        if int(said) != real:
            out.append(f"the graph line says {key}={said}; the plan computes {key}={real}.")
    real_pairs = {frozenset(pair) for pair in computed.overlap_only}
    if _pair_set(declared.group(4)) != real_pairs:
        out.append(
            f"the graph line says overlap_only={declared.group(4)}; "
            f"the plan computes overlap_only={_render_pairs(computed.overlap_only)}."
        )
    return out


def validate(plan: Plan, max_concurrent: int) -> list[str]:
    defects = list(plan.defects)
    if not plan.units:
        return defects or ["the plan block declares no units."]
    defects += _unit_defects(plan) + _edge_defects(plan) + _pin_defects(plan)
    defects += _version_defects(plan) + _section_defects(plan)
    after = _serial(plan)
    cycle = _cycle(after)
    if cycle:
        # 0086: a cycle has no longest chain, so the graph line is not checked.
        return [*defects, f"serial edges form a cycle: {' -> '.join(cycle)}."]
    defects += _shared_defects(plan, _reach(after))
    return defects + _graph_defects(plan, max_concurrent)

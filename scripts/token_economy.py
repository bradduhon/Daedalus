#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# Plan 11 A: one token table per orchestrated run, read from the agent transcripts.
# Usage is summed per message.id from its last JSONL line; the main session is left out.
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.audit import (  # noqa: E402
    SESSION_ID,
    AuditLockError,
    project_data_dir,
    read_log,
    root_info,
)
from lib.config import ConfigError, load_config  # noqa: E402
from lib.train_state import (  # noqa: E402
    AUDIT_BOUNDS,
    AUDIT_SUFFIX,
    DOCS_SUFFIX,
    TRAIN_ID,
    TrainStateError,
    audit_session,
)
from lib.train_state import load as load_state  # noqa: E402

DESCRIPTION = (
    "Print the standard token table of one orchestrated run, or of every run in one session, "
    "from the agent transcripts under the Claude projects folder (Plan 11 A). "
    "history prints the totals row of every saved report."
)
# Plan 11 A item 4: the one column set; a change here is a deliberate edit of this tuple.
COLUMNS: tuple[str, ...] = (
    "run type",
    "run id",
    "phase",
    "agent",
    "unit or round",
    "turns",
    "input",
    "output",
    "cache write",
    "cache read",
    "wall time",
)
NONE = "none"
TOTAL, MEAN = "total", "mean"
USAGE_FIELDS = (
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)
PREFIX = "daedalus:"
BUILD, PUSH, DOC = "Build Train", "Push Train", "Document Train"
# 0163: agents the main session starts outside any run group under the session itself.
SESSION = "session"
CODER = "repo-coder"
ROOT_RUN_TYPES = {
    "orchestrator": BUILD,
    "pr-train-conductor": PUSH,
    "doc-deriver": DOC,
    "change-logger": DOC,
}
# Plan 11 A: the Build Train phase an agent type works in when its prompt names none.
BUILD_PHASES = {
    "planner": "1",
    "standards-rules-specialist": "1",
    "contract-spec": "1",
    "charter-docs": "1",
    "repo-coder": "2",
    "verifier": "2",
    "web-researcher": "2",
    "security-auditor": "3",
    "docs-writer": "3",
    "framework-specialist": "3",
    "terraform-reviewer": "3",
    "dependency-auditor": "3",
}
UNIT_AGENTS = frozenset({"repo-coder", "verifier"})
ROUND_AGENTS = frozenset({"security-auditor"})
_UNIT = re.compile(rf"(?:worktrees|daedalus-unit)/{TRAIN_ID.pattern}-([a-z0-9][a-z0-9-]*)")
_ROUND = re.compile(r"\bround (\d+)\b", re.IGNORECASE)
_PHASE = re.compile(r"\bPhase (\d+)\b")
_CHALLENGE = re.compile(r"^Mode: challenge$", re.MULTILINE)
_RUN_ID = re.compile(TRAIN_ID.pattern)
_AGENT_TYPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
# spec 4, 0134: the audit worktree and the docs stage are train stages, not plan units.
STAGES = frozenset({AUDIT_SUFFIX[1:], DOCS_SUFFIX[1:]})
_LATEST = datetime.max.replace(tzinfo=UTC)
_ROW = re.compile(r"^\|(.*)\|\s*$")


class TokenError(Exception):
    pass


@dataclass
class Usage:
    turns: int = 0
    tokens: list[int] = field(default_factory=lambda: [0, 0, 0, 0])
    seconds: float = 0.0

    def add(self, other: Usage) -> None:
        self.turns += other.turns
        self.tokens = [a + b for a, b in zip(self.tokens, other.tokens, strict=True)]
        self.seconds += other.seconds


@dataclass
class Segment:
    label: str | None
    prompt: str
    first: datetime | None = None
    last: datetime | None = None
    usage: Usage = field(default_factory=Usage)


@dataclass
class Agent:
    agent_id: str
    agent_type: str
    parent: str | None
    description: str
    segments: list[Segment]
    plugin: bool = False

    @property
    def opening(self) -> str:
        return self.segments[0].prompt if self.segments else ""


@dataclass
class Row:
    agent_id: str
    run_type: str
    run_id: str
    phase: str | None
    agent: str
    label: str | None
    kind: str | None
    usage: Usage
    first: datetime | None


@dataclass
class Run:
    run_type: str
    run_id: str
    rows: list[Row] = field(default_factory=list)
    first: datetime | None = None
    spans: list[tuple[datetime, datetime]] = field(default_factory=list)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.exit(1, f"token_economy: {message}. Next: run with --help for the usage.\n")


def _parse(argv: list[str]) -> argparse.Namespace:
    parser = _Parser(prog="token_economy.py", description=DESCRIPTION, allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    report = sub.add_parser("report", allow_abbrev=False)
    which = report.add_mutually_exclusive_group(required=True)
    which.add_argument("--session")
    which.add_argument("--run")
    where = report.add_mutually_exclusive_group()
    where.add_argument("--out")
    where.add_argument("--save", action="store_true")
    history = sub.add_parser("history", allow_abbrev=False)
    for each in (report, history):
        each.add_argument("--cwd", "--repo", dest="cwd", default=os.getcwd())
    args = parser.parse_args(argv)
    args.cwd = os.path.abspath(args.cwd)
    if not os.path.isdir(args.cwd):
        parser.exit(
            1,
            f"token_economy: --cwd {args.cwd} is not an existing directory. "
            "Next: pass the repo directory whose runs you want to report.\n",
        )
    return args


def projects_dir() -> Path:
    # Plan 11 A: Claude Code keeps transcripts under <config dir>/projects/<project slug>/.
    base = os.environ.get("CLAUDE_CONFIG_DIR")
    return (Path(base) if base else Path.home() / ".claude") / "projects"


def _slug(root: Path) -> str:
    return re.sub(r"[^A-Za-z0-9]", "-", str(root))


def transcript_files(session: str, root: Path) -> list[Path]:
    # Plan 11 A: a subagent transcript is linked by the sessionId on its first line.
    base = projects_dir()
    homes = [base / _slug(root)]
    homes += [p for p in sorted(base.glob(f"*/{session}")) if p.is_dir()]
    found: dict[str, Path] = {}
    for home in homes:
        for pattern in (f"{session}/subagents/agent-*.jsonl", "subagents/agent-*.jsonl"):
            for path in sorted(home.glob(pattern)):
                if path.name not in found and _first_session(path) == session:
                    found[path.name] = path
        for path in sorted(home.glob("agent-*.jsonl")):
            if path.name not in found and _first_session(path) == session:
                found[path.name] = path
    return list(found.values())


def _first_session(path: Path) -> str | None:
    try:
        with path.open(encoding="utf-8") as handle:
            line = handle.readline()
        data: object = json.loads(line)
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    value = data.get("sessionId") if isinstance(data, dict) else None
    return value if isinstance(value, str) else None


def _ts(raw: object) -> datetime | None:
    try:
        stamp = datetime.fromisoformat(str(raw))
    except ValueError:
        return None
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=UTC)


def _prompt_text(line: dict[str, object]) -> str | None:
    # An inbound prompt is a user line of text; a tool result is not a prompt.
    if line.get("type") != "user":
        return None
    message = line.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        return content
    if not isinstance(content, list) or not content:
        return None
    blocks = [b for b in content if isinstance(b, dict)]
    if any(b.get("type") == "tool_result" for b in blocks):
        return None
    texts = [str(b.get("text", "")) for b in blocks if b.get("type") == "text"]
    return "\n".join(texts) if texts else None


def label_of(agent_type: str, prompt: str) -> str | None:
    # Plan 11 A: a coder or verifier prompt naming a unit worktree or branch opens that unit.
    if agent_type in ROUND_AGENTS:
        match = _ROUND.search(prompt)
        return f"round {match.group(1)}" if match else None
    if agent_type in UNIT_AGENTS:
        match = _UNIT.search(prompt)
        return match.group(1) if match else None
    return None


def read_segments(path: Path, agent_type: str) -> list[Segment]:
    # Plan 11 A: dedup by message.id, usage from its last line, the turn in its first line's span.
    segments: list[Segment] = []
    owner: dict[str, int] = {}
    usage: dict[str, list[int]] = {}
    with path.open(encoding="utf-8") as handle:
        for raw in handle:
            try:
                line: object = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(line, dict):
                continue
            prompt = _prompt_text(line)
            is_reminder = prompt is not None and prompt.lstrip().startswith("<system-reminder>")
            if prompt is not None and not (is_reminder and segments):
                label = label_of(agent_type, prompt)
                inherited = segments[-1].label if segments else None
                segments.append(Segment(label or inherited, prompt))
            if not segments:
                segments.append(Segment(None, ""))
            current = segments[-1]
            stamp = _ts(line.get("timestamp"))
            if stamp is not None:
                current.first = current.first or stamp
                current.last = stamp
            message = line.get("message")
            if line.get("type") != "assistant" or not isinstance(message, dict):
                continue
            key = str(message.get("id") or line.get("uuid"))
            owner.setdefault(key, len(segments) - 1)
            fields = message.get("usage")
            fields = fields if isinstance(fields, dict) else {}
            usage[key] = [_int(fields.get(name)) for name in USAGE_FIELDS]
    for key, index in owner.items():
        seg = segments[index]
        seg.usage.turns += 1
        seg.usage.tokens = [a + b for a, b in zip(seg.usage.tokens, usage[key], strict=True)]
    for seg in segments:
        if seg.first is not None and seg.last is not None:
            seg.usage.seconds = (seg.last - seg.first).total_seconds()
    return segments


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _meta(path: Path) -> dict[str, object]:
    try:
        data: object = json.loads(path.with_suffix(".meta.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return {}
    return {str(k): v for k, v in data.items()} if isinstance(data, dict) else {}


def audit_types(records: list[dict[str, object]]) -> dict[str, str]:
    # Plan 11 A: the audit log's SubagentStart names each agent's type; it wins over meta.
    types: dict[str, str] = {}
    for rec in records:
        agent_id, agent_type = rec.get("agent_id"), rec.get("agent_type")
        if rec.get("event") == "SubagentStart" and agent_id and isinstance(agent_type, str):
            types[str(agent_id)] = agent_type
    return types


def load_agents(files: list[Path], types: dict[str, str]) -> list[Agent]:
    agents = []
    for path in files:
        meta = _meta(path)
        agent_id = path.stem.removeprefix("agent-")
        raw_type = types.get(agent_id) or meta.get("agentType") or "unknown"
        agent_type = str(raw_type).removeprefix(PREFIX)
        if not _AGENT_TYPE.fullmatch(agent_type):
            agent_type = "unknown"
        parent = meta.get("parentAgentId")
        agents.append(
            Agent(
                agent_id=agent_id,
                agent_type=agent_type,
                parent=str(parent) if parent else None,
                description=str(meta.get("description") or ""),
                segments=read_segments(path, agent_type),
                plugin=str(raw_type).startswith(PREFIX),
            )
        )
    return agents


def _root(agent: Agent, by_id: dict[str, Agent]) -> Agent:
    seen = {agent.agent_id}
    while agent.parent and agent.parent in by_id and agent.parent not in seen:
        agent = by_id[agent.parent]
        seen.add(agent.agent_id)
    return agent


def _run_type(root: Agent) -> str | None:
    if root.agent_type == "planner":
        return "brainstorm" if _CHALLENGE.search(root.opening) else "plan"
    return ROOT_RUN_TYPES.get(root.agent_type)


def _named_id(agent: Agent) -> str | None:
    for text in (agent.description, agent.opening):
        match = _RUN_ID.search(text)
        if match:
            return match.group(0)
    return None


def _phase(run_type: str, agent_type: str, prompt: str) -> str | None:
    if run_type != BUILD:
        return None
    match = _PHASE.search(prompt)
    return match.group(1) if match else BUILD_PHASES.get(agent_type)


def build_runs(agents: list[Agent], session: str) -> list[Run]:
    # Plan 11 A: a run is a root agent's whole tree; an unclassed root joins a run it names.
    by_id = {a.agent_id: a for a in agents}
    runs: dict[tuple[str, str], Run] = {}
    owners: dict[str, tuple[str, str]] = {}
    for agent in agents:
        root = _root(agent, by_id)
        run_type = _run_type(root)
        if run_type is not None:
            owners[agent.agent_id] = (run_type, _named_id(root) or root.agent_id)
    ids: dict[str, tuple[str, str]] = {}
    for owned in sorted(set(owners.values())):
        ids.setdefault(owned[1], owned)
    for agent in agents:
        key = owners.get(agent.agent_id)
        named = _named_id(agent)
        if key is None and agent.plugin and agent.parent is None and named in ids:
            key = ids[named]
        run = runs.setdefault(key or (SESSION, session), Run(*(key or (SESSION, session))))
        _add_rows(run, agent)
    # 0163: the session group prints after the runs it sits beside.
    return sorted(
        runs.values(), key=lambda r: (r.run_type == SESSION, r.first or _LATEST, r.run_id)
    )


def _add_rows(run: Run, agent: Agent) -> None:
    rows: dict[str | None, Row] = {}
    for seg in agent.segments:
        if seg.first is not None and seg.last is not None:
            run.first = min(run.first, seg.first) if run.first else seg.first
            run.spans.append((seg.first, seg.last))
        label = None if run.run_type == SESSION else seg.label
        row = rows.get(label)
        if row is None:
            kind = None
            if label is not None and label not in STAGES:
                kind = "round" if agent.agent_type in ROUND_AGENTS else "unit"
            phase = _phase(run.run_type, agent.agent_type, seg.prompt)
            row = Row(
                agent.agent_id,
                run.run_type,
                run.run_id,
                phase,
                agent.agent_type,
                label,
                kind,
                Usage(),
                seg.first,
            )
            rows[label] = row
            run.rows.append(row)
        row.usage.add(seg.usage)
    run.rows.sort(key=lambda r: (r.first or _LATEST, r.agent))


def active_seconds(spans: list[tuple[datetime, datetime]]) -> float:
    # Plan 11 A: time any agent of the run was active; overlapping spans count once.
    total, end = 0.0, None
    for start, stop in sorted(spans):
        if end is None or start > end:
            total += (stop - start).total_seconds()
            end = stop
        elif stop > end:
            total += (stop - end).total_seconds()
            end = stop
    return total


def duration(seconds: float | None) -> str:
    if seconds is None:
        return NONE
    whole = int(round(seconds))
    hours, rest = divmod(whole, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}h{minutes:02d}m{secs:02d}s" if hours else f"{minutes}m{secs:02d}s"


def _cell(value: object) -> str:
    if value is None or value == "":
        return NONE
    return str(value).replace("|", "/")


def table_row(cells: list[object]) -> str:
    # Plan 11 A: a missing value prints none, never a blank cell.
    if len(cells) != len(COLUMNS):
        raise TokenError(f"a row has {len(cells)} cells, not {len(COLUMNS)}")
    return "| " + " | ".join(_cell(c) for c in cells) + " |"


def header() -> list[str]:
    return ["| " + " | ".join(COLUMNS) + " |", "|" + "---|" * len(COLUMNS)]


def _numbers(usage: Usage) -> list[object]:
    return [f"{usage.turns:,}", *(f"{n:,}" for n in usage.tokens)]


def totals_row(run: Run) -> str:
    total = Usage()
    for row in run.rows:
        total.add(row.usage)
    agents = len({r.agent_id for r in run.rows})
    units = len({r.label for r in run.rows if r.kind == "unit"})
    rounds = len({r.label for r in run.rows if r.kind == "round"})
    span = active_seconds(run.spans) if run.spans else None
    cells: list[object] = [run.run_type, run.run_id, TOTAL, f"{agents} agents"]
    cells += [f"{units} units, {rounds} rounds", *_numbers(total), duration(span)]
    return table_row(cells)


def mean_row(run: Run, kind: str) -> str:
    # Plan 11 A: the unit mean is coders only, as the hand reports divided; verifiers stay in total.
    picked = [r for r in run.rows if r.kind == kind and (kind != "unit" or r.agent == CODER)]
    count = len({r.label for r in picked})
    label = f"per {kind}"
    if not count:
        return table_row([run.run_type, run.run_id, MEAN, label, f"0 {kind}s", *[NONE] * 6])
    total = Usage()
    for row in picked:
        total.add(row.usage)
    turns = round(total.turns / count)
    tokens = [f"{round(n / count):,}" for n in total.tokens]
    cells: list[object] = [run.run_type, run.run_id, MEAN, label, f"{count} {kind}s"]
    cells += [f"{turns:,}", *tokens, duration(total.seconds / count)]
    return table_row(cells)


def detail_row(row: Row) -> str:
    cells: list[object] = [row.run_type, row.run_id, row.phase, row.agent, row.label]
    cells += [*_numbers(row.usage), duration(row.usage.seconds)]
    return table_row(cells)


def _audit_records(root: Path, session: str) -> list[dict[str, object]]:
    path = project_data_dir(str(root)) / "audit" / f"{session}.jsonl"
    if not path.is_file():
        return []
    try:
        text = read_log(path)
    except (AuditLockError, OSError, UnicodeDecodeError):
        return []
    records: list[dict[str, object]] = []
    for raw in text.splitlines():
        try:
            rec: object = json.loads(raw)
        except ValueError:
            continue
        if isinstance(rec, dict):
            records.append({str(k): v for k, v in rec.items()})
    return records


def session_runs(
    session: str, root: Path, records: list[dict[str, object]] | None = None
) -> tuple[list[Run], int]:
    # Returns the runs, the session group included, and the transcript count.
    files = transcript_files(session, root)
    types = audit_types(_audit_records(root, session) if records is None else records)
    return build_runs(load_agents(files, types), session), len(files)


def _merge(runs: list[Run]) -> list[Run]:
    # A run resumed in a later session keeps one row set and one totals row.
    merged: dict[tuple[str, str], Run] = {}
    for run in runs:
        into = merged.setdefault((run.run_type, run.run_id), Run(run.run_type, run.run_id))
        into.rows += run.rows
        into.spans += run.spans
        if run.first is not None:
            into.first = min(into.first, run.first) if into.first else run.first
    return sorted(
        merged.values(), key=lambda r: (r.run_type == SESSION, r.first or _LATEST, r.run_id)
    )


LEGEND = (
    "Agents only: the main session's own tokens are left out. The four token counts are summed "
    "apart, once per message id, from its last transcript line. Wall time on an agent row adds "
    "up that agent's active spans; on a total row it is the time any agent of the run was active. "
    "The mean per unit counts coders only. Run type session holds the agents the main session "
    "started outside any run."
)


def render(runs: list[Run], source: str) -> str:
    lines = ["# Token economy", "", f"source: {source}", "", LEGEND, "", *header()]
    for run in runs:
        lines += [detail_row(row) for row in run.rows]
        lines += [totals_row(run), mean_row(run, "unit"), mean_row(run, "round")]
    return "\n".join(lines) + "\n"


def _session_arg(session: str) -> str:
    if not SESSION_ID.fullmatch(session):
        raise TokenError(
            f"--session must match [A-Za-z0-9_-]+ (got {session!r}). "
            "Next: pass a session id, the file name of a log in .claude/daedalus/audit/."
        )
    return session


def _run_sessions(root: Path, run_id: str) -> list[str]:
    if not TRAIN_ID.fullmatch(run_id):
        raise TokenError(
            f"--run {run_id!r} is not a train id (YYYYMMDD-HHMMSS). "
            "Next: pass --session <id> for a run outside a train."
        )
    try:
        state = load_state(root, run_id)
    except TrainStateError as exc:
        raise TokenError(str(exc)) from exc
    sessions = [audit_session(state)]
    bounds = state.get(AUDIT_BOUNDS)
    sessions += [str(k) for k in bounds] if isinstance(bounds, dict) else []
    found = [s for s in dict.fromkeys(sessions) if s and SESSION_ID.fullmatch(s)]
    if not found:
        raise TokenError(
            f"train {run_id} names no audit session. "
            "Next: pass --session <id> with the session the train ran in."
        )
    return found


def report(root: Path, session: str | None, run_id: str | None) -> str:
    if session is not None:
        runs, files = session_runs(_session_arg(session), root)
        if not files:
            raise TokenError(
                f"no agent transcript names session {session} under {projects_dir()}. "
                "Next: check the session id; Claude Code removes old transcripts."
            )
        return render(_merge(runs), f"session {session}")
    assert run_id is not None
    sessions = _run_sessions(root, run_id)
    picked: list[Run] = []
    for each in sessions:
        picked += [r for r in session_runs(each, root)[0] if r.run_id == run_id]
    if not picked:
        raise TokenError(
            f"no agent transcript under {projects_dir()} belongs to run {run_id} "
            f"(sessions {', '.join(sessions)}). Next: check the run id; Claude Code removes "
            "old transcripts."
        )
    return render(_merge(picked), f"run {run_id}, sessions {', '.join(sessions)}")


def _charter(root: Path) -> Path | None:
    try:
        config = load_config(str(root))
    except ConfigError as exc:
        raise TokenError(str(exc)) from exc
    return (root / config.charter_root).resolve() if config.charter_root else None


def saved_path(root: Path, run_id: str) -> Path:
    # Plan 11 A item 2: the Charter reports folder when declared, else the run's scratch folder.
    charter = _charter(root)
    if charter is not None:
        return charter / "reports" / f"{date.today().isoformat()}-tokens-{run_id}.md"
    return root / "docs" / ".tmp" / "daedalus" / run_id / "tokens.md"


def saved_files(root: Path) -> list[Path]:
    charter = _charter(root)
    files = sorted((charter / "reports").glob("*-tokens-*.md")) if charter else []
    return files + sorted((root / "docs" / ".tmp" / "daedalus").glob("*/tokens.md"))


def total_rows(text: str) -> list[str]:
    # Plan 11 A item 3: a saved file's total rows; any row of the fixed width with phase total.
    rows = []
    for line in text.splitlines():
        match = _ROW.match(line.strip())
        cells = [c.strip() for c in match.group(1).split("|")] if match else []
        if len(cells) == len(COLUMNS) and cells[2] == TOTAL:
            rows.append(table_row(list(cells)))
    return rows


def history(root: Path) -> str:
    files = saved_files(root)
    rows = [row for path in files for row in total_rows(path.read_text(encoding="utf-8"))]
    if not rows:
        return (
            "no saved token report found. Next: run token_economy.py report --run <run id> "
            "--save after a run.\n"
        )
    return "\n".join(["# Token history", "", LEGEND, "", *header(), *rows]) + "\n"


def audit_lines(session: str, root: Path, records: list[dict[str, object]]) -> list[str]:
    # Plan 11 A item 2: the audit report's token section; it never fails the audit report.
    lines = ["## Token economy", ""]
    try:
        runs, files = session_runs(session, root, records)
    except (OSError, UnicodeDecodeError) as exc:
        return lines + [f"token totals not shown: the transcripts could not be read ({exc})."]
    if not files:
        return lines + [
            f"no agent transcript found for session {session} under {projects_dir()}; "
            "token totals not shown."
        ]
    lines += header()
    for run in _merge(runs):
        lines += [totals_row(run), mean_row(run, "unit")]
    return lines


def _write(text: str, out: str, cwd: str) -> Path:
    # Plan 11 A: the audit report's --out guard and writer, never a second implementation.
    from audit_report import ReportError, _out_target, _write_report

    try:
        target = _out_target(out, cwd)
        _write_report(target, text)
    except ReportError as exc:
        raise TokenError(str(exc)) from exc
    return target


def main(argv: list[str]) -> int:
    args = _parse(argv)
    try:
        root = root_info(args.cwd)[0]
        if args.command == "history":
            sys.stdout.write(history(root))
            return 0
        if args.save and args.run is None:
            raise TokenError(
                "--save writes one run's table and needs a run id, not a session id. "
                "Next: pass --run with the train id, or name a file with --out."
            )
        text = report(root, args.session, args.run)
        out = str(saved_path(root, args.run)) if args.save else args.out
        if out is None:
            sys.stdout.write(text)
        else:
            print(f"wrote {_write(text, out, args.cwd)}")
        return 0
    except TokenError as exc:
        print(f"token_economy: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(
            f"token_economy: could not read or write ({exc}). "
            "Next: check that the transcripts are readable and the output path is writable.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

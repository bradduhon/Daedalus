#!/usr/bin/env python3
# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import NoReturn

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import atomic, narrow  # noqa: E402
from lib.audit import (  # noqa: E402
    SESSION_ID,
    AuditLockError,
    project_data_dir,
    read_log,
    root_info,
)
from lib.controls import Control, ControlsError, failure_line  # noqa: E402
from lib.controls import load as load_controls  # noqa: E402
from verify_audit_chain import NOT_UTF8, verify_lines  # noqa: E402

# 22: the --help text, kept below the future import as a plain string.
DESCRIPTION = (
    "Render a Markdown digest of one session's audit chain after verifying it. "
    "The chain is verified first; a broken chain prints the verifier's message and exits 1. "
    "Default session is the newest *.jsonl under <repo>/.claude/daedalus/audit/ (0010)."
)
_OK = re.compile(r"OK: (\d+) records, chain intact, head=([0-9a-f]{64})")
_STATUS = (
    re.compile(r"\[STATUS: [A-Z_]+\]"),
    re.compile(r"\[VERDICT: [A-Z]+\]"),
    re.compile(r"\[STANDARDS: [A-Z]+\]"),
)
_TOOLS = ("Write", "Edit", "Bash")
_EDIT_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
_REFUSALS = ("block", "ask")
_HOOK_PREFIX = re.compile(r"([A-Za-z][A-Za-z0-9_.-]{0,63}): ")
_MD_SPECIAL = re.compile(r"([\\`*_\[\]()!#|~])")
TIMELINE_CHARS = 120
STATUS_CHARS = 200


class ReportError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.exit(1, f"audit_report: {message}. Next: run with --help for the usage.\n")


def _parse(argv: list[str]) -> argparse.Namespace:
    parser = _Parser(prog="audit_report.py", description=DESCRIPTION, allow_abbrev=False)
    parser.add_argument("--session")
    parser.add_argument("--cwd", "--repo", dest="cwd", default=os.getcwd())
    parser.add_argument("--out")
    # 6.2: the control cost table alone, after the same chain check.
    parser.add_argument("--controls", action="store_true")
    args = parser.parse_args(argv)
    args.cwd = os.path.abspath(args.cwd)
    if not os.path.isdir(args.cwd):
        parser.exit(
            1,
            f"audit_report: --cwd {args.cwd} is not an existing directory. "
            "Next: pass the repo directory whose session you want to report.\n",
        )
    return args


def _session_path(cwd: str, session: str | None) -> Path:
    if root_info(cwd)[1] != "git":
        raise ReportError(
            f"{cwd} is not inside a git repository. Next: run from the repo whose "
            "session you want to report."
        )
    audit_dir = project_data_dir(cwd) / "audit"
    if not audit_dir.is_dir():
        raise ReportError(
            f"no audit directory at {audit_dir}. Next: run a Claude Code session with the "
            "plugin loaded in this repo, then report it."
        )
    if session is None:
        sessions = sorted(audit_dir.glob("*.jsonl"), key=lambda p: (p.stat().st_mtime, p.name))
        if not sessions:
            raise ReportError(
                f"{audit_dir} holds no session logs. Next: run a Claude Code session with the "
                "plugin loaded in this repo, then report it."
            )
        return sessions[-1]
    if not SESSION_ID.fullmatch(session):
        raise ReportError(
            f"--session must match [A-Za-z0-9_-]+ (got {session!r}). "
            f"Next: list {audit_dir} and pass an existing session id."
        )
    path = audit_dir / f"{session}.jsonl"
    if not path.is_file():
        raise ReportError(
            f"no session log {path}. Next: list {audit_dir} and pass an existing session id."
        )
    return path


def _read_lines(path: Path) -> list[str]:
    # issue 10: the read waits on the writer's lock, so an append in flight reads whole.
    try:
        return read_log(path).splitlines(keepends=True)
    except UnicodeDecodeError as exc:
        raise ReportError(NOT_UTF8.format(path=path)) from exc
    except AuditLockError as exc:
        raise ReportError(str(exc)) from exc


def md_escape(value: Any, limit: int | None = None) -> str:
    # 8.6: agent text is untrusted; cut, then HTML and Markdown escape so it renders inert.
    text = "" if value is None else str(value)
    if limit is not None:
        text = text[:limit]
    text = _MD_SPECIAL.sub(r"\\\1", html.escape(text, quote=False))
    return " ".join(text.splitlines())


def _timeline(records: list[dict[str, Any]]) -> list[str]:
    agents: dict[str, dict[str, Any]] = {}
    for rec in records:
        if rec.get("event") not in ("SubagentStart", "SubagentStop") or not rec.get("agent_id"):
            continue
        row = agents.setdefault(
            str(rec["agent_id"]),
            {"type": rec.get("agent_type"), "start": None, "stop": None, "head": None},
        )
        if rec["event"] == "SubagentStart":
            row["start"] = rec.get("seq")
        else:
            row["stop"], row["head"] = rec.get("seq"), rec.get("last_message_head")
    lines = [
        "## Subagent timeline",
        "",
        "| agent_id | agent_type | start seq | stop seq | last message |",
        "|---|---|---|---|---|",
    ]
    for agent_id, row in agents.items():
        start = "-" if row["start"] is None else row["start"]
        stop = "open" if row["stop"] is None else row["stop"]
        head = md_escape(row["head"], TIMELINE_CHARS)
        lines.append(
            f"| {md_escape(agent_id)} | {md_escape(row['type'])} | {start} | {stop} | {head} |"
        )
    return lines


def _tool_table(records: list[dict[str, Any]]) -> list[str]:
    counts: dict[tuple[str, str], Counter[str]] = {}
    for rec in records:
        if rec.get("event") != "PreToolUse" or rec.get("tool_name") not in _TOOLS:
            continue
        key = (str(rec.get("agent_type")), str(rec["tool_name"]))
        counts.setdefault(key, Counter())[str(rec.get("decision"))] += 1
    lines = [
        "## Write, Edit and Bash calls",
        "",
        "| agent_type | tool | allow | block |",
        "|---|---|---|---|",
    ]
    for (agent_type, tool), tally in sorted(counts.items()):
        lines.append(f"| {md_escape(agent_type)} | {tool} | {tally['allow']} | {tally['block']} |")
    return lines


def _blocks(records: list[dict[str, Any]]) -> list[str]:
    lines = ["## Blocks", ""]
    for rec in records:
        if rec.get("decision") in _REFUSALS:
            ask = " (ask)" if rec.get("decision") == "ask" else ""
            lines.append(
                f"- seq {rec.get('seq')} {md_escape(rec.get('agent_type'))} "
                f"{md_escape(rec.get('tool_name'))}{ask}: {md_escape(rec.get('reason'))}"
            )
    if len(lines) == 2:
        lines.append("none")
    return lines


def _status_lines(records: list[dict[str, Any]]) -> list[str]:
    lines = ["## Status lines", ""]
    for rec in records:
        for field in ("last_message_head", "reason"):
            text = rec.get(field)
            if not isinstance(text, str):
                continue
            for line in text.splitlines():
                if any(p.search(line) for p in _STATUS):
                    lines.append(
                        f"- seq {rec.get('seq')} {md_escape(rec.get('agent_type'))}: "
                        f"{md_escape(line.strip(), STATUS_CHARS)}"
                    )
    if len(lines) == 2:
        lines.append("none")
    return lines


def _totals(records: list[dict[str, Any]]) -> list[str]:
    tally = Counter(str(rec.get("event")) for rec in records)
    lines = ["## Totals by event", "", "| event | records |", "|---|---|"]
    lines.extend(f"| {md_escape(event)} | {n} |" for event, n in sorted(tally.items()))
    return lines


def _hook_of(rec: dict[str, Any]) -> str:
    # 0105: an ask is its own row beside the same hook's blocks.
    reason = rec.get("reason")
    match = _HOOK_PREFIX.match(reason) if isinstance(reason, str) else None
    hook = match.group(1) if match else "unprefixed"
    return f"{hook} (ask)" if rec.get("decision") == "ask" else hook


def _seconds(start: Any, end: Any) -> float | None:
    try:
        return (
            datetime.fromisoformat(str(end)) - datetime.fromisoformat(str(start))
        ).total_seconds()
    except (TypeError, ValueError):
        return None


def _fmt(seconds: float | None) -> str:
    return "none" if seconds is None else f"{seconds:.1f}"


def _until_allowed(
    pre: list[dict[str, Any]], origin: dict[str, Any], tools: tuple[str, ...] | None = None
) -> str:
    # 6.2: seconds from origin to the same agent's next allowed call, optionally of these tools.
    seq = narrow.integer(origin, "seq", 0)
    for rec in pre:
        if narrow.integer(rec, "seq", 0) <= seq or rec.get("agent_id") != origin.get("agent_id"):
            continue
        if rec.get("decision") == "allow" and (tools is None or rec.get("tool_name") in tools):
            return _fmt(_seconds(origin.get("ts"), rec.get("ts")))
    return "none"


def _control_rows() -> dict[str, Control]:
    try:
        return load_controls()
    except ControlsError as exc:
        raise ReportError(str(exc)) from exc


def _controls(records: list[dict[str, Any]]) -> list[str]:
    # 6.2: hook names, agent types, tools and timings only; no reason body or reply text.
    pre = [r for r in records if r.get("event") == "PreToolUse"]
    blocks = [r for r in pre if r.get("decision") in _REFUSALS]
    tally = Counter((_hook_of(r), str(r.get("agent_type"))) for r in blocks)
    lines = ["## Control cost", "", "### Blocks per hook", ""]
    lines += ["| hook | agent_type | blocks |", "|---|---|---|"]
    lines += [f"| {md_escape(h)} | {md_escape(a)} | {n} |" for (h, a), n in sorted(tally.items())]
    lines += ["", "### Failure behind each blocking hook", ""]
    rows = _control_rows()
    for hook in sorted({h.removesuffix(" (ask)") for h, _ in tally}):
        # pin B2 -> B6: the Phase 3 contradiction item reads one failure line per hook.
        lines += [f"- {md_escape(hook)}", f"  {failure_line(hook, rows)}"]
    lines += ["", "### Seconds from each block to that agent's next allowed call", ""]
    lines += ["| seq | agent_type | hook | tool | seconds |", "|---|---|---|---|---|"]
    for rec in blocks:
        cells = [rec.get("agent_type"), _hook_of(rec), rec.get("tool_name")]
        named = " | ".join(md_escape(c) for c in cells)
        lines.append(f"| {rec.get('seq')} | {named} | {_until_allowed(pre, rec)} |")
    lines += ["", "### Seconds from agent start to its first allowed Write or Edit", ""]
    lines += ["| agent_id | agent_type | seconds |", "|---|---|---|"]
    for start in (r for r in records if r.get("event") == "SubagentStart" and r.get("agent_id")):
        named = f"{md_escape(start['agent_id'])} | {md_escape(start.get('agent_type'))}"
        lines.append(f"| {named} | {_until_allowed(pre, start, _EDIT_TOOLS)} |")
    judged = [r.get("judge_ms") for r in pre]
    timed = [float(ms) for ms in judged if isinstance(ms, (int, float))]
    lines.append("")
    if timed:
        lines.append(f"mean judge time: {sum(timed) / len(timed):.1f} ms over {len(timed)} calls")
    else:
        lines.append("mean judge time: no PreToolUse record carries judge_ms")
    return lines


def render(path: Path, controls_only: bool = False) -> str:
    # 8.6: one read; verify and render the same lines so the header describes the rows shown.
    lines = _read_lines(path)
    ok, message = verify_lines(lines)
    if not ok:
        raise ReportError(message)
    match = _OK.fullmatch(message)
    if match is None:
        raise ReportError(
            f"unexpected verifier output {message!r}. Next: report this line as a Daedalus bug."
        )
    count, head = int(match.group(1)), match.group(2)
    records = [json.loads(raw) for raw in lines if raw.strip()]
    header = ["# Daedalus audit report", "", f"session: {md_escape(path.stem)}"]
    header.extend((f"records: {count}", f"head={head}"))
    if records and records[0].get("project_root"):
        header.append(f"project_root: {md_escape(records[0]['project_root'])}")
    if controls_only:
        sections = [header, _controls(records)]
    else:
        sections = [
            header,
            _timeline(records),
            _tool_table(records),
            _blocks(records),
            _controls(records),
            _status_lines(records),
            _totals(records),
        ]
    return "\n\n".join("\n".join(s) for s in sections) + "\n"


def _in_data_dir(path: Path) -> bool:
    # 0010: case-folded so a case-insensitive mount (/mnt/c) cannot spell its way past.
    parts = [part.casefold() for part in path.parts]
    return any(parts[i : i + 2] == [".claude", "daedalus"] for i in range(len(parts) - 1))


def _out_target(out: str, cwd: str) -> Path:
    not_file = "Next: pass a file path, not a directory."
    if out == "-":
        raise ReportError("--out - is not stdout here. Next: omit --out to print to stdout.")
    # 8.6: raw-string checks first; a trailing separator or `.` makes islink look through a link.
    if not out or out.endswith((os.sep, "/")):
        raise ReportError(f"--out {out!r} is empty or ends with a separator. {not_file}")
    if out.split("/")[-1].split(os.sep)[-1] in (".", ".."):
        raise ReportError(f"--out {out} ends in a . or .. component. {not_file}")
    # 8.6: abspath collapses . and .. without following links, so islink sees the real final name.
    target = Path(os.path.abspath(out))
    if os.path.islink(target):
        raise ReportError(
            f"--out {out} is a symlink. Next: pass a regular file path, not a symlink."
        )
    if target.exists() and not target.is_file():
        raise ReportError(f"--out {out} is not a regular file. {not_file}")
    resolved = target.resolve()
    write_path = target.parent.resolve() / target.name
    data = project_data_dir(cwd).resolve()
    # 0010: any repo's data dir is off limits, not only the --cwd repo's.
    for path in (resolved, write_path):
        if path == data or data in path.parents or _in_data_dir(path):
            raise ReportError(
                f"--out {path} is inside a .claude/daedalus data dir. "
                "Next: write the report outside .claude/daedalus/, for example docs/.tmp/."
            )
    # 8.6: os.replace onto the unresolved final name never follows a link planted after the check.
    return write_path


def _write_report(target: Path, text: str) -> None:
    parent = target.parent
    if parent.exists() and not parent.is_dir():
        raise ReportError(
            f"{parent} is not a directory. Next: pass a path under an existing directory."
        )
    if not parent.is_dir():
        raise ReportError(f"{parent} does not exist. Next: create it or pass another --out.")
    atomic.write_atomic(target, text)


def main(argv: list[str]) -> int:
    args = _parse(argv)
    try:
        path = _session_path(args.cwd, args.session)
        target = None if args.out is None else _out_target(args.out, args.cwd)
        report = render(path, args.controls)
        if target is None:
            sys.stdout.write(report)
        else:
            _write_report(target, report)
            print(f"wrote {target}")
        return 0
    except ReportError as exc:
        print(f"audit_report: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(
            f"audit_report: could not read or write ({exc}). "
            "Next: check that the session log is readable and the --out path is writable.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

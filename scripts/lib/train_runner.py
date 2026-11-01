# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0032, 0069, 0072: the state machine the main session steps through, one Bash call per step.
# Only the session holds the Agent tool, so a dispatch stage prints what to dispatch and waits
# for check-reply. Exits: 0 action taken, 1 stopped with a Next line, 2 routed failure,
# 3 an operator question, 4 waiting for a reply.
from __future__ import annotations

import hashlib
import hmac
import os
import posixpath
import re
import shlex
import subprocess
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from lib import (
    audit_rounds,
    git,
    manifest,
    plan_record,
    train_definition,
    train_state,
    unit_binding,
    workspace,
)
from lib import coder_model as coder_model_lib
from lib.audit import ReplyKeyError, message_hmac, reply_key
from lib.audit_proof import (
    AUDITOR,
    R_BOTH_VERDICTS,
    SUMMARY_DIR,
    TIP,
    VERDICT_APPROVED,
    VERDICT_BOTH,
    VERDICT_REJECTED,
    ProofError,
    auditor_round,
    docs_findings_path,
    docs_keys,
    findings_path,
    hooks_live,
    ledger_parent,
    live_log,
    live_summary,
    newest_log,
    read_chain,
    read_findings,
    round_keys,
    round_verdict,
    tip_admits,
    tip_problem,
    verdict_tip,
)
from lib.config import ConfigError, load_config
from lib.jail import CoderBoundary, _coder_boundary, normalize_agent, protected_reason
from lib.narrow import integer as _int
from lib.narrow import obj as _obj
from lib.narrow import objects as _objects
from lib.narrow import strings as _strings
from lib.narrow import text as _text
from lib.project_root import project_root
from lib.train_definition import (
    _ASK,
    _BACK,
    _CONSULT,
    _PLACEHOLDER,
    _SLUG,
    _STOP,
    DEFINITION_NEXT,
    MAIN,
    OFF_CONTRACT,
    PASS,
    PER_UNIT,
    Definition,
    DefinitionError,
    Origin,
)
from lib.train_summary import LEDGER, LEDGER_PENDING, SummaryError, first_session, write_summary

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
MODE_DEFINED = "defined"
# 0024: the first step proves the hooks live; start cannot, its own call precedes the marker.
STEP_NEEDLE = "daedalus_train.py step"
HOOKS_LIVE = "hooks-live"
QUEUED, DISPATCHED, RETURNED, FAILED, SUPERSEDED = (
    "queued",
    "dispatched",
    "returned",
    "failed",
    "superseded",
)
EXIT_OK, EXIT_STOP, EXIT_ROUTED, EXIT_ASK, EXIT_WAIT = 0, 1, 2, 3, 4
COMPLETE_LINE = "[STATUS: COMPLETE]"
YIELD_PREFIX = "[STATUS: YIELD"
VERDICTS = {
    VERDICT_APPROVED: train_state.APPROVED,
    VERDICT_REJECTED: train_state.REJECTED,
}
VERDICT_NEEDLE = "daedalus_train.py verdict"
# 0083: the Standards Packet is written once to the train's scratch folder after the pick commit.
STANDARDS_FILE = "standards-packet.md"
PACKETS = ("contract", "standards")
PICK_LINE = "Pick ledger ids:"
NOT_CHOSEN = "not chosen"
NEXT_NONE = "Next: none, the run needs nothing from the operator."
NO_RUN = "no Daedalus run is active here. Next: start a new run with /daedalus:run."
_UNIT_HEADING = re.compile(r"### Unit ([A-Za-z0-9][A-Za-z0-9-]*): (.+)")
_HEADING = re.compile(r"#{1,3} ")
_PHASE = re.compile(r"[a-z][a-z-]{0,31}")
_LEDGER_ID = re.compile(r"[0-9]{1,6}(?:-[A-Za-z0-9]{1,16}){0,2}")
_CHOICE_MAX = 200
_SCRIPT = re.compile(r"[a-z0-9_]+\.py")
_SCRIPT_TIMEOUT_S = 900
OUTPUT_QUESTION = (
    "output: this folder is not a git repository, so the train needs a folder for its outputs.",
    "Options: 1) the project's docs folder {docs}, 2) a new folder under /tmp, "
    "3) a folder you name.",
    "Next: ask the operator which folder, then rerun start with --output and that path.",
)


class RunnerError(RuntimeError):
    pass


class NoTrainError(RunnerError):
    pass


@dataclass
class Outcome:
    code: int
    lines: list[str] = field(default_factory=list)


def _seqs(state: dict[str, object]) -> list[int]:
    # 4.6: audit records already checked in; one agent reply checks in once.
    raw = state.get("consumed_records")
    items = raw if isinstance(raw, list) else []
    return [s for s in items if isinstance(s, int) and not isinstance(s, bool)]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run_next(repo: Path, verb: str) -> str:
    return f"Next: move the train on with daedalus_train.py {verb} --repo {repo}"


def _scratch(repo: Path, train_id: str) -> Path:
    return repo / SUMMARY_DIR / train_id


def reply_path(brief: Path) -> Path:
    # 4.7: a reply sits beside its brief, under replies/ with the same stage and number.
    return brief.parent.parent / "replies" / brief.name


def _definition_file(root: Path, plugin_root: Path, name: str) -> tuple[Path, Origin]:
    # issue 52, 0073: the manifest's trains_dir is searched before the plugin's own trains folder.
    loaded = manifest.load(root)
    folder = loaded.trains_dir if loaded is not None else None
    if folder is not None:
        path = root / folder / f"{name}.json"
        if os.path.lexists(path):
            if not path.resolve().is_relative_to(root.resolve()):
                raise DefinitionError(
                    f"the train definition {path} resolves outside the project {root}"
                )
            return path, "project"
    return plugin_root / "trains" / f"{name}.json", "plugin"


def _brief_base(session: Session) -> Path:
    # spec 3.1: a plugin brief resolves from the plugin root, a project brief beside its definition.
    path = session.defn.path.resolve()
    return (
        session.plugin_root if path.is_relative_to(session.plugin_root.resolve()) else path.parent
    )


def _loaded(state: dict[str, object]) -> Definition:
    # 0024: the definition is read once per call and must match the hash start recorded.
    path = Path(_text(state, "definition"))
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RunnerError(
            f"the train definition {path} could not be read ({exc}). "
            "Next: restore the definition file, or stop the train."
        ) from exc
    if _sha256(data) != _text(state, "definition_sha256"):
        raise RunnerError(
            f"the train definition {path} changed after the train started. "
            "Next: stop the train and start it again with the changed definition."
        )
    try:
        return train_definition.load(path)
    except DefinitionError as exc:
        raise RunnerError(f"{exc}. {DEFINITION_NEXT}") from exc


def _stages(defn: Definition) -> list[dict[str, object]]:
    return [{str(k): v for k, v in stage.items()} for stage in defn.stages]


def _feature_on(state: dict[str, object], key: str) -> bool:
    # 0069: an absent ledger switch runs the ledger stages only when start found a ledger.
    value = _obj(state, "features").get(key)
    if key == "ledger" and value is None:
        return _text(state, "ledger_line") not in ("", workspace.LEDGER_NONE, workspace.LEDGER_OFF)
    return bool(value)


def _condition(state: dict[str, object], when: str) -> bool:
    if when.startswith("features."):
        return _feature_on(state, when.removeprefix("features."))
    value = _obj(state, "records").get(when, state.get(when))
    if value is None:
        # 0024: an unknown condition stops the train rather than skipping a guarded stage.
        raise RunnerError(
            f"the stage condition {when} names no recorded field. "
            "Next: fix the when condition in the train definition, then start again."
        )
    return bool(value) and value not in ("false", "0")


def _value(state: dict[str, object], name: str, unit: dict[str, object] | None) -> str | None:
    if unit is not None and name.startswith("unit_"):
        raw: object = unit.get(name.removeprefix("unit_"))
    else:
        raw = _obj(state, "records").get(name, state.get(name))
    if isinstance(raw, bool) or not isinstance(raw, str | int):
        return None
    return str(raw)


def _fill(text: str, state: dict[str, object], unit: dict[str, object] | None) -> str:
    def swap(match: re.Match[str]) -> str:
        value = _value(state, match.group(1), unit)
        if value is None:
            raise RunnerError(
                f"the placeholder {match.group(0)} has no recorded value. "
                "Next: rerun the stage that records it, or stop the train."
            )
        if value.startswith("-"):
            # 0024: a value parsed from an agent reply never becomes a script option.
            raise RunnerError(
                f"the placeholder {match.group(0)} holds {value!r}, which reads as an option. "
                "Next: stop the train and report the reply that recorded this value."
            )
        return value

    return _PLACEHOLDER.sub(swap, text)


def _script_argv(
    stage: dict[str, object],
    state: dict[str, object],
    plugin_root: Path,
    unit: dict[str, object] | None,
) -> list[str]:
    # spec 3.1: a proof script is a plugin script; each word fills alone, so no value splits.
    words = shlex.split(_text(_obj(stage, "proof"), "script"))
    script = plugin_root / "scripts" / (words[0] if words else "")
    if not words or not _SCRIPT.fullmatch(words[0]) or not script.is_file():
        raise RunnerError(
            f"stage {_text(stage, 'id')} proof script is not a script the plugin ships. "
            "Next: name a script under the plugin's scripts folder in the definition."
        )
    return [sys.executable, str(script), *(_fill(word, state, unit) for word in words[1:])]


def _parse_records(text: str, names: list[str], reply: Path | None) -> dict[str, object]:
    found: dict[str, object] = {}
    for name in names:
        if name == "reply_file" and reply is not None:
            found[name] = str(reply)
            continue
        pattern = rf"(?<![A-Za-z0-9_.]){re.escape(name)}\s*[=:]\s*`?([^\s`,;]+)"
        match = re.search(pattern, text)
        if match:
            found[name] = match.group(1)
    return found


def _contract_line(text: str, accepted: list[str]) -> str | None:
    # 0024: the status line ends the reply; a heading form may stand anywhere; a verdict may lead.
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return None
    for want in accepted:
        if lines[-1].startswith(want):
            return want
    for want in accepted:
        if want.startswith("#") and want in lines:
            return want
    for want in accepted:
        if lines[0].startswith(want):
            return want
    return None


@dataclass
class Session:
    repo: Path
    train_id: str
    state: dict[str, object]
    defn: Definition
    plugin_root: Path
    lines: list[str] = field(default_factory=list)
    edits: list[Callable[[dict[str, object]], None]] = field(default_factory=list)

    @property
    def stages(self) -> list[dict[str, object]]:
        return _stages(self.defn)

    def edit(self, change: Callable[[dict[str, object]], None]) -> None:
        change(self.state)
        self.edits.append(change)

    def commit(self) -> None:
        # 0024: deltas replay on a fresh read under the lock, so a script's own writes survive.
        if not self.edits:
            return
        edits = list(self.edits)
        self.edits.clear()

        def replay(state: dict[str, object]) -> None:
            for change in edits:
                change(state)

        self.state = train_state.change(self.repo, self.train_id, replay)


def _active(cwd: Path) -> tuple[Path, str]:
    repo = project_root(cwd.resolve())
    train_id = train_state.active_train(repo)
    if train_id is None:
        raise NoTrainError(
            f"no Daedalus train is active in {repo}. "
            "Next: start one with daedalus_train.py start and the train's name."
        )
    return repo, train_id


def _session(cwd: Path, plugin_root: Path) -> Session:
    repo, train_id = _active(cwd)
    try:
        state = train_state.load(repo, train_id)
    except train_state.TrainStateError as exc:
        raise RunnerError(str(exc)) from exc
    if state.get("mode") != MODE_DEFINED:
        raise RunnerError(
            f"train {train_id} was not started from a definition. "
            "Next: finish it with the workspace commands, or stop it and start a defined train."
        )
    return Session(repo, train_id, state, _loaded(state), plugin_root)


def _log(session: Session, entry: dict[str, object]) -> None:
    def change(state: dict[str, object]) -> None:
        state["stage_log"] = [*_objects(state, "stage_log"), entry]

    session.edit(change)


def _set(session: Session, key: str, value: object) -> None:
    def change(state: dict[str, object]) -> None:
        state[key] = value

    session.edit(change)


def _merge_records(session: Session, found: dict[str, object]) -> None:
    def change(state: dict[str, object]) -> None:
        state["records"] = {**_obj(state, "records"), **found}

    session.edit(change)


def _set_dispatch(session: Session, n_key: tuple[str, int], **fields: object) -> None:
    def change(state: dict[str, object]) -> None:
        items = _objects(state, "dispatches")
        for item in items:
            if (item.get("stage"), item.get("n")) == n_key:
                item.update(fields)
        state["dispatches"] = items

    session.edit(change)


def _halt(session: Session, next_line: str) -> Outcome:
    _set(session, "halted", next_line)
    session.lines.append(
        f"train {session.train_id} is halted; run daedalus_train.py stop to tear it down."
    )
    session.lines.append(next_line)
    return Outcome(EXIT_STOP, session.lines)


def _advance(session: Session, index: int) -> None:
    _set(session, "stage_index", index)
    _set(session, "consults_open", [])


def _route(session: Session, stage: dict[str, object], label: str, route: str) -> Outcome:
    sid = _text(stage, "id")
    stop = _STOP.fullmatch(route)
    if stop is not None or not route:
        text = stop.group(1) if stop else "read the stage output above and stop the train"
        session.lines.append(f"stage {sid}: {label}, so the train stops.")
        return _halt(session, f"Next: {text}")
    back = _BACK.fullmatch(route)
    if back is not None:
        return _back(session, sid, label, back.group(1), int(back.group(2) or "1"))
    ask = _ASK.fullmatch(route)
    if ask is not None:
        session.lines += [
            f"stage {sid}: {label}.",
            f"Ask the operator: {route.removeprefix('ask: ')}",
            # 0149: the gate labels the operator picks from, verbatim.
            "Next: put the question to the operator with the choices `Fix it now`, "
            "`Skip, track or exempt it` and `Stop the run`; run step to retry the stage, "
            "or stop on `Stop the run`.",
        ]
        return Outcome(EXIT_OK, session.lines)
    consult = _CONSULT.fullmatch(route)
    agent = consult.group(1) if consult else route
    _set(session, "consults_open", [*_strings(session.state.get("consults_open")), agent])
    session.lines += [
        f"stage {sid}: {label}.",
        f"Consult: {agent}",
        f"Next: dispatch {agent} with the waiting agent's question, resume that agent with the "
        "answer, save its new reply over the same reply file, then run check-reply again.",
    ]
    return Outcome(EXIT_OK, session.lines)


def _back(session: Session, sid: str, label: str, target: str, rounds: int) -> Outcome:
    key = f"{sid}->{target}"
    used = _int(_obj(session.state, "rounds"), key, 0)
    if used >= rounds:
        session.lines.append(f"stage {sid}: {label}, and the route back to {target} is spent.")
        return _halt(
            session,
            f"Next: the route back to stage {target} ran all {rounds} rounds; read the saved "
            "replies with the operator and decide whether to stop the train.",
        )
    ids = [_text(stage, "id") for stage in session.stages]
    index = ids.index(target)
    later = set(ids[index:])

    def change(state: dict[str, object]) -> None:
        state["rounds"] = {**_obj(state, "rounds"), key: used + 1}
        items = _objects(state, "dispatches")
        for item in items:
            if item.get("stage") in later and item.get("status") in (DISPATCHED, RETURNED):
                item["status"] = SUPERSEDED
        state["dispatches"] = items

    session.edit(change)
    _advance(session, index)
    session.lines += [
        f"stage {sid}: {label}, so the train goes back to stage {target} "
        f"(round {used + 1} of {rounds}).",
        _run_next(session.repo, "step"),
    ]
    return Outcome(EXIT_OK, session.lines)


def _hooks_proven(session: Session) -> bool:
    return any(e.get("stage") == HOOKS_LIVE for e in _objects(session.state, "stage_log"))


def _stage_dispatches(session: Session, sid: str) -> list[dict[str, object]]:
    return [d for d in _objects(session.state, "dispatches") if d.get("stage") == sid]


def _render(
    session: Session,
    stage: dict[str, object],
    unit: dict[str, object] | None,
    coder: str | None = None,
) -> Path:
    sid = _text(stage, "id")
    told = _text(_obj(stage, "scope"), "told")
    template = _brief_base(session) / told
    try:
        text = template.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RunnerError(
            f"the brief template {template} could not be read ({exc}). "
            "Next: restore the template the definition names, or stop the train."
        ) from exc
    packets, hashes = _packet_lines(session)
    blocks = [_fill(text, session.state, unit).rstrip("\n")]
    if packets:
        blocks.append("\n".join(packets))
    section = _unit_section(session, unit)
    if section:
        blocks.append(section)
    reminder = _reminder(unit, hashes)
    if reminder:
        blocks.append(reminder)
    body = "\n\n".join(blocks) + "\n"
    n = len(_stage_dispatches(session, sid)) + 1
    brief = _scratch(session.repo, session.train_id) / "briefs" / f"{sid}-{n}.md"
    try:
        brief.parent.mkdir(parents=True, exist_ok=True)
        reply_path(brief).parent.mkdir(parents=True, exist_ok=True)
        brief.write_text(body, encoding="utf-8")
    except OSError as exc:
        raise RunnerError(
            f"cannot write the brief {brief} ({exc}). "
            f"Next: make the briefs folder {brief.parent} writable, then step again."
        ) from exc
    entry: dict[str, object] = {
        "stage": sid,
        "n": n,
        "agent": _text(stage, "agent"),
        "unit": _text(unit, "name") if unit else None,
        "status": DISPATCHED,
        "brief": str(brief),
        "reply": str(reply_path(brief)),
        "coder": coder,
        **{f"{name}_sha256": value for name, value in hashes.items()},
    }

    def change(state: dict[str, object]) -> None:
        state["dispatches"] = [*_objects(state, "dispatches"), entry]

    session.edit(change)
    return brief


def _read_packet(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise RunnerError(
            f"the {label} {path} could not be read ({exc}). "
            f"Next: write the {label} to {path}, then step again."
        ) from exc


def _packet_lines(session: Session) -> tuple[list[str], dict[str, str]]:
    # 0083: each packet goes to the brief by path and hash, never pasted.
    contract = _text(session.state, "contract_path")
    standards = _scratch(session.repo, session.train_id) / STANDARDS_FILE
    lines: list[str] = []
    hashes: dict[str, str] = {}
    if contract:
        hashes["contract"] = _sha256(_read_packet(Path(contract), "Locked Contract Packet"))
        lines.append(f"Contract: {contract} sha256={hashes['contract']}")
    if contract or os.path.lexists(standards):
        data = _read_packet(standards, "Standards Packet")
        hashes["standards"] = _sha256(data)
        lines.append(f"Standards: {standards} sha256={hashes['standards']}")
        picks = [
            line.strip()
            for line in data.decode("utf-8", errors="replace").splitlines()
            if line.startswith(PICK_LINE)
        ]
        lines.append(picks[-1] if picks else f"{PICK_LINE} none")
    return lines, hashes


def _plan_units(text: str) -> dict[str, tuple[str, str, str]]:
    # 0083: a unit section runs from its heading to the next heading outside a code fence.
    lines = text.splitlines()
    starts: list[int] = []
    fenced = False
    for number, line in enumerate(lines):
        if line.startswith("```"):
            fenced = not fenced
        elif not fenced and _HEADING.match(line):
            starts.append(number)
    found: dict[str, tuple[str, str, str]] = {}
    for position, start in enumerate(starts):
        heading = _UNIT_HEADING.fullmatch(lines[start].rstrip())
        if heading is None:
            continue
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        section = "\n".join(lines[start:end]).rstrip()
        found[heading.group(1).casefold()] = (heading.group(1), heading.group(2).strip(), section)
    return found


def _plan_text(state: dict[str, object], check: bool) -> str | None:
    record = _obj(state, train_state.PLAN)
    path = _text(record, "path")
    if not path:
        return None
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise RunnerError(
            f"the plan {path} could not be read ({exc}). "
            "Next: restore it, then rerun daedalus_train.py plan --path with it."
        ) from exc
    if check and not hmac.compare_digest(_sha256(data), _text(record, "sha256")):
        raise RunnerError(
            f"the plan {path} changed after it was recorded. "
            f"Next: validate it, then rerun daedalus_train.py plan --path {path}."
        )
    return data.decode("utf-8", errors="replace")


def _unit_key(state: dict[str, object], unit: dict[str, object]) -> str:
    return _text(unit, "name").removeprefix(f"{_text(state, 'train_id')}-")


def _unit_section(session: Session, unit: dict[str, object] | None) -> str | None:
    text = _plan_text(session.state, check=True) if unit is not None else None
    if unit is None or text is None:
        return None
    key = _unit_key(session.state, unit)
    found = _plan_units(text).get(key.casefold())
    if found is None:
        raise RunnerError(
            f"the plan names no section '### Unit {key}: <title>' for unit {_text(unit, 'name')}. "
            "Next: add the unit's section, rerun daedalus_train.py plan --path, then step again."
        )
    return found[2]


def _reminder(unit: dict[str, object] | None, hashes: dict[str, str]) -> str | None:
    parts: list[str] = []
    path = _text(unit, "path") if unit is not None else ""
    if path:
        parts.append(
            f"Work only in {path}: every file path and every git pathspec you use is absolute "
            f"or goes through `git -C {path}`. When blocked, commit WIP and return one "
            "`[STATUS: YIELD_*]` line; you will be resumed with the answer."
        )
    if hashes:
        fields = " ".join(f"{name}=<first 12 hex>" for name in hashes)
        parts.append(
            "Check each packet hash with sha256sum before you start; a "
            f"`{COMPLETE_LINE}` line carries {fields}."
        )
    return "Reminder: " + " ".join(parts) if parts else None


def _dispatch_lines(stage: dict[str, object], brief: Path) -> list[str]:
    expect = " or ".join(_strings(_obj(stage, "scope").get("reply")))
    return [f"Dispatch: {_text(stage, 'agent')}", f"Prompt file: {brief}", f"Expect: {expect}"]


def _waiting(session: Session, stage: dict[str, object], open_: list[dict[str, object]]) -> Outcome:
    sid = _text(stage, "id")
    for item in open_:
        session.lines.append(
            f"Waiting: {_text(item, 'agent')} for stage {sid}, prompt {_text(item, 'brief')}"
        )
    replies = ", ".join(_text(item, "reply") for item in open_)
    session.lines.append(
        f"Next: save each reply verbatim with the Write tool to {replies}, then run "
        f"daedalus_train.py check-reply --repo {session.repo} --stage {sid}"
    )
    return Outcome(EXIT_WAIT, session.lines)


def _resume_lines(
    stage: dict[str, object], coder: str, unit: dict[str, object], brief: Path
) -> list[str]:
    expect = " or ".join(_strings(_obj(stage, "scope").get("reply")))
    return [
        f"Resume: {_text(stage, 'agent')} {coder} in worktree {_text(unit, 'path')}",
        f"Prompt file: {brief}",
        f"Expect: {expect}",
    ]


def _warm(session: Session, stage: dict[str, object], unit: dict[str, object], coder: str) -> None:
    # 0086: the coder that built the base resumes on this unit and is rebound to its worktree.
    from lib.unit_binding import rebind

    held = [
        d
        for d in _stage_dispatches(session, _text(stage, "id"))
        if d.get("coder") == coder and d.get("status") == RETURNED
    ]
    from_unit = _text(held[-1], "unit") if held else ""
    refused = rebind(session.repo, session.train_id, coder, from_unit, _text(unit, "name"))
    if refused is not None:
        raise RunnerError(refused)
    brief = _render(session, stage, unit, coder)
    session.lines += _resume_lines(stage, coder, unit, brief)


def _fill_queue(session: Session, stage: dict[str, object]) -> tuple[int, int]:
    # 0072: queued units dispatch up to the concurrency; a stacked unit waits for its base unit.
    sid = _text(stage, "id")
    current = [d for d in _stage_dispatches(session, sid) if d.get("status") != SUPERSEDED]
    returned = {_text(d, "unit"): d for d in current if d.get("status") == RETURNED}
    active = {_text(d, "unit") for d in current if d.get("status") == DISPATCHED}
    busy = {_text(d, "coder") for d in current if d.get("status") == DISPATCHED} - {""}
    units = train_state.units(session.state)
    branches = {_text(u, "branch"): _text(u, "name") for u in units}
    queued = [u for u in units if _text(u, "name") not in set(returned) | active]
    room = max(_int(session.state, "max_concurrent_builders", 5) - len(active), 0)
    started = 0
    for unit in queued:
        base = branches.get(_text(unit, "base"), "")
        if started >= room or (base and base not in returned):
            continue
        coder = _text(returned[base], "coder") if base else ""
        if coder in busy:
            continue  # 0086: the warm coder is on another unit; this one waits for it.
        if coder:
            busy.add(coder)
            _warm(session, stage, unit, coder)
        else:
            session.lines += _dispatch_lines(stage, _render(session, stage, unit))
        started += 1
    return started, len(queued) - started


def _no_units(session: Session, sid: str) -> Outcome:
    session.lines.append(
        f"stage {sid} runs once per unit, and train {session.train_id} records no units. "
        "Next: create each unit worktree with daedalus_workspace.py create, then run step."
    )
    return Outcome(EXIT_STOP, session.lines)


def _per_unit_agent(session: Session, index: int, stage: dict[str, object]) -> Outcome | None:
    sid = _text(stage, "id")
    if not train_state.units(session.state):
        return _no_units(session, sid)
    started, left = _fill_queue(session, stage)
    current = [d for d in _stage_dispatches(session, sid) if d.get("status") != SUPERSEDED]
    open_ = [d for d in current if d.get("status") == DISPATCHED]
    if started:
        return Outcome(EXIT_OK, session.lines)
    if open_:
        return _waiting(session, stage, open_)
    if left:
        session.lines.append(
            f"stage {sid} holds {left} unit(s) whose base unit never returned. "
            "Next: stop the train and rerun it with the base unit fixed."
        )
        return Outcome(EXIT_STOP, session.lines)
    _log(session, {"stage": sid, "outcome": PASS})
    _advance(session, index + 1)
    return None


def _agent_stage(session: Session, index: int, stage: dict[str, object]) -> Outcome | None:
    if stage.get("repeat") == PER_UNIT:
        return _per_unit_agent(session, index, stage)
    open_ = [
        d for d in _stage_dispatches(session, _text(stage, "id")) if d.get("status") == DISPATCHED
    ]
    if open_:
        return _waiting(session, stage, open_)
    session.lines += _dispatch_lines(stage, _render(session, stage, None))
    return Outcome(EXIT_OK, session.lines)


def _script_stage(session: Session, index: int, stage: dict[str, object]) -> Outcome | None:
    sid = _text(stage, "id")
    proof = _obj(stage, "proof")
    units: list[dict[str, object] | None] = (
        list(train_state.units(session.state)) if stage.get("repeat") == PER_UNIT else [None]
    )
    if not units:
        return _no_units(session, sid)
    for unit in units:
        argv = _script_argv(stage, session.state, session.plugin_root, unit)
        try:
            done = subprocess.run(
                argv,
                cwd=session.repo,
                capture_output=True,
                text=True,
                timeout=_SCRIPT_TIMEOUT_S,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            session.lines.append(f"stage {sid}: the proof script did not run ({exc}).")
            return _halt(session, "Next: fix the cause named above, then start the train again.")
        session.lines += [line for line in (done.stdout + done.stderr).splitlines() if line]
        outcome = _text(_obj(proof, "exit"), str(done.returncode))
        who = f" for unit {_text(unit, 'name')}" if unit else ""
        _log(
            session,
            {
                "stage": sid,
                "unit": _text(unit, "name") if unit else None,
                "exit": done.returncode,
                "outcome": outcome or "unmapped",
            },
        )
        if outcome != PASS:
            label = f"exit {done.returncode}{who} is {outcome or 'an exit the proof does not map'}"
            return _route(session, stage, label, _text(_obj(stage, "on_fail"), outcome))
        _merge_records(session, _parse_records(done.stdout, _strings(proof.get("records")), None))
        session.lines.append(f"stage {sid}: exit 0{who}, pass.")
    _advance(session, index + 1)
    session.lines.append(_run_next(session.repo, "step"))
    return Outcome(EXIT_OK, session.lines)


def _enter_phase(session: Session, gate: str, start_gate: str) -> None:
    # 0085: step names the phase by the stage's gate; a choice --phase holds until the gate moves.
    phase = _text(session.state, train_state.PHASE)
    if phase == gate or (phase and gate == start_gate):
        return
    _set(session, train_state.PHASE, gate)
    _set(session, train_state.WEIGHT, NOT_CHOSEN)


def step(cwd: Path, plugin_root: Path = PLUGIN_ROOT) -> Outcome:
    try:
        session = _session(cwd, plugin_root)
    except RunnerError as exc:
        return Outcome(EXIT_STOP, [str(exc)])
    try:
        return _step(session)
    except RunnerError as exc:
        session.lines.append(str(exc))
        return Outcome(EXIT_STOP, session.lines)
    finally:
        session.commit()


def _step(session: Session) -> Outcome:
    halted = _text(session.state, "halted")
    if halted:
        return Outcome(EXIT_STOP, [f"train {session.train_id} is halted.", halted])
    if not _hooks_proven(session):
        try:
            proof = hooks_live(session.repo, STEP_NEEDLE)
        except ProofError as exc:
            return Outcome(EXIT_STOP, [str(exc)])
        _log(session, {"stage": HOOKS_LIVE, "outcome": PASS, "detail": proof})
        session.lines.append(proof)
    stages = session.stages
    index = _int(session.state, "stage_index", 0)
    start_gate = _text(stages[index], "gate") if index < len(stages) else ""
    while index < len(stages):
        stage = stages[index]
        when = _text(stage, "when")
        if when and not _condition(session.state, when):
            _log(session, {"stage": _text(stage, "id"), "outcome": "skipped", "when": when})
            session.lines.append(f"stage {_text(stage, 'id')}: skipped, {when} is off.")
            index += 1
            _advance(session, index)
            continue
        _enter_phase(session, _text(stage, "gate"), start_gate)
        run = _script_stage if _text(stage, "agent") == MAIN else _agent_stage
        outcome = run(session, index, stage)
        if outcome is not None:
            return outcome
        index = _int(session.state, "stage_index", index + 1)
    session.lines += [
        f"train {session.train_id}: every stage of {session.defn.name} has passed.",
        f"Next: close the finished train with daedalus_train.py stop --repo {session.repo} "
        "--reason done",
    ]
    return Outcome(EXIT_OK, session.lines)


Saved = tuple[dict[str, object], Path, str, str]


def _stops_for(
    records: list[dict[str, object]], agent: str, used: set[int]
) -> list[dict[str, object]]:
    return [
        r
        for r in records
        if r.get("event") == "SubagentStop"
        and normalize_agent(str(r.get("agent_type") or "")) == agent
        and r.get("seq") not in used
    ]


def _saved(open_: list[dict[str, object]], key: bytes) -> list[Saved]:
    # SI-7: an unreadable or non-UTF-8 reply raises, and the caller counts it a mismatch.
    found: list[Saved] = []
    for item in open_:
        path = Path(_text(item, "reply"))
        if not os.path.lexists(path):
            continue
        if path.is_symlink():
            raise OSError(f"{path} is a symlink")
        data = path.read_bytes()
        found.append((item, path, message_hmac(key, data), data.decode("utf-8")))
    return found


def _mismatch(session: Session, sid: str, agent: str, why: str) -> Outcome:
    session.lines.append(
        f"stage {sid}: the saved reply does not match what {agent} returned ({why})."
    )
    return _halt(
        session,
        "Next: the saved reply differs from the agent's own reply; stop the train and report "
        "the saved reply file to the operator.",
    )


def check_reply(cwd: Path, stage_id: str, plugin_root: Path = PLUGIN_ROOT) -> Outcome:
    try:
        session = _session(cwd, plugin_root)
    except RunnerError as exc:
        return Outcome(EXIT_STOP, [str(exc)])
    try:
        return _check_reply(session, stage_id)
    except RunnerError as exc:
        session.lines.append(str(exc))
        return Outcome(EXIT_STOP, session.lines)
    finally:
        session.commit()


def _check_reply(session: Session, sid: str) -> Outcome:
    halted = _text(session.state, "halted")
    if halted:
        return Outcome(EXIT_STOP, [f"train {session.train_id} is halted.", halted])
    stages = session.stages
    index = _int(session.state, "stage_index", 0)
    current = _text(stages[index], "id") if index < len(stages) else "none"
    if sid != current:
        raise RunnerError(
            f"stage {sid} is not the current stage; the train is at {current}. "
            "Next: run daedalus_train.py step to see what the train waits for."
        )
    stage = stages[index]
    open_ = [d for d in _stage_dispatches(session, sid) if d.get("status") == DISPATCHED]
    if not open_:
        raise RunnerError(
            f"no dispatch of stage {sid} is waiting for a reply. "
            "Next: run step to see what the train waits for."
        )
    agent = _text(stage, "agent")
    try:
        key = reply_key(str(session.repo), create=False)
        records = read_chain(newest_log(session.repo))
        saved = _saved(open_, key)
    except (ReplyKeyError, ProofError, OSError, UnicodeError) as exc:
        return _mismatch(session, sid, agent, str(exc))
    if not saved:
        paths = ", ".join(_text(d, "reply") for d in open_)
        return _mismatch(session, sid, agent, f"no reply was saved at {paths}")
    stops = _stops_for(records, agent, set(_seqs(session.state)))
    newest = stops[-1].get("seq") if stops else "none"
    for position, record in reversed(list(enumerate(stops))):
        digest = record.get("last_message_hmac")
        for item, path, mac, text in saved:
            if not (isinstance(digest, str) and hmac.compare_digest(digest, mac)):
                continue
            # 4.6: one open dispatch checks in only the agent's newest reply, never an older one.
            if not stage.get("parallel") and position != len(stops) - 1:
                why = f"a newer unread {agent} stop record, seq {newest}, follows the saved reply"
                return _mismatch(session, sid, agent, why)
            # 4.6: more unread replies than open dispatches means one was dispatched off-train.
            if len(stops) > len(open_):
                why = f"{len(stops)} unread {agent} stop records for {len(open_)} open dispatch(es)"
                return _mismatch(session, sid, agent, why)
            return _checked_in(session, index, stage, item, path, text, record)
    return _mismatch(session, sid, agent, f"newest unread {agent} stop record: seq {newest}")


def _integration_tip(repo: Path, train_id: str) -> str:
    branch = f"daedalus/{train_id}"
    try:
        return workspace._out(repo, "rev-parse", "--verify", f"refs/heads/{branch}").strip()
    except workspace.WorkspaceError as exc:
        raise RunnerError(f"the integration branch {branch} has no readable tip: {exc}") from exc


def _verdict_record(status: str, tip: str, round_: int, seq: object) -> dict[str, object]:
    # 0089: the one verdict shape A2's push gate reads, from check-reply and the verdict command.
    return {"status": status, "tip": tip, "round": round_, "seq": seq}


def _packet_refusal(item: dict[str, object], text: str, line: str) -> str | None:
    # 0083, 0091: on the keyed reply, a COMPLETE line echoes the packet hashes its brief named.
    want = {name: _text(item, f"{name}_sha256") for name in PACKETS}
    want = {name: value for name, value in want.items() if value}
    if not want or not line.startswith(COMPLETE_LINE):
        return None
    status = [row.strip() for row in text.splitlines() if row.strip().startswith(COMPLETE_LINE)]
    got: dict[str, str] = {}
    for name in want:
        found = re.findall(rf"(?<![A-Za-z0-9_]){name}=([0-9a-f]{{12}})\b", status[-1])
        if found:
            got[name] = found[-1]
    if all(hmac.compare_digest(got.get(name, ""), value[:12]) for name, value in want.items()):
        return None
    shown = " ".join(f"{name}={got.get(name, 'missing')}" for name in want)
    return f"carries {shown}, which do not match the packets its brief named"


def _checked_in(
    session: Session,
    index: int,
    stage: dict[str, object],
    item: dict[str, object],
    path: Path,
    text: str,
    record: dict[str, object],
) -> Outcome:
    sid, n_key = _text(stage, "id"), (_text(item, "stage"), _int(item, "n", 0))
    line = _contract_line(text, _strings(_obj(stage, "scope").get("reply")))
    verdict = next((v for k, v in VERDICTS.items() if line and line.startswith(k)), None)
    # 0089: the tip is read before any edit, so a failed read leaves the reply unconsumed.
    tip = _integration_tip(session.repo, session.train_id) if verdict else ""
    seq = record.get("seq")
    _set(session, "consumed_records", [*_seqs(session.state), seq])
    # 0086: the coder's binding id, so a unit stacked on this one resumes the same coder.
    coder = record.get("agent_id")
    if isinstance(coder, str) and coder:
        _set_dispatch(session, n_key, coder=coder)
    unit = _text(item, "unit")
    who = f" for unit {unit}" if unit else ""
    refusal = (
        "ends with none of its contract lines"
        if line is None
        else _packet_refusal(item, text, line)
    )
    if refusal is not None or line is None:
        _set_dispatch(session, n_key, status=FAILED, outcome=OFF_CONTRACT)
        _log(session, {"stage": sid, "unit": unit or None, "outcome": OFF_CONTRACT})
        route = _text(_obj(stage, "on_fail"), OFF_CONTRACT) or _text(
            session.defn.raw, "off_contract"
        )
        _route(session, stage, f"the reply{who} {refusal}", route)
        return Outcome(EXIT_STOP, session.lines)
    if verdict is not None:
        prior = _int(_obj(session.state, train_state.VERDICT), "round", 0)
        _set(session, train_state.VERDICT, _verdict_record(verdict, tip, prior + 1, seq))
    key = train_definition.reply_route_key(stage, line)
    if key is not None:
        route = _text(_obj(stage, "on_fail"), key)
        keep = _CONSULT.fullmatch(route) is not None
        if not keep:
            _set_dispatch(session, n_key, status=FAILED, outcome=key, line=line)
        _log(session, {"stage": sid, "unit": unit or None, "outcome": key, "line": line})
        _route(session, stage, f"the reply{who} is {line}", route)
        return Outcome(EXIT_ROUTED, session.lines)
    found = _parse_records(text, _strings(_obj(stage, "proof").get("records")), path)
    _set_dispatch(session, n_key, status=RETURNED, outcome=PASS, line=line, records=found)
    _log(session, {"stage": sid, "unit": unit or None, "outcome": PASS, "line": line})
    session.lines.append(f"stage {sid}{who}: {line}, pass.")
    if stage.get("repeat") != PER_UNIT:
        _merge_records(session, found)
        _advance(session, index + 1)
        session.lines.append(_run_next(session.repo, "step"))
        return Outcome(EXIT_OK, session.lines)
    started, _ = _fill_queue(session, stage)
    if not started:
        session.lines.append(_run_next(session.repo, "step"))
    return Outcome(EXIT_OK, session.lines)


def start(cwd: Path, train: str, output: str | None, plugin_root: Path = PLUGIN_ROOT) -> Outcome:
    if not _SLUG.fullmatch(train):
        return Outcome(
            EXIT_STOP,
            [
                f"train name {train!r} is not a lowercase name. "
                "Next: pass a train name such as build."
            ],
        )
    root = project_root(cwd.resolve())
    try:
        path, origin = _definition_file(root, plugin_root, train)
        defn = train_definition.load(path)
    except manifest.ManifestError as exc:
        return Outcome(EXIT_STOP, [str(exc)])
    except DefinitionError as exc:
        return Outcome(EXIT_STOP, [f"check 1: {exc}", DEFINITION_NEXT])
    defects = train_definition.validate(defn, plugin_root, origin)
    if defects:
        return Outcome(EXIT_STOP, [*defects, DEFINITION_NEXT])
    try:
        features = manifest.features(root)
        config = load_config(path=root / ".claude" / "daedalus" / "config.json")
    except (manifest.ManifestError, ConfigError) as exc:
        return Outcome(EXIT_STOP, [str(exc)])
    kind = manifest.scope_kind(root, features)
    scopes = _strings(defn.raw.get("scopes"))
    if kind not in scopes:
        return Outcome(
            EXIT_STOP,
            [
                f"train {defn.name} runs only in {' or '.join(scopes)} scope, and {root} is "
                f"{kind} scope. Next: run it in a {scopes[0]} project, or set the scope key in "
                "the features object of service-manifest.json."
            ],
        )
    try:
        if kind == "repository":
            repo = workspace.repo_root(root)
            lines = workspace.begin(repo, features.ledger)
        else:
            if output is None:
                docs = root / "docs"
                return Outcome(EXIT_ASK, [line.format(docs=docs) for line in OUTPUT_QUESTION])
            repo = root
            lines = workspace.begin_folder(root, features.ledger)
    except workspace.LedgerQuestion as exc:
        return Outcome(EXIT_ASK, str(exc).splitlines())
    except workspace.WorkspaceError as exc:
        return Outcome(EXIT_STOP, [str(exc)])
    return _record_start(repo, defn, kind, features, output, config.max_concurrent_builders, lines)


def _record_start(
    repo: Path,
    defn: Definition,
    kind: str,
    features: manifest.Features,
    output: str | None,
    builders: int,
    lines: list[str],
) -> Outcome:
    train_id = train_state.active_train(repo)
    if train_id is None:
        return Outcome(
            EXIT_STOP,
            [
                *lines,
                f"begin left no train marker in {repo}. Next: run start again for this train.",
            ],
        )
    out_dir: str | None = None
    if output is not None:
        try:
            out_dir = str(workspace.checked_output(repo, output, "start"))
        except workspace.WorkspaceError as exc:
            return Outcome(EXIT_STOP, [*lines, str(exc)])
    train_state.update(
        repo,
        train_id,
        mode=MODE_DEFINED,
        definition=str(defn.path.resolve()),
        definition_sha256=_sha256(defn.path.read_bytes()),
        scope_kind=kind,
        features=asdict(features),
        output_dir=out_dir,
        max_concurrent_builders=builders,
        stage_index=0,
        records={},
        dispatches=[],
        stage_log=[],
        rounds={},
        consults_open=[],
        consumed_records=[],
        halted=None,
    )
    shown = f", outputs in {out_dir}" if out_dir else ""
    return Outcome(
        EXIT_OK,
        [
            *lines,
            f"definition: {defn.name} v{defn.version}, {len(defn.stages)} stages, {kind} scope, "
            f"up to {builders} coders at once{shown}",
            f"{_run_next(repo, 'step')}; its first call proves the audit hooks are live.",
        ],
    )


def allowed_dispatch(state: dict[str, object]) -> tuple[set[str], str, str]:
    # 4.8, AC-3: open fresh dispatches of the current stage only, its gate's consults, and
    # consult routes opened since the stage began; a warm resume is no Agent call.
    defn = _loaded(state)
    stages = _stages(defn)
    index = _int(state, "stage_index", 0)
    if index >= len(stages):
        # 73, spec 3.5: after the last stage only a reaudit or resume consult is admitted.
        return set(_strings(state.get("consults_open"))), "none", "none"
    sid, gate = _text(stages[index], "id"), _text(stages[index], "gate")
    allowed = {
        _text(d, "agent")
        for d in _objects(state, "dispatches")
        if d.get("stage") == sid and d.get("status") == DISPATCHED and not d.get("coder")
    }
    allowed |= set(_strings(_obj(defn.raw, "consults").get(gate)))
    allowed |= set(_strings(state.get("consults_open")))
    return allowed, sid, gate


def _recorded(
    cwd: Path, edit: Callable[[Path, str], list[str]], stopped: str | None = None
) -> Outcome:
    # spec 3.3, 3.5: a main-session command on a stopped train names the workspace resume first.
    try:
        repo, train_id = _active(cwd)
        return Outcome(EXIT_OK, edit(repo, train_id))
    except NoTrainError as exc:
        if stopped is None:
            return Outcome(EXIT_STOP, [str(exc)])
        root = project_root(cwd.resolve())
        return Outcome(
            EXIT_STOP,
            [
                f"no Daedalus train is active in {root}. Next: run daedalus_workspace.py resume "
                f"--repo {root} to mark the stopped train active, then rerun {stopped}."
            ],
        )
    except (RunnerError, train_state.TrainStateError) as exc:
        return Outcome(EXIT_STOP, [str(exc)])


def _one_line(label: str, value: str, command: str = "choice") -> str:
    text = value.strip()
    if not text or len(text) > _CHOICE_MAX or not text.isprintable():
        raise RunnerError(
            f"--{label} must be one printable line of 1 to {_CHOICE_MAX} characters. "
            f"Next: rerun {command} with one short printable line for --{label}."
        )
    return text


def choice(
    cwd: Path,
    chose: str,
    over: str,
    cost: str,
    phase: str | None = None,
    driver: str | None = None,
    rule: str | None = None,
) -> Outcome:
    # 0085: every choice is printed and recorded before it is taken.
    def edit(repo: Path, train_id: str) -> list[str]:
        entry: dict[str, object] = {
            "chose": _one_line("chose", chose),
            "over": _one_line("over", over),
            "cost": _one_line("cost", cost),
        }
        # 0129: the priorities fields keep the same one-line rule as the fields above.
        for label, value in (("driver", driver), ("rule", rule)):
            if value is not None:
                entry[label] = _one_line(label, value)
        if phase is not None:
            if not _PHASE.fullmatch(phase):
                raise RunnerError(
                    f"--phase {phase!r} is not a lowercase phase name. "
                    "Next: rerun choice with a phase such as plan or implementation."
                )
            entry["phase"] = phase

        def change(state: dict[str, object]) -> None:
            state[train_state.CHOICES] = [*_objects(state, train_state.CHOICES), entry]
            if phase is not None:
                state[train_state.PHASE] = phase
                state[train_state.WEIGHT] = entry["chose"]

        train_state.change(repo, train_id, change)
        line = f"Chose {entry['chose']} over {entry['over']}: {entry['cost']}"
        if "driver" in entry or "rule" in entry:
            line += f" (driver {entry.get('driver', 'none')}, rule {entry.get('rule', 'none')})"
        return [line]

    return _recorded(cwd, edit)


def record_plan(cwd: Path, path: Path) -> Outcome:
    # 0086, 0088: the plan gate reads this record; a changed file no longer matches its hash.
    def edit(repo: Path, train_id: str) -> list[str]:
        target = (path if path.is_absolute() else repo / path).resolve()
        if not target.is_file():
            raise RunnerError(
                f"no plan file at {target}. "
                "Next: write the plan with the plan skill (/daedalus:plan), then rerun plan."
            )
        try:
            sha = _sha256(target.read_bytes())
        except OSError as exc:
            raise RunnerError(
                f"cannot read the plan {target} ({exc}). "
                "Next: make the plan file readable, then rerun plan."
            ) from exc

        def change(state: dict[str, object]) -> None:
            record = {"path": str(target), "sha256": sha}
            if state.get(train_state.PLAN) == record:
                return
            # 0156, 0089: a no-contract lock holds only for the plan it was taken on.
            if state.get("lock_sha") and state.get("packet_version") is None:
                raise RunnerError(
                    f"train {train_id} locked with no contract on its skipped plan, so a new "
                    "plan is refused. Next: stop the train with daedalus_train.py stop, then "
                    "start a new train with the new plan."
                )
            state[train_state.PLAN] = record
            # 0156: a new plan voids an earlier skip; the contract subcommand judges it again.
            state.pop(train_state.CONTRACT_SKIP, None)

        train_state.change(repo, train_id, change)
        return [f"plan: {target} sha256={sha}"]

    return _recorded(cwd, edit)


WIRE_NONE = "wire: none"
_CONTRACT_RERUN = "record the plan with daedalus_train.py plan --path, then rerun contract"


def _wire_none(text: str) -> bool:
    # agents/planner.md: the `wire: none` line sits below the plan block, outside any fence.
    fenced, plan_open, after = False, False, False
    for line in (raw.strip() for raw in text.splitlines()):
        if line.startswith("```"):
            if fenced:
                after = after or plan_open
                fenced, plan_open = False, False
            else:
                fenced, plan_open = True, line == "```plan"
        elif after and not fenced and line == WIRE_NONE:
            return True
    return False


_CONTROL = manifest.Manifest(plan_record.CONTROL_PATHS)


def _skip_boundary(repo: Path) -> CoderBoundary | str:
    # 0182: the coder jail's protected list; an unreadable config fails closed as a reason.
    try:
        return _coder_boundary(str(repo), load_config(str(repo)))
    except ConfigError as exc:
        return str(exc)


def _contract_reason(plan: plan_record.Plan, text: str, repo: Path) -> str | None:
    # 0156, 0182: the first failed test of the contract skip row, or None when the contract skips.
    if len(plan.units) != 1:
        return f"{len(plan.units)} units, more than 1"
    files = plan.units[0].files
    if len(files) > plan_record.CONTRACT_SKIP_FILES:
        return f"{len(files)} files, more than {plan_record.CONTRACT_SKIP_FILES}"
    for name in files:
        # 0187: `.` names the whole repository, a folder like `./`.
        if any(c in name for c in "*?[") or name.endswith("/") or posixpath.normpath(name) == ".":
            return f"unit names a file glob or folder: {name}"
        rel = posixpath.normpath(name)
        if posixpath.isabs(rel) or rel.split("/")[0] == "..":
            return f"unit names a path outside the repository: {name}"
        if manifest.path_hit(_CONTROL, rel):
            return f"unit touches a control path: {name}"
    boundary = _skip_boundary(repo)
    if isinstance(boundary, str):
        return f"protected paths unknown: {boundary}"
    for name in files:
        if protected_reason(posixpath.normpath(name), name, boundary) is not None:
            return f"unit touches a protected path: {name}"
    if plan.pins:
        return "a pin line"
    return None if _wire_none(text) else f"no {WIRE_NONE} line"


def contract(cwd: Path) -> Outcome:
    # 0156, 0182: a one-unit plan of at most 3 non-control files, no pin and `wire: none` skips.
    def edit(repo: Path, train_id: str) -> list[str]:
        state = train_state.load(repo, train_id)
        before = _plan_text(state, True)
        if before is None:
            raise RunnerError(f"train {train_id} records no plan. Next: {_CONTRACT_RERUN}.")
        path = Path(_text(_obj(state, train_state.PLAN), "path"))
        try:
            plan = plan_record.load(path)
        except plan_record.PlanError as exc:
            raise RunnerError(f"{exc} Next: {_CONTRACT_RERUN}.") from exc
        text = _plan_text(state, True) or ""
        if plan.defects:
            raise RunnerError(
                f"the plan {path} has {len(plan.defects)} defect(s): {' '.join(plan.defects)} "
                f"Next: fix the plan, then {_CONTRACT_RERUN}."
            )
        reason = _contract_reason(plan, text, repo)
        if reason is not None:
            return [f"contract: required ({reason})"]
        train_state.update(repo, train_id, **{train_state.CONTRACT_SKIP: True})
        return ["contract: skip"]

    return _recorded(cwd, edit)


CODERS = "coders"


def _unit_record(state: dict[str, object], train_id: str, unit_id: str) -> dict[str, object]:
    for unit in train_state.units(state):
        label = workspace._unit_label(train_id, str(unit.get("name")))
        if not train_state.is_audit_unit(unit) and label.casefold() == unit_id.casefold():
            return unit
    raise RunnerError(
        f"train {train_id} records no worktree for unit {unit_id}. "
        "Next: create the unit worktree with daedalus_workspace.py create first."
    )


def coder_model(cwd: Path, unit_id: str) -> Outcome:
    # 0187, issue 115: the coder model of one unit dispatch, recorded on the unit with its reason.
    def edit(repo: Path, train_id: str) -> list[str]:
        try:
            models = load_config(cwd=str(repo)).coder_models
            state = train_state.load(repo, train_id)
            plan = workspace._recorded_plan(state)
            records = workspace._audit_records(repo, state)
        except (ConfigError, workspace.WorkspaceError) as exc:
            raise RunnerError(str(exc)) from exc
        planned = next((u for u in plan.units if u.id.casefold() == unit_id.casefold()), None)
        if planned is None:
            raise RunnerError(
                f"the recorded plan names no unit {unit_id}. "
                "Next: pass a unit id the recorded plan names."
            )
        unit = _unit_record(state, train_id, unit_id)
        refuted = workspace.unit_refutations(records, Path(str(unit["path"])))
        tier, reason = coder_model_lib.coder_tier(planned.files, plan_record.CONTROL_PATHS, refuted)
        entry: dict[str, object] = {"model": models[tier], "tier": tier, "reason": reason}
        prior = _objects(unit, CODERS)
        # 0187: a repeated call records nothing new and never frees the unit twice.
        if prior and {k: prior[-1].get(k) for k in entry} == entry:
            return [models[tier], _coder_line(unit_id, entry)]
        if tier == coder_model_lib.ESCALATED:
            why = unit_binding.release(repo, train_id, str(unit["name"]))
            if why is not None:
                raise RunnerError(why)

        def add(state: dict[str, object]) -> None:
            raw = state.get("units")
            for each in raw if isinstance(raw, list) else []:
                if isinstance(each, dict) and each.get("name") == unit["name"]:
                    each[CODERS] = [*_objects(each, CODERS), entry]

        train_state.change(repo, train_id, add)
        return [models[tier], _coder_line(unit_id, entry)]

    return _recorded(cwd, edit)


def _coder_line(unit_id: str, entry: dict[str, object]) -> str:
    return f"coder {unit_id}: {entry['model']} ({entry['reason']})"


def _exemption_args(ledger_id: str, finding: str, tracking: str, other: str | None) -> None:
    if not _LEDGER_ID.fullmatch(ledger_id):
        raise RunnerError(
            f"ledger id {ledger_id!r} is not a ledger id such as 0101-DAE-PLT. "
            "Next: rerun exception with the id charter-docs returned."
        )
    if not finding.strip() or not finding.isprintable():
        raise RunnerError(
            "--finding must name one finding id of the rejected round. "
            "Next: rerun exception with a finding id from the round's findings file."
        )
    if tracking not in train_state.TRACKING:
        raise RunnerError(
            f"--tracking {tracking!r} is not one of {', '.join(train_state.TRACKING)}. "
            "Next: rerun exception with the operator's tracking answer."
        )
    if (tracking == "other") != (other is not None):
        raise RunnerError(
            "--other carries the operator's own words, and only with --tracking other. "
            "Next: rerun exception with --tracking other --other <words>, or without --other."
        )
    if other is not None:
        _one_line("other", other, "exception")


def _exemption_entry(
    ledger_id: str, tip: str, tracking: str, other: str | None
) -> dict[str, object]:
    entry: dict[str, object] = {"ledger_id": ledger_id, "tip": tip, "tracking": tracking}
    if other is not None:
        entry["other"] = other.strip()
    return entry


def _docs_exemption(
    repo: Path,
    train_id: str,
    state: dict[str, object],
    current: str,
    ledger_id: str,
    finding: str,
) -> tuple[dict[str, object], list[str]] | None:
    # 0131, 0133: a refuted docs claim's exemption lands in the docs record, bound to its tip.
    docs = train_state.record(state, train_state.DOCS_VERDICT)
    if docs.get("status") != train_state.REFUTED:
        return None
    try:
        keys = docs_keys(repo, train_id, state)
    except ProofError as exc:
        raise RunnerError(str(exc)) from exc
    if finding not in keys:
        return None
    tip = _text(docs, "tip")
    # 0131: the exemption ruling's one ledger commit may sit on top of the docs record's tip.
    if tip != current and ledger_parent(repo, current) != tip:
        raise RunnerError(
            f"the docs record names tip {tip[:12]}, not the integration tip {current[:12]}. "
            "Next: record the docs verdict again with daedalus_train.py verdict --gate docs."
        )
    if finding in train_state.record(docs, "exemptions"):
        raise RunnerError(
            f"docs claim {finding} already carries an exemption. "
            "Next: record the next finding; one exemption stands per finding."
        )
    return docs, keys


def record_exception(
    cwd: Path, ledger_id: str, finding: str, tracking: str, other: str | None = None
) -> Outcome:
    # 0133, 0139: one exemption per finding of the recorded rejected round, with its tracking.
    def edit(repo: Path, train_id: str) -> list[str]:
        _exemption_args(ledger_id, finding, tracking, other)
        current = _integration_tip(repo, train_id)
        out: list[str] = []

        def change(state: dict[str, object]) -> None:
            docs = _docs_exemption(repo, train_id, state, current, ledger_id, finding)
            if docs is not None:
                docs_record, keys = docs
                granted = train_state.record(docs_record, "exemptions")
                granted[finding] = _exemption_entry(
                    ledger_id, _text(docs_record, "tip"), tracking, other
                )
                docs_record["exemptions"] = granted
                state[train_state.DOCS_VERDICT] = docs_record
                out.append(
                    f"exemption recorded finding={finding} gate=docs ledger={ledger_id} "
                    f"tracking={tracking} remaining={len([k for k in keys if k not in granted])}"
                )
                return
            verdict = train_state.record(state, train_state.VERDICT)
            round_ = _int(verdict, "round", 0)
            if verdict.get("status") != train_state.REJECTED or round_ < 1:
                raise RunnerError(
                    f"train {train_id} records no rejected verdict, so no finding needs an "
                    "exemption. Next: record the rejected round with daedalus_train.py verdict."
                )
            judged = _text(verdict, "tip")
            problem = tip_problem(repo, judged, current)
            if problem is not None:
                raise RunnerError(f"{problem}. Next: run the security audit on {current[:12]}.")
            try:
                keys = round_keys(repo, train_id, state, round_)
            except ProofError as exc:
                raise RunnerError(str(exc)) from exc
            if finding not in keys:
                raise RunnerError(
                    f"finding {finding!r} is not in the rejected round {round_}. "
                    "Next: rerun exception with a finding id from the round's findings file."
                )
            exemptions = train_state.record(state, train_state.EXEMPTIONS)
            granted = train_state.record(exemptions, str(round_))
            if finding in granted:
                raise RunnerError(
                    f"finding {finding} of round {round_} already carries an exemption. "
                    "Next: record the next finding; one exemption stands per finding."
                )
            granted[finding] = _exemption_entry(ledger_id, judged, tracking, other)
            exemptions[str(round_)] = granted
            state[train_state.EXEMPTIONS] = exemptions
            left = len([key for key in keys if key not in granted])
            out.append(
                f"exemption recorded finding={finding} round={round_} ledger={ledger_id} "
                f"tracking={tracking} remaining={left}"
            )

        train_state.change(repo, train_id, change)
        return out

    return _recorded(cwd, edit)


# 73, spec 3.3: reaudit {judged, tip, round}; spec 3.5: resume {summary}, pin D1 -> E4 ledger.
REAUDIT, RESUME = "reaudit", "resume"
AUDITOR_AGENT, ORCHESTRATOR_AGENT = "auditor", "orchestrator"


def _open_consult(state: dict[str, object], agent: str) -> None:
    consults = _strings(state.get("consults_open"))
    state["consults_open"] = consults if agent in consults else [*consults, agent]


def _close_consult(state: dict[str, object], agent: str) -> None:
    state["consults_open"] = [a for a in _strings(state.get("consults_open")) if a != agent]


def reaudit(cwd: Path) -> Outcome:
    # 73, spec 3.3: one recovery round when the approved tip moved; the main session runs it.
    def edit(repo: Path, train_id: str) -> list[str]:
        state = train_state.load(repo, train_id)
        verdict = train_state.record(state, train_state.VERDICT)
        if verdict.get("status") != train_state.APPROVED:
            raise RunnerError(
                f"train {train_id} records no approved verdict, so no audited tip moved. "
                "Next: run the security audit round of the Build Train (/daedalus:run)."
            )
        current = _integration_tip(repo, train_id)
        if _text(train_state.record(state, REAUDIT), "tip") == current:
            raise RunnerError(
                f"a recovery round already ran on tip {current[:12]}. Next: put each finding to "
                "the operator as its own question; no second recovery round runs on one tip."
            )
        judged = verdict.get("tip")
        if tip_admits(repo, train_id, state, judged, current) is None:
            raise RunnerError(
                f"the approved verdict already admits the tip {current[:12]}. Next: no recovery "
                f"round is needed; run the push proof verify_audit_chain.py --approved {train_id} "
                f"--repo {repo} again."
            )
        round_ = derived_round(state)

        def change(fresh: dict[str, object]) -> None:
            fresh[REAUDIT] = {"judged": judged, "tip": current, "round": round_}
            _open_consult(fresh, AUDITOR_AGENT)

        train_state.change(repo, train_id, change)
        return [f"reaudit round={round_} tip={current}"]

    return _recorded(cwd, edit, REAUDIT)


def _unmerged(repo: Path, train_id: str, state: dict[str, object]) -> list[str]:
    # spec 3.5: each unit the recorded plan names has a branch on daedalus/<train-id>.
    try:
        named = sorted(workspace._plan_ids(state))
    except workspace.WorkspaceError as exc:
        raise RunnerError(str(exc)) from exc
    branches = {
        workspace._unit_label(train_id, _text(u, "name")).casefold(): _text(u, "branch")
        for u in train_state.units(state)
    }
    integration = f"refs/heads/daedalus/{train_id}"
    missing: list[str] = []
    for uid in named:
        branch = branches.get(uid, "")
        try:
            # 0024: a recorded branch never becomes a git option.
            done = (
                bool(branch)
                and not branch.startswith("-")
                and (
                    git.run(["merge-base", "--is-ancestor", branch, integration], repo).returncode
                    == 0
                )
            )
        except (OSError, git.GitTimeout) as exc:
            raise RunnerError(
                f"git merge-base did not finish for unit {uid} ({exc}). "
                "Next: check git from your own shell, then rerun resume."
            ) from exc
        if not done:
            missing.append(uid)
    return missing


def resume(cwd: Path) -> Outcome:
    # 3, spec 3.5: a train stopped before its ledger commit resumes for that one step.
    def edit(repo: Path, train_id: str) -> list[str]:
        state = train_state.load(repo, train_id)
        ledger = train_state.record(state, LEDGER)
        if ledger:
            raise RunnerError(
                f"train {train_id} already records its ledger commit "
                f"{_text(ledger, 'sha')[:12]}. Next: run the Push Train (/daedalus:run push)."
            )
        if train_state.record(state, RESUME):
            raise RunnerError(
                f"a ledger resume of train {train_id} is already open. Next: wait for the "
                "resumed orchestrator's TRAIN_COMPLETE; it runs the ledger step once."
            )
        missing = _unmerged(repo, train_id, state)
        if missing:
            raise RunnerError(
                f"unit(s) {', '.join(missing)} of the recorded plan are not merged into "
                f"daedalus/{train_id}. Next: resume the Build Train at its finish step; the "
                "ledger resume runs only after every plan unit merged."
            )
        rel = (SUMMARY_DIR / f"{train_id}-summary.md").as_posix()
        try:
            text = (repo / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise RunnerError(
                f"cannot read the summary {rel} ({exc}). Next: resume the Build Train; it "
                "writes the summary before its ledger step."
            ) from exc
        if not any(line.strip().startswith(LEDGER_PENDING) for line in text.splitlines()):
            raise RunnerError(
                f"the summary {rel} holds no `{LEDGER_PENDING}` line, so its ledger step ran. "
                "Next: run the Push Train (/daedalus:run push)."
            )

        def change(fresh: dict[str, object]) -> None:
            fresh[RESUME] = {"summary": rel}
            _open_consult(fresh, ORCHESTRATOR_AGENT)

        train_state.change(repo, train_id, change)
        return [f"resume ledger train={train_id} summary={rel}"]

    return _recorded(cwd, edit, RESUME)


def record_ledger(cwd: Path, sha: str, ids: str) -> Outcome:
    # pin D1 -> E4: the ledger commit the summary's Ledger ids line reads.
    def edit(repo: Path, train_id: str) -> list[str]:
        if not TIP.fullmatch(sha):
            raise RunnerError(
                f"--sha {sha!r} is not a 40 lowercase hex commit sha. "
                "Next: rerun ledger with the sha of charter-docs' COMMITTED line."
            )
        names = ids.split(",")
        if len(set(names)) != len(names) or not all(_LEDGER_ID.fullmatch(n) for n in names):
            raise RunnerError(
                f"--ids {ids!r} is not a comma-separated list of distinct ledger ids such as "
                "0101-DAE-PLT. Next: rerun ledger with the ids of charter-docs' COMMITTED line."
            )

        def change(state: dict[str, object]) -> None:
            state[LEDGER] = {"sha": sha, "ids": names}
            if train_state.record(state, RESUME):
                _close_consult(state, ORCHESTRATOR_AGENT)

        train_state.change(repo, train_id, change)
        return [f"ledger recorded sha={sha} ids={','.join(names)}"]

    return _recorded(cwd, edit)


def _auditor_seq(repo: Path, train_id: str, status: str, seq: int | None) -> tuple[int, str | None]:
    # 0089: the verdict is read from this session's auditor reply records, never from the caller.
    try:
        log, _ = live_log(repo, VERDICT_NEEDLE)
        records = read_chain(log)
    except ProofError as exc:
        raise RunnerError(str(exc)) from exc
    state = train_state.load(repo, train_id)
    # issue 60: the reader walks the log of the session the train's bound belongs to.
    session = train_state.audit_session(state) or log.stem
    if session != log.stem:
        raise RunnerError(
            f"the train's audit bound belongs to session {session}, not this session "
            f"{log.stem}. Next: run verify_audit_chain.py --hooks-live --repo {repo}, then run "
            "the security audit again."
        )
    start = train_state.session_bound(state, session)
    if start is None:
        raise RunnerError(
            f"the state of train {train_id} records no start_seq to bound the auditor search. "
            f"Next: run verify_audit_chain.py --hooks-live --repo {repo}, then run the security "
            "audit again."
        )
    want = VERDICT_APPROVED if status == train_state.APPROVED else VERDICT_REJECTED
    # 0089, issue 57: only the newest auditor turn after start_seq counts.
    turn = auditor_round(records, start)
    verdict, found = round_verdict(turn)
    if verdict == VERDICT_BOTH:
        raise RunnerError(R_BOTH_VERDICTS.format(seq=found))
    problem = None
    if not turn:
        problem = f"audit log {log.name} holds no {AUDITOR} reply after seq {start}"
    elif seq is not None and seq not in {r.get("seq") for r in turn}:
        problem = f"seq {seq} is not the newest {AUDITOR} reply, which is seq {found}"
    elif verdict != want:
        problem = (
            f"the newest {AUDITOR} reply, seq {found}, carries "
            f"{verdict or 'no verdict line'}, not {want}"
        )
    if problem is not None:
        raise RunnerError(
            f"{problem}. Next: run the security audit; the verdict is recorded from the "
            "auditor's reply, never typed."
        )
    return found, verdict_tip(turn, found)


def derived_round(state: dict[str, object]) -> int:
    # 67: a pre-D1 approval wrote no audit_rounds entry, so the recorded verdict round counts too.
    recorded = _int(train_state.record(state, train_state.VERDICT), "round", 0)
    rounds = audit_rounds.next_round(train_state.record(state, train_state.AUDIT_ROUNDS))
    return max(rounds, recorded + 1 if recorded > 0 else 1)


def _round_findings(
    repo: Path, train_id: str, status: str, round_: int, path: Path
) -> dict[str, audit_rounds.Finding]:
    # pin C3 -> C1: the auditor's list for this round, at its one path; approved lists none.
    want = findings_path(repo, train_id, round_)
    given = os.path.normpath(path if path.is_absolute() else repo / path)
    if given != str(want) or want.is_symlink() or not want.is_file():
        raise RunnerError(
            f"--findings {path} is not the round {round_} finding list file. "
            f"Next: have the auditor write {want}, then rerun verdict with --findings {want}."
        )
    try:
        found = read_findings(want)
    except ProofError as exc:
        raise RunnerError(str(exc)) from exc
    if (status == train_state.REJECTED) != bool(found):
        raise RunnerError(
            f"the {status} round {round_} lists {len(found)} findings in {want}, off-contract. "
            "Next: have the auditor list each blocking finding for a rejection and none for "
            "an approval."
        )
    return found


def record_verdict(
    cwd: Path,
    status: str,
    given_round: int | None = None,
    seq: int | None = None,
    tip: str | None = None,
    findings: Path | None = None,
) -> Outcome:
    # 0089, 59: records the tip the auditor judged; 0109, 0133: and the round's finding map.
    def edit(repo: Path, train_id: str) -> list[str]:
        if status not in (train_state.APPROVED, train_state.REJECTED):
            raise RunnerError(
                f"verdict status {status!r} is neither approved nor rejected. "
                "Next: rerun verdict with the status the auditor's verdict line names."
            )
        # 67: the round comes from train state; --round stays accepted and must agree.
        round_ = derived_round(train_state.load(repo, train_id))
        if given_round is not None and given_round != round_:
            raise RunnerError(
                f"--round {given_round} is not round {round_}, one more than the highest round "
                f"the train recorded. Next: rerun verdict with --round {round_} or no --round."
            )
        if seq is not None and seq < 0:
            raise RunnerError(
                f"audit seq {seq} is out of range. "
                "Next: rerun verdict with the auditor's stop record seq, or with no --seq."
            )
        named_tip = tip is not None and TIP.fullmatch(tip) is not None
        if (tip is not None or status == train_state.APPROVED) and not named_tip:
            raise RunnerError(
                f"--tip {tip} is not a 40-hex tip; an approved verdict must name one. "
                "Next: rerun verdict with --tip set to the tip= value on the auditor's "
                "verdict line."
            )
        if status == train_state.REJECTED and findings is None:
            want = findings_path(repo, train_id, round_)
            raise RunnerError(
                f"a rejected verdict needs the round {round_} finding list, and this call passed "
                f"no --findings. Next: have the auditor write {want}, then rerun verdict with "
                f"--findings {want}."
            )
        listed = _round_findings(repo, train_id, status, round_, findings) if findings else None
        found, named = _auditor_seq(repo, train_id, status, seq)
        current = _integration_tip(repo, train_id)
        if tip is not None:
            if named != tip:
                raise RunnerError(
                    f"the {AUDITOR} verdict names tip {named or 'none'}, not --tip {tip}. "
                    "Next: rerun verdict with the tip= value of the auditor's verdict line."
                )
            problem = tip_problem(repo, tip, current)
            if problem is not None:
                raise RunnerError(f"{problem}. Next: run the security audit on {current[:12]}.")
        judged = tip or current

        def change(state: dict[str, object]) -> None:
            if derived_round(state) != round_:
                raise RunnerError(
                    f"another verdict call recorded round {round_} first. "
                    "Next: rerun verdict with no --round."
                )
            state[train_state.VERDICT] = _verdict_record(status, judged, round_, found)
            # 73: the recovery round's auditor consult closes with its verdict.
            if train_state.record(state, REAUDIT):
                _close_consult(state, AUDITOR_AGENT)
            rounds = train_state.record(state, train_state.AUDIT_ROUNDS)
            # 67: an approval without a list records an empty round, so the next round derives.
            if listed is None:
                rounds[str(round_)] = {}
                state[train_state.AUDIT_ROUNDS] = rounds
                return
            rounds[str(round_)] = {
                f.key: {"severity": f.severity, "class": f.kind} for f in listed.values()
            }
            state[train_state.AUDIT_ROUNDS] = rounds

        train_state.change(repo, train_id, change)
        if status == train_state.REJECTED and listed is not None:
            # 0133: a record only; the orchestrator puts each finding to the operator.
            return [f"recorded rejected round={round_} findings={len(listed)}"]
        return [f"Verdict {status} recorded on tip {judged[:12]} (round {round_})"]

    return _recorded(cwd, edit)


def _docs_claims(
    repo: Path, train_id: str, status: str, findings: Path | None
) -> dict[str, object]:
    # 0131: a refuted verdict names its claim file at its one path; a verified one names none.
    want = docs_findings_path(repo, train_id)
    if (status == train_state.REFUTED) != (findings is not None):
        raise RunnerError(
            f"a {status} docs verdict takes --findings only when refuted. Next: rerun verdict "
            f"--gate docs with --findings {want} for refuted, or with no --findings for verified."
        )
    if findings is None:
        return {}
    given = os.path.normpath(findings if findings.is_absolute() else repo / findings)
    if given != str(want):
        raise RunnerError(
            f"--findings {findings} is not the docs claim file. "
            f"Next: write the refuted claims to {want}, then rerun verdict --gate docs."
        )
    try:
        listed = read_findings(want)
    except ProofError as exc:
        raise RunnerError(str(exc)) from exc
    if not listed:
        raise RunnerError(
            f"the refuted docs verdict lists no claims in {want}. "
            "Next: write one line per refuted claim, then rerun verdict --gate docs."
        )
    return {f.key: {"severity": f.severity, "class": f.kind} for f in listed.values()}


def _docs_unit(train_id: str, state: dict[str, object]) -> dict[str, object]:
    name = f"{train_id}{train_state.DOCS_SUFFIX}"
    unit = next((u for u in train_state.units(state) if u.get("name") == name), None)
    if unit is None:
        raise RunnerError(
            f"train {train_id} records no docs worktree {name}. "
            "Next: run the documentation stage, then rerun verdict --gate docs."
        )
    return unit


def _docs_judged(
    repo: Path, train_id: str, state: dict[str, object], judged: str, current: str
) -> None:
    # 0131: the Docs tip the verifier judged is the docs branch head, merged into the tip.
    rerun = "rerun verdict --gate docs with --judged set to the Docs tip: sha the verifier judged"
    if not TIP.fullmatch(judged):
        raise RunnerError(
            f"--judged {judged!r} is not a 40 lowercase hex commit sha. Next: {rerun}."
        )
    branch = _text(_docs_unit(train_id, state), "branch")
    try:
        head = workspace._out(repo, "rev-parse", "--verify", f"refs/heads/{branch}").strip()
    except workspace.WorkspaceError as exc:
        raise RunnerError(f"the docs branch {branch} has no readable head: {exc}") from exc
    if workspace._run(repo, "merge-base", "--is-ancestor", head, current).returncode:
        raise RunnerError(
            f"the docs branch head {head[:12]} is not merged into the integration tip "
            f"{current[:12]}. Next: merge the docs branch with daedalus_workspace.py finish, "
            f"then {rerun}."
        )
    if judged != head:
        raise RunnerError(
            f"the merged docs commits end at {head[:12]}, not at the judged docs tip "
            f"{judged[:12]}. Next: send the docs branch to the verifier again, then {rerun}."
        )


def _docs_verified(repo: Path, train_id: str, state: dict[str, object]) -> None:
    # 0121, 0131: a verified docs verdict is read from the verifier's reply, never typed.
    unit = _docs_unit(train_id, state)
    try:
        verified = workspace.unit_verified(
            workspace._audit_records(repo, state), Path(_text(unit, "path"))
        )
    except workspace.WorkspaceError as exc:
        raise RunnerError(str(exc)) from exc
    if not verified:
        raise RunnerError(
            f"no verifier reply ends {workspace.VERIFIED} for the docs worktree "
            f"{_text(unit, 'path')}. Next: run the verifier's claims pass, then rerun verdict "
            "--gate docs."
        )


def record_docs_verdict(
    cwd: Path,
    status: str,
    tip: str | None = None,
    findings: Path | None = None,
    judged: str | None = None,
) -> Outcome:
    # 0131, 0134: the docs verifier's verdict on the integration tip, beside the security verdict.
    def edit(repo: Path, train_id: str) -> list[str]:
        if status not in (train_state.VERIFIED, train_state.REFUTED):
            raise RunnerError(
                f"docs verdict status {status!r} is neither verified nor refuted. "
                "Next: rerun verdict --gate docs with the status the verifier's line names."
            )
        if judged is not None and status != train_state.VERIFIED:
            raise RunnerError(
                "--judged belongs to a verified docs verdict only. "
                "Next: rerun verdict --gate docs without --judged."
            )
        current = _integration_tip(repo, train_id)
        if tip is not None and tip != current:
            raise RunnerError(
                f"--tip {tip} is not the integration tip {current}. Next: merge the docs branch "
                "with daedalus_workspace.py finish, then rerun verdict --gate docs with no --tip."
            )
        claims = _docs_claims(repo, train_id, status, findings)
        state = train_state.load(repo, train_id)
        if status == train_state.VERIFIED:
            _docs_verified(repo, train_id, state)
        if judged is not None:
            _docs_judged(repo, train_id, state, judged, current)
        record: dict[str, object] = {"status": status, "tip": current}
        if judged is not None:
            record["judged"] = judged
        if claims:
            record["findings"] = claims
        train_state.update(repo, train_id, **{train_state.DOCS_VERDICT: record})
        return [f"docs verdict recorded status={status} tip={current[:12]}"]

    return _recorded(cwd, edit)


# spec 6: the bindings file records coder dispatches only (dispatch_binding._dispatch_reason).
BOUND_AGENT = "coder"
BINDINGS_UNREADABLE = (
    "the unit bindings file could not be read. Next: stop the run and start a new one."
)
Bound = dict[str, dict[str, object]]


def _bindings(repo: Path, train_id: str) -> Bound:
    from lib.unit_binding import _read, bindings_path

    return _read(bindings_path(repo, train_id))


def _done(name: str, latest: dict[str, dict[str, object]], bound: Bound) -> bool:
    # spec 4: a merged unit is done whatever its dispatch says; 0086: so is a retired one.
    record = bound.get(name, {})
    if record.get("finished") is True:
        return True
    if name in latest:
        return _text(latest[name], "status") == RETURNED
    return bool(record.get("retired_to"))


def _unit_status(
    unit: dict[str, object],
    latest: dict[str, dict[str, object]],
    labels: dict[str, str],
    by_branch: dict[str, str],
    bound: Bound,
) -> str:
    name = _text(unit, "name")
    dispatch = latest.get(name)
    status = _text(dispatch, "status") if dispatch else ""
    if _done(name, latest, bound):
        return "done"
    if dispatch is None and name in bound:
        # spec 6: a hand-driven recipe leaves no runner dispatch; the bindings file holds the unit.
        return f"running ({BOUND_AGENT})"
    if status == DISPATCHED and dispatch is not None:
        return f"running ({_text(dispatch, 'agent')})"
    if status == FAILED and dispatch is not None:
        yielded = _text(dispatch, "line").startswith(YIELD_PREFIX)
        return "waiting on an answer" if yielded else "stopped"
    base = by_branch.get(_text(unit, "base"), "")
    if base and not _done(base, latest, bound):
        return f"waiting on {labels.get(base, base)}"
    return "queued"


def _listed(header: str, rows: list[str]) -> list[str]:
    return [f"{header}:", *rows] if rows else [f"{header}: none"]


def progress(cwd: Path) -> Outcome:
    # 0085, spec 5.1: the operator view; no sha, agent handle or absolute path reaches it.
    # 0169: the note's sentences say run; script names keep train.
    try:
        repo, train_id = _active(cwd)
        state = train_state.load(repo, train_id)
    except NoTrainError:
        return Outcome(EXIT_OK, [NO_RUN])
    except (RunnerError, train_state.TrainStateError):
        return Outcome(
            EXIT_STOP,
            ["the run state could not be read. Next: run daedalus_train.py state for the cause."],
        )
    try:
        text = _plan_text(state, check=False)
    except RunnerError:
        text = None
    plan = _plan_units(text) if text else {}
    try:
        bound = _bindings(repo, train_id)
    except train_state.TrainStateError:
        return Outcome(EXIT_STOP, [BINDINGS_UNREADABLE])
    # pin C4 -> C7, issue 71: the audit worktree is a train unit, never a line of the note.
    units = [u for u in train_state.units(state) if not train_state.is_audit_unit(u)]
    labels: dict[str, str] = {}
    for unit in units:
        key = _unit_key(state, unit)
        found = plan.get(key.casefold())
        labels[_text(unit, "name")] = found[0] if found else key
    latest: dict[str, dict[str, object]] = {}
    for dispatch in _objects(state, "dispatches"):
        if dispatch.get("status") != SUPERSEDED and _text(dispatch, "unit"):
            latest[_text(dispatch, "unit")] = dispatch
    by_branch = {_text(u, "branch"): _text(u, "name") for u in units}
    phase = _text(state, train_state.PHASE) or "not started"
    lines = [f"Phase: {phase} (weight: {_text(state, train_state.WEIGHT) or NOT_CHOSEN})"]
    open_: list[str] = []
    for unit in units:
        name = _text(unit, "name")
        found = plan.get(_unit_key(state, unit).casefold())
        title = f"{labels[name]} {found[1]}" if found else labels[name]
        status = _unit_status(unit, latest, labels, by_branch, bound)
        lines.append(f"{title}: {status}")
        if status == "waiting on an answer":
            open_.append(f"{labels[name]}: {_text(latest[name], 'line')}")
    open_ += [
        f"consult {agent}: answering a waiting agent"
        for agent in _strings(state.get("consults_open"))
    ]
    choices = [
        f"Chose {_text(c, 'chose')} over {_text(c, 'over')}: {_text(c, 'cost')}"
        for c in _objects(state, train_state.CHOICES)
    ]
    lines += _listed("Choices", choices) + _listed("Open", open_)
    answers = [row for row in open_ if not row.startswith("consult ")]
    if _text(state, "halted"):
        lines.append("Next: the run is halted; tear it down with daedalus_train.py stop.")
    elif answers:
        noun = "item" if len(answers) == 1 else "items"
        lines.append(f"Next: answer the open {noun} above, then run step to retry the stage.")
    else:
        lines.append(NEXT_NONE)
    return Outcome(EXIT_OK, lines)


def state_lines(cwd: Path, plugin_root: Path = PLUGIN_ROOT) -> Outcome:
    try:
        session = _session(cwd, plugin_root)
    except NoTrainError as exc:
        # 4.1: state always exits 0; no train is an answer, not a stop.
        return Outcome(EXIT_OK, [str(exc)])
    except RunnerError as exc:
        return Outcome(EXIT_STOP, [str(exc)])
    stages = session.stages
    index = _int(session.state, "stage_index", 0)
    at = _text(stages[index], "id") if index < len(stages) else "done"
    open_ = [d for d in _objects(session.state, "dispatches") if d.get("status") == DISPATCHED]
    return Outcome(
        EXIT_OK,
        [
            f"train: {session.train_id}  definition: {session.defn.name} v{session.defn.version}",
            f"scope: {_text(session.state, 'scope_kind')}  "
            f"stage: {at} ({min(index + 1, len(stages))} of {len(stages)})",
            f"waiting on: {', '.join(_text(d, 'brief') for d in open_) or 'nothing'}",
            f"halted: {_text(session.state, 'halted') or 'no'}",
        ],
    )


def summary(cwd: Path) -> Outcome:
    # W3.2: the summary from state and the audit logs; this command's record anchors the proof.
    def edit(repo: Path, train_id: str) -> list[str]:
        try:
            return [write_summary(repo, train_id, live_summary(repo).stem)]
        except (ProofError, SummaryError) as exc:
            raise RunnerError(str(exc)) from exc

    return _recorded(cwd, edit, "summary")


def _stop_summary(repo: Path) -> list[str]:
    # W3.2: stop rewrites the summary first; a refusal is shown and never blocks the teardown.
    train_id = train_state.active_train(repo)
    if train_id is None or not train_state.state_path(repo, train_id).is_file():
        return []
    try:
        # 0069: a folder-scope train has no repository to hold a summary.
        if train_state.load(repo, train_id).get("scope_kind") == "folder":
            return []
    except train_state.TrainStateError as exc:
        return [f"summary not written: {exc}"]
    session = first_session(repo, train_id)
    if session is None:
        try:
            session = newest_log(repo).stem
        except ProofError:
            session = None
    try:
        return [write_summary(repo, train_id, session)]
    except (SummaryError, train_state.TrainStateError) as exc:
        return [f"summary not written: {exc}"]


def stop(cwd: Path, reason: str, next_action: str | None) -> Outcome:
    repo = project_root(cwd.resolve())
    written = _stop_summary(repo)
    lines, ok = workspace.stop(repo, reason, next_action)
    return Outcome(EXIT_OK if ok else EXIT_STOP, [*written, *lines])

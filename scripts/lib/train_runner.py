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
import re
import shlex
import subprocess
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from lib import manifest, train_definition, train_state, workspace
from lib.audit import ReplyKeyError, message_hmac, reply_key
from lib.audit_proof import SUMMARY_DIR, ProofError, hooks_live, newest_log, read_chain
from lib.config import ConfigError, load_config
from lib.jail import normalize_agent
from lib.project_root import in_git_work_tree, project_root
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
)

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


def _text(block: dict[str, object], key: str) -> str:
    value = block.get(key)
    return value if isinstance(value, str) else ""


def _obj(block: dict[str, object], key: str) -> dict[str, object]:
    value = block.get(key)
    return {str(k): v for k, v in value.items()} if isinstance(value, dict) else {}


def _objects(block: dict[str, object], key: str) -> list[dict[str, object]]:
    value = block.get(key)
    items = value if isinstance(value, list) else []
    return [{str(k): v for k, v in item.items()} for item in items if isinstance(item, dict)]


def _strings(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _int(block: dict[str, object], key: str, default: int) -> int:
    value = block.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else default


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


def _definition_file(plugin_root: Path, name: str) -> Path:
    return plugin_root / "trains" / f"{name}.json"


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


def _session(cwd: Path, plugin_root: Path) -> Session:
    repo = project_root(cwd.resolve())
    train_id = train_state.active_train(repo)
    if train_id is None:
        raise NoTrainError(
            f"no Daedalus train is active in {repo}. "
            "Next: start one with daedalus_train.py start and the train's name."
        )
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
            "Next: put the question to the operator, then run step to retry the stage "
            "or stop to end the train.",
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
    template = session.plugin_root / told
    try:
        text = template.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RunnerError(
            f"the brief template {template} could not be read ({exc}). "
            "Next: restore the template the definition names, or stop the train."
        ) from exc
    body = _fill(text, session.state, unit)
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
    }

    def change(state: dict[str, object]) -> None:
        state["dispatches"] = [*_objects(state, "dispatches"), entry]

    session.edit(change)
    return brief


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
    while index < len(stages):
        stage = stages[index]
        when = _text(stage, "when")
        if when and not _condition(session.state, when):
            _log(session, {"stage": _text(stage, "id"), "outcome": "skipped", "when": when})
            session.lines.append(f"stage {_text(stage, 'id')}: skipped, {when} is off.")
            index += 1
            _advance(session, index)
            continue
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
    seq = record.get("seq")
    _set(session, "consumed_records", [*_seqs(session.state), seq])
    # 0086: the coder's binding id, so a unit stacked on this one resumes the same coder.
    coder = record.get("agent_id")
    if isinstance(coder, str) and coder:
        _set_dispatch(session, n_key, coder=coder)
    accepted = _strings(_obj(stage, "scope").get("reply"))
    line = _contract_line(text, accepted)
    unit = _text(item, "unit")
    who = f" for unit {unit}" if unit else ""
    if line is None:
        _set_dispatch(session, n_key, status=FAILED, outcome=OFF_CONTRACT)
        _log(session, {"stage": sid, "unit": unit or None, "outcome": OFF_CONTRACT})
        route = _text(_obj(stage, "on_fail"), OFF_CONTRACT) or _text(
            session.defn.raw, "off_contract"
        )
        _route(session, stage, f"the reply{who} ends with none of its contract lines", route)
        return Outcome(EXIT_STOP, session.lines)
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
    path = _definition_file(plugin_root, train)
    try:
        defn = train_definition.load(path)
    except DefinitionError as exc:
        return Outcome(EXIT_STOP, [f"check 1: {exc}", DEFINITION_NEXT])
    defects = train_definition.validate(defn, plugin_root, "plugin")
    if defects:
        return Outcome(EXIT_STOP, [*defects, DEFINITION_NEXT])
    root = project_root(cwd.resolve())
    try:
        features = manifest.features(root)
        config = load_config(path=root / ".claude" / "daedalus" / "config.json")
    except (manifest.ManifestError, ConfigError) as exc:
        return Outcome(EXIT_STOP, [str(exc)])
    kind = features.scope or ("repository" if in_git_work_tree(root) else "folder")
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
        target = Path(output) if Path(output).is_absolute() else repo / output
        try:
            target.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return Outcome(
                EXIT_STOP,
                [
                    *lines,
                    f"cannot create the output folder {target} ({exc}). "
                    "Next: pick a writable folder and rerun start.",
                ],
            )
        out_dir = str(target.resolve())
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
        return set(), "none", "none"
    sid, gate = _text(stages[index], "id"), _text(stages[index], "gate")
    allowed = {
        _text(d, "agent")
        for d in _objects(state, "dispatches")
        if d.get("stage") == sid and d.get("status") == DISPATCHED and not d.get("coder")
    }
    allowed |= set(_strings(_obj(defn.raw, "consults").get(gate)))
    allowed |= set(_strings(state.get("consults_open")))
    return allowed, sid, gate


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


def stop(cwd: Path, reason: str, next_action: str | None) -> Outcome:
    repo = project_root(cwd.resolve())
    lines, ok = workspace.stop(repo, reason, next_action)
    return Outcome(EXIT_OK if ok else EXIT_STOP, lines)

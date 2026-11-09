# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# issue 29, 0044: the coder dispatch, the warm resume rebind and the coder's first-write claim.
# lib.jail imports this module, so lib.jail names are imported at call time.
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from lib import atomic, locks, plan_record, unit_binding, writer_mode
from lib.audit import LOCK_TIMEOUT_S, SESSION_ID
from lib.audit_proof import PUBLIC_DOCS as PUBLIC_DOCS
from lib.audit_proof import SUMMARY_DIR
from lib.config import DEFAULT_MAX_CONCURRENT_BUILDERS
from lib.narrow import integer
from lib.project_root import project_root
from lib.train_scope import policed_outside_train
from lib.train_state import DOCS_SUFFIX as DOCS_SUFFIX
from lib.train_state import TRAIN_ID, TrainStateError, active_train, is_audit_unit
from lib.train_state import load as load_train
from lib.train_state import units as units_of
from lib.unit_binding import claim, rebind, record_dispatch
from lib.workspace import UNMARK_NEXT, before_payload, train_marker

R_NO_TRAIN = (
    "a coder writes only inside a Daedalus train (issue 29). Next: start coders from /daedalus:run."
)
R_WORKTREE_LINE = (
    "a coder dispatched during a train names its unit on exactly one line "
    "'Worktree: <absolute path>' (issue 29). Next: name the unit worktree on one Worktree: line."
)
R_TWO_UNITS = (
    "one command may write into one unit worktree only (issue 29). "
    "Next: write only in the unit worktree you were dispatched to."
)
R_NO_CODER_ID = (
    "the hook input has neither agent_id nor session_id, so the coder cannot be bound "
    "(issue 29). Next: report this hook payload to the operator."
)
R_NOT_PRINTED = (
    "the train runner did not print a dispatch of {agent} for stage {stage}, and {agent} is no "
    "consult agent of gate {gate} (0024). Next: run daedalus_train.py step and dispatch only "
    "the agent it prints, or a consult agent of the current gate."
)
R_NO_PLAN = (
    "a coder starts during a train only after the train's recorded plan validates "
    "(spec 4.1, 0088): {why} Next: run /daedalus:plan to write and record this train's plan, "
    "then dispatch the coder again."
)
R_RESUME_LINE = (
    "a resume that hands a coder a unit names it on exactly one line "
    "'Worktree: <absolute path>' (0086). Next: name the unit worktree on one Worktree: line."
)
R_RESUME_TARGET = (
    "a resume carrying a Worktree: line names the coder in its to field (0086). "
    "Next: address the coder by the agent id its first dispatch returned."
)
R_RESUME_UNBOUND = (
    "coder {coder} holds no unit in train {train}, so a resume cannot move it to unit {unit} "
    "(0086). Next: resume it without the Worktree: line while it is on its first unit, or "
    "dispatch a cold coder for unit {unit}."
)
R_AUDIT_UNIT = (
    "{path} is the audit worktree of train {train}; it holds the auditor's tests, not a coder's "
    "unit (spec 4). Next: name the coder's own unit worktree on the Worktree: line, as "
    "daedalus_workspace.py create printed it."
)
R_DOCS_WORKTREE = (
    "a public docs writer dispatched during train {train} names exactly one line "
    "'Worktree: {docs}', the train's docs worktree, and no other worktree (0134). Next: create "
    "it with daedalus_workspace.py create --name {name} and name it on one Worktree: line."
)
R_DOCS_REBIND = (
    "the docs worktree {name} takes only the writer its own dispatch names, and a resume "
    "never moves an agent onto it (0134). Next: dispatch the writer with one Worktree: "
    "line naming the docs worktree, and resume coders only onto their own units."
)
R_NO_SOURCES = (
    "a writer dispatched with no Worktree: line derives a document, and train {train} has no "
    "frozen sources file at {path} (0190, D.7). Next: freeze the sources first, or name the docs "
    "worktree on one Worktree: line for the public docs."
)
WRITER = writer_mode.WRITER
CODER = "coder"
DISPATCH_TOOLS = frozenset({"Agent", "Task"})
RESUME_TOOLS = frozenset({"SendMessage"})
_WORKTREE_LINE = re.compile(r"Worktree: (/\S+)")
_SHA256 = re.compile(r"[0-9a-f]{64}")
# issue 29: git forms that change a unit's index, history or files; -C names the unit.
_UNIT_GIT_WRITES = frozenset({"add", "stage", "commit", "stash", "restore", "checkout"})


def _step_reason(tool_input: dict[str, object], cwd: str) -> str | None:
    # 4.8, AC-3, AC-6: in a defined train the Agent gate is default deny, scoped to one stage.
    from lib.jail import _train_active, normalize_agent
    from lib.train_runner import MODE_DEFINED, RunnerError, allowed_dispatch

    if not os.path.isabs(cwd) or not _train_active(cwd):
        return None
    repo = project_root(Path(cwd))
    train = active_train(repo)
    if train is None:
        return None
    try:
        state = load_train(repo, train)
        if state.get("mode") != MODE_DEFINED:
            return None
        allowed, stage, gate = allowed_dispatch(state)
    except (TrainStateError, RunnerError) as exc:
        return str(exc)
    raw = str(tool_input.get("subagent_type") or "")
    agent = normalize_agent(raw)
    if agent != raw and agent in allowed:
        return None
    return R_NOT_PRINTED.format(agent=agent or "an unnamed agent", stage=stage, gate=gate)


def _other_train(repo: Path, path: Path, train: str) -> str | None:
    # spec 4.1: a plan under another train's scratch folder never opens this train's gate.
    roots = (repo / SUMMARY_DIR, Path(os.path.realpath(repo / SUMMARY_DIR)))
    for candidate in (Path(os.path.normpath(path)), Path(os.path.realpath(path))):
        for root in roots:
            parts = candidate.relative_to(root).parts if candidate.is_relative_to(root) else ()
            if parts and TRAIN_ID.fullmatch(parts[0]) and parts[0] != train:
                return parts[0]
    return None


def _plan_defect(repo: Path, train: str, state: dict[str, object]) -> str | None:
    # spec 4.1, 0086: the hash covers the raw file bytes; validate runs at the train's builder cap.
    record = state.get("plan")
    if not isinstance(record, dict):
        return f"the state of train {train} records no plan."
    raw, sha = record.get("path"), record.get("sha256")
    if not isinstance(raw, str) or not raw or not isinstance(sha, str):
        return f"the plan record of train {train} needs a path and a sha256, both strings."
    if not _SHA256.fullmatch(sha):
        return f"the plan record of train {train} has a sha256 that is not 64 lowercase hex."
    path = repo / raw
    other = _other_train(repo, path, train)
    if other is not None:
        return f"the plan {raw} sits under train {other}, not train {train}."
    # issue 105: one read; the hash and the parse cover the same bytes.
    try:
        data = path.read_bytes()
        text = data.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return f"the plan file {raw} could not be read ({exc})."
    digest = hashlib.sha256(data).hexdigest()
    if digest != sha:
        return (
            f"the plan file {raw} hashes to {digest}, not {sha}; it changed after it was recorded."
        )
    cap = integer(state, "max_concurrent_builders", DEFAULT_MAX_CONCURRENT_BUILDERS)
    defects = plan_record.validate(plan_record.loads(text), cap)
    if defects:
        return f"the plan {raw} has {len(defects)} defect(s): {' '.join(defects)}"
    return None


def _names_a_coder(subagent: str) -> bool:
    # issue 29: fail closed; a coder under any namespace meets the coder plan gate.
    return subagent.rpartition(":")[2] == CODER


def _ours(subagent: str, agent: str) -> bool:
    # W1.3: train_scope's namespace check decides which dispatch records a unit binding.
    prefix, sep, name = subagent.partition(":")
    return (name if sep else prefix) == agent and policed_outside_train(subagent)


def _dispatch_reason(tool_input: dict[str, object], cwd: str, main: bool = False) -> str | None:
    # issue 29: during a train a coder dispatch names exactly one recorded unit, once.
    # 0190: main marks the main session's path, where a refusal only warns and the agent runs.
    from lib.jail import _train_active

    step = _step_reason(tool_input, cwd)
    subagent = str(tool_input.get("subagent_type") or "")
    if _names_writer(subagent):
        return _writer_dispatch_reason(tool_input, cwd, subagent, step, main)
    if step is not None:
        return step
    if not _names_a_coder(subagent) or not os.path.isabs(cwd):
        return None
    if not _train_active(cwd):
        return None
    repo = project_root(Path(cwd))
    train = active_train(repo)
    if train is None:
        marker = train_marker(repo)
        return f"{marker} names no train id. " + UNMARK_NEXT.format(repo=repo)
    lines = _worktree_lines(str(tool_input.get("prompt") or ""))
    match = _WORKTREE_LINE.fullmatch(lines[0]) if len(lines) == 1 else None
    if match is None:
        return R_WORKTREE_LINE
    try:
        state = load_train(repo, train)
    except TrainStateError as exc:
        return str(exc)
    # spec 4.1: checked before record_dispatch, so a refused coder is never recorded.
    why = _plan_defect(repo, train, state)
    if why is not None:
        return R_NO_PLAN.format(why=why)
    unit, refused = _coder_unit(state, match.group(1), train)
    if refused is not None:
        return refused
    if not _ours(subagent, CODER):
        return unit_binding.held_reason(repo, train, unit)  # issue 29: once, never bound.
    return record_dispatch(repo, train, unit)


def docs_unit(train_id: str) -> str:
    # 0134: the docs stage worktree is the train unit named <train-id>-docstage.
    return f"{train_id}{DOCS_SUFFIX}"


def _names_writer(subagent: str) -> bool:
    # 0134, 0190: fail closed; a writer under any namespace meets the writer dispatch gate.
    return subagent.rpartition(":")[2] == WRITER


def _derived_kind(repo: Path, train: str) -> tuple[str | None, str | None]:
    # 0190: no Worktree: line is the derived kind, which needs the run's frozen sources file.
    import freeze_sources  # scripts/ is on sys.path in every hook process and test.

    path = freeze_sources.manifest_path(repo, train)
    if not path.is_file():
        return None, R_NO_SOURCES.format(train=train, path=path)
    return writer_mode.DERIVED, None


def _writer_kind(
    tool_input: dict[str, object], repo: Path, train: str, ours: bool
) -> tuple[str | None, str | None]:
    # 0134, 0190: (kind, refusal); a Worktree: line is the public docs kind, bound to the docs
    # worktree alone, and no line is the derived kind.
    lines = _worktree_lines(str(tool_input.get("prompt") or ""))
    if not lines:
        return _derived_kind(repo, train)
    try:
        state = load_train(repo, train)
    except TrainStateError as exc:
        return None, str(exc)
    name = docs_unit(train)
    match = _WORKTREE_LINE.fullmatch(lines[0]) if len(lines) == 1 else None
    unit = _unit_named(state, match.group(1)) if match else None
    if unit is None or unit.get("name") != name:
        docs = next((str(u["path"]) for u in units_of(state) if u.get("name") == name), None)
        why = R_DOCS_WORKTREE.format(train=train, docs=docs or "<docs worktree path>", name=name)
        return None, why
    held = (
        record_dispatch(repo, train, name) if ours else unit_binding.held_reason(repo, train, name)
    )
    return (None, held) if held else (writer_mode.PUBLIC_DOCS, None)


def _writer_dispatch_reason(
    tool_input: dict[str, object], cwd: str, subagent: str, step: str | None, main: bool
) -> str | None:
    # 0190: a refusable dispatch records its kind only into an empty queue; on the main path
    # every dispatch runs, so each one queues, a refused one as kind none.
    from lib.jail import _train_active

    if not os.path.isabs(cwd) or not _train_active(cwd):
        return step
    repo = project_root(Path(cwd))
    train = active_train(repo)
    if train is None:
        return f"{train_marker(repo)} names no train id. " + UNMARK_NEXT.format(repo=repo)
    ours = _ours(subagent, WRITER)
    if not main:
        waiting = step or (writer_mode.pending_reason(repo, train) if ours else None)
        if waiting is not None:
            return waiting
        kind, why = _writer_kind(tool_input, repo, train, ours)
        if why is not None or not ours:
            return why
        return writer_mode.record_dispatch(repo, train, str(kind))
    kind, why = (None, step) if step else _writer_kind(tool_input, repo, train, ours)
    queued = writer_mode.queue_dispatch(repo, train, kind or writer_mode.NONE) if ours else None
    return why or queued


def _worktree_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("Worktree:")]


def _unit_named(state: dict[str, object], path: str) -> dict[str, object] | None:
    # issue 29: the recorded unit whose worktree the line names, compared by real path.
    named = os.path.realpath(path)
    for unit in units_of(state):
        if unit.get("path") and unit.get("name"):
            if os.path.realpath(str(unit["path"])) == named:
                return unit
    return None


def _coder_unit(state: dict[str, object], path: str, train: str) -> tuple[str, str | None]:
    # spec 4: the unit a coder may take, or the refusal; the audit worktree is never one.
    unit = _unit_named(state, path)
    if unit is None:
        return "", _not_a_unit(path, train)
    if is_audit_unit(unit):
        return "", R_AUDIT_UNIT.format(path=path, train=train)
    # 0134: the docs stage worktree takes the public docs writer only, by dispatch or by resume.
    if unit.get("name") == docs_unit(train):
        return "", R_DOCS_REBIND.format(name=docs_unit(train))
    return str(unit["name"]), None


def _not_a_unit(path: str, train: str) -> str:
    return (
        f"{path} is not a unit worktree of train {train}. "
        "Next: name the unit worktree on one Worktree: line, as daedalus_workspace.py create "
        "printed it."
    )


def _strings(value: object) -> list[str]:
    # 0086: every text a structured message carries, so no Worktree: line hides in a field.
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for item in value.values() for s in _strings(item)]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


def _resume_reason(tool_input: dict[str, object], cwd: str) -> str | None:
    # 0086, spec 8: a resume naming another unit's worktree rebinds the coder before it is sent.
    from lib.jail import _train_active

    # 0086: every field but the target, since the message key is ASSUMED, not verified live.
    fields = {key: value for key, value in tool_input.items() if key != "to"}
    lines = _worktree_lines(before_payload("\n".join(_strings(fields))))
    if not lines or not os.path.isabs(cwd) or not _train_active(cwd):
        return None
    repo = project_root(Path(cwd))
    train = active_train(repo)
    if train is None:
        return f"{train_marker(repo)} names no train id. " + UNMARK_NEXT.format(repo=repo)
    match = _WORKTREE_LINE.fullmatch(lines[0]) if len(lines) == 1 else None
    if match is None:
        return R_RESUME_LINE
    coder = str(tool_input.get("to") or "")
    if not coder:
        return R_RESUME_TARGET
    try:
        state = load_train(repo, train)
        bound = unit_binding._read(unit_binding.bindings_path(repo, train))
    except TrainStateError as exc:
        return str(exc)
    why = _plan_defect(repo, train, state)
    if why is not None:
        return R_NO_PLAN.format(why=why)
    unit, refused = _coder_unit(state, match.group(1), train)
    if refused is not None:
        return refused
    if bound.get(unit, {}).get("agent_id") == coder:
        return None  # 0086: the runner's queue rebound it already, or the coder holds this unit.
    held = [name for name, record in bound.items() if record.get("agent_id") == coder]
    if not held:
        return R_RESUME_UNBOUND.format(coder=coder, train=train, unit=unit)
    return rebind(repo, train, coder, held[0], unit)


def _binding_reason(hook_input: dict[str, object], cwd: str, units: set[str]) -> str | None:
    # issue 29: the first write claims the dispatched unit; every later write stays in it.
    if not units:
        return None
    repo = project_root(Path(cwd))
    train = active_train(repo)
    if train is None:
        return R_NO_TRAIN
    if len(units) > 1:
        return R_TWO_UNITS
    # B1: a coder run as the session agent (--agent) has no agent_id; its session binds.
    session = str(hook_input.get("session_id") or "")
    coder = str(hook_input.get("agent_id") or "") or (f"session:{session}" if session else "")
    if not coder:
        return R_NO_CODER_ID
    return claim(repo, train, coder, next(iter(units)))


# issue 188: run bindings, one store per session under the plugin data folder, never per cwd.
RUN_BINDINGS = "run-bindings"
RUN_SCHEMA = 1
CLAIM_SOLE = "sole"
CLAIM_RUN = "run"
R_STORE_MALFORMED = (
    "the run binding store {path} is malformed, so every agent of this session is judged by its "
    "payload cwd (issue 188). Next: the operator deletes {path}; no stop or unmark step clears it"
)


class RunStoreError(Exception):
    """issue 188: a malformed run binding store, left as it is."""


_RUN_CAP = 256
_DISPATCHER = "orchestrator"


@dataclass(frozen=True)
class RunBinding:
    # issue 188: the run a dispatched agent belongs to; claim says how its first call matched.
    repo: str
    worktree: str | None
    train_id: str
    claim: str
    claimed_now: bool

    def record(self) -> dict[str, object]:
        return {
            "train_id": self.train_id,
            "repo": self.repo,
            "worktree": self.worktree,
            "claim": self.claim,
        }


def _short(agent: str) -> str:
    return agent.rpartition(":")[2]


def run_store(session: object) -> Path | None:
    # issue 188: the file name is a full SESSION_ID match under an absolute data folder, or none.
    root = os.environ.get("CLAUDE_PLUGIN_DATA") or ""
    if not os.path.isabs(root) or not isinstance(session, str) or not SESSION_ID.fullmatch(session):
        return None
    return Path(root) / RUN_BINDINGS / f"{session}.json"


@contextmanager
def _run_lock(path: Path) -> Iterator[None]:
    # issue 188: one bounded lock per read-modify-write; the folder is 0700 and never a link.
    atomic.refuse_links(path.parent.parent)
    path.parent.mkdir(mode=0o700, exist_ok=True)
    atomic.refuse_links(path.parent)
    os.chmod(path.parent, 0o700)
    with locks.locked(path.with_suffix(".lock"), LOCK_TIMEOUT_S, "run binding lock"):
        yield


def _abs_text(value: object) -> bool:
    return isinstance(value, str) and os.path.isabs(value)


def _entry_ok(entry: object) -> bool:
    if not isinstance(entry, dict):
        return False
    train, created = entry.get("train_id"), entry.get("created")
    worktree, agent_id = entry.get("worktree"), entry.get("agent_id")
    return (
        isinstance(entry.get("agent_type"), str)
        and _abs_text(entry.get("repo"))
        and (worktree is None or _abs_text(worktree))
        and isinstance(train, str)
        and TRAIN_ID.fullmatch(train) is not None
        and (agent_id is None or isinstance(agent_id, str))
        and entry.get("claim") in (None, CLAIM_SOLE, CLAIM_RUN)
        and isinstance(created, int | float)
        and not isinstance(created, bool)
    )


def _load_runs(path: Path) -> list[dict[str, object]] | None:
    # issue 188: None on any malformed store, so no binding applies and the payload cwd judges.
    try:
        atomic.refuse_links(path)
        data: object = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("version") != RUN_SCHEMA:
        return None
    entries = data.get("entries")
    if not isinstance(entries, list) or not all(_entry_ok(e) for e in entries):
        return None
    return [{str(k): v for k, v in e.items()} for e in entries]


def _live(entry: dict[str, object]) -> bool:
    # issue 188: a binding counts while its repo's marker names its train and the unit stays.
    repo, train = Path(str(entry["repo"])), str(entry["train_id"])
    if active_train(repo) != train:
        return False
    if entry.get("worktree") is None:
        return True
    try:
        return _unit_named(load_train(repo, train), str(entry["worktree"])) is not None
    except (TrainStateError, OSError):
        return False


def _save_runs(path: Path, entries: list[dict[str, object]]) -> None:
    # issue 188: entries whose marker cleared are dropped on every write.
    kept = [e for e in entries if _live(e)][-_RUN_CAP:]
    text = json.dumps({"version": RUN_SCHEMA, "entries": kept}, indent=1) + "\n"
    atomic.write_atomic(path, text, 0o600)


def _dispatcher(hook_input: dict[str, object]) -> bool:
    # issue 188: the main session (no agent_id) or a Daedalus orchestrator starts agents.
    raw = str(hook_input.get("agent_type") or "main")
    if raw == "main":
        return not hook_input.get("agent_id")
    return policed_outside_train(raw) and _short(raw) == _DISPATCHER


def record_run_dispatch(hook_input: dict[str, object]) -> None:
    # issue 188: an allowed Daedalus dispatch during a run queues one pending entry.
    from lib.jail import _train_active

    raw = hook_input.get("tool_input")
    tool_input: dict[str, object] = raw if isinstance(raw, dict) else {}
    subagent = str(tool_input.get("subagent_type") or "")
    cwd = hook_input.get("cwd")
    path = run_store(hook_input.get("session_id"))
    if hook_input.get("tool_name") not in DISPATCH_TOOLS or not _dispatcher(hook_input):
        return
    if path is None or not policed_outside_train(subagent) or _short(subagent) == "main":
        return
    if not isinstance(cwd, str) or not os.path.isabs(cwd):
        return
    # issue 188: the same single Worktree: line the dispatch gate checked.
    lines = _worktree_lines(str(tool_input.get("prompt") or ""))
    match = _WORKTREE_LINE.fullmatch(lines[0]) if len(lines) == 1 else None
    worktree = os.path.realpath(match.group(1)) if match else None
    repo = project_root(Path(worktree or cwd))
    train = active_train(repo) if _train_active(str(repo)) else None
    if train is None:
        return
    entry: dict[str, object] = {
        "agent_type": _short(subagent),
        "repo": str(repo),
        "worktree": worktree,
        "train_id": train,
        "agent_id": None,
        "claim": None,
        "created": time.time(),
    }
    if worktree is not None and not _live(entry):
        entry["worktree"] = None
    with _run_lock(path):
        entries = _load_runs(path)
        if entries is None:
            raise RunStoreError(R_STORE_MALFORMED.format(path=path))  # issue 188: never rewritten.
        _save_runs(path, [*entries, entry])


def _binding(entry: dict[str, object], now: bool) -> RunBinding | None:
    if not _live(entry):
        return None  # issue 188: a stale binding is ignored.
    worktree = entry.get("worktree")
    return RunBinding(
        str(entry["repo"]),
        str(worktree) if worktree is not None else None,
        str(entry["train_id"]),
        str(entry.get("claim") or CLAIM_SOLE),
        now,
    )


def _held_run(entries: list[dict[str, object]], agent_id: str) -> dict[str, object] | None:
    return next((e for e in entries if e.get("agent_id") == agent_id), None)


def bound_run(hook_input: dict[str, object]) -> RunBinding | None:
    # issue 188: the agent's run; its first call claims a pending entry of its type only when
    # every candidate shares one repo and train. A claim never moves.
    agent_id = hook_input.get("agent_id")
    raw = str(hook_input.get("agent_type") or "")
    path = run_store(hook_input.get("session_id"))
    if not isinstance(agent_id, str) or not agent_id or path is None:
        return None
    if not policed_outside_train(raw) or not path.is_file():
        return None
    entries = _load_runs(path)
    if entries is None:
        return None
    held = _held_run(entries, agent_id)
    if held is not None:
        return _binding(held, False)
    with _run_lock(path):
        entries = _load_runs(path)
        if entries is None:
            return None
        held = _held_run(entries, agent_id)
        if held is not None:
            return _binding(held, False)
        pending = sorted(
            (e for e in entries if e.get("agent_id") is None and e["agent_type"] == _short(raw)),
            key=lambda e: float(str(e["created"])),
        )
        pending = [e for e in pending if _live(e)]
        runs = {(e["repo"], e["train_id"]) for e in pending}
        if len(runs) != 1:
            return None  # issue 188: candidates of two runs bind neither; never by an agent path.
        if len(pending) > 1:
            # issue 188, issue 29: same-run candidates bind the run root; unit_binding owns units.
            for entry in pending:
                entry["worktree"], entry["claim"] = None, CLAIM_RUN
        chosen = pending[0]
        chosen["agent_id"] = agent_id
        chosen["claim"] = chosen.get("claim") or CLAIM_SOLE
        _save_runs(path, entries)
    return _binding(chosen, True)

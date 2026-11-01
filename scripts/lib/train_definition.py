# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0032, 0033: the one loader and validator of train definitions; the runner imports it too.
# Each defect line leads with its spec 3.4 check number; check 7 lands in 3.2, check 12 in 2.4.
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from lib import agent_files
from lib.agent_aliases import current as current_name
from lib.human_text import MIN_WORDS, plain_words
from lib.manifest import FEATURE_KEYS, SCOPE_KINDS, repo_relative
from lib.narrow import integer
from lib.narrow import obj as _obj
from lib.narrow import objects as _objects
from lib.narrow import strings as _texts
from lib.narrow import text as _text

TOP_FIELDS = (
    "name",
    "version",
    "description",
    "scopes",
    "gates",
    "consults",
    "stages",
    "off_contract",
)
STAGE_FIELDS = ("id", "gate", "agent", "scope", "proof", "on_fail")
OPTIONAL_STAGE_FIELDS = ("verifies", "when", "repeat", "parallel")
SCOPE_FIELDS = ("told", "touch", "reply")
PROOF_FIELDS = ("script", "exit", "records")
PATH_CLASSES = (
    "none",
    "unit-src-tests",
    "contracts",
    "charter-specs",
    "charter",
    "docs",
    "scratch",
)
MAIN = "main"
PASS = "pass"
OFF_CONTRACT = "off-contract"
NO_BRIEF = "none"
PER_UNIT = "per-unit"
# 0024: state fields begin and start write before the first stage; any placeholder may name one.
STATE_FIELDS = frozenset(
    {
        "train_id",
        "repo",
        "base_branch",
        "base_sha",
        "charter_root",
        "charter_base",
        "ledger_line",
        "cache_dir",
        "definition",
        "definition_sha256",
        "scope_kind",
        "output_dir",
        "max_concurrent_builders",
        # 0072: a per-unit stage fills these from the unit the runner dispatches.
        "unit_name",
        "unit_branch",
        "unit_path",
        "unit_base",
    }
)
DEFINITION_NEXT = "Next: fix each defect above in the train definition, then rerun the validator."
_SLUG = re.compile(r"[a-z0-9][a-z0-9-]*")
_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")
_EXIT_CODE = re.compile(r"0|[1-9][0-9]*")
_ROUNDS = re.compile(r"[1-9][0-9]*")
_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_.]*)\}")
# 0031: the group keeps the operator-line scanner from reading this pattern as a message.
_STOP = re.compile(r"stop: (?:Next): (\S.*)")
_BACK = re.compile(r"back:(\S+)(?: rounds=(\S+))?")
_ASK = re.compile(r"ask: \S.*")
_CONSULT = re.compile(r"consult:(\S+)")
_FEATURE = "features."
_STATUS_WORD = re.compile(r"\[[A-Z]+: ([A-Z_]+)\]")

Origin = Literal["plugin", "project"]


class DefinitionError(ValueError):
    pass


@dataclass(frozen=True)
class Definition:
    path: Path
    raw: dict[str, object]

    @property
    def name(self) -> str:
        value = self.raw.get("name")
        return value if isinstance(value, str) else self.path.stem

    @property
    def version(self) -> int:
        return integer(self.raw, "version", 0)

    @property
    def stages(self) -> list[dict[str, object]]:
        return _objects(self.raw, "stages")


def load(path: Path) -> Definition:
    # 0003: stdlib JSON; the message is a defect line and the caller adds the Next line.
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DefinitionError(f"{path} could not be read ({exc})") from exc
    try:
        raw: object = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise DefinitionError(f"{path} is not valid JSON ({exc})") from exc
    if not isinstance(raw, dict):
        raise DefinitionError(f"{path} is not a JSON object")
    return Definition(path, _current_names(raw))


def _current_names(raw: dict[str, object]) -> dict[str, object]:
    # 0190: old agent names in stages and consults read as their new names for one release.
    stages = raw.get("stages")
    for stage in stages if isinstance(stages, list) else []:
        if isinstance(stage, dict) and isinstance(stage.get("agent"), str):
            stage["agent"] = current_name(stage["agent"])
    consults = raw.get("consults")
    if isinstance(consults, dict):
        for gate, names in consults.items():
            if isinstance(names, list):
                consults[gate] = [current_name(n) if isinstance(n, str) else n for n in names]
    return raw


def _strings_only(value: object, allow_empty: bool = False) -> bool:
    if not isinstance(value, list) or (not value and not allow_empty):
        return False
    return all(isinstance(item, str) and item for item in value)


def _routes(stage: dict[str, object]) -> dict[str, str]:
    return {str(k): v for k, v in _obj(stage, "on_fail").items() if isinstance(v, str)}


def _outcomes(stage: dict[str, object]) -> set[str]:
    exits = _obj(_obj(stage, "proof"), "exit")
    return {value for value in exits.values() if isinstance(value, str)}


def reply_route_key(stage: dict[str, object], line: str) -> str | None:
    # 0024: a reply line routes by itself, or by its status word when the exit map names it.
    routes = _routes(stage)
    if line in routes:
        return line
    word = _STATUS_WORD.match(line)
    key = word.group(1).lower() if word else ""
    failing = _outcomes(stage) - {PASS, OFF_CONTRACT}
    return key if key and key in routes and key in failing else None


def _replies(stage: dict[str, object]) -> list[str]:
    return _texts(_obj(stage, "scope").get("reply"))


def _agent_path(name: str, plugin_root: Path) -> Path | None:
    # 0044: a name outside the agent-name form reads as a missing file, never as a path.
    if not agent_files.AGENT_NAME.fullmatch(name):
        return None
    path = plugin_root / "agents" / f"{name}.md"
    return path if path.is_file() else None


def touch_grants(agent: agent_files.AgentFile) -> frozenset[str]:
    # spec 3.4 check 5: root_writes --touch classes, unit-src-tests for unit_writes, else none.
    granted: set[str] = set()
    # 0190: a writer's grants are those of every mode it may be dispatched in.
    hooks = {hook for chain in agent.chains().values() for hook in chain}
    scripts = {hook.script for hook in hooks}
    for hook in hooks:
        flags = list(hook.flags)
        if hook.script == "root_writes" and "--touch" in flags[:-1]:
            granted.update(flags[flags.index("--touch") + 1].split(","))
    if "unit_writes" in scripts:
        granted.add("unit-src-tests")
    # 0109: the audit class holds findings outside the judged tree, so its holder touches none.
    if not scripts & {"root_writes", "unit_writes"} or granted == {"audit"}:
        granted.add("none")
    return frozenset(granted)


def contract_heads(line: str) -> set[str]:
    # spec 3.4 check 4: a reply names a status line whole, or its text before the placeholders.
    heads = {line}
    if line.startswith("[") and "]" in line:
        heads.add(line[: line.index("]") + 1])
    cut = line.split("<", 1)[0].rstrip()
    if cut:
        heads.add(cut)
    return heads


def _distinct_names(value: object) -> bool:
    return _strings_only(value) and isinstance(value, list) and len(set(value)) == len(value)


def _check1(defn: Definition) -> list[str]:
    raw = defn.raw
    out = [
        f"check 1: the definition lacks the top-level field {k}" for k in TOP_FIELDS if k not in raw
    ]
    unknown = sorted(str(key) for key in set(raw) - set(TOP_FIELDS))
    if unknown:
        out.append(f"check 1: the definition has unknown top-level fields {unknown}")
    name = raw.get("name", defn.path.stem)
    if not (isinstance(name, str) and _SLUG.fullmatch(name) and name == defn.path.stem):
        out.append(f"check 1: name {name!r} must be a slug equal to the file name {defn.path.stem}")
    version = raw.get("version", 1)
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        out.append(f"check 1: version {version!r} must be a whole number of at least 1")
    if "description" in raw and not _text(raw, "description").strip():
        out.append("check 1: description must be a non-empty line of text")
    if "gates" in raw and not _distinct_names(raw["gates"]):
        out.append("check 1: gates must be a non-empty list of distinct gate names")
    consults = raw.get("consults", {})
    if not isinstance(consults, dict) or not all(
        _strings_only(agents, allow_empty=True) for agents in consults.values()
    ):
        out.append("check 1: consults must map each gate to a list of agent names")
    stages = raw.get("stages", [{}])
    if not isinstance(stages, list) or not stages or not all(isinstance(s, dict) for s in stages):
        out.append("check 1: stages must be a non-empty list of stage objects")
    if "off_contract" in raw and not _text(raw, "off_contract").strip():
        out.append("check 1: off_contract must be a route written as text")
    return out


def _scope_shape(value: object) -> list[str]:
    if not isinstance(value, dict) or set(value) != set(SCOPE_FIELDS):
        return ["scope must be an object holding exactly told, touch and reply"]
    out = []
    if not _text(value, "told"):
        out.append("scope.told must name a brief template, or none")
    touch = value["touch"]
    if not _strings_only(touch) or any(c not in PATH_CLASSES for c in _texts(touch)):
        out.append(f"scope.touch must be a non-empty list drawn from {', '.join(PATH_CLASSES)}")
    if not _strings_only(value["reply"]):
        out.append("scope.reply must be a non-empty list of accepted reply lines")
    return out


def _proof_shape(value: object) -> list[str]:
    if not isinstance(value, dict) or set(value) != set(PROOF_FIELDS):
        return ["proof must be an object holding exactly script, exit and records"]
    out = []
    if not _text(value, "script").strip():
        out.append("proof.script must name the command the runner runs or reads")
    exits = value["exit"]
    if (
        not isinstance(exits, dict)
        or not exits
        or not all(
            _EXIT_CODE.fullmatch(str(code)) and isinstance(outcome, str) and outcome
            for code, outcome in exits.items()
        )
    ):
        out.append("proof.exit must map each exit code to a named outcome")
    records = value["records"]
    if not _strings_only(records, allow_empty=True) or not all(
        _FIELD.fullmatch(name) for name in _texts(records)
    ):
        out.append("proof.records must list the state field names the stage writes")
    return out


def _optional_shape(stage: dict[str, object]) -> list[str]:
    out = []
    for key in ("verifies", "when"):
        if key in stage and not _text(stage, key).strip():
            out.append(f"{key} must be non-empty text")
    if "repeat" in stage and stage["repeat"] != PER_UNIT:
        out.append(f"repeat must be {PER_UNIT}")
    if "parallel" in stage and not isinstance(stage["parallel"], bool):
        out.append("parallel must be true or false")
    elif stage.get("parallel") is True and stage.get("repeat") != PER_UNIT:
        out.append(f"parallel needs repeat {PER_UNIT}")
    return out


def _check2(stages: list[dict[str, object]]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for number, stage in enumerate(stages, 1):
        sid = stage.get("id")
        label = f"stage {sid}" if isinstance(sid, str) and sid else f"stage number {number}"
        found: list[str] = []
        missing = [key for key in STAGE_FIELDS if key not in stage]
        if missing:
            found.append(f"lacks the required fields {missing}")
        unknown = sorted(set(map(str, stage)) - set(STAGE_FIELDS) - set(OPTIONAL_STAGE_FIELDS))
        if unknown:
            found.append(f"has unknown fields {unknown}")
        if "id" in stage and not (isinstance(sid, str) and _SLUG.fullmatch(sid)):
            found.append("id must be a slug")
        elif isinstance(sid, str) and sid in seen:
            found.append("repeats an id another stage uses")
        seen.add(str(sid))
        found += [
            f"{k} must be non-empty text"
            for k in ("gate", "agent")
            if k in stage and not _text(stage, k)
        ]
        if "scope" in stage:
            found += _scope_shape(stage["scope"])
        if "proof" in stage:
            found += _proof_shape(stage["proof"])
        on_fail = stage.get("on_fail", {})
        if not isinstance(on_fail, dict) or not all(
            isinstance(v, str) and v for v in on_fail.values()
        ):
            found.append("on_fail must map each failing outcome to a route written as text")
        found += _optional_shape(stage)
        out += [f"check 2: {label} {detail}" for detail in found]
    return out


def _check3(
    stages: list[dict[str, object]], plugin_root: Path
) -> tuple[dict[str, agent_files.AgentFile], list[str]]:
    agents: dict[str, agent_files.AgentFile] = {}
    out = []
    for stage in stages:
        sid, name = _text(stage, "id"), _text(stage, "agent")
        if name == MAIN or name in agents:
            continue
        path = _agent_path(name, plugin_root)
        if path is None:
            out.append(
                f"check 3: stage {sid} names agent {name}, which has no agent file in the "
                f"plugin (agents/{name}.md)"
            )
            continue
        try:
            agents[name] = agent_files.load(path)
        except agent_files.AgentFileError as exc:
            reason = str(exc).split(" Next:", 1)[0]
            out.append(f"check 3: stage {sid} agent file agents/{name}.md is unusable: {reason}")
    return agents, out


def _check4(stages: list[dict[str, object]], agents: dict[str, agent_files.AgentFile]) -> list[str]:
    out = []
    for stage in stages:
        agent = agents.get(_text(stage, "agent"))
        if agent is None:
            continue
        allowed = set().union(*(contract_heads(line) for line in agent.status_lines))
        for reply in _replies(stage):
            if reply not in allowed:
                out.append(
                    f"check 4: stage {_text(stage, 'id')} accepts reply line {reply!r}, which "
                    f"is not a line of the {agent.name} status contract"
                )
    return out


def _check5(stages: list[dict[str, object]], agents: dict[str, agent_files.AgentFile]) -> list[str]:
    out = []
    for stage in stages:
        agent = agents.get(_text(stage, "agent"))
        if agent is None:
            continue
        granted = touch_grants(agent)
        for cls in _texts(_obj(stage, "scope").get("touch")):
            if cls not in granted:
                out.append(
                    f"check 5: stage {_text(stage, 'id')} touches {cls}, which the "
                    f"{agent.name} hooks do not grant (granted: {', '.join(sorted(granted))})"
                )
    return out


def _check6(stages: list[dict[str, object]]) -> list[str]:
    # 0024: on_fail keys name an exit outcome or a reply line; off_contract routes off-contract.
    out = []
    for stage in stages:
        sid, routes, outcomes, replies = (
            _text(stage, "id"),
            _routes(stage),
            _outcomes(stage),
            _replies(stage),
        )
        for outcome in sorted(outcomes - {PASS, OFF_CONTRACT} - set(routes)):
            out.append(f"check 6: stage {sid} exit outcome {outcome} has no route in on_fail")
        unrouted = [reply for reply in replies if reply_route_key(stage, reply) is None]
        if PASS not in outcomes:
            for reply in unrouted:
                out.append(
                    f"check 6: stage {sid} reply line {reply!r} has no route: no exit "
                    "outcome passes and on_fail does not name it"
                )
        elif len(unrouted) > 1:
            # 0024: only one reply line may pass unrouted, so a rejecting line cannot pass.
            out.append(
                f"check 6: stage {sid} reply lines {unrouted} all pass with no route; route "
                "every reply line but the one passing line in on_fail"
            )
        for key in sorted(set(routes) - outcomes - set(replies)):
            out.append(
                f"check 6: stage {sid} routes {key!r}, which is neither an exit outcome nor a "
                "reply line of the stage"
            )
    return out


def _check8(raw: dict[str, object], stages: list[dict[str, object]]) -> list[str]:
    order = {gate: index for index, gate in enumerate(_texts(raw.get("gates")))}
    ids = [_text(stage, "id") for stage in stages]
    out = []
    last, last_gate = -1, ""
    for position, stage in enumerate(stages):
        sid, gate = ids[position], _text(stage, "gate")
        if gate not in order:
            out.append(f"check 8: stage {sid} names gate {gate}, which gates does not declare")
        elif order[gate] < last:
            out.append(
                f"check 8: stage {sid} in gate {gate} is out of the declared gate order; it "
                f"follows a stage of the later gate {last_gate}"
            )
        else:
            last, last_gate = order[gate], gate
        for key, route in sorted(_routes(stage).items()):
            back = _BACK.fullmatch(route)
            if back is None:
                continue
            target, rounds = back.groups()
            if target in ids and ids.index(target) >= position:
                out.append(
                    f"check 8: stage {sid} routes back to {target}, which is not an earlier stage"
                )
            if rounds is None:
                out.append(
                    f"check 8: stage {sid} route for {key!r} goes back without a rounds= count"
                )
            elif not _ROUNDS.fullmatch(rounds):
                out.append(f"check 8: stage {sid} route for {key!r} needs rounds= of at least 1")
    if _BACK.fullmatch(_text(raw, "off_contract")):
        out.append("check 8: off_contract cannot route back, because it belongs to no stage")
    return out


def _route_problem(route: str, ids: list[str], plugin_root: Path) -> str | None:
    if _STOP.fullmatch(route) or _ASK.fullmatch(route):
        return None
    back = _BACK.fullmatch(route)
    if back is not None:
        target = back.group(1)
        return (
            None if target in ids else f"routes back to {target}, which is no stage of this train"
        )
    consult = _CONSULT.fullmatch(route)
    if consult is not None:
        name = consult.group(1)
        if _agent_path(name, plugin_root) is None:
            return f"consults {name}, which has no agent file in the plugin (agents/{name}.md)"
        return None
    return "has a route that is not one of the four route forms (stop, back, ask, consult)"


def _check9(
    raw: dict[str, object], stages: list[dict[str, object]], plugin_root: Path
) -> list[str]:
    ids = [_text(stage, "id") for stage in stages]
    out = []
    for stage in stages:
        for key, route in sorted(_routes(stage).items()):
            problem = _route_problem(route, ids, plugin_root)
            if problem is not None:
                out.append(f"check 9: stage {_text(stage, 'id')} on_fail {key!r} {problem}")
    problem = _route_problem(_text(raw, "off_contract"), ids, plugin_root)
    if problem is not None:
        out.append(f"check 9: off_contract {problem}")
    gates = set(_texts(raw.get("gates")))
    for gate, agents in sorted(_obj(raw, "consults").items()):
        if gate not in gates:
            out.append(f"check 9: consults names gate {gate}, which gates does not declare")
        for name in _texts(agents):
            if _agent_path(name, plugin_root) is None:
                out.append(
                    f"check 9: consults for gate {gate} names {name}, which has no agent file "
                    f"in the plugin (agents/{name}.md)"
                )
    return out


def _unrecorded(text: str, recorded: set[str]) -> list[str]:
    return sorted({name for name in _PLACEHOLDER.findall(text) if name not in recorded})


def _check10(
    defn: Definition, stages: list[dict[str, object]], plugin_root: Path, origin: Origin
) -> list[str]:
    # spec 3.1: a plugin brief resolves from the plugin root, a project brief beside its definition.
    base = plugin_root if origin == "plugin" else defn.path.parent
    recorded = set(STATE_FIELDS)
    out = []
    for stage in stages:
        sid, agent, told = (
            _text(stage, "id"),
            _text(stage, "agent"),
            _text(_obj(stage, "scope"), "told"),
        )
        proof = _obj(stage, "proof")
        if told == NO_BRIEF:
            if agent != MAIN:
                out.append(f"check 10: stage {sid} dispatches {agent} but names no brief template")
        elif not repo_relative(told) or told.endswith("/"):
            out.append(
                f"check 10: stage {sid} brief template path {told} must be relative, without '..'"
            )
        else:
            try:
                text = (base / told).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                out.append(
                    f"check 10: stage {sid} brief template {told} does not exist or cannot be read"
                )
            else:
                for name in _unrecorded(text, recorded):
                    out.append(
                        f"check 10: stage {sid} brief template {told} names {{{name}}}, which no "
                        "earlier stage records"
                    )
        for name in _unrecorded(_text(proof, "script"), recorded):
            out.append(
                f"check 10: stage {sid} proof script names {{{name}}}, which no earlier stage "
                "records"
            )
        recorded.update(_texts(proof.get("records")))
    return out


def _thin_next(route: str) -> str | None:
    stop = _STOP.fullmatch(route)
    if stop is None or len(plain_words(stop.group(1))) >= MIN_WORDS:
        return None
    return stop.group(1)


def _check11(raw: dict[str, object], stages: list[dict[str, object]]) -> list[str]:
    # 0031: the description and each next step name things in words, not ids alone.
    out = []
    if len(plain_words(_text(raw, "description"))) < MIN_WORDS:
        out.append("check 11: the description needs at least four plain words, ids and paths aside")
    for stage in stages:
        for key, route in sorted(_routes(stage).items()):
            thin = _thin_next(route)
            if thin is not None:
                out.append(
                    f"check 11: stage {_text(stage, 'id')} on_fail {key!r} stop route needs at "
                    f"least four plain words in its next step: {thin!r}"
                )
    thin = _thin_next(_text(raw, "off_contract"))
    if thin is not None:
        out.append(f"check 11: off_contract stop route needs at least four plain words: {thin!r}")
    return out


def _check13(raw: dict[str, object], stages: list[dict[str, object]]) -> list[str]:
    # 0069, 0070: scope kinds and feature names come from the manifest reader's own lists.
    out = []
    scopes = raw.get("scopes")
    if not _distinct_names(scopes) or any(kind not in SCOPE_KINDS for kind in _texts(scopes)):
        out.append(
            f"check 13: scopes {scopes!r} must be a non-empty list of distinct scope kinds "
            f"drawn from {', '.join(SCOPE_KINDS)}"
        )
    for stage in stages:
        when = _text(stage, "when")
        if when.startswith(_FEATURE) and when[len(_FEATURE) :] not in FEATURE_KEYS:
            out.append(
                f"check 13: stage {_text(stage, 'id')} runs when {when}, which names no "
                f"manifest feature (known: {', '.join(FEATURE_KEYS)})"
            )
    return out


def validate(defn: Definition, plugin_root: Path, origin: Origin) -> list[str]:
    # 0033: structure first; checks 3 to 13 read fields that checks 1 and 2 proved well formed.
    out = _check1(defn)
    if out:
        return out
    stages = defn.stages
    out = _check2(stages)
    if out:
        return out
    agents, out = _check3(stages, plugin_root)
    return [
        *out,
        *_check4(stages, agents),
        *_check5(stages, agents),
        *_check6(stages),
        *_check8(defn.raw, stages),
        *_check9(defn.raw, stages, plugin_root),
        *_check10(defn, stages, plugin_root, origin),
        *_check11(defn.raw, stages),
        *_check13(defn.raw, stages),
    ]

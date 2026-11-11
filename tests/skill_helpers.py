# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import ast
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from lib.human_text import DROP_SPANS, EDGE, plain_words

from tests.conftest import REPO_ROOT
from tests.helpers import phase_text

SKILLS = sorted((REPO_ROOT / "skills").glob("*/SKILL.md"))


COPYRIGHT = "<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->"


_SCRIPT_REF = re.compile(r"\$\{?CLAUDE_PLUGIN_ROOT\}?/scripts/([^\s`\"')]+?\.py)")


def _split(path: Path) -> tuple[dict[str, str], str]:
    text = path.read_text(encoding="utf-8")
    assert text.startswith("---\n"), path
    block, body = text[4:].split("\n---\n", 1)
    fields: dict[str, str] = {}
    for line in block.splitlines():
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields, body


_AGENT_REF = re.compile(r"Agent\(`([a-z-]+)`\)")


RUN_SKILL = REPO_ROOT / "skills" / "run" / "SKILL.md"


def _run_skill() -> str:
    # 0173: the run entry is the main session's relay; the orchestrator is the glue.
    return RUN_SKILL.read_text(encoding="utf-8")


ORCHESTRATOR = REPO_ROOT / "agents" / "orchestrator.md"


# 0165: the phase skills the orchestrator reads and runs, in run order.
RUN_PHASES = ("plan", "build", "verify", "audit", "document")


def _orchestrator() -> str:
    return ORCHESTRATOR.read_text(encoding="utf-8")


# 0186: the standards method the plan, build, audit and document phases load.
STANDARDS_SKILL = REPO_ROOT / "skills" / "plan" / "standards" / "SKILL.md"


def _standards_skill() -> str:
    return STANDARDS_SKILL.read_text(encoding="utf-8")


def _recipe() -> str:
    # 0165: the recipe is the orchestrator's glue plus the phase skills it runs.
    return "\n".join([_orchestrator(), *(phase_text(name) for name in RUN_PHASES)])


def _rules() -> str:
    return _orchestrator().split("## Entry shapes", 1)[0]


BEGIN = "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py begin --repo <repo>`"


STOP_CMD = (
    "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py stop "
    '--repo <repo> --reason "<what happened>" --next "<next action>"`'
)


# 0060: the orchestrator writes the plugin root out in full; the hook refuses the variable.
PLUGIN = "`python3 <plugin root>/scripts/"


_PHASE_DISPATCH = re.compile(r"(?:[Dd]ispatch(?: one)? `|Agent\(`?|goes to `)([a-z]+(?:-[a-z]+)*)")


ESCALATION_START = (
    "Put it to the operator with AskUserQuestion, in the decision-brief shape (0103), one "
    "question per finding:"
)


ESCALATION_END = (
    "Never start a fix round without a `Fix it now` pick, and never stop the train on your "
    "own authority."
)


def _escalation(text: str) -> str:
    flat = " ".join(text.split())
    assert flat.count(ESCALATION_START) == 1, "one per-finding prompt"
    return flat.split(ESCALATION_START, 1)[1].split(ESCALATION_END, 1)[0]


VERDICT_CMD = PLUGIN + "daedalus_train.py verdict --repo <repo> --status {status} --round <n>"


# 0174: the release phase holds the push recipe.
RELEASE = REPO_ROOT / "skills" / "release" / "SKILL.md"


def _release() -> str:
    return RELEASE.read_text(encoding="utf-8")


RELEASE_CMD = (
    "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py release --repo <repo> "
    "--merge-sha <merge sha>`"
)


def _section(text: str, head: str, nxt: str) -> str:
    return text.split(head, 1)[1].split(nxt, 1)[0]


def _phase_step(name: str, first: int, last: int | None = None) -> str:
    # 0165: steps <first> to <last> of a phase skill the orchestrator reads and runs.
    body = phase_text(name).split(f"\n{first}. ", 1)[1]
    end = first if last is None else last
    return re.split(rf"\n(?:{end + 1}\. |#)", body, maxsplit=1)[0]


def _phase_row(name: str, status: str) -> str:
    # 0165: one row of a phase skill's reply table, by its status line.
    return next(ln.strip() for ln in phase_text(name).splitlines() if f"| `[{status}" in ln)


# 0022: the train makes the worktrees; the merge-base check stays as a defence.
DESCENT_STOP = (
    '"Unit <b> does not descend from the integration branch. Next: start the run again; if it '
    'repeats, file an issue with the run summary."'
)


BRANCH_STOP = (
    '"Unit <unit> reported branch <b>; the run created `daedalus-unit/<train-id>-<unit-slug>`. '
    'Next: start the run again; if it repeats, file an issue with the run summary."'
)


MARK = "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py mark --repo <repo> --train "


UNMARK = "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_workspace.py unmark --repo <repo>`"


_SKILL_SCRIPT = re.compile(r"`(python3 \$\{CLAUDE_PLUGIN_ROOT\}/scripts/[^`]+)`")


_CONDUCTOR_CMD = re.compile(r"(?:[Rr]un|then) `((?:git|gh|gitleaks) [^`]+)`")


def _conductor_commands(
    path: Path = RELEASE, head: str = "## Push", end: str = "## Hand-off"
) -> list[str]:
    # 0028, 0078: every command Push and Charter branch hand the conductor, minus never-run lines.
    text = path.read_text(encoding="utf-8")
    push = _section(text, head, end)
    allowed = "\n".join(ln for ln in push.splitlines() if "Use only the commands above" not in ln)
    return sorted(set(_CONDUCTOR_CMD.findall(allowed)))


def _conductor_decide(repo_cwd: Path, project_data: Path, command: str) -> Any:
    from lib.config import Config

    from tests.hook_chain import judge as decide
    from tests.jail_cases import audited_train

    # spec 4.2: an audited train, so the push and pr create meet an approved verdict.
    audited_train(repo_cwd, "20261016-120000")
    # 0078: a declared charter root whose origin names the <charter slug> the skill records.
    charter = repo_cwd.parent / "Charter"
    if not charter.exists():
        subprocess.run(["git", "init", "-q", str(charter)], check=True)
        url = "https://github.com/acme/charter.git"
        subprocess.run(["git", "-C", str(charter), "remote", "add", "origin", url], check=True)
    config = json.dumps({"local_docs_folder": str(charter)})
    (project_data / "config.json").write_text(config, encoding="utf-8")
    for name, value in (
        ("<repo>", str(repo_cwd)),
        ("<train-id>", "20261016-120000"),
        ("<charter_root>", str(charter)),
        ("<charter slug>", "acme/charter"),
    ):
        command = command.replace(name, value)
    concrete = re.sub(r"<[^>]+>", "x", command)
    payload = {
        "tool_name": "Bash",
        "tool_input": {"command": concrete},
        "cwd": str(repo_cwd),
        "session_id": "s",
        "agent_type": "releaser",
        "agent_id": "a-1",
    }
    return decide(payload, Config())


DOCTOR = REPO_ROOT / "skills" / "doctor" / "SKILL.md"


DOCTOR_CMD = "python3 ${CLAUDE_SKILL_DIR}/../../scripts/daedalus_doctor.py"


# 0031: operator lines name things in words; lib.human_text holds the one word counter.
_NEXT_CONST = re.compile(r"_?[A-Z_]*NEXT")


_SENTENCE_END = re.compile(r"\.\s+(?=[A-Z])")


_SKILL_NEXT = re.compile(r"(?:^|(?<=[.:;]\s))Next:")


AGENT_FACING = {"scripts/lib/jail.py", "scripts/lib/shell.py", "scripts/lib/dispatch_binding.py"}
AGENT_FACING |= {"scripts/lib/router.py"} | {
    str(p.relative_to(REPO_ROOT)) for p in (REPO_ROOT / "scripts" / "checks").glob("*.py")
}


_words = plain_words


def _forward_only(text: str) -> bool:
    return not DROP_SPANS.sub("", text).strip(" " + EDGE)


def _render(node: ast.AST, consts: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                name = value.value.id if isinstance(value.value, ast.Name) else ""
                parts.append(consts.get(name, "{x}"))
        return "".join(parts)
    return None


def _script_lines(path: Path) -> list[tuple[int, str, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    consts: dict[str, str] = {}
    found: list[tuple[int, str, str]] = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            text = _render(node.value, consts)
            if text is not None:
                consts[name] = text
            if _NEXT_CONST.fullmatch(name):
                values = node.value.values if isinstance(node.value, ast.Dict) else [node.value]
                for value in values:
                    rendered = _render(value, consts)
                    if rendered is not None and "Next:" not in rendered:
                        found.append((node.lineno, "next", rendered))
    inner = {id(v) for n in ast.walk(tree) if isinstance(n, ast.JoinedStr) for v in n.values}
    for node in ast.walk(tree):
        text = None if id(node) in inner else _render(node, consts)
        if text is None or "Next:" not in text:
            continue
        message, *nexts = text.split("Next:")
        if "{x}" not in message and not message.startswith("usage:"):
            found.append((node.lineno, "stop", message))
        found.extend((node.lineno, "next", part) for part in nexts)
    return found


def _skill_lines(path: Path) -> list[tuple[int, str, str]]:
    found: list[tuple[int, str, str]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        flat = re.sub(r"`[^`]*`", "`x`", line)
        for part in _SKILL_NEXT.split(flat)[1:]:
            found.append((number, "next", _SENTENCE_END.split(part, 1)[0]))
        for quoted in re.findall(r'stop with "([^"]+)"', line):
            found.append((number, "stop", quoted.split("Next:", 1)[0]))
    return found


def _operator_lines() -> list[tuple[str, int, str, str]]:
    out = []
    for path in sorted((REPO_ROOT / "scripts").rglob("*.py")):
        if str(path.relative_to(REPO_ROOT)) in AGENT_FACING:
            continue
        for number, kind, text in _script_lines(path):
            out.append((str(path.relative_to(REPO_ROOT)), number, kind, text))
    for path in SKILLS:
        for number, kind, text in _skill_lines(path):
            out.append((str(path.relative_to(REPO_ROOT)), number, kind, text))
    return out


HUMAN_TEXT_RULE = (
    "Text a human reads names each item in words: a short label or one line on what it is and "
    "what it does. Ids (ruling ids, issue numbers, task codes, agent names, snake_case keys) may "
    "trail in parentheses, never replace the description. Logs, status lines and messages to "
    "other agents may use ids alone. Documents carry both."
)


MAIN = "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/"


WORKSPACE_RESUME = MAIN + "daedalus_workspace.py resume --repo <repo>`"


REAUDIT_CMD = MAIN + "daedalus_train.py reaudit --repo <repo>`"


RESUME_CMD = MAIN + "daedalus_train.py resume --repo <repo>`"


# W3.2: the phrases the recipes used for a hand Write or Edit of the summary.
HAND_WRITES = re.compile(
    r"with one Write|summary (?:file )?with the (?:Write|Edit) tool|[Ss]ummary Write\b|"
    r"Write the summary now|using the Edit tool|summary's `Ledger ids: pending` line with"
)


# 0165, spec 3: the seven phase skills.
PHASE_SKILLS = ("plan", "build", "verify", "release", "brainstorm", "audit", "document")


PHASES = {"brainstorm", "plan", "build", "verify", "audit", "document", "release"}


# spec 3.6, 3.8: none ends a run where the operator stops or a folder run presents.
NEXT_NAMES = PHASES | {"none"}


# 0173: the run entry loads by its folder and speaks to the operator like the phase skills.
LOADED_SKILLS = (*PHASE_SKILLS, "run")


PHASE_PARTS = (
    "## What the phase does well",
    "## Evidence that ends it",
    "## Agents it uses",
    "## Suggested next",
)


_NEXT_ITEM = re.compile(r"- `([a-z]+)`: \S")


# 0169: a code span holding a path, command, id or placeholder keeps its train name.
_SPAN = re.compile(r"`[^`\n]*`")


_CODE_CHARS = re.compile(r"[/_<.:\[=-]")


_PLACEHOLDER = re.compile(r"<[^<>\n]*>")


def _phase_skill(name: str) -> Path:
    return REPO_ROOT / "skills" / name / "SKILL.md"


def _drop_code_spans(text: str) -> str:
    kept = _SPAN.sub(lambda m: "" if _CODE_CHARS.search(m.group(0)) else m.group(0), text)
    return _PLACEHOLDER.sub("", kept)


FOLDER_REFUSAL = (
    '"A plain folder can only brainstorm, plan, write documents and check their claims. '
    "Building, auditing and pushing need a git repository. Next: open the session in a git "
    'repository, or run git init in this folder, then run /daedalus:run again."'
)


def _run_step(number: int) -> str:
    body = _run_skill().split(f"\n{number}. ", 1)[1]
    return re.split(rf"\n(?:{number + 1}\. |#)", body, maxsplit=1)[0]


ASSETS_CMD = (
    "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py assets --repo <repo> --base <base "
    "sha> --tip daedalus/<train-id>`"
)


CODER_PACKS = (
    "<plugin root>/packs/coder/secure-architecture/rules.md",
    "<plugin root>/packs/coder/adversarial-coding/rules.md",
)


def _build_step4() -> str:
    text = (REPO_ROOT / "skills" / "build" / "SKILL.md").read_text()
    return " ".join(text.split("4. Brief by file", 1)[1].split("5. Dispatch.", 1)[0].split())


def _flat(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def _verify_rows_mode() -> str:
    return _flat(_phase_skill("verify")).split("### Rows mode", 1)[1].split("### Unit mode", 1)[0]


def _verify_unit_mode() -> str:
    return _flat(_phase_skill("verify")).split("### Unit mode", 1)[1].split("### Claims mode")[0]

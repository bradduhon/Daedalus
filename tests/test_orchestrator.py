# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0060: the orchestrator agent starts and resumes agents under its dispatch gate; no one else does.
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from lib import jail, router, train_state, unit_binding
from lib.config import Config
from lib.train_scope import KNOWN_AGENTS
from lib.workspace import create, mark_train

from tests.conftest import CWD, REPO_ROOT, TRAIN_BRANCH
from tests.conftest import git as _git
from tests.hook_chain import evaluate, load
from tests.hook_chain import judge as decide
from tests.test_dispatch_binding import TRAIN, seed_plan
from tests.test_skills import HAND_WRITES

ORCHESTRATOR = "daedalus:orchestrator"
AGENT_FILE = REPO_ROOT / "agents" / "orchestrator.md"
CODER_ID = "coder-1"


def _call(tool: str, cwd: str, **tool_input: object) -> dict[str, object]:
    return {
        "agent_type": ORCHESTRATOR,
        "agent_id": "orch-1",
        "session_id": "s",
        "tool_name": tool,
        "tool_input": dict(tool_input),
        "cwd": cwd,
    }


def _start(cwd: str, subagent: str, prompt: str = "x") -> dict[str, object]:
    return _call("Agent", cwd, subagent_type=subagent, prompt=prompt, description="d")


def _resume(cwd: str, to: str, message: object) -> dict[str, object]:
    return _call("SendMessage", cwd, to=to, message=message)


@pytest.fixture
def units(repo_cwd: Path, project_data: Path) -> tuple[Path, Path]:
    ident = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    _git(repo_cwd, *ident, "commit", "-q", "--allow-empty", "-m", "base")
    _git(repo_cwd, "branch", f"daedalus/{TRAIN}")
    train_state.save(repo_cwd, TRAIN, {"train_id": TRAIN})
    mark_train(repo_cwd, TRAIN)
    first = create(repo_cwd, "u1", f"daedalus/{TRAIN}")
    second = create(repo_cwd, "u2", f"daedalus/{TRAIN}")
    jail._registered_worktrees.cache_clear()
    return first, second


def _bindings(repo: Path) -> dict[str, Any]:
    path = unit_binding.bindings_path(repo, TRAIN)
    return dict(json.loads(path.read_text(encoding="utf-8"))["units"])


def _bound_to_u1(repo: Path, first: Path) -> None:
    # issue 29: the dispatch records u1, and the coder's first write binds it.
    seed_plan(repo, TRAIN)
    d = decide(_start(str(repo), "daedalus:repo-coder", f"Build.\nWorktree: {first}\n"), Config())
    assert d.allow, d.reason
    assert unit_binding.claim(repo, TRAIN, CODER_ID, "u1") is None


@pytest.mark.parametrize("tool", ["Agent", "SendMessage"])
def test_orchestrator_may_start_and_resume_agents(tool: str) -> None:
    payload = (
        _start(CWD, "daedalus:web-researcher") if tool == "Agent" else _resume(CWD, "a1", "go")
    )
    assert router.route(payload, REPO_ROOT) == (True, None, "")


@pytest.mark.parametrize("tool", ["Agent", "SendMessage", "Task"])
def test_every_other_routed_agent_is_refused_agent_and_sendmessage(tool: str) -> None:
    for agent in sorted(KNOWN_AGENTS - {"main", "orchestrator"}):
        payload = {**_start(CWD, "daedalus:web-researcher"), "agent_type": f"daedalus:{agent}"}
        payload["tool_name"] = tool
        allow, reason, hook = router.route(payload, REPO_ROOT)
        assert (allow, reason, hook) == (False, jail.R_TOOL, "tool_bound"), agent
    task = {**_start(CWD, "daedalus:web-researcher"), "tool_name": "Task"}
    assert router.route(task, REPO_ROOT) == (False, jail.R_TOOL, "tool_bound")


@pytest.mark.parametrize(
    "subagent",
    ["general-purpose", "Explore", "repo-coder", "daedalus:mystery", "other:planner", ""],
)
def test_orchestrator_starts_only_catalog_agents(subagent: str) -> None:
    gate = load("dispatch_gate")
    assert evaluate("dispatch_gate", _start(CWD, subagent)) == gate.R_FOREIGN_AGENT


@pytest.mark.parametrize("agent", ["pr-train-conductor", "orchestrator"])
def test_orchestrator_never_starts_the_conductor_or_itself(agent: str) -> None:
    reason = evaluate("dispatch_gate", _start(CWD, f"daedalus:{agent}"))
    assert reason is not None and agent in reason and "Next:" in reason


def test_coder_dispatch_refused_without_a_recorded_plan(
    repo_cwd: Path, units: tuple[Path, Path]
) -> None:
    payload = _start(str(repo_cwd), "daedalus:repo-coder", f"Build.\nWorktree: {units[0]}\n")
    d = decide(payload, Config())
    assert not d.allow and "records no plan" in str(d.reason), d.reason
    assert not unit_binding.bindings_path(repo_cwd, TRAIN).exists()
    seed_plan(repo_cwd, TRAIN)
    assert decide(payload, Config()).allow


@pytest.mark.parametrize("prompt", ["Build the unit.", "Worktree: a\nWorktree: b", "Worktree: rel"])
def test_coder_dispatch_refused_without_a_worktree_line(
    repo_cwd: Path, units: tuple[Path, Path], prompt: str
) -> None:
    seed_plan(repo_cwd, TRAIN)
    d = decide(_start(str(repo_cwd), "daedalus:repo-coder", prompt), Config())
    assert not d.allow and "'Worktree: <absolute path>'" in str(d.reason), d.reason


def test_warm_resume_rebinds_the_unit(repo_cwd: Path, units: tuple[Path, Path]) -> None:
    # 0086, spec 8: the resume moves the coder's binding; the main session never writes it.
    first, second = units
    _bound_to_u1(repo_cwd, first)
    message = f"RESUME. Brief file: b.md\nWorktree: {second}\nGo."
    d = decide(_resume(str(repo_cwd), CODER_ID, message), Config())
    assert d.allow, d.reason
    bound = _bindings(repo_cwd)
    assert bound["u1"] == {"agent_id": None, "retired_to": "u2"}
    assert bound["u2"] == {"agent_id": CODER_ID}
    assert unit_binding.claim(repo_cwd, TRAIN, CODER_ID, "u2") is None
    assert "moved on to unit u2" in str(unit_binding.claim(repo_cwd, TRAIN, CODER_ID, "u1"))
    # 0086: a repeat of the same resume, or the runner's own rebind, finds the coder bound.
    assert decide(_resume(str(repo_cwd), CODER_ID, message), Config()).allow


def test_resume_without_a_worktree_line_binds_nothing(
    repo_cwd: Path, units: tuple[Path, Path]
) -> None:
    _bound_to_u1(repo_cwd, units[0])
    before = _bindings(repo_cwd)
    assert decide(_resume(str(repo_cwd), CODER_ID, "RESUME. Research payload: x"), Config()).allow
    assert _bindings(repo_cwd) == before


def test_resume_with_two_worktree_lines_is_refused(
    repo_cwd: Path, units: tuple[Path, Path]
) -> None:
    first, second = units
    _bound_to_u1(repo_cwd, first)
    message = f"Worktree: {first}\nWorktree: {second}"
    reason = evaluate("dispatch_gate", _resume(str(repo_cwd), CODER_ID, message))
    gate = load("dispatch_gate")
    assert reason == gate.dispatch_binding.R_RESUME_LINE


def test_resume_without_a_target_is_refused(repo_cwd: Path, units: tuple[Path, Path]) -> None:
    _bound_to_u1(repo_cwd, units[0])
    reason = evaluate("dispatch_gate", _resume(str(repo_cwd), "", f"Worktree: {units[1]}"))
    assert reason == load("dispatch_gate").dispatch_binding.R_RESUME_TARGET


def test_resume_of_an_unbound_coder_is_refused(repo_cwd: Path, units: tuple[Path, Path]) -> None:
    _bound_to_u1(repo_cwd, units[0])
    reason = evaluate("dispatch_gate", _resume(str(repo_cwd), "stranger", f"Worktree: {units[1]}"))
    assert reason is not None and "coder stranger holds no unit" in reason and "Next:" in reason
    assert "u2" not in _bindings(repo_cwd)


def test_resume_into_a_dispatched_unit_is_refused(repo_cwd: Path, units: tuple[Path, Path]) -> None:
    first, second = units
    _bound_to_u1(repo_cwd, first)
    other = _start(str(repo_cwd), "daedalus:repo-coder", f"Worktree: {second}")
    assert decide(other, Config()).allow
    reason = evaluate("dispatch_gate", _resume(str(repo_cwd), CODER_ID, f"Worktree: {second}"))
    assert reason is not None and "unit u2 was already dispatched" in reason


def test_resume_naming_a_path_outside_the_train_is_refused(
    repo_cwd: Path, units: tuple[Path, Path], tmp_path: Path
) -> None:
    _bound_to_u1(repo_cwd, units[0])
    message = {"text": f"Worktree: {tmp_path}"}
    reason = evaluate("dispatch_gate", _resume(str(repo_cwd), CODER_ID, message))
    assert reason is not None and "is not a unit worktree of train" in reason


@pytest.mark.parametrize("key", ["content", "summary", "body"])
def test_resume_gate_reads_every_field_but_the_target(
    repo_cwd: Path, units: tuple[Path, Path], key: str
) -> None:
    # 0086: the message key is ASSUMED, so a Worktree: line under any other key still rebinds.
    first, second = units
    _bound_to_u1(repo_cwd, first)
    payload = _call("SendMessage", str(repo_cwd), to=CODER_ID, **{key: f"Worktree: {second}"})
    assert decide(payload, Config()).allow
    assert _bindings(repo_cwd)["u2"] == {"agent_id": CODER_ID}


def test_resume_target_field_is_not_scanned(repo_cwd: Path, units: tuple[Path, Path]) -> None:
    _bound_to_u1(repo_cwd, units[0])
    payload = _call("SendMessage", str(repo_cwd), to=f"Worktree: {units[1]}", message="go")
    assert decide(payload, Config()).allow
    assert "u2" not in _bindings(repo_cwd)


def test_orchestrator_writes_only_its_scratch_folder(
    repo_cwd: Path, units: tuple[Path, Path]
) -> None:
    # 0060, W3.2: the train folder passes; the summary, the rest of docs/ and the ledger do not.
    scratch = repo_cwd / "docs" / ".tmp" / "daedalus"
    allowed = [scratch / TRAIN / "briefs" / "u1.md", scratch / TRAIN / "summary-notes.md"]
    refused = [
        scratch / f"{TRAIN}-summary.md",
        repo_cwd / "docs" / "howto" / "README.md",
        repo_cwd / "docs" / "private" / "specs" / "x.md",
        repo_cwd / "docs" / "decisions.md",
        scratch / "20261015-090000-summary.md",
        scratch / "20261015-090000" / "plan.md",
        repo_cwd / "src" / "a.py",
    ]
    for path in allowed:
        payload = _call("Write", str(repo_cwd), file_path=str(path), content="x")
        assert decide(payload, Config()).allow, path
    for path in refused:
        payload = _call("Write", str(repo_cwd), file_path=str(path), content="x")
        d = decide(payload, Config())
        assert not d.allow and "Next:" in str(d.reason), path


def test_orchestrator_without_the_dispatch_gate_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 0060: an agent file that drops its dispatch gate loses Agent and SendMessage.
    agents = tmp_path / "agents"
    agents.mkdir()
    text = AGENT_FILE.read_text(encoding="utf-8")
    gate = next(ln for ln in text.splitlines() if "dispatch_gate.py" in ln)
    (agents / "orchestrator.md").write_text(text.replace(gate + "\n", ""), encoding="utf-8")
    module = load("tool_bound")
    monkeypatch.setattr(module, "PLUGIN_ROOT", tmp_path)
    for payload in (_start(CWD, "daedalus:planner"), _resume(CWD, "a1", "go")):
        assert evaluate("tool_bound", payload) == module.R_NO_DISPATCH_GATE
    assert evaluate("tool_bound", _call("Read", CWD, file_path=f"{CWD}/a")) is None


_RECIPE_CMD = re.compile(r"`(python3 <plugin root>/scripts/[^`]+)`")
# 0165: the phase skills the orchestrator reads and runs, in run order.
RUN_PHASES = ("plan", "build", "verify", "audit", "document")
# 0119: the main session runs these two; the phase skills name them as its commands.
MAIN_ONLY = ("daedalus_train.py exception", "daedalus_train.py reaudit")


def _phase_text(name: str) -> str:
    # 0060: the orchestrator writes the plugin root out in full; its hook refuses the variable.
    text = (REPO_ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8")
    return text.replace("${CLAUDE_PLUGIN_ROOT}", "<plugin root>")


def _phase_step(name: str, first: int, last: int | None = None) -> str:
    body = _phase_text(name).split(f"\n{first}. ", 1)[1]
    end = first if last is None else last
    return re.split(rf"\n(?:{end + 1}\. |#)", body, maxsplit=1)[0]


INSPECT = [
    "git merge-base --is-ancestor abc123 daedalus-unit/t-u1",
    f"git -C {CWD} rev-parse daedalus/t",
    "git -C /work/Charter status --porcelain",
    f"sha256sum {CWD}/contracts/c.md {CWD}/docs/.tmp/daedalus/t/standards-packet.md",
    "find /work/rules -type f -newermt '2026-10-19 12:00'",
    f"cat {CWD}/.claude/daedalus/config.json",
    "git diff abc123...daedalus/t --stat",
]


def _recipe_commands() -> list[str]:
    text = AGENT_FILE.read_text(encoding="utf-8").split("\n---\n", 1)[1]
    # 0165: the commands of every phase skill the orchestrator runs pass its hooks too.
    text = "\n".join([text, *(_phase_text(name) for name in RUN_PHASES)])
    # The rules line names the template `python3 <plugin root>/scripts/<script>` itself.
    found = [
        m.replace("<plugin root>", str(REPO_ROOT))
        for m in _RECIPE_CMD.findall(text)
        if "/scripts/<script>" not in m and not any(cmd in m for cmd in MAIN_ONLY)
    ]
    # MAP -> REQ: the map's --out names the active train, which the jail fakes read as TRAIN_BRANCH.
    train = TRAIN_BRANCH.removeprefix("daedalus/")
    found = [m.replace("<repo>", CWD).replace("<train-id>", train) for m in found]
    return [re.sub(r"<[^>]+>", "x", m) for m in found]


def test_recipe_names_every_train_script_it_may_run() -> None:
    commands = _recipe_commands()
    names = {cmd.split()[1].rsplit("/", 1)[1] for cmd in commands}
    allowlist = load("command_allowlist")
    # refresh_frameworks.py is the operator's own-shell Next line, never the orchestrator's call.
    # Pin SRC -> MAP: the document phase's derived mode runs freeze_sources.py (0165).
    assert names - {"refresh_frameworks.py"} == set(allowlist.TRAIN_SCRIPTS)


@pytest.mark.usefixtures("jail_fakes")
def test_recipe_commands_pass_the_orchestrator_hooks() -> None:
    # 0060: every plugin script command and read the recipe runs passes the orchestrator's chain.
    commands = [c for c in _recipe_commands() if "refresh_frameworks.py" not in c]
    assert len(commands) >= 10
    for command in [*commands, *INSPECT]:
        payload = _call("Bash", CWD, command=command)
        assert router.route(payload, REPO_ROOT) == (True, None, ""), command


def test_recipe_runs_the_refresh_and_model_subcommands() -> None:
    # pin C4 -> C5: the two subcommands C4 admits are recipe commands the hook test above routes.
    names = {" ".join(cmd.split()[1:3]).rsplit("/", 1)[1] for cmd in _recipe_commands()}
    assert {"daedalus_workspace.py refresh", "daedalus_train.py model"} <= names


def test_recipe_names_the_verifier_step_and_the_one_pass_rule() -> None:
    # spec 5: once per unit, after the COMPLETE checks and before finish; one FIX pass (0161).
    verify = "Read and run `<plugin root>/skills/verify/SKILL.md` in unit mode"
    assert verify in AGENT_FILE.read_text(encoding="utf-8")
    step = " ".join(_phase_step("verify", 1, 4).split())
    assert step.startswith("When it runs (spec 5). Once per unit, after its `[STATUS: COMPLETE]`")
    assert "passes the branch, packet, descent and jail check rows" in step
    assert "and before the build phase's finish merges it" in step
    assert "Dispatch `verifier` with:" in step and "The verifier stays warm (0086)" in step
    assert "`[VERDICT: VERIFIED] claims=<n>` or `[VERDICT: REFUTED] <rows>`" in step
    # 0086: a resume's Worktree: line rebinds a coder, so the verifier gets a Unit worktree: line.
    assert "the line `Unit worktree: <unit worktree path>`" in step
    assert "never a `Worktree:` line" in step
    # V1 req 1, spec 9.2: the verifier reads named ranges; -U0 is the form the hook admits.
    assert "the line `Read: <file>:<first>-<last>[, ...]`" in step
    # prepush-2026-10-27 finding 3: the full diff stays a required read; ranges only guide.
    assert (
        '"Read the full diff `git -C <unit worktree path> diff <lock sha>...<b>`, removed lines '
        "included; the `Read:` ranges guide your attention and never bound it." in step
    )
    assert "never replaces the full diff, whose `-` lines show a removed guard" in step
    assert "`git -C <repo> diff -U0 <lock sha>...<b>`" in step
    route = _phase_step("verify", 5)
    refuted = next(ln for ln in route.splitlines() if ln.startswith("   - `[VERDICT: REFUTED]"))
    fix = 'SendMessage(that unit\'s coder, "FIX. The verifier refuted: <code and scope rows>")'
    assert fix in refuted
    # 0161: a later refutation goes to the operator; it no longer stops the run by itself.
    assert "A later REFUTED on the same unit goes to the operator as a decision" in refuted
    assert any(ln.startswith("   - `[VERDICT: VERIFIED] claims=<n>`") for ln in route.splitlines())
    merge = _phase_step("build", 10)
    assert "its verifier verdict is `[VERDICT: VERIFIED]`" in merge


PLUGIN = "`python3 <plugin root>/scripts/"
LEDGER_CMD = PLUGIN + "daedalus_train.py ledger --repo <repo> --sha <sha> --ids <ids>`"


def _recipe() -> str:
    return AGENT_FILE.read_text(encoding="utf-8")


def _step5() -> str:
    # 0165: the ledger, verdict and summary step lives in the audit phase skill.
    return _phase_step("audit", 9)


def _recovery() -> str:
    return _recipe().split("\n## Recovery\n", 1)[1].split("\n## Status contract", 1)[0]


SUMMARY_CMD = PLUGIN + "daedalus_train.py summary --repo <repo>`"


def test_recipe_records_the_ledger_then_the_verdict_then_the_summary_command() -> None:
    # 3, 73, W3.2: ledger on COMMITTED, the verdict record, then the last summary command.
    step5 = _step5()
    committed = step5.split("   - `[STATUS: COMMITTED] <sha> ids=<id>[,<id>]`: ", 1)[1]
    committed = committed.split("\n", 1)[0]
    assert "the notes file's `## Rulings` lines" in committed
    assert "Edit tool" not in committed and "`ledger recorded sha=<sha> ids=<ids>`" in committed
    approved = PLUGIN + "daedalus_train.py verdict --repo <repo> --status approved --round <n>"
    last = "   - Summary command, the last step (issue 73, 0046): after the verdict record, run"
    assert step5.index(LEDGER_CMD) < step5.index(approved) < step5.index(last)
    assert step5.index(last) < step5.rindex(SUMMARY_CMD)
    # 0165: the orchestrator's Completion step follows the audit phase's last summary command.
    assert "Completion. Print the State Block" in _recipe()
    # audit_proof.summary_anchor: the first summary command record after the recorded reply.
    assert "the first summary command record after the auditor reply the verdict record" in step5
    assert "this command runs after the verdict record and before any later auditor round" in step5
    assert "a Write of the summary file never satisfies the proof" in step5
    # REAUDIT reaches the orchestrator only by SendMessage, so it runs in the build session.
    round_ = _recovery().split("Recovery round (issue 73). ", 1)[1].split("\nLedger resume", 1)[0]
    assert "the round runs in the session the summary's `Session <id>:` line names" in round_
    assert "The round runs in the session the summary's `Session <id>:` line names" in (
        _phase_step("audit", 10)
    )


def test_recipe_routes_a_probe_only_reply_as_a_resume_to_append() -> None:
    # issue 20: a charter-docs LEDGER_PROBED reply resumes it to append; it is no off-contract stop.
    step5 = _step5()
    route = step5.split("`[STATUS: LEDGER_PROBED]`", 1)[1].split("; `[STATUS:", 1)[0]
    assert route.startswith(" resumes charter-docs to append and commit")
    assert "`[STATUS: LEDGER_APPENDED]` resumes it to commit" in step5


def test_recipe_handles_the_reaudit_and_ledger_resume_messages() -> None:
    # pin D1 -> D5, 0119: the two main-session messages; the recipe never runs reaudit or resume.
    text, recovery = _recipe(), _recovery()
    assert "`REAUDIT. reaudit round=<n> tip=<40 hex>`" in recovery
    assert (
        "`RESUME LEDGER. resume ledger train=<train-id> summary=<repo-relative path>`" in recovery
    )
    for cmd in ("daedalus_train.py reaudit", "daedalus_train.py resume"):
        assert PLUGIN + cmd not in text, cmd
    brief = text.split("## Your brief", 1)[1].split("Rules for the whole train:", 1)[0]
    assert "A prompt whose first line starts `RESUME LEDGER.` is a ledger resume" in brief
    rules = text.split("Rules for the whole train:", 1)[1].split("## Entry shapes", 1)[0]
    assert "no reaudit and no exception record" in rules
    round_ = recovery.split("Recovery round (issue 73). ", 1)[1].split("\nLedger resume", 1)[0]
    assert "read and run the recovery round of `<plugin root>/skills/audit/SKILL.md`" in round_
    # 0165: the round itself is the audit phase's step 10, refreshed before the auditor resumes.
    audit = _phase_step("audit", 10)
    refresh = "refresh the audit worktree as step 3 says"
    approved = (
        PLUGIN + "daedalus_train.py verdict --repo <repo> --status approved --round <n> "
        "--findings <findings path> --tip <judged tip>`"
    )
    order = [refresh, "resume the auditor with the step 5 items", approved, "the summary command"]
    places = [audit.index(part) for part in order]
    assert places == sorted(places)
    assert PLUGIN + "daedalus_workspace.py refresh --repo <repo> --name <train-id>-audit`" in (
        _phase_step("audit", 3)
    )
    rejected = round_.split("On `[VERDICT: REJECTED] tip=<sha>`, ", 1)[1]
    assert "no fix round runs" in rejected and "`[STATUS: DECISION]`" in rejected
    assert "no second recovery round runs on your own authority" in rejected


def test_recipe_ledger_resume_runs_the_ledger_step_only() -> None:
    # 3, spec 3.5, W3.2: codes, Charter, charter-docs, ledger, verdict, summary, TRAIN_COMPLETE.
    resume = _recovery().split("Ledger resume (issue 3). ", 1)[1]
    assert "`<repo>/docs/.tmp/daedalus/<train-id>/ledger-notes.md`" in resume
    assert "`Ledger ids: pending. Codes: --repo <R> --type <T>.`" in resume
    verdict = (
        PLUGIN + "daedalus_train.py verdict --repo <repo> --status approved --tip <judged tip>`"
    )
    order = [
        "the Charter ledger check",
        "the charter-docs dispatch",
        "`ledger` on `[STATUS: COMMITTED]`",
        verdict,
        "and the summary command",
        "Then Completion.",
    ]
    places = [resume.index(part) for part in order]
    assert places == sorted(places)
    assert "run its step 9 ledger step only" in resume
    # The notes file the resume reads is written beside the pending summary.
    step5 = _step5()
    assert step5.index("`<repo>/docs/.tmp/daedalus/<train-id>/ledger-notes.md`") < step5.index(
        "Dispatch `charter-docs`"
    )


def test_recipe_copies_the_version_line_only_when_the_plan_carries_one() -> None:
    # pin D4 -> D5: the summary's Version class line comes from the plan's optional version line.
    shape = _recipe().split("Shape:", 1)[1].split("\nCompletion. ", 1)[0]
    lines = shape.splitlines()
    at = lines.index("       Version class: <x.y.z> <class>: <reason>")
    note = lines[at + 1]
    assert note.startswith("         only when the recorded plan carries a version line")
    assert "`version: <x.y.z> | class: <X, Y or Z> | reason: <one line> | unit: <unit id>`" in note
    assert "with no version line, no Version class line" in note
    assert lines[at - 1].startswith("       [POLICY: none declared]")


def test_recipe_ledger_command_is_admitted_for_the_orchestrator() -> None:
    # pin D1 -> D6: the allowlist admits ledger; the hook test above routes the full command.
    names = {" ".join(cmd.split()[1:3]).rsplit("/", 1)[1] for cmd in _recipe_commands()}
    assert "daedalus_train.py ledger" in names
    # W3.2: the summary command runs in place of the recipe's summary Write and Edit.
    assert "daedalus_train.py summary" in names


def test_no_recipe_step_writes_the_summary_by_hand() -> None:
    # W3.2: every summary rewrite in the recipe is the summary command, never a Write or Edit.
    text = _recipe()
    assert HAND_WRITES.findall(text) == []
    for part in (_step5(), _recovery()):
        assert SUMMARY_CMD in part
    assert "the hook refuses your Write or Edit of it (0046)" in text


def test_summary_command_runs_through_the_orchestrator_hooks(
    repo_cwd: Path, units: tuple[Path, Path]
) -> None:
    # W3.2: the allowlist admits summary; the Write of the summary file is refused.
    command = f"python3 {REPO_ROOT}/scripts/daedalus_train.py summary --repo {repo_cwd}"
    assert decide(_call("Bash", str(repo_cwd), command=command), Config()).allow
    summary = repo_cwd / "docs" / ".tmp" / "daedalus" / f"{TRAIN}-summary.md"
    write = _call("Write", str(repo_cwd), file_path=str(summary), content="x")
    assert not decide(write, Config()).allow


def _part(head: str, nxt: str) -> str:
    return _recipe().split(f"\n## {head}\n", 1)[1].split(f"\n## {nxt}\n", 1)[0]


def test_glue_holds_the_new_sections_in_order() -> None:
    # 0165, spec 4: the body is the rules, the State Block and the glue; no phase text stays.
    heads = re.findall(r"^## .+$", _recipe().split("\n---\n", 1)[1], re.M)
    assert heads == [
        "## Your brief",
        "## Entry shapes",
        "## Sizing",
        "## Announce and go",
        "## Phases",
        "## Named compositions",
        "## Folder scope",
        "## Summary notes and completion",
        "## Recovery",
        "## Status contract",
    ]
    for gone in ("## Phase 1", "## Phase 2", "## Phase 3", "## Documentation stage"):
        assert gone not in _recipe(), gone


def test_entry_shapes_name_the_three_inputs_and_the_composition_line() -> None:
    # 0173, spec 4.1: a task in prose, a plan path, a spec path; brainstorm stays in main (0179).
    entry = " ".join(_part("Entry shapes", "Sizing").split())
    assert "1. `Task: <words>`, a task in prose." in entry
    assert "For a small effort you write a one-unit plan yourself" in entry
    plan = "2. `Plan: <path>`, a plan file `/daedalus:plan` or the brainstorm hand-off wrote."
    assert plan in entry
    assert "from the validator's graph line (units, critical path, width)" in entry
    assert "dispatch no planner" in entry and "3. `Spec: <path>`" in entry
    assert "The main session runs brainstorm before it starts you" in entry
    assert "A `Composition: <name>` line picks that named composition and skips the sizing" in entry
    assert "you still record the size" in entry


SIZE_ROWS = (
    "| small | one unit; at most 3 files and about 150 changed lines expected; no file under "
    "`scripts/checks/`, `agents/`, `skills/` or `hooks/`, and not `scripts/lib/jail.py`, "
    "`scripts/lib/shell.py` or `scripts/enforce_agent_jail.py`; no protected path; "
    "`contract: skip` | build, verify, audit in the short form; document only when the change "
    "touches what the four public docs describe |",
    "| medium | up to 4 units in one wave, or a small change that touches agent, skill or hook "
    "files; a contract may be needed | plan, build, verify, audit, document |",
    "| full | more than 4 units, more than one wave, any jail check file, a revised contract or a "
    "cross-module change | plan with the standards and contract stages, build, verify, audit "
    "with the reachability pass, document |",
)


def test_sizing_table_carries_the_ruled_small_row() -> None:
    # 0175, spec 4.2: the three rows, the excluded paths and the measured audit.
    sizing = _part("Sizing", "Announce and go")
    rows = [ln for ln in sizing.splitlines() if ln.startswith("| ")]
    assert rows[0] == "| Size | When | Phases |"
    assert tuple(rows[1:]) == SIZE_ROWS
    flat = " ".join(sizing.split())
    assert "The small row is ruled (small change defined, 0175)." in flat
    required = "When the contract command prints `contract: required (<reason>)`, the run is not"
    assert required + " small" in flat
    assert "A size estimate never shrinks the audit by itself." in flat
    assert "either check failing means the full procedure" in flat
    # 0175: the auditor's short form names the same excluded paths the small row names.
    auditor = " ".join((REPO_ROOT / "agents" / "security-auditor.md").read_text().split())
    for path in ("`scripts/checks/`, `agents/`, `skills/` or `hooks/`", "`scripts/lib/shell.py`"):
        assert path in auditor and path in SIZE_ROWS[0], path


ANNOUNCE_LINE = (
    "`Run <run id>: <size>, because <one-clause reason>. Phases: <list>. Reply to change it.`"
)
ANNOUNCE_STATUS = "[STATUS: ANNOUNCE] size=<size> phases=<list>"


def test_announce_and_go_records_prints_and_ends_with_the_status_line() -> None:
    # 0168, spec 4.3: choice with --phase, one plain line, the status line, then GO. or CHANGE.
    part = " ".join(_part("Announce and go", "Phases").split())
    choice = (
        PLUGIN + "daedalus_train.py choice --repo <repo> --phase <first phase> --chose "
        '"<size>: <phases in order>" --over "<the next shape up or down>" --cost "<agents and '
        'rounds it adds or saves>"`'
    )
    assert part.index(choice) < part.index(ANNOUNCE_LINE) < part.index(f"`{ANNOUNCE_STATUS}`")
    assert "It prints `Chose <what> over <alternative>: <cost>`" in part
    assert "joined by a comma and a space" in part and "joined by commas with no space" in part
    assert "resumes you at once with `GO.`; it never asks the operator to confirm" in part
    assert "A resume message whose last line starts `CHANGE. `" in part
    assert "A phase already finished stays finished." in part
    contract = _recipe().split("## Status contract\n", 1)[1]
    assert f"- `{ANNOUNCE_STATUS}`" in contract.splitlines()


def test_each_phase_line_reads_its_skill_by_the_full_plugin_root() -> None:
    # 0165: one line per phase skill; the hook refuses the plugin root variable in a command.
    phases = _part("Phases", "Named compositions")
    for name in RUN_PHASES:
        line = f"Read and run `<plugin root>/skills/{name}/SKILL.md`"
        assert line in phases, name
        assert (REPO_ROOT / "skills" / name / "SKILL.md").is_file(), name
    assert "${CLAUDE_PLUGIN_ROOT}" not in _recipe().split("\n---\n", 1)[1]
    flat = " ".join(phases.split())
    for overlap in (
        "the plan beside the standards packet",
        "verify per unit while later units build",
        "the compliance judges beside the audit worktree creation",
        "the docs writer after the security verdict record",
    ):
        assert overlap in flat, overlap
    # 0179: brainstorm and release stay in the main session; the hook refuses the conductor.
    assert "Brainstorm and release run in the main session, never here" in flat
    assert "You never start the release phase" in flat
    assert "`--phase <the phase skill's name>`" in flat


def test_named_compositions_table_matches_spec_six() -> None:
    # spec 6, 0167: build, push and doc are compositions; only build runs in the orchestrator.
    part = _part("Named compositions", "Folder scope")
    rows = [ln for ln in part.splitlines() if ln.startswith("| ")]
    assert rows[0] == "| Name | Phases in order | Notes |"
    assert [row.split(" | ", 1)[0] for row in rows[1:]] == ["| build", "| push", "| doc"]
    assert rows[1].startswith("| build | plan, build, verify, audit, document | ")
    assert "Sized phases are not trimmed when the operator names it." in rows[1]
    assert rows[2].startswith(
        "| push | release, with one audit recovery round first when the tip moved after the "
        "verdict | Runs in the main session"
    )
    assert rows[3].startswith(
        "| doc | document in derived document mode, verify in claims mode, then the change gate "
        "and the present step | "
    )
    flat = " ".join(part.split())
    assert "You run build. The main session runs push and doc itself" in flat
    assert "next=run it from the main session with /daedalus:run`" in flat


def test_folder_scope_never_sizes_into_build_audit_or_release() -> None:
    # 0178, spec 9: no audit in a folder; the stop names a repository.
    flat = " ".join(_part("Folder scope", "Summary notes and completion").split())
    assert "Never size a folder run into build, audit or release" in flat
    assert "(no audit in a folder, 0178)" in flat
    assert (
        "`[STATUS: STOP] reason=a plain folder cannot build, audit or push next=open the session "
        "in a git repository, then run /daedalus:run again`"
    ) in flat

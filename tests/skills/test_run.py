# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from tests.skill_helpers import (
    BEGIN,
    FOLDER_REFUSAL,
    REAUDIT_CMD,
    RESUME_CMD,
    STOP_CMD,
    WORKSPACE_RESUME,
    _run_skill,
    _run_step,
    _section,
)


def test_begin_never_asks_about_decisions() -> None:
    # 0247: no name, no decisions; begin reads the named file or none and never asks.
    pre = _section(_run_skill(), "## Preconditions", "## Phase 1")
    assert "Exit 3" not in _run_skill() and "append_ledger.py --probe" not in pre
    assert "Begin never asks about decisions (0247)." in pre
    assert "reads the decisions file the service manifest names, or none (0004, 0247)" in pre


def test_build_train_names_the_push_train_in_present_tense() -> None:
    # 0173: the run entry names the push composition by its new command.
    text = _run_skill()
    assert "/daedalus:run push" in text and "/daedalus:push-train" not in text
    assert "Push Train will" not in text and "adds the Push Train" not in text
    assert "A later Daedalus release adds `/daedalus:run push`" not in text


def test_build_train_proves_live_hooks_after_begin() -> None:
    # 0035: begin creates the data dir; the next command proves hooks live, as in the Push Train.
    pre = _section(_run_skill(), "## Preconditions", "## Relay")
    step = pre.split("\n5. ", 1)[1]
    hooks = (
        "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/verify_audit_chain.py --hooks-live --repo <repo>`"
    )
    assert step.startswith(f"Run {hooks}.")
    assert pre.index(BEGIN) < pre.index(hooks)
    assert "record `<id>` in the State Block as `audit session: <id>`" in step
    assert "ends in `audit session: pending`" in pre


def test_build_train_runs_without_config_json() -> None:
    # 0020: test_begin_invalid_config_stops_with_its_next; absent config is the empty config.
    pre = _section(_run_skill(), "## Preconditions", "## Phase 1")
    assert "an absent config.json means the defaults" in pre


def test_build_train_relays_the_recovery_round_after_train_complete() -> None:
    # 73, spec 3.3, pin D1 -> D5: resume the stopped train, reaudit, then the REAUDIT relay.
    recovery = _run_skill().split("## Recovery", 1)[1]
    assert WORKSPACE_RESUME in recovery.split("\n- ", 1)[0]
    item = recovery.split("- Recovery round (issue 73): ", 1)[1].split("\n- ", 1)[0]
    assert item.startswith("after TRAIN_COMPLETE, the operator reports a commit on the integration")
    assert "`reaudit round=<n> tip=<40 hex>`" in item
    order = [
        "Run the resume command",
        REAUDIT_CMD,
        'SendMessage(orchestrator, "REAUDIT. <its printed line>")',
        "replies TRAIN_COMPLETE again",
        "no second recovery round runs on this session's authority",
    ]
    places = [item.index(part) for part in order]
    assert places == sorted(places)
    assert "one question per finding and the three per-finding choices" in item


def test_build_train_admits_the_ledger_resume_as_a_resume() -> None:
    # 3, spec 3.5: the one orchestrator start after the first, admitted only after resume printed.
    text = _run_skill()
    item = text.split("- Ledger resume (issue 3): ", 1)[1].split("\n", 1)[0]
    assert "`Ledger ids: pending`" in item
    assert "`resume ledger train=<train-id> summary=<repo-relative path>`" in item
    order = [
        "Run the resume command",
        RESUME_CMD,
        "Agent(`orchestrator`) with `model: <that word>`",
        "`RESUME LEDGER. <its printed line>`",
        "replies TRAIN_COMPLETE",
    ]
    places = [item.index(part) for part in order]
    assert places == sorted(places)
    step9 = _section(text, "## Relay", "## Recovery").split("\n9. ", 1)[1].split("\n10. ", 1)[0]
    assert step9.startswith("If SendMessage to the orchestrator fails, never start a second")
    assert (
        "The exceptions are the ledger resume below, after its `resume` command printed its "
        "line, which resumes the stopped run for one step, not a second run;"
    ) in step9
    assert "a fresh orchestrator started from the state file at a checkpoint" in step9


def test_build_train_precondition_stops_on_stale_agents() -> None:
    # spec 6, pin D1 -> D5: hooks-live prints the stale line and exits 0; the skill stops on it.
    step = _section(_run_skill(), "## Preconditions", "## Relay").split("\n5. ", 1)[1]
    step = step.split("\n\n", 1)[0]
    stale = step.split("`stale agents: <names>`", 1)[1]
    assert "stop and show that line." in stale
    assert "Next: start a new Claude Code session, then run /daedalus:run again." in stale


def test_run_skill_refuses_build_audit_and_release_in_a_folder() -> None:
    # 0178, spec 9: a plain folder admits brainstorm, plan, document and verify, and no audit.
    scope = " ".join(_run_step(1).split())
    print_scope = "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_doctor.py --print-scope`"
    assert scope.startswith(f"Run {print_scope}.")
    assert "`scope: repository`: go on at step 2." in scope
    folder = scope.split("- `scope: folder`: ", 1)[1]
    assert "It admits only brainstorm, plan, document and verify" in folder
    assert "no security audit runs in it (no audit in a folder, 0178)" in folder
    assert "never start the orchestrator" in folder
    assert "a task in words, a plan path, `build` or `push`, needs build, audit or release" in (
        folder
    )
    assert f"stop with {FOLDER_REFUSAL}" in folder
    assert _run_skill().index("## Scope") < _run_skill().index("## Preconditions")


def test_run_skill_relays_the_announce_line_and_goes() -> None:
    # 0168: print the announce line, resume with GO. at once, never ask to confirm.
    route = _run_step(7)
    announce = next(ln for ln in route.splitlines() if "`[STATUS: ANNOUNCE]" in ln)
    assert announce.startswith("   - `[STATUS: ANNOUNCE] size=<size> phases=<list>`: print")
    line = "`Run <run id>: <size>, because <reason>. Phases: <list>. Reply to change it.`"
    assert line in announce and 'at once SendMessage(orchestrator, "GO.")' in announce
    assert "Never ask the operator to confirm the size or the phases" in announce
    change = " ".join(_run_step(8).split())
    assert "relay the words unchanged as the last line of the next message" in change
    assert "`CHANGE. <the operator's words>`" in change
    assert "At an announce reply that line is the whole message, in place of `GO.`" in change
    done = next(ln for ln in route.splitlines() if "`[STATUS: TRAIN_COMPLETE]" in ln)
    assert "then run /daedalus:run push to push the branch" in done
    assert "never start it on your own" in done


def test_run_skill_carries_the_build_train_preconditions_and_relay() -> None:
    # 0173: the run entry takes the build-train skill's preconditions, relay and recovery.
    run, build = _run_skill(), _run_skill()
    for part in (
        BEGIN,
        "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/verify_audit_chain.py --hooks-live --repo <repo>`",
        "When the output also prints a `stale agents: <names>` line",
        "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py model --repo <repo> --agent "
        "orchestrator`",
        "The first six lines of the **State Block** are begin's output",
        "- `[STATUS: DECISION] brief=<path> questions=<n>`: read the brief file.",
        "- `[STATUS: STOP] reason=<what happened> next=<next action>`: run the stop command",
        WORKSPACE_RESUME,
        REAUDIT_CMD,
        RESUME_CMD,
        'SendMessage(orchestrator, "REAUDIT. <its printed line>")',
        "`RESUME LEDGER. <its printed line>`",
        "never start a second orchestrator",
    ):
        assert part in run and part in build, part
    assert run.index(BEGIN) < run.index("--hooks-live") < run.index("Agent(`orchestrator`)")
    assert STOP_CMD in run
    assert "git push" not in run


def test_run_skill_reads_each_argument_shape() -> None:
    # 0173, spec 4.1: words, a plan or spec path, brainstorm, and a leading composition name.
    args = " ".join(_run_step(2).split())
    assert args.startswith("Read the first word of `$ARGUMENTS` (spec 4.1):")
    brainstorm = args.split("- `brainstorm`: ", 1)[1].split(" - `build`: ", 1)[0]
    # 0179: brainstorm runs in the main session, never in the orchestrator.
    assert "in the main session, never in the orchestrator (brainstorm stays in main, 0179)" in (
        brainstorm
    )
    assert "`${CLAUDE_PLUGIN_ROOT}/skills/brainstorm/SKILL.md`" in brainstorm
    assert "go on with that file as a plan path" in brainstorm
    assert "the orchestrator prompt carries the line `Composition: build`" in args
    push = args.split("- `push`: ", 1)[1].split(" - `doc`: ", 1)[0]
    assert "never start the orchestrator for it" in push
    assert "`${CLAUDE_PLUGIN_ROOT}/skills/release/SKILL.md`" in push
    doc = args.split("- `doc`: ", 1)[1].split(" - Anything else", 1)[0]
    assert "`${CLAUDE_PLUGIN_ROOT}/skills/document/SKILL.md` in derived document mode" in doc
    assert "the verify phase in claims mode" in doc
    effort = args.split("- Anything else is the effort itself.", 1)[1]
    validate = "`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/validate_plan.py <path>` exits 0"
    assert validate in effort and "so the prompt carries `Plan: <path>`" in effort
    assert "so it carries `Spec: <path>`" in effort
    assert "so it carries `Task: <the words>`" in effort
    assert "Nothing at all: stop. Next: run /daedalus:run again with a task in words" in effort
    relay = _run_step(6)
    assert "the effort line of step 2" in relay and "`Composition: build` when step 2 set it" in (
        relay
    )


def test_run_skill_starts_a_folder_run_with_the_folder_begin() -> None:
    # issue 48, 0178: ask the output folder, begin with --out, hooks check, phases, then stop.
    assert "run as the Folder run section below says" in " ".join(_run_step(1).split())
    section = " ".join(_run_skill().split("\n## Folder run\n", 1)[1].split())
    plugin = "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/"
    asked = section.index("1) the project's docs folder `<repo>/docs`, 2) a new folder under /tmp")
    begin = section.index(
        f"`{plugin}daedalus_workspace.py begin --repo <repo> --scope folder --out <out>`"
    )
    live = section.index(f"`{plugin}verify_audit_chain.py --hooks-live --repo <repo>`")
    phases = section.index("- Phases.")
    end = section.index(
        f'`{plugin}daedalus_workspace.py stop --repo <repo> --reason "run complete"'
    )
    assert asked < begin < live < phases < end
    assert "the last one `scope: folder out: <out>`" in section
    assert "never starts the orchestrator (no audit in a folder, 0178)" in section
    for skill in ("brainstorm", "plan", "verify"):
        assert f"`${{CLAUDE_PLUGIN_ROOT}}/skills/{skill}/SKILL.md`" in section
    assert "`${CLAUDE_PLUGIN_ROOT}/skills/document/SKILL.md` in derived document mode" in section
    assert "The phase agents write their finished files straight into `<out>`" in section
    assert "Build, audit and release never run here." in section
    assert "with Read and Write" not in section

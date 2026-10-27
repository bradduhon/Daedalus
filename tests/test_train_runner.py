# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from lib import audit, gh_policy, train_runner, train_state, workspace
from lib.audit_proof import ProofError, live_log
from lib.config import Config
from lib.jail import decide
from lib.train_runner import STEP_NEEDLE

from tests.conftest import REPO_ROOT, SCRIPTS_DIR, replay_auditor
from tests.conftest import git as _git

SESSION = "sess-run"
# 0024: the probe script prints a record line and exits with the code it is given.
PROBE = (
    "import sys\n"
    "print('probe_value: 42')\n"
    "print('probe args ' + ' '.join(sys.argv[2:]))\n"
    "sys.exit(int(sys.argv[1]))\n"
)
CODE_TEMPLATE = "Worktree: {unit_path}\nBuild unit {unit_name} for train {train_id}.\n"
SOLO_TEMPLATE = "Build the change for train {train_id} in {repo}.\n"
COMPLETE = "Done.\n[STATUS: COMPLETE] branch=b packet_version=1 files=x"


def _probe_stage(code: int = 0, when: str | None = None) -> dict[str, Any]:
    stage: dict[str, Any] = {
        "id": "probe",
        "gate": "build",
        "agent": "main",
        "scope": {"told": "none", "touch": ["none"], "reply": ["exit 0"]},
        "proof": {
            "script": f"probe.py {code} {{train_id}}",
            "exit": {"0": "pass", "1": "stopped"},
            "records": ["probe_value"],
        },
        "on_fail": {"stopped": "stop: Next: read the probe output above and fix it"},
    }
    if when:
        stage["when"] = when
    return stage


def _code_stage(per_unit: bool = False, yield_route: str | None = None) -> dict[str, Any]:
    stage: dict[str, Any] = {
        "id": "code",
        "gate": "build",
        "agent": "repo-coder",
        "scope": {
            "told": "trains/t/code.md" if per_unit else "trains/t/solo.md",
            "touch": ["unit-src-tests"],
            "reply": ["[STATUS: COMPLETE]", "[STATUS: YIELD_CONTRACT]"],
        },
        "proof": {
            "script": "daedalus_train.py check-reply --stage code",
            "exit": {"0": "pass", "1": "off-contract"},
            "records": ["reply_file", "packet_version"],
        },
        "on_fail": {
            "[STATUS: YIELD_CONTRACT]": yield_route
            or "stop: Next: answer the contract question, then start again"
        },
    }
    if per_unit:
        stage.update({"repeat": "per-unit", "parallel": True})
    return stage


def _definition(stages: list[dict[str, Any]], scopes: tuple[str, ...]) -> dict[str, Any]:
    return {
        "name": "t",
        "version": 1,
        "description": "A small test train the runner steps through",
        "scopes": list(scopes),
        "gates": ["build", "merge"],
        "consults": {"build": ["web-researcher"], "merge": []},
        "stages": stages,
        "off_contract": "stop: Next: rerun the test train after reading the reply",
    }


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # 0020: a temp HOME keeps the operator's settings and plugin cache out of these tests.
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)
    for key in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{key}_NAME", "t")
        monkeypatch.setenv(f"GIT_{key}_EMAIL", "t@example.invalid")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "commit.gpgsign")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "false")


@pytest.fixture
def plugin(tmp_path: Path) -> Path:
    # 0032: a plugin root with the real agents and a scripts folder holding only the probe.
    root = tmp_path.resolve() / "plugin"
    (root / "trains" / "t").mkdir(parents=True)
    (root / "scripts").mkdir()
    (root / "agents").symlink_to(REPO_ROOT / "agents")
    (root / "scripts" / "probe.py").write_text(PROBE)
    (root / "trains" / "t" / "code.md").write_text(CODE_TEMPLATE)
    (root / "trains" / "t" / "solo.md").write_text(SOLO_TEMPLATE)
    return root


def _write_train(plugin: Path, stages: list[dict[str, Any]], scopes: tuple[str, ...]) -> Path:
    path = plugin / "trains" / "t.json"
    path.write_text(json.dumps(_definition(stages, scopes)))
    return path


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path.resolve() / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / "README.md").write_text("r\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    return root


@pytest.fixture
def plain(tmp_path: Path) -> Path:
    root = tmp_path.resolve() / "plain"
    root.mkdir()
    return root


def _manifest(root: Path, features: dict[str, object], commit: bool = False) -> None:
    (root / "service-manifest.json").write_text(json.dumps({"features": features}))
    if commit:
        _git(root, "add", "-A")
        _git(root, "commit", "-q", "-m", "manifest")


def _config(root: Path, doc: dict[str, object]) -> None:
    data = root / ".claude" / "daedalus"
    data.mkdir(parents=True, exist_ok=True)
    (data / ".gitignore").write_text("*\n")
    (data / "config.json").write_text(json.dumps(doc))


def _record(repo: Path, **fields: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "session_id": SESSION,
        "hook_event_name": "PreToolUse",
        "cwd": str(repo),
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "tool_use_id": "t1",
    }
    payload.update(fields)
    rec = audit.audit_append(payload)
    assert rec is not None
    return rec


def _agent_stop(repo: Path, agent: str, message: str, agent_id: str = "a1") -> dict[str, Any]:
    return _record(
        repo,
        hook_event_name="SubagentStop",
        tool_name=None,
        tool_input=None,
        agent_id=agent_id,
        agent_type=f"daedalus:{agent}",
        last_assistant_message=message,
    )


def _state(root: Path) -> dict[str, object]:
    train = train_state.active_train(root)
    assert train is not None
    return train_state.load(root, train)


def _started(root: Path, plugin: Path, output: str | None = None) -> train_runner.Outcome:
    outcome = train_runner.start(root, "t", output, plugin)
    assert outcome.code == 0, outcome.lines
    return outcome


def _step(root: Path, plugin: Path) -> train_runner.Outcome:
    _record(
        root, tool_input={"command": f"python3 /p/scripts/daedalus_train.py step --repo {root}"}
    )
    return train_runner.step(root, plugin)


def _check(root: Path, plugin: Path, stage: str) -> train_runner.Outcome:
    _record(root, tool_input={"command": f"daedalus_train.py check-reply --stage {stage}"})
    return train_runner.check_reply(root, stage, plugin)


def _prompt(outcome: train_runner.Outcome) -> list[Path]:
    return [
        Path(line.removeprefix("Prompt file: ")) for line in outcome.lines if "Prompt file" in line
    ]


def _reply(
    repo: Path, brief: Path, text: str, agent: str = "repo-coder", agent_id: str = "a1"
) -> dict[str, Any]:
    train_runner.reply_path(brief).write_text(text, encoding="utf-8")
    return _agent_stop(repo, agent, text, agent_id)


def _nothing_written(root: Path) -> None:
    assert not (root / ".claude" / "daedalus" / "train.active").exists()
    assert not (root / train_state.STATE_DIR).exists()


def test_start_proves_live_hooks_with_its_own_command_line(repo: Path, plugin: Path) -> None:
    # spec 3.5 ASSUMED, refuted: the start call precedes the marker, so the hooks skip it.
    _write_train(plugin, [_probe_stage()], ("repository",))
    start_input = {
        "session_id": SESSION,
        "hook_event_name": "PreToolUse",
        "cwd": str(repo),
        "tool_name": "Bash",
        "tool_input": {"command": f"daedalus_train.py start --repo {repo} --train t"},
    }
    assert audit.audit_append(start_input) is None
    _started(repo, plugin)
    _record(
        repo, tool_input={"command": f"python3 /p/scripts/daedalus_train.py step --repo {repo}"}
    )
    log, count = live_log(repo, STEP_NEEDLE)
    assert log.stem == SESSION and count == 1
    _record(repo, tool_input={"command": "ls"})
    with pytest.raises(ProofError, match="NOT LIVE"):
        live_log(repo, STEP_NEEDLE)
    refused = train_runner.step(repo, plugin)
    assert refused.code == 1 and "NOT LIVE" in refused.lines[0]
    proved = _step(repo, plugin)
    assert proved.code == 0, proved.lines
    assert proved.lines[0].startswith("OK hooks live: session sess-run")
    log_entries = train_state.load(repo, str(_state(repo)["train_id"]))["stage_log"]
    assert isinstance(log_entries, list) and log_entries[0]["stage"] == "hooks-live"


def test_start_refuses_an_invalid_definition_and_writes_nothing(repo: Path, plugin: Path) -> None:
    path = _write_train(plugin, [_probe_stage()], ("repository",))
    doc = json.loads(path.read_text())
    del doc["off_contract"]
    path.write_text(json.dumps(doc))
    outcome = train_runner.start(repo, "t", None, plugin)
    assert outcome.code == 1
    assert outcome.lines[0] == "check 1: the definition lacks the top-level field off_contract"
    assert outcome.lines[-1].startswith("Next: fix each defect above")
    _nothing_written(repo)
    assert train_runner.start(repo, "../t", None, plugin).code == 1
    _nothing_written(repo)


def test_start_runs_begin_and_records_the_definition_hash(repo: Path, plugin: Path) -> None:
    path = _write_train(plugin, [_probe_stage()], ("repository",))
    outcome = _started(repo, plugin)
    assert outcome.lines[0].startswith("train: ") and " base: main @ " in outcome.lines[0]
    state = _state(repo)
    assert state["mode"] == "defined"
    assert state["definition"] == str(path.resolve())
    assert state["definition_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert state["scope_kind"] == "repository" and state["stage_index"] == 0
    assert state["features"] == {
        "scope": None,
        "secrets_scan": False,
        "scrub_file": None,
        "ledger": None,
        "github": False,
        "dependency_web_lookup": None,
        "terraform_tools": None,
        "terraform_validate": False,
    }
    assert state["base_branch"] == "main" and state["output_dir"] is None
    next_line = f"Next: move the train on with daedalus_train.py step --repo {repo}"
    assert outcome.lines[-1].startswith(next_line)


def test_step_runs_a_script_stage_and_records_its_exit(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_probe_stage(0), _probe_stage(1) | {"id": "again"}], ("repository",))
    _started(repo, plugin)
    first = _step(repo, plugin)
    assert first.code == 0, first.lines
    state = _state(repo)
    train = str(state["train_id"])
    assert f"probe args {train}" in first.lines
    assert "stage probe: exit 0, pass." in first.lines
    assert state["stage_index"] == 1 and state["records"] == {"probe_value": "42"}
    log = state["stage_log"]
    assert isinstance(log, list)
    assert log[-1] == {"stage": "probe", "unit": None, "exit": 0, "outcome": "pass"}
    second = _step(repo, plugin)
    assert second.code == 1
    assert second.lines[-1] == "Next: read the probe output above and fix it"
    assert _state(repo)["halted"] == "Next: read the probe output above and fix it"
    assert _step(repo, plugin).code == 1


def test_step_prints_dispatch_prompt_and_expect_for_an_agent_stage(
    repo: Path, plugin: Path
) -> None:
    _write_train(plugin, [_code_stage()], ("repository",))
    _started(repo, plugin)
    outcome = _step(repo, plugin)
    assert outcome.code == 0, outcome.lines
    train = str(_state(repo)["train_id"])
    brief = repo / "docs" / ".tmp" / "daedalus" / train / "briefs" / "code-1.md"
    assert outcome.lines[1:] == [
        "Dispatch: repo-coder",
        f"Prompt file: {brief}",
        "Expect: [STATUS: COMPLETE] or [STATUS: YIELD_CONTRACT]",
    ]
    assert brief.read_text() == f"Build the change for train {train} in {repo}.\n"
    waiting = _step(repo, plugin)
    assert waiting.code == 4
    assert waiting.lines[-1].startswith("Next: save each reply verbatim with the Write tool to ")


def test_check_reply_pass(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_code_stage()], ("repository",))
    _started(repo, plugin)
    (brief,) = _prompt(_step(repo, plugin))
    _reply(repo, brief, COMPLETE)
    outcome = _check(repo, plugin, "code")
    assert outcome.code == 0, outcome.lines
    assert outcome.lines[0] == "stage code: [STATUS: COMPLETE], pass."
    state = _state(repo)
    assert state["stage_index"] == 1
    assert state["records"] == {
        "reply_file": str(train_runner.reply_path(brief)),
        "packet_version": "1",
    }
    done = _step(repo, plugin)
    assert done.code == 0 and "every stage of t has passed" in done.lines[0]


def test_check_reply_routed_failure(repo: Path, plugin: Path) -> None:
    stages = [_probe_stage(), _code_stage(yield_route="back:probe rounds=1")]
    _write_train(plugin, stages, ("repository",))
    _started(repo, plugin)
    _step(repo, plugin)
    (brief,) = _prompt(_step(repo, plugin))
    _reply(repo, brief, "Blocked.\n[STATUS: YIELD_CONTRACT] which field?")
    routed = _check(repo, plugin, "code")
    assert routed.code == 2, routed.lines
    assert "goes back to stage probe (round 1 of 1)" in routed.lines[0]
    assert _state(repo)["stage_index"] == 0
    _step(repo, plugin)
    (again,) = _prompt(_step(repo, plugin))
    assert again.name == "code-2.md"
    _reply(repo, again, "Still blocked.\n[STATUS: YIELD_CONTRACT] which field?")
    spent = _check(repo, plugin, "code")
    assert spent.code == 2 and "is spent" in spent.lines[0]
    assert _state(repo)["halted"]


def test_check_reply_off_contract(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_code_stage()], ("repository",))
    _started(repo, plugin)
    (brief,) = _prompt(_step(repo, plugin))
    _reply(repo, brief, "I wrote some code but forgot the status line.")
    outcome = _check(repo, plugin, "code")
    assert outcome.code == 1
    assert "ends with none of its contract lines" in outcome.lines[0]
    assert outcome.lines[-1] == "Next: rerun the test train after reading the reply"


def test_check_reply_hash_mismatch_stops(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_code_stage()], ("repository",))
    _started(repo, plugin)
    (brief,) = _prompt(_step(repo, plugin))
    _agent_stop(repo, "repo-coder", COMPLETE)
    train_runner.reply_path(brief).write_text(COMPLETE.replace("b", "c", 1))
    outcome = _check(repo, plugin, "code")
    assert outcome.code == 1
    assert "does not match what repo-coder returned" in outcome.lines[0]
    assert outcome.lines[-1].startswith("Next: the saved reply differs")
    assert _step(repo, plugin).code == 1


@pytest.mark.parametrize("damage", ["no-key", "no-reply", "bad-utf8", "chain"])
def test_check_reply_fails_closed_on_any_read_error(repo: Path, plugin: Path, damage: str) -> None:
    # SI-7: a missing key, a missing or undecodable reply, or a broken log is a mismatch.
    _write_train(plugin, [_code_stage()], ("repository",))
    _started(repo, plugin)
    (brief,) = _prompt(_step(repo, plugin))
    _reply(repo, brief, COMPLETE)
    data = repo / ".claude" / "daedalus"
    if damage == "no-key":
        (data / audit.REPLY_KEY).unlink()
    elif damage == "no-reply":
        train_runner.reply_path(brief).unlink()
    elif damage == "bad-utf8":
        train_runner.reply_path(brief).write_bytes(b"\xff\xfe")
    else:
        log = data / "audit" / f"{SESSION}.jsonl"
        log.write_text(log.read_text().replace('"seq":2', '"seq":9', 1))
    outcome = train_runner.check_reply(repo, "code", plugin)
    assert outcome.code == 1, outcome.lines
    assert "does not match what repo-coder returned" in outcome.lines[0]
    assert _state(repo)["halted"]


def _agent_call(repo: Path, subagent: str) -> dict[str, object]:
    return {
        "session_id": SESSION,
        "hook_event_name": "PreToolUse",
        "cwd": str(repo),
        "tool_name": "Agent",
        "tool_input": {"subagent_type": subagent, "prompt": "Look this up."},
    }


def test_dispatch_the_runner_did_not_print_is_refused(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_code_stage()], ("repository",))
    _started(repo, plugin)
    _step(repo, plugin)
    refused = decide(_agent_call(repo, "daedalus:contract-spec"), Config())
    assert not refused.allow
    assert "the train runner did not print a dispatch of contract-spec" in str(refused.reason)
    assert "Next:" in str(refused.reason)
    assert not decide(_agent_call(repo, "general-purpose"), Config()).allow


def test_stage_printed_agent_is_allowed_through_the_gate(repo: Path, plugin: Path) -> None:
    # 4.8, AC-3: the gate passes the agent the current stage printed, and only while it is current.
    from lib.dispatch_binding import _step_reason

    _write_train(plugin, [_probe_stage(), _code_stage()], ("repository",))
    _started(repo, plugin)
    call = _agent_call(repo, "daedalus:repo-coder")
    tool_input = call["tool_input"]
    assert isinstance(tool_input, dict)
    before = _step_reason(tool_input, str(repo))
    assert before is not None and "did not print a dispatch of repo-coder for stage probe" in before
    assert not decide(call, Config()).allow
    _step(repo, plugin)
    printed = _step(repo, plugin)
    assert "Dispatch: repo-coder" in printed.lines
    assert _step_reason(tool_input, str(repo)) is None
    assert _step_reason({**tool_input, "subagent_type": "repo-coder"}, str(repo)) is not None


def test_consult_agent_of_the_current_gate_is_allowed(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_code_stage()], ("repository",))
    _started(repo, plugin)
    _step(repo, plugin)
    assert decide(_agent_call(repo, "daedalus:web-researcher"), Config()).allow


def _record_argv(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    seen: list[list[str]] = []
    real_run, real_popen = subprocess.run, subprocess.Popen

    def run(argv: Any, *args: Any, **kwargs: Any) -> Any:
        seen.append([str(a) for a in argv])
        return real_run(argv, *args, **kwargs)

    def popen(argv: Any, *args: Any, **kwargs: Any) -> Any:
        seen.append([str(a) for a in argv])
        return real_popen(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(subprocess, "Popen", popen)
    return seen


def test_start_in_a_plain_folder_runs_no_git_command(
    plain: Path, plugin: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_train(plugin, [_probe_stage()], ("folder",))
    seen = _record_argv(monkeypatch)
    _started(plain, plugin, "out")
    assert [argv for argv in seen if argv and Path(argv[0]).name == "git"] == []
    assert _state(plain)["scope_kind"] == "folder"


def test_start_in_a_plain_folder_asks_where_outputs_go(plain: Path, plugin: Path) -> None:
    _write_train(plugin, [_probe_stage()], ("folder",))
    outcome = train_runner.start(plain, "t", None, plugin)
    assert outcome.code == 3
    assert outcome.lines[1] == (
        f"Options: 1) the project's docs folder {plain / 'docs'}, 2) a new folder under /tmp, "
        "3) a folder you name."
    )
    assert outcome.lines[-1].startswith("Next: ask the operator which folder")
    assert not (plain / ".claude").exists()


def test_start_with_output_records_the_output_folder(
    plain: Path, plugin: Path, tmp_path: Path
) -> None:
    _write_train(plugin, [_probe_stage()], ("folder",))
    outcome = _started(plain, plugin, "out")
    assert outcome.lines[0].startswith("train: ") and f"folder: {plain}" in outcome.lines[0]
    state = _state(plain)
    assert state["output_dir"] == str(plain / "out") and (plain / "out").is_dir()
    assert state["base_branch"] is None and state["charter_branch_created"] is False
    stopped = train_runner.stop(plain, "done", None)
    assert stopped.code == 0
    assert "folder scope: no worktrees or branches to restore" in stopped.lines


def test_scope_kind_outside_the_definition_is_refused(plain: Path, plugin: Path) -> None:
    _write_train(plugin, [_probe_stage()], ("repository",))
    outcome = train_runner.start(plain, "t", "out", plugin)
    assert outcome.code == 1
    assert "runs only in repository scope" in outcome.lines[0]
    assert "set the scope key in the features object of service-manifest.json" in outcome.lines[0]
    _nothing_written(plain)


def test_manifest_scope_overrides_detection(repo: Path, plain: Path, plugin: Path) -> None:
    _write_train(plugin, [_probe_stage()], ("repository", "folder"))
    _manifest(repo, {"scope": "folder"}, commit=True)
    asked = train_runner.start(repo, "t", None, plugin)
    assert asked.code == 3 and asked.lines[0].startswith("output: ")
    _manifest(plain, {"scope": "repository"})
    refused = train_runner.start(plain, "t", None, plugin)
    assert refused.code == 1 and "is not inside a git work tree" in refused.lines[0]
    _nothing_written(plain)


@pytest.mark.parametrize(
    ("ledger", "code", "line"),
    [
        (True, 3, workspace.LEDGER_NONE),
        (None, 0, workspace.LEDGER_NONE),
        (False, 0, workspace.LEDGER_OFF),
    ],
)
def test_ledger_question_only_when_the_ledger_feature_is_on(
    repo: Path, plugin: Path, ledger: bool | None, code: int, line: str
) -> None:
    _write_train(plugin, [_probe_stage()], ("repository",))
    _manifest(repo, {} if ledger is None else {"ledger": ledger}, commit=True)
    outcome = train_runner.start(repo, "t", None, plugin)
    assert outcome.code == code, outcome.lines
    assert outcome.lines[1 if code == 0 else 0] == line
    if code == 3:
        assert workspace.LEDGER_QUESTION in outcome.lines
        _nothing_written(repo)
    else:
        assert _state(repo)["ledger_line"] == line


def test_step_skips_a_stage_whose_feature_is_off(repo: Path, plugin: Path) -> None:
    stages = [_probe_stage(when="features.ledger"), _probe_stage() | {"id": "after"}]
    _write_train(plugin, stages, ("repository",))
    _manifest(repo, {"ledger": False}, commit=True)
    _started(repo, plugin)
    outcome = _step(repo, plugin)
    assert "stage probe: skipped, features.ledger is off." in outcome.lines
    assert "stage after: exit 0, pass." in outcome.lines
    log = _state(repo)["stage_log"]
    assert isinstance(log, list)
    assert {"stage": "probe", "outcome": "skipped", "when": "features.ledger"} in log


def _units(repo: Path, names: list[str], stacked: dict[str, str] | None = None) -> None:
    train = str(_state(repo)["train_id"])
    branches = {name: f"daedalus-unit/{train}-{name}" for name in names}
    for name in names:
        base = branches.get((stacked or {}).get(name, ""), f"daedalus/{train}")
        path = repo / ".claude" / "worktrees" / f"{train}-{name}"
        train_state.add_unit(repo, train, f"{train}-{name}", branches[name], path, base)


def test_parallel_stage_dispatches_up_to_the_configured_concurrency(
    repo: Path, plugin: Path
) -> None:
    _write_train(plugin, [_code_stage(per_unit=True)], ("repository",))
    _config(repo, {"max_concurrent_builders": 2})
    _started(repo, plugin)
    _units(repo, ["u1", "u2", "u3"])
    outcome = _step(repo, plugin)
    assert outcome.code == 0, outcome.lines
    briefs = _prompt(outcome)
    assert [b.name for b in briefs] == ["code-1.md", "code-2.md"]
    assert [line for line in outcome.lines if line.startswith("Dispatch: ")] == [
        "Dispatch: repo-coder"
    ] * 2
    train = str(_state(repo)["train_id"])
    unit_path = repo / ".claude" / "worktrees" / f"{train}-u1"
    assert briefs[0].read_text().startswith(f"Worktree: {unit_path}\n")
    assert _step(repo, plugin).code == 4


def test_next_queued_unit_starts_when_one_returns(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_code_stage(per_unit=True)], ("repository",))
    _config(repo, {"max_concurrent_builders": 2})
    _started(repo, plugin)
    _units(repo, ["u1", "u2", "u3"])
    briefs = _prompt(_step(repo, plugin))
    assert len(briefs) == 2
    _reply(repo, briefs[0], COMPLETE, agent_id="coder-1")
    checked = _check(repo, plugin, "code")
    assert checked.code == 0, checked.lines
    train = str(_state(repo)["train_id"])
    assert checked.lines[0] == f"stage code for unit {train}-u1: [STATUS: COMPLETE], pass."
    assert checked.lines[1] == "Dispatch: repo-coder", "u3 builds on no unit, so it starts cold"
    (third,) = _prompt(checked)
    assert third.name == "code-3.md" and f"{train}-u3" in third.read_text()
    for n, brief in enumerate((briefs[1], third), start=2):
        _reply(repo, brief, COMPLETE + f" {brief.stem}", agent_id=f"coder-{n}")
        assert _check(repo, plugin, "code").code == 0
    done = _step(repo, plugin)
    assert done.code == 0 and "every stage of t has passed" in done.lines[-2]


def test_stacked_unit_resumes_the_coder_that_built_its_base(repo: Path, plugin: Path) -> None:
    # 0086: a unit stacked on a returned unit goes to that unit's coder, rebound to its worktree.
    from lib import unit_binding

    _write_train(plugin, [_code_stage(per_unit=True)], ("repository",))
    _started(repo, plugin)
    _units(repo, ["u1", "u2", "u3"], stacked={"u2": "u1", "u3": "u1"})
    first = _step(repo, plugin)
    (brief,) = _prompt(first)
    assert "Dispatch: repo-coder" in first.lines, "no coder built a base yet, so u1 starts cold"
    _reply(repo, brief, COMPLETE, agent_id="coder-a")
    checked = _check(repo, plugin, "code")
    assert checked.code == 0, checked.lines
    train = str(_state(repo)["train_id"])
    u2_path = repo / ".claude" / "worktrees" / f"{train}-u2"
    assert checked.lines[1] == f"Resume: repo-coder coder-a in worktree {u2_path}"
    assert not [line for line in checked.lines if line.startswith("Dispatch: ")]
    (second,) = _prompt(checked)
    assert second.read_text().startswith(f"Worktree: {u2_path}\n")
    assert unit_binding.claim(repo, train, "coder-a", f"{train}-u2") is None
    assert _step(repo, plugin).code == 4, "u3 waits for coder-a, which is busy on u2"
    refused = decide(_agent_call(repo, "daedalus:repo-coder"), Config())
    assert not refused.allow, "a resume is no fresh Agent dispatch of repo-coder"
    _reply(repo, second, COMPLETE + " u2", agent_id="coder-a")
    again = _check(repo, plugin, "code")
    u3_path = repo / ".claude" / "worktrees" / f"{train}-u3"
    assert again.lines[1] == f"Resume: repo-coder coder-a in worktree {u3_path}"


def test_concurrency_defaults_to_five_and_refuses_zero(
    repo: Path, plain: Path, plugin: Path
) -> None:
    _write_train(plugin, [_probe_stage()], ("repository", "folder"))
    _started(repo, plugin)
    assert _state(repo)["max_concurrent_builders"] == 5
    _config(plain, {"max_concurrent_builders": 0})
    refused = train_runner.start(plain, "t", "out", plugin)
    assert refused.code == 1
    assert "max_concurrent_builders must be a whole number of at least 1" in refused.lines[0]
    _nothing_written(plain)


def test_cli_prints_lines_and_returns_the_exit(plain: Path, plugin: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / "daedalus_train.py"), "state", "--repo", str(plain)],
        capture_output=True,
        text=True,
        check=False,
        cwd=plain,
    )
    # 4.1: state exits 0 even with no train; step still stops with exit 1.
    assert result.returncode == 0
    assert result.stdout.startswith(f"no Daedalus train is active in {plain}. Next: ")
    assert train_runner.step(plain, plugin).code == 1


def test_check_reply_refuses_an_older_reply_when_a_newer_one_waits(
    repo: Path, plugin: Path
) -> None:
    # 4.6: a session cannot check in an earlier passing reply over the agent's newest one.
    _write_train(plugin, [_code_stage()], ("repository",))
    _started(repo, plugin)
    (brief,) = _prompt(_step(repo, plugin))
    _reply(repo, brief, COMPLETE)
    _agent_stop(repo, "repo-coder", "Second thoughts.\n[STATUS: YIELD_CONTRACT] which field?")
    outcome = _check(repo, plugin, "code")
    assert outcome.code == 1, outcome.lines
    assert "a newer unread repo-coder stop record" in outcome.lines[0]
    assert _state(repo)["halted"]


def test_check_reply_refuses_more_replies_than_open_dispatches(repo: Path, plugin: Path) -> None:
    # 4.6: an extra reply of the stage's agent means one ran outside the train; the train halts.
    _write_train(plugin, [_code_stage(per_unit=True)], ("repository",))
    _started(repo, plugin)
    _units(repo, ["u1", "u2"])
    briefs = _prompt(_step(repo, plugin))
    assert len(briefs) == 2
    _agent_stop(repo, "repo-coder", "A stray coder.\n[STATUS: COMPLETE] branch=x")
    _reply(repo, briefs[0], COMPLETE, agent_id="coder-1")
    _agent_stop(repo, "repo-coder", COMPLETE + " u2", agent_id="coder-2")
    outcome = _check(repo, plugin, "code")
    assert outcome.code == 1, outcome.lines
    assert "3 unread repo-coder stop records for 2 open dispatch(es)" in outcome.lines[0]


def test_reply_value_that_reads_as_an_option_is_refused(repo: Path, plugin: Path) -> None:
    # 0024: a value parsed from a reply never reaches a script's argv as an option.
    stages = [
        _code_stage(),
        _probe_stage()
        | {
            "id": "after",
            "proof": {
                "script": "probe.py 0 {packet_version}",
                "exit": {"0": "pass", "1": "stopped"},
                "records": [],
            },
        },
    ]
    _write_train(plugin, stages, ("repository",))
    _started(repo, plugin)
    (brief,) = _prompt(_step(repo, plugin))
    _reply(repo, brief, "Done.\n[STATUS: COMPLETE] packet_version=--repo=/elsewhere")
    assert _check(repo, plugin, "code").code == 0
    assert _state(repo)["records"] == {
        "reply_file": str(train_runner.reply_path(brief)),
        "packet_version": "--repo=/elsewhere",
    }
    refused = _step(repo, plugin)
    assert refused.code == 1
    assert "holds '--repo=/elsewhere', which reads as an option. Next:" in refused.lines[-1]
    log = _state(repo)["stage_log"]
    assert isinstance(log, list) and not [e for e in log if e.get("stage") == "after"]


def test_definition_changed_mid_train_stops(repo: Path, plugin: Path) -> None:
    path = _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    doc = copy.deepcopy(json.loads(path.read_text()))
    doc["version"] = 2
    path.write_text(json.dumps(doc))
    outcome = _step(repo, plugin)
    assert outcome.code == 1 and "changed after the train started" in outcome.lines[0]


PLAN = (
    "# Plan\n\n"
    "### Unit A1: first piece\n\n"
    "Files: a.py\n\n"
    "```python\n# a comment line, not a heading\n```\n"
    "- [ ] Step 1\n\n"
    "### Unit A2: second piece\n\n"
    "Files: b.py\n\n"
    "## After the units\n"
)
A1_SECTION = (
    "### Unit A1: first piece\n\n"
    "Files: a.py\n\n"
    "```python\n# a comment line, not a heading\n```\n"
    "- [ ] Step 1"
)
CONTRACT = "## Locked Contract Packet\npacket_version=1\n"
STANDARDS = "## Standards Packet\n- a rule\n\nPick ledger ids: pick 1 = 0101-DAE-PLT\n"


def _plan(repo: Path) -> Path:
    path = repo / "plan.md"
    path.write_text(PLAN, encoding="utf-8")
    assert train_runner.record_plan(repo, path).code == 0
    return path


def _packets(repo: Path) -> tuple[Path, Path]:
    # 0083: the contract lives where lock records it; the Standards Packet sits in the scratch dir.
    train = str(_state(repo)["train_id"])
    contract = repo / "contracts" / "c.md"
    contract.parent.mkdir(exist_ok=True)
    contract.write_text(CONTRACT, encoding="utf-8")
    standards = repo / "docs" / ".tmp" / "daedalus" / train / "standards-packet.md"
    standards.parent.mkdir(parents=True, exist_ok=True)
    standards.write_text(STANDARDS, encoding="utf-8")
    train_state.update(repo, train, contract_path=str(contract))
    return contract, standards


def _hex(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _integration(repo: Path) -> str:
    _git(repo, "branch", "-f", f"daedalus/{_state(repo)['train_id']}", "HEAD")
    return _tip(repo)


def _tip(repo: Path) -> str:
    # 0089: the auditor's check, the verdict tip equals git rev-parse daedalus/<train-id>.
    train = str(_state(repo)["train_id"])
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", f"daedalus/{train}"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _audit_stage() -> dict[str, Any]:
    return {
        "id": "audit",
        "gate": "merge",
        "agent": "security-auditor",
        "scope": {
            "told": "trains/t/solo.md",
            "touch": ["none"],
            "reply": ["[VERDICT: APPROVED]", "[VERDICT: REJECTED]"],
        },
        "proof": {
            "script": "daedalus_train.py check-reply --stage audit",
            "exit": {"0": "pass", "1": "off-contract"},
            "records": [],
        },
        "on_fail": {"[VERDICT: REJECTED]": "back:probe rounds=2"},
    }


def _verdict(word: str, tip: str | None = None) -> str:
    # pin C1 -> C3: the verdict line names the tip the auditor judged.
    mark = f"[VERDICT: {word}]" + (f" tip={tip}" if tip else "")
    return f"{mark}\nThe findings or the rationale.\n{mark}"


def test_progress_prints_phase_weight_units_choices_open_and_next(repo: Path, plugin: Path) -> None:
    # 0085: the operator view reads state only and carries no sha, handle or absolute path.
    _write_train(
        plugin, [_code_stage(per_unit=True, yield_route="ask: which field?")], ("repository",)
    )
    _started(repo, plugin)
    _units(repo, ["a1", "a2"])
    _plan(repo)
    briefs = _prompt(_step(repo, plugin))
    _reply(repo, briefs[0], COMPLETE, agent_id="coder-1")
    assert _check(repo, plugin, "code").code == 0
    _reply(repo, briefs[1], "Blocked.\n[STATUS: YIELD_CONTRACT] which field?", agent_id="coder-2")
    assert _check(repo, plugin, "code").code == 2
    chose = train_runner.choice(
        repo, "contract packet", "one-line plan", "two minutes", phase="implementation"
    )
    assert chose.code == 0, chose.lines
    outcome = train_runner.progress(repo)
    assert outcome.code == 0, outcome.lines
    assert outcome.lines == [
        "Phase: implementation (weight: contract packet)",
        "A1 first piece: done",
        "A2 second piece: waiting on an answer",
        "Choices:",
        "Chose contract packet over one-line plan: two minutes",
        "Open:",
        "A2: [STATUS: YIELD_CONTRACT]",
        "Next: answer the open item above, then run step to retry the stage.",
    ]
    text = "\n".join(outcome.lines)
    assert str(repo) not in text and "coder-" not in text and "/" not in text
    assert re.search(r"\b[0-9a-f]{12,}\b", text) is None


def test_progress_names_the_unit_a_waiting_unit_waits_on(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_code_stage(per_unit=True)], ("repository",))
    _started(repo, plugin)
    _units(repo, ["a1", "a2"], stacked={"a2": "a1"})
    _plan(repo)
    _step(repo, plugin)
    outcome = train_runner.progress(repo)
    assert outcome.lines == [
        "Phase: build (weight: not chosen)",
        "A1 first piece: running (repo-coder)",
        "A2 second piece: waiting on A1",
        "Choices: none",
        "Open: none",
        train_runner.NEXT_NONE,
    ]
    assert train_runner.NEXT_NONE.startswith("Next: none")


def test_choice_appends_and_prints_the_line(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    first = train_runner.choice(repo, "warm resume", "cold dispatch", "about 40k tokens")
    assert first.code == 0 and first.lines == [
        "Chose warm resume over cold dispatch: about 40k tokens"
    ]
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS_DIR / "daedalus_train.py"),
            "choice",
            "--repo",
            str(repo),
            "--chose",
            "a one-line plan",
            "--over",
            "a contract packet",
            "--cost",
            "five minutes",
            "--phase",
            "plan",
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=repo,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == "Chose a one-line plan over a contract packet: five minutes\n"
    state = _state(repo)
    assert state["choices"] == [
        {"chose": "warm resume", "over": "cold dispatch", "cost": "about 40k tokens"},
        {
            "chose": "a one-line plan",
            "over": "a contract packet",
            "cost": "five minutes",
            "phase": "plan",
        },
    ]
    assert state["phase"] == "plan" and state["weight"] == "a one-line plan"
    refused = train_runner.choice(repo, "two\nlines", "x", "y")
    assert refused.code == 1 and "Next:" in refused.lines[0]
    assert len(_state(repo)["choices"]) == 2  # type: ignore[arg-type]


def test_plan_records_path_and_sha256(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_code_stage(per_unit=True)], ("repository",))
    _started(repo, plugin)
    _units(repo, ["a1"])
    missing = train_runner.record_plan(repo, repo / "nope.md")
    assert missing.code == 1 and "Next:" in missing.lines[0]
    path = _plan(repo)
    assert _state(repo)["plan"] == {"path": str(path.resolve()), "sha256": _hex(path)}
    path.write_text(PLAN + "\nedited\n", encoding="utf-8")
    refused = _step(repo, plugin)
    assert refused.code == 1 and "changed after it was recorded" in refused.lines[-1]


# 0156, 0089: the contract skip check over the recorded plan.
SKIP_UNIT = "unit: U1 | title: one | files: a.py | base: integration\n"
SKIP_GRAPH = "graph: units=1 critical_path=1 width=1 overlap_only=\n"


def _skip_plan(units: str = SKIP_UNIT, extra: str = "", below: str = "wire: none\n") -> str:
    return f"# plan\n\n```plan\n{units}{extra}{SKIP_GRAPH}```\n\n{below}"


def _contract_run(repo: Path, plugin: Path, text: str) -> train_runner.Outcome:
    if train_state.active_train(repo) is None:
        _write_train(plugin, [_probe_stage()], ("repository",))
        _started(repo, plugin)
    path = repo / "plan.md"
    path.write_text(text, encoding="utf-8")
    assert train_runner.record_plan(repo, path).code == 0
    return train_runner.contract(repo)


def test_contract_skips_a_one_unit_one_file_plan_with_wire_none(repo: Path, plugin: Path) -> None:
    outcome = _contract_run(repo, plugin, _skip_plan())
    assert (outcome.code, outcome.lines) == (0, ["contract: skip"])
    assert _state(repo)["contract_skip"] is True
    done = _train_cli(repo, "contract", "--repo", str(repo))
    assert (done.returncode, done.stdout) == (0, "contract: skip\n"), done.stderr
    # 0156: recording a new plan voids the skip until the check runs again.
    again = _contract_run(repo, plugin, _skip_plan(below=""))
    assert again.lines == ["contract: required (no wire: none line)"]
    assert "contract_skip" not in _state(repo)


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        (
            _skip_plan(SKIP_UNIT + "unit: U2 | title: two | files: b.py | base: integration\n"),
            "2 units",
        ),
        (_skip_plan(SKIP_UNIT.replace("a.py", "a.py, b.py")), "2 files"),
        (_skip_plan(SKIP_UNIT.replace("a.py", "src/*.py")), "a file glob"),
        (_skip_plan(extra="pin: U1 -> U2 | the shape\n"), "a pin line"),
        (_skip_plan(below=""), "no wire: none line"),
        (_skip_plan(below="```text\nwire: none\n```\n"), "no wire: none line"),
        ("wire: none\n\n" + _skip_plan(below=""), "no wire: none line"),
    ],
    ids=["two-units", "two-files", "glob", "pin", "no-wire", "fenced-wire", "wire-above"],
)
def test_contract_is_required_and_records_nothing(
    repo: Path, plugin: Path, text: str, reason: str
) -> None:
    outcome = _contract_run(repo, plugin, text)
    assert (outcome.code, outcome.lines) == (0, [f"contract: required ({reason})"])
    assert "contract_skip" not in _state(repo)


def test_contract_stops_on_no_plan_a_changed_plan_or_a_defect(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    none = train_runner.contract(repo)
    assert none.code == 1 and "records no plan. Next: record the plan" in none.lines[0]
    changed = _contract_run(repo, plugin, _skip_plan())
    (repo / "plan.md").write_text(_skip_plan() + "x\n", encoding="utf-8")
    assert changed.code == 0
    edited = train_runner.contract(repo)
    assert edited.code == 1 and "changed after it was recorded" in edited.lines[0]
    broken = _contract_run(repo, plugin, _skip_plan(extra="pin: nonsense\n"))
    assert broken.code == 1 and "defect(s)" in broken.lines[0] and "Next: fix" in broken.lines[0]


def test_check_reply_records_an_approved_verdict_with_the_tip(repo: Path, plugin: Path) -> None:
    # 0089: the verdict binds the integration branch tip at check-reply time.
    _write_train(plugin, [_probe_stage(), _audit_stage()], ("repository",))
    _started(repo, plugin)
    tip = _integration(repo)
    _step(repo, plugin)
    (brief,) = _prompt(_step(repo, plugin))
    record = _reply(repo, brief, _verdict("APPROVED"), agent="security-auditor")
    outcome = _check(repo, plugin, "audit")
    assert outcome.code == 0, outcome.lines
    assert _state(repo)["verdict"] == {
        "status": "approved",
        "tip": tip,
        "round": 1,
        "seq": record["seq"],
    }


def test_check_reply_records_a_rejected_verdict(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_probe_stage(), _audit_stage()], ("repository",))
    _started(repo, plugin)
    first_tip = _integration(repo)
    _step(repo, plugin)
    (brief,) = _prompt(_step(repo, plugin))
    record = _reply(repo, brief, _verdict("REJECTED"), agent="security-auditor")
    routed = _check(repo, plugin, "audit")
    assert routed.code == 2, routed.lines
    assert _state(repo)["verdict"] == {
        "status": "rejected",
        "tip": first_tip,
        "round": 1,
        "seq": record["seq"],
    }
    train = str(_state(repo)["train_id"])
    (repo / "fix.txt").write_text("fix\n")
    _git(repo, "switch", "-q", f"daedalus/{train}")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "fix")
    moved = _tip(repo)
    assert moved != first_tip
    _step(repo, plugin)
    (again,) = _prompt(_step(repo, plugin))
    second = _reply(repo, again, _verdict("APPROVED"), agent="security-auditor")
    assert _check(repo, plugin, "audit").code == 0
    assert _state(repo)["verdict"] == {
        "status": "approved",
        "tip": moved,
        "round": 2,
        "seq": second["seq"],
    }


def test_brief_carries_the_plan_section_and_both_packet_hashes(repo: Path, plugin: Path) -> None:
    # 0083: the brief names each packet by path and hash; nothing is pasted.
    _write_train(plugin, [_code_stage(per_unit=True)], ("repository",))
    _started(repo, plugin)
    _units(repo, ["a1"])
    _plan(repo)
    contract, standards = _packets(repo)
    (brief,) = _prompt(_step(repo, plugin))
    train = str(_state(repo)["train_id"])
    unit_path = repo / ".claude" / "worktrees" / f"{train}-a1"
    text = brief.read_text()
    head = f"Worktree: {unit_path}\nBuild unit {train}-a1 for train {train}.\n"
    assert text.startswith(head)
    lines = text.splitlines()
    assert f"Contract: {contract} sha256={_hex(contract)}" in lines
    assert f"Standards: {standards} sha256={_hex(standards)}" in lines
    assert "Pick ledger ids: pick 1 = 0101-DAE-PLT" in lines
    assert A1_SECTION in text and "### Unit A2" not in text
    assert CONTRACT not in text and "- a rule" not in text
    (reminder,) = [line for line in lines if line.startswith("Reminder: ")]
    assert f"Work only in {unit_path}:" in reminder
    assert "contract=<first 12 hex> standards=<first 12 hex>" in reminder
    order = [
        lines.index(line)
        for line in lines
        if line.startswith(("Contract:", "Standards:", "Pick ", "### Unit A1", "Reminder:"))
    ]
    assert order == sorted(order) and len(order) == 5
    (entry,) = _state(repo)["dispatches"]  # type: ignore[misc]
    assert entry["contract_sha256"] == _hex(contract)
    assert entry["standards_sha256"] == _hex(standards)


def test_dispatch_prompt_is_three_lines(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_code_stage()], ("repository",))
    _started(repo, plugin)
    _packets(repo)
    outcome = _step(repo, plugin)
    assert outcome.code == 0, outcome.lines
    (brief,) = _prompt(outcome)
    assert outcome.lines[1:] == [
        "Dispatch: repo-coder",
        f"Prompt file: {brief}",
        "Expect: [STATUS: COMPLETE] or [STATUS: YIELD_CONTRACT]",
    ]


@pytest.mark.parametrize("case", ["contract", "standards", "missing", "match"])
def test_complete_with_wrong_packet_hash_is_refused(repo: Path, plugin: Path, case: str) -> None:
    _write_train(plugin, [_code_stage()], ("repository",))
    _started(repo, plugin)
    contract, standards = _packets(repo)
    (brief,) = _prompt(_step(repo, plugin))
    c, s = _hex(contract)[:12], _hex(standards)[:12]
    tail = {
        "contract": f" contract={'0' * 12} standards={s}",
        "standards": f" contract={c} standards={'f' * 12}",
        "missing": "",
        "match": f" contract={c} standards={s}",
    }[case]
    _reply(repo, brief, COMPLETE + tail)
    outcome = _check(repo, plugin, "code")
    if case == "match":
        assert outcome.code == 0, outcome.lines
        return
    assert outcome.code == 1, outcome.lines
    assert "do not match the packets its brief named" in outcome.lines[0]
    (entry,) = _state(repo)["dispatches"]  # type: ignore[misc]
    assert entry["status"] == "failed"


NEVER_TYPED = "Next: run the security audit; the verdict is recorded from the auditor's reply"
HOOKS_LIVE_CMD = "verify_audit_chain.py --hooks-live"


def _verdict_call(
    repo: Path,
    status: str,
    round_: int | None,
    seq: int | None = None,
    tip: str | None = None,
    findings: Path | None = None,
) -> Any:
    # 0024: the jail appends this call's PreToolUse record before the command runs.
    _record(repo, tool_input={"command": f"python3 /p/scripts/daedalus_train.py verdict {repo}"})
    return train_runner.record_verdict(repo, status, round_, seq, tip, findings)


def _marked(repo: Path) -> int:
    # issue 57: the train's hooks-live call, which records start_seq in its state.
    from lib.audit_proof import hooks_live

    _record(repo, tool_input={"command": f"python3 /p/scripts/{HOOKS_LIVE_CMD} --repo {repo}"})
    hooks_live(repo, HOOKS_LIVE_CMD, mark=True)
    start = train_state.start_seq(_state(repo))
    assert start is not None
    return start


@pytest.mark.parametrize("status", ["approved", "rejected"])
def test_verdict_records_the_newest_matching_auditor_stop(
    repo: Path, plugin: Path, status: str
) -> None:
    # 0089: the verdict comes from the auditor's stop record, bound to the tip at call time.
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    _marked(repo)
    tip = _integration(repo)
    _agent_stop(repo, "security-auditor", _verdict(status.upper(), tip), "aud-1")
    newest = _agent_stop(repo, "security-auditor", _verdict(status.upper(), tip), "aud-1")
    _agent_stop(repo, "repo-coder", COMPLETE, "coder-1")
    # 67, 0133: a rejection always carries its finding list, so it prints the round record.
    listed = _findings(repo, 1, A) if status == "rejected" else None
    outcome = _verdict_call(repo, status, 1, tip=tip, findings=listed)
    assert outcome.code == 0, outcome.lines
    want = f"Verdict {status} recorded on tip {tip[:12]} (round 1)"
    assert outcome.lines == ["recorded rejected round=1 findings=1" if listed else want]
    record = {"status": status, "tip": tip, "round": 1, "seq": newest["seq"]}
    assert _state(repo)["verdict"] == record
    assert tip == _tip(repo)


def test_verdict_with_no_auditor_stop_refuses(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    _marked(repo)
    tip = _integration(repo)
    _agent_stop(repo, "repo-coder", _verdict("APPROVED", tip), "coder-1")
    refused = _verdict_call(repo, "approved", 1, tip=tip)
    assert refused.code == 1 and NEVER_TYPED in refused.lines[0]
    assert "verdict" not in _state(repo)


def test_verdict_with_the_other_verdict_refuses(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    _marked(repo)
    tip = _integration(repo)
    _agent_stop(repo, "security-auditor", _verdict("REJECTED", tip), "aud-1")
    refused = _verdict_call(repo, "approved", 1, tip=tip)
    assert refused.code == 1 and NEVER_TYPED in refused.lines[0]
    assert "verdict" not in _state(repo)


def test_verdict_seq_must_name_the_matching_auditor_stop(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    _marked(repo)
    tip = _integration(repo)
    auditor = _agent_stop(repo, "security-auditor", _verdict("APPROVED", tip), "aud-1")
    coder = _agent_stop(repo, "repo-coder", _verdict("APPROVED", tip), "coder-1")
    refused = _verdict_call(repo, "approved", 1, int(coder["seq"]), tip)
    assert refused.code == 1 and NEVER_TYPED in refused.lines[0]
    assert "verdict" not in _state(repo)
    passed = _verdict_call(repo, "approved", 1, int(auditor["seq"]), tip)
    assert passed.code == 0, passed.lines
    record = {"status": "approved", "tip": tip, "round": 1, "seq": auditor["seq"]}
    assert _state(repo)["verdict"] == record


def test_verdict_reads_only_the_newest_auditor_stop(repo: Path, plugin: Path) -> None:
    # 0089: a rejection after an approval is never skipped for the older approval.
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    _marked(repo)
    tip = _integration(repo)
    older = _agent_stop(repo, "security-auditor", _verdict("APPROVED", tip), "aud-1")
    _agent_stop(repo, "security-auditor", _verdict("REJECTED", tip), "aud-1")
    refused = _verdict_call(repo, "approved", 1, tip=tip)
    assert refused.code == 1 and NEVER_TYPED in refused.lines[0]
    assert "carries [VERDICT: REJECTED], not [VERDICT: APPROVED]" in refused.lines[0]
    stale = _verdict_call(repo, "approved", 1, int(older["seq"]), tip)
    assert stale.code == 1 and f"seq {older['seq']} is not the newest" in stale.lines[0]
    assert "verdict" not in _state(repo)
    first = _agent_stop(repo, "security-auditor", _verdict("APPROVED", tip), "aud-1")
    again = _agent_stop(repo, "security-auditor", _verdict("APPROVED", tip), "aud-1")
    older_approved = _verdict_call(repo, "approved", 1, int(first["seq"]), tip)
    assert older_approved.code == 1 and "is not the newest" in older_approved.lines[0]
    passed = _verdict_call(repo, "approved", 1, tip=tip)
    assert passed.code == 0, passed.lines
    record = {"status": "approved", "tip": tip, "round": 1, "seq": again["seq"]}
    assert _state(repo)["verdict"] == record


def test_verdict_cli_finds_the_seq_itself(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    _marked(repo)
    tip = _integration(repo)
    stop = _agent_stop(repo, "security-auditor", _verdict("APPROVED", tip), "aud-1")
    argv = [sys.executable, str(SCRIPTS_DIR / "daedalus_train.py"), "verdict", "--repo"]
    argv += [str(repo), "--status", "approved", "--round", "1"]
    # pin C3 -> C5: an approval without --tip refuses before any record is read.
    no_tip = subprocess.run(argv, capture_output=True, text=True, check=False, cwd=repo)
    assert no_tip.returncode == 1 and "requires --tip, the tip the auditor" in no_tip.stdout
    argv += ["--tip", tip]
    _record(repo, tool_input={"command": " ".join(argv)})
    result = subprocess.run(argv, capture_output=True, text=True, check=False, cwd=repo)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == f"Verdict approved recorded on tip {tip[:12]} (round 1)\n"
    record = {"status": "approved", "tip": tip, "round": 1, "seq": stop["seq"]}
    assert _state(repo)["verdict"] == record


def test_verdict_refuses_an_unknown_status_a_bad_round_and_no_branch(
    repo: Path, plugin: Path
) -> None:
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    _marked(repo)
    _agent_stop(repo, "security-auditor", _verdict("APPROVED", "a" * 40), "aud-1")
    no_branch = _verdict_call(repo, "approved", 1, tip="a" * 40)
    assert no_branch.code == 1 and "integration branch" in no_branch.lines[0]
    tip = _integration(repo)
    for status, round_, given in (
        ("passed", 1, tip),
        ("approved", 0, tip),
        ("approved", 1, None),
        ("approved", 1, tip.upper()),
        ("rejected", 1, "--tip"),
    ):
        refused = _verdict_call(repo, status, round_, tip=given)
        assert refused.code == 1 and "Next:" in refused.lines[0], (status, given)
    assert "verdict" not in _state(repo)


def test_verdict_with_no_train_refuses(plain: Path) -> None:
    outcome = train_runner.record_verdict(plain, "approved", 1)
    assert outcome.code == 1
    assert outcome.lines[0].startswith("no Daedalus train is active in ")


def _handback(repo: Path, message: str) -> dict[str, Any]:
    return _record(
        repo,
        hook_event_name="PostToolUse",
        tool_name="SubagentHandback",
        tool_input={"message": message},
        tool_response={"success": True},
        agent_id="aud-1",
        agent_type="daedalus:security-auditor",
    )


def test_verdict_finds_train_a_verdict_in_the_hand_back_and_the_push_gate_passes(
    repo: Path, plugin: Path
) -> None:
    # issue 57: the verdict is in the auditor's hand-back record; the push gate then passes.
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    _marked(repo)
    tip = _integration(repo)
    replay_auditor(repo, SESSION)
    refused = gh_policy.verdict_reason(str(repo), "git push")
    assert refused is not None and "no verdict is recorded" in refused
    # 59: Train A's hand-back is found, but its verdict line names no tip.
    untipped = _verdict_call(repo, "approved", 1, tip=tip)
    assert untipped.code == 1 and "verdict names tip none, not --tip" in untipped.lines[0]
    named = _handback(repo, f"[VERDICT: APPROVED] tip={tip}")
    _agent_stop(repo, "security-auditor", "Sent the round 4 verdict.", "aud-1")
    passed = _verdict_call(repo, "approved", None, tip=tip)
    assert passed.code == 0, passed.lines
    record = {"status": "approved", "tip": tip, "round": 1, "seq": named["seq"]}
    assert _state(repo)["verdict"] == record
    assert gh_policy.verdict_reason(str(repo), "git push") is None
    assert gh_policy.verdict_reason(str(repo), "gh pr create") is None


def test_verdict_refuses_train_a_without_its_hand_back_records(repo: Path, plugin: Path) -> None:
    # issue 57: the bug as Train A met it; the stop records alone carry no verdict line.
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    _marked(repo)
    tip = _integration(repo)
    replay_auditor(repo, SESSION, handbacks=False)
    refused = _verdict_call(repo, "approved", 1, tip=tip)
    assert refused.code == 1 and "carries no verdict line" in refused.lines[0]
    assert "verdict" not in _state(repo)
    reason = gh_policy.verdict_reason(str(repo), "git push")
    assert reason is not None and "no verdict is recorded" in reason


def test_verdict_newer_rejection_in_a_hand_back_wins(repo: Path, plugin: Path) -> None:
    # 0089: the newest turn's rejection wins over Train A's approvals and its own relay.
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    _marked(repo)
    tip = _integration(repo)
    replay_auditor(repo, SESSION)
    rejection = _handback(repo, "[VERDICT: REJECTED] a.py:1 high")
    _agent_stop(repo, "security-auditor", "Sent the round 4 verdict.", "aud-1")
    refused = _verdict_call(repo, "approved", 1, tip=tip)
    assert refused.code == 1
    assert "carries [VERDICT: REJECTED], not [VERDICT: APPROVED]" in refused.lines[0]
    passed = _verdict_call(repo, "rejected", None, findings=_findings(repo, 1, A))
    assert passed.code == 0, passed.lines
    record = {"status": "rejected", "tip": tip, "round": 1, "seq": rejection["seq"]}
    assert _state(repo)["verdict"] == record


def test_verdict_ignores_an_auditor_stop_before_start_seq(repo: Path, plugin: Path) -> None:
    # issue 57: an earlier train's auditor stop in the same session log never counts.
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    tip = _integration(repo)
    _agent_stop(repo, "security-auditor", _verdict("APPROVED", tip), "aud-0")
    no_start = _verdict_call(repo, "approved", 1, tip=tip)
    assert no_start.code == 1 and "records no start_seq" in no_start.lines[0]
    start = _marked(repo)
    refused = _verdict_call(repo, "approved", 1, tip=tip)
    assert refused.code == 1 and NEVER_TYPED in refused.lines[0]
    assert f"holds no daedalus:security-auditor reply after seq {start}" in refused.lines[0]
    assert "verdict" not in _state(repo)


def _findings(repo: Path, round_: int, *lines: str) -> Path:
    # pin C3 -> C1: the auditor's finding list at its one path for the round.
    train = str(_state(repo)["train_id"])
    path = repo / "docs" / ".tmp" / "daedalus" / train / "audit" / f"round{round_}" / "findings.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
    return path


def _rejected_round(repo: Path, tip: str, round_: int, *lines: str) -> Any:
    _agent_stop(repo, "security-auditor", _verdict("REJECTED", tip), "aud-1")
    return _verdict_call(
        repo, "rejected", round_, tip=tip, findings=_findings(repo, round_, *lines)
    )


A = "audit/round1/test_scope_a.py::test_refused | medium | scope"
B = "audit/round1/test_scope_b.py::test_refused | low | scope"
C = "scripts/lib/jail.py:12 contract | low | contract"


def test_rejected_rounds_record_each_set(repo: Path, plugin: Path) -> None:
    # 0109, 0133: each rejected round records its set; a recurring set prints no stall word.
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    _marked(repo)
    tip = _integration(repo)
    first = _rejected_round(repo, tip, 1, A, B, C)
    assert first.code == 0 and first.lines == ["recorded rejected round=1 findings=3"]
    second = _rejected_round(repo, tip, 2, A, B)
    assert second.lines == ["recorded rejected round=2 findings=2"]
    third = _rejected_round(repo, tip, 3, A, B)
    assert third.lines == ["recorded rejected round=3 findings=2"]
    rounds = _state(repo)["audit_rounds"]
    assert sorted(rounds) == ["1", "2", "3"]
    assert rounds["1"]["scripts/lib/jail.py:12 contract"] == {
        "severity": "low",
        "class": "contract",
    }
    assert _state(repo)["verdict"]["tip"] == tip


def test_findings_must_be_the_round_file_and_match_the_status(repo: Path, plugin: Path) -> None:
    # pin C3 -> C1: one path per round; a rejection lists findings and an approval lists none.
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    _marked(repo)
    tip = _integration(repo)
    _agent_stop(repo, "security-auditor", _verdict("REJECTED", tip), "aud-1")
    elsewhere = repo / "findings.txt"
    elsewhere.write_text(A + "\n", encoding="utf-8")
    wrong = _verdict_call(repo, "rejected", 1, tip=tip, findings=elsewhere)
    assert wrong.code == 1 and "is not the round 1 finding list file. Next: " in wrong.lines[0]
    other_round = _verdict_call(repo, "rejected", None, tip=tip, findings=_findings(repo, 2, A))
    assert other_round.code == 1 and "round 1 finding list" in other_round.lines[0]
    empty = _verdict_call(repo, "rejected", 1, tip=tip, findings=_findings(repo, 1))
    assert empty.code == 1 and "the rejected round 1 lists 0 findings" in empty.lines[0]
    bad = _verdict_call(repo, "rejected", 1, tip=tip, findings=_findings(repo, 1, "x | y"))
    assert bad.code == 1 and "Next: " in bad.lines[0]
    assert "verdict" not in _state(repo)
    _agent_stop(repo, "security-auditor", _verdict("APPROVED", tip), "aud-1")
    listed = _verdict_call(repo, "approved", 1, tip=tip, findings=_findings(repo, 1, A))
    assert listed.code == 1 and "the approved round 1 lists 1 findings" in listed.lines[0]
    relative = (
        Path("docs/.tmp/daedalus") / str(_state(repo)["train_id"]) / "audit/round1/findings.txt"
    )
    _findings(repo, 1)
    passed = _verdict_call(repo, "approved", 1, tip=tip, findings=relative)
    assert passed.lines == [f"Verdict approved recorded on tip {tip[:12]} (round 1)"]
    assert _state(repo)["audit_rounds"] == {"1": {}}


def test_tip_must_be_the_auditor_tip_and_the_integration_tip(repo: Path, plugin: Path) -> None:
    # 59: --tip equals the auditor's tip=, and the integration tip has not moved past it.
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    _marked(repo)
    tip = _integration(repo)
    _agent_stop(repo, "security-auditor", _verdict("APPROVED", "b" * 40), "aud-1")
    other = _verdict_call(repo, "approved", 1, tip=tip)
    assert other.code == 1 and f"names tip {'b' * 40}, not --tip {tip}" in other.lines[0]
    _agent_stop(repo, "security-auditor", _verdict("APPROVED", tip), "aud-1")
    (repo / "src.py").write_text("x\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "after the audit")
    moved = _integration(repo)
    stale = _verdict_call(repo, "approved", 1, tip=tip)
    assert stale.code == 1 and f"moved past the judged tip {tip[:12]}" in stale.lines[0]
    assert f"Next: run the security audit on {moved[:12]}." in stale.lines[0]
    assert "verdict" not in _state(repo)
    reason = gh_policy.verdict_reason(str(repo), "git push")
    assert reason is not None and "no verdict is recorded" in reason


def _train_cli(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    argv = [sys.executable, str(SCRIPTS_DIR / "daedalus_train.py"), *args]
    return subprocess.run(argv, capture_output=True, text=True, check=False, cwd=cwd)


def test_model_prints_the_effective_model_inside_and_outside_a_train(
    repo: Path, plugin: Path
) -> None:
    # spec 4, pin C3 -> C5: the model word alone, from the override, config, then agent file.
    outside = _train_cli(repo, "model", "--repo", str(repo), "--agent", "repo-coder")
    assert (outside.returncode, outside.stdout) == (0, "opus\n"), outside.stderr
    _config(repo, {"agent_models": {"repo-coder": "sonnet"}})
    configured = _train_cli(repo, "model", "--repo", str(repo), "--agent", "repo-coder")
    assert configured.stdout == "sonnet\n"
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    inside = _train_cli(repo, "model", "--repo", str(repo), "--agent", "repo-coder")
    assert (inside.returncode, inside.stdout) == (0, "sonnet\n")
    argv = ("model", "--repo", str(repo), "--agent", "repo-coder", "--override", "haiku")
    assert _train_cli(repo, *argv).stdout == "haiku\n"
    assert _train_cli(repo, "model", "--repo", str(repo), "--agent", "planner").stdout == "opus\n"


@pytest.mark.parametrize(
    "extra", [("--agent", "mystery"), ("--agent", "planner", "--override", "gpt-4")], ids=str
)
def test_model_refuses_an_unknown_agent_or_model(repo: Path, extra: tuple[str, ...]) -> None:
    done = _train_cli(repo, "model", "--repo", str(repo), *extra)
    assert done.returncode == 1 and "Next: " in done.stdout


def test_model_reports_a_bad_config(repo: Path) -> None:
    _config(repo, {"agent_models": {"repo-coder": "gpt-4"}})
    done = _train_cli(repo, "model", "--repo", str(repo), "--agent", "repo-coder")
    assert done.returncode == 1 and "agent_models.repo-coder" in done.stdout


def test_a_repo_outside_the_working_directory_root_is_refused(repo: Path, plain: Path) -> None:
    # 63, pin C3 -> C4: --repo must realpath to the project root of the process cwd.
    for argv in (("state", "--repo", str(plain)), ("model", "--repo", str(plain), "--agent", "x")):
        done = _train_cli(repo, *argv)
        assert done.returncode == 1
        assert done.stdout == (
            f"--repo {plain} is not the project root of the working directory ({repo}). "
            f"Next: run the command from {plain}, or pass --repo {repo}.\n"
        )
    sub = repo / "docs"
    sub.mkdir()
    linked = repo.parent / "link"
    linked.symlink_to(repo)
    assert _train_cli(sub, "state", "--repo", str(linked)).returncode == 0


def _audit_train(repo: Path, plugin: Path) -> str:
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    _marked(repo)
    return _integration(repo)


def test_an_ask_route_names_the_three_gate_labels(repo: Path, plugin: Path) -> None:
    # 0149: the ask route's Next line carries the plain gate labels, not the old choice prose.
    stage = _probe_stage(1)
    stage["on_fail"] = {"stopped": "ask: Retry the probe?"}
    _write_train(plugin, [stage], ("repository",))
    _started(repo, plugin)
    outcome = _step(repo, plugin)
    assert outcome.code == 0, outcome.lines
    assert outcome.lines[-1] == (
        "Next: put the question to the operator with the choices `Fix it now`, "
        "`Skip, track or exempt it` and `Stop the train`; run step to retry the stage, "
        "or stop on `Stop the train`."
    )
    assert "end the train" not in "\n".join(outcome.lines)


def _docs_branch(repo: Path) -> tuple[str, str, str]:
    # 0131: a verified docs worktree whose branch head is merged into the integration tip.
    from tests.test_docs_stage import _docs_unit, _verifier_says

    base = _integration(repo)
    worktree = _docs_unit(repo)
    branch = f"daedalus-unit/{_state(repo)['train_id']}{train_state.DOCS_SUFFIX}"
    (repo / "README.md").write_text("docs\n")
    _git(repo, "commit", "-q", "-am", "docs")
    head = _integration(repo)
    _git(repo, "branch", "-f", branch, head)
    _verifier_says(repo, worktree, "[VERDICT: VERIFIED] claims=1")
    return base, head, branch


def test_docs_verdict_records_the_judged_docs_tip(repo: Path, plugin: Path) -> None:
    # 0131: --judged is the docs branch head merged into the tip, recorded beside tip.
    _audit_train(repo, plugin)
    base, head, branch = _docs_branch(repo)
    bad = train_runner.record_docs_verdict(repo, "verified", judged="HEAD")
    assert bad.code == 1 and "is not a 40 lowercase hex commit sha. Next:" in bad.lines[0]
    other = train_runner.record_docs_verdict(repo, "verified", judged=base)
    assert (
        other.code == 1
        and (
            f"the merged docs commits end at {head[:12]}, not at the judged docs tip {base[:12]}. "
            "Next:"
        )
        in other.lines[0]
    )
    _git(repo, "switch", "-q", "-c", "side")
    (repo / "README.md").write_text("side\n")
    _git(repo, "commit", "-q", "-am", "side")
    side = _git(repo, "rev-parse", "HEAD").stdout.strip()
    _git(repo, "switch", "-q", "main")
    _git(repo, "branch", "-f", branch, side)
    unmerged = train_runner.record_docs_verdict(repo, "verified", judged=side)
    assert unmerged.code == 1 and "is not merged into the integration tip" in unmerged.lines[0]
    assert "docs_verdict" not in _state(repo)
    _git(repo, "branch", "-f", branch, head)
    done = train_runner.record_docs_verdict(repo, "verified", judged=head)
    assert done.lines == [f"docs verdict recorded status=verified tip={head[:12]}"]
    assert _state(repo)["docs_verdict"] == {"status": "verified", "tip": head, "judged": head}


def test_the_docs_verdict_command_requires_judged_on_verified(repo: Path, plugin: Path) -> None:
    # 0131: the command line refuses a verified docs verdict with no --judged, and --judged
    # on the security gate.
    _audit_train(repo, plugin)
    _, head, _ = _docs_branch(repo)
    gate = ("verdict", "--repo", str(repo), "--gate", "docs", "--status", "verified")
    missing = _train_cli(repo, *gate)
    assert missing.returncode == 1 and "requires --judged" in missing.stdout
    assert "Next:" in missing.stdout and "docs_verdict" not in _state(repo)
    stray = _train_cli(
        repo, "verdict", "--repo", str(repo), "--status", "approved", "--judged", head
    )
    assert stray.returncode == 1 and "belongs to --gate docs only. Next:" in stray.stdout
    done = _train_cli(repo, *gate, "--judged", head)
    assert done.returncode == 0, done.stdout + done.stderr
    assert train_state.record(_state(repo), train_state.DOCS_VERDICT)["judged"] == head


def test_verdict_derives_the_round_from_audit_rounds(repo: Path, plugin: Path) -> None:
    # 67, spec 3.1: one more than the highest recorded round, else 1; --round may be left out.
    tip = _audit_train(repo, plugin)
    assert train_runner.derived_round(_state(repo)) == 1
    _agent_stop(repo, "security-auditor", _verdict("REJECTED", tip), "aud-1")
    first = _verdict_call(repo, "rejected", None, tip=tip, findings=_findings(repo, 1, A, B))
    assert first.lines == ["recorded rejected round=1 findings=2"]
    _agent_stop(repo, "security-auditor", _verdict("REJECTED", tip), "aud-1")
    second = _verdict_call(repo, "rejected", 2, tip=tip, findings=_findings(repo, 2, A))
    assert second.lines == ["recorded rejected round=2 findings=1"]
    _agent_stop(repo, "security-auditor", _verdict("APPROVED", tip), "aud-1")
    approved = _verdict_call(repo, "approved", None, tip=tip)
    assert approved.lines == [f"Verdict approved recorded on tip {tip[:12]} (round 3)"]
    assert train_state.record(_state(repo), "audit_rounds")["3"] == {}
    assert train_runner.derived_round(_state(repo)) == 4


@pytest.mark.parametrize(
    ("state", "want"),
    [
        ({}, 1),
        ({"audit_rounds": {"1": {}, "2": {}}}, 3),
        # 67: a pre-D1 approval of round 3 left audit_rounds at {1, 2}.
        ({"audit_rounds": {"1": {}, "2": {}}, "verdict": {"status": "approved", "round": 3}}, 4),
        ({"audit_rounds": {"1": {}, "2": {}, "3": {}}, "verdict": {"round": 3}}, 4),
        ({"audit_rounds": {"1": {}}, "verdict": {"round": True}}, 2),
        ({"verdict": {"round": "5"}}, 1),
        ({"verdict": {"round": -2}}, 1),
    ],
)
def test_derived_round_counts_the_recorded_verdict_round(
    state: dict[str, object], want: int
) -> None:
    assert train_runner.derived_round(state) == want


def test_a_state_from_before_d1_takes_the_next_round(repo: Path, plugin: Path) -> None:
    # 67: audit_rounds {1, 2} and an approved round 3 verdict derive round 4, and --round 4 passes.
    tip = _audit_train(repo, plugin)
    train = str(_state(repo)["train_id"])
    verdict = {"status": "approved", "tip": tip, "round": 3, "seq": 1}
    train_state.update(repo, train, verdict=verdict, audit_rounds={"1": {}, "2": {}})
    _agent_stop(repo, "security-auditor", _verdict("REJECTED", tip), "aud-1")
    stale = _verdict_call(repo, "rejected", 3, tip=tip, findings=_findings(repo, 3, A))
    assert stale.code == 1 and "--round 3 is not round 4" in stale.lines[0]
    passed = _verdict_call(repo, "rejected", 4, tip=tip, findings=_findings(repo, 4, A))
    assert passed.code == 0, passed.lines
    assert sorted(train_state.record(_state(repo), "audit_rounds")) == ["1", "2", "4"]
    assert train_runner.derived_round(_state(repo)) == 5


def test_a_differing_round_is_refused_naming_both_numbers(repo: Path, plugin: Path) -> None:
    tip = _audit_train(repo, plugin)
    _agent_stop(repo, "security-auditor", _verdict("APPROVED", tip), "aud-1")
    refused = _verdict_call(repo, "approved", 2, tip=tip)
    assert refused.code == 1
    assert refused.lines == [
        "--round 2 is not round 1, one more than the highest round the train recorded. "
        "Next: rerun verdict with --round 1 or no --round."
    ]
    assert "verdict" not in _state(repo)


def test_a_rejection_without_findings_is_refused_naming_the_path(repo: Path, plugin: Path) -> None:
    # 67: a rejection always carries its list, so the stall word prints on every rejection.
    tip = _audit_train(repo, plugin)
    _agent_stop(repo, "security-auditor", _verdict("REJECTED", tip), "aud-1")
    refused = _verdict_call(repo, "rejected", 1, tip=tip)
    want = repo / "docs" / ".tmp" / "daedalus" / str(_state(repo)["train_id"]) / "audit"
    path = want / "round1" / "findings.txt"
    assert refused.code == 1
    assert refused.lines[0].endswith(
        f"Next: have the auditor write {path}, then rerun verdict with --findings {path}."
    )
    assert "verdict" not in _state(repo)
    approval = _agent_stop(repo, "security-auditor", _verdict("APPROVED", tip), "aud-1")
    passed = _verdict_call(repo, "approved", 1, tip=tip)
    assert passed.code == 0, passed.lines
    assert _state(repo)["verdict"] == {
        "status": "approved",
        "tip": tip,
        "round": 1,
        "seq": approval["seq"],
    }


def test_verdict_refuses_a_reply_with_both_verdicts(repo: Path, plugin: Path) -> None:
    # spec 3.6: the hand-back's whole message carries both kinds.
    tip = _audit_train(repo, plugin)
    both = _handback(repo, f"[VERDICT: APPROVED] tip={tip}\nnotes\n[VERDICT: REJECTED] a.py:1 high")
    refused = _verdict_call(repo, "approved", None, tip=tip)
    assert refused.lines == [
        f"auditor reply at seq {both['seq']} carries both verdicts. Next: rerun the audit round."
    ]


def _approved_state(repo: Path, tip: str) -> None:
    train = str(_state(repo)["train_id"])
    verdict = {"status": "approved", "tip": tip, "round": 1, "seq": 1}
    train_state.update(repo, train, verdict=verdict, audit_rounds={"1": {}}, stage_index=1)


def _commit_on_integration(repo: Path) -> str:
    (repo / "src.py").write_text("moved\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "after the audit")
    return _integration(repo)


def test_reaudit_admits_one_recovery_round_on_a_moved_tip(repo: Path, plugin: Path) -> None:
    # 73, spec 3.3: refused with no approval and on an admitted tip; one round per moved tip.
    tip = _audit_train(repo, plugin)
    none = train_runner.reaudit(repo)
    assert none.code == 1 and "records no approved verdict" in none.lines[0]
    assert "Next:" in none.lines[0]
    _approved_state(repo, tip)
    admitted = train_runner.reaudit(repo)
    assert admitted.code == 1 and "already admits the tip" in admitted.lines[0]
    assert "run the push proof verify_audit_chain.py --approved" in admitted.lines[0]
    assert train_runner.allowed_dispatch(_state(repo))[0] == set()
    moved = _commit_on_integration(repo)
    outcome = train_runner.reaudit(repo)
    assert outcome.code == 0, outcome.lines
    assert outcome.lines == [f"reaudit round=2 tip={moved}"]
    state = _state(repo)
    assert state["reaudit"] == {"judged": tip, "tip": moved, "round": 2}
    assert train_runner.allowed_dispatch(state)[0] == {"security-auditor"}
    again = train_runner.reaudit(repo)
    assert again.code == 1 and f"already ran on tip {moved[:12]}" in again.lines[0]
    assert "Next:" in again.lines[0]
    _agent_stop(repo, "security-auditor", _verdict("APPROVED", moved), "aud-1")
    recorded = _verdict_call(repo, "approved", 2, tip=moved)
    assert recorded.lines == [f"Verdict approved recorded on tip {moved[:12]} (round 2)"]
    assert train_runner.allowed_dispatch(_state(repo))[0] == set()
    closed = train_runner.reaudit(repo)
    assert closed.code == 1 and "already" in closed.lines[0]


def test_reaudit_and_resume_on_a_stopped_train_name_the_workspace_resume(repo: Path) -> None:
    for verb in ("reaudit", "resume"):
        done = _train_cli(repo, verb, "--repo", str(repo))
        assert done.returncode == 1
        assert done.stdout == (
            f"no Daedalus train is active in {repo}. Next: run daedalus_workspace.py resume "
            f"--repo {repo} to mark the stopped train active, then rerun {verb}.\n"
        )


RESUME_PLAN = (
    "# plan\n\n```plan\n"
    "unit: U1 | title: one | files: u1.txt | base: integration\n"
    "unit: U2 | title: two | files: u2.txt | base: integration\n"
    "```\n"
    "\n### U1: one\n\nRequirements:\n1. Write `u1.txt`.\n"
    "\n### U2: two\n\nRequirements:\n1. Write `u2.txt`.\n"
)


def _resumable(repo: Path, plugin: Path, pending: bool = True) -> tuple[str, Path]:
    # spec 3.5: a recorded plan of two units, U2 merged and U1 on its own branch.
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    train = str(_state(repo)["train_id"])
    plan = repo / "docs" / ".tmp" / "daedalus" / train / "plan.md"
    plan.parent.mkdir(parents=True, exist_ok=True)
    plan.write_text(RESUME_PLAN, encoding="utf-8")
    assert train_runner.record_plan(repo, plan).code == 0
    _integration(repo)
    _units(repo, ["u1", "u2"])
    _git(repo, "branch", f"daedalus-unit/{train}-u2", "HEAD")
    _git(repo, "switch", "-q", "-c", f"daedalus-unit/{train}-u1")
    (repo / "u1.txt").write_text("u1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "u1")
    _git(repo, "switch", "-q", "main")
    summary = repo / "docs" / ".tmp" / "daedalus" / f"{train}-summary.md"
    line = "Ledger ids: pending. Codes: --repo DAE --type PLT." if pending else "Ledger ids: x."
    summary.write_text(f"# Build Train {train}\n{line}\n", encoding="utf-8")
    return train, summary


def test_resume_admits_one_ledger_resume_after_every_unit_merged(repo: Path, plugin: Path) -> None:
    # 3, spec 3.5: refused with an unmerged unit, admitted once, then the ledger record closes it.
    train, _ = _resumable(repo, plugin)
    unmerged = train_runner.resume(repo)
    assert unmerged.code == 1 and "unit(s) u1 of the recorded plan" in unmerged.lines[0]
    assert "Next: resume the Build Train at its finish step" in unmerged.lines[0]
    _git(repo, "branch", "-f", f"daedalus/{train}", f"daedalus-unit/{train}-u1")
    train_state.update(repo, train, stage_index=1)
    outcome = train_runner.resume(repo)
    assert outcome.code == 0, outcome.lines
    rel = f"docs/.tmp/daedalus/{train}-summary.md"
    assert outcome.lines == [f"resume ledger train={train} summary={rel}"]
    assert train_runner.allowed_dispatch(_state(repo))[0] == {"orchestrator"}
    again = train_runner.resume(repo)
    assert again.code == 1 and "already open" in again.lines[0] and "Next:" in again.lines[0]
    sha = "a" * 40
    ledger = _train_cli(repo, "ledger", "--repo", str(repo), "--sha", sha, "--ids", "0120-DAE-PLT")
    assert ledger.stdout == f"ledger recorded sha={sha} ids=0120-DAE-PLT\n", ledger.stderr
    assert train_runner.allowed_dispatch(_state(repo))[0] == set()
    recorded = train_runner.resume(repo)
    assert (
        recorded.code == 1
        and "already records its ledger commit aaaaaaaaaaaa" in (recorded.lines[0])
    )


def test_resume_refuses_a_ledger_record_and_a_summary_without_pending(
    repo: Path, plugin: Path
) -> None:
    train, summary = _resumable(repo, plugin, pending=False)
    _git(repo, "branch", "-f", f"daedalus/{train}", f"daedalus-unit/{train}-u1")
    no_pending = train_runner.resume(repo)
    assert no_pending.code == 1 and "holds no `Ledger ids: pending` line" in no_pending.lines[0]
    summary.unlink()
    missing = train_runner.resume(repo)
    assert missing.code == 1 and "cannot read the summary" in missing.lines[0]
    train_state.update(repo, train, ledger={"sha": "b" * 40, "ids": ["0120-DAE-PLT"]})
    refused = train_runner.resume(repo)
    assert refused.code == 1 and "already records its ledger commit" in refused.lines[0]
    assert "resume" not in _state(repo)


def test_ledger_records_the_commit_and_refuses_bad_values(repo: Path, plugin: Path) -> None:
    # pin D1 -> E4: {sha, ids} in train state; each refusal exits 1 with a Next line.
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    sha = "c" * 40
    done = train_runner.record_ledger(repo, sha, "0120-DAE-PLT,0121-DAE-PLT")
    assert done.lines == [f"ledger recorded sha={sha} ids=0120-DAE-PLT,0121-DAE-PLT"]
    assert _state(repo)["ledger"] == {"sha": sha, "ids": ["0120-DAE-PLT", "0121-DAE-PLT"]}
    for bad_sha, ids in (
        ("C" * 40, "0120-DAE-PLT"),
        ("c" * 39, "0120-DAE-PLT"),
        (sha, ""),
        (sha, "0120-DAE-PLT,0120-DAE-PLT"),
        (sha, "--x"),
    ):
        refused = train_runner.record_ledger(repo, bad_sha, ids)
        assert refused.code == 1 and "Next:" in refused.lines[0], (bad_sha, ids)
    assert _state(repo)["ledger"] == {"sha": sha, "ids": ["0120-DAE-PLT", "0121-DAE-PLT"]}


def _summary_cmd(repo: Path) -> str:
    return f"python3 {SCRIPTS_DIR / 'daedalus_train.py'} summary --repo {repo}"


def _summary_file(repo: Path) -> Path:
    train = train_state.active_train(repo)
    assert train is not None
    return repo / "docs" / ".tmp" / "daedalus" / f"{train}-summary.md"


def test_summary_writes_the_file_from_state_after_its_own_bash_record(
    repo: Path, plugin: Path
) -> None:
    # W3.2: the command proves the hooks live like verdict, then writes from state and the log.
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    train = train_state.active_train(repo)
    script = SCRIPTS_DIR / "daedalus_train.py"
    coder = {"agent_id": "c1", "agent_type": "daedalus:repo-coder"}
    for command, who in (
        ("ls", {}),
        (f"python3 {script}  summary --repo {repo}", {}),
        (f"python3 {script} summary --repo {repo.parent}", {}),
        (_summary_cmd(repo), coder),
    ):
        _record(repo, tool_input={"command": command}, **who)
        refused = train_runner.summary(repo)
        assert refused.code == 1 and refused.lines[0].startswith("NOT LIVE:"), command
        assert not _summary_file(repo).exists()
    _record(repo, tool_input={"command": _summary_cmd(repo)})
    done = train_runner.summary(repo)
    rel = f"docs/.tmp/daedalus/{train}-summary.md"
    assert done.lines == [f"summary written train={train} path={rel} ledger=pending"], done.lines
    text = _summary_file(repo).read_text(encoding="utf-8")
    assert text.startswith(f"# Build Train {train}\n")
    assert "\nLedger ids: pending.\n" in text
    assert f"\nSession {SESSION}: .claude/daedalus/audit/{SESSION}.jsonl\n" in text
    assert str(repo) not in text
    train_runner.record_ledger(repo, "c" * 40, "0127-DAE-PLT")
    _record(repo, tool_input={"command": _summary_cmd(repo)})
    assert train_runner.summary(repo).lines[0].endswith("ledger=recorded")
    assert f"Ledger ids: 0127-DAE-PLT in commit {'c' * 40}." in _summary_file(repo).read_text()


def test_summary_withholds_a_log_path_and_still_writes(repo: Path, plugin: Path) -> None:
    # W3.2: an audit log record cannot be edited, so its refused path prints as the marker.
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    _agent_stop(repo, "repo-coder", "[STATUS: YIELD_WEB] fields at https://x.io/docs/hooks")
    _record(repo, tool_input={"command": _summary_cmd(repo)})
    assert train_runner.summary(repo).code == 0
    text = _summary_file(repo).read_text(encoding="utf-8")
    assert "YIELD_WEB fields at \\[path withheld\\]" in text and "x.io" not in text


def test_summary_reads_the_notes_file_and_refuses_a_bad_one(repo: Path, plugin: Path) -> None:
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    train = train_state.active_train(repo)
    notes = repo / "docs" / ".tmp" / "daedalus" / str(train) / "summary-notes.md"
    notes.parent.mkdir(parents=True, exist_ok=True)
    notes.write_text("Task: one task\n## Rulings\nnone\n", encoding="utf-8")
    command = _summary_cmd(repo)
    _record(repo, tool_input={"command": command})
    assert train_runner.summary(repo).code == 0
    assert "\nTask: one task\n" in _summary_file(repo).read_text(encoding="utf-8")
    notes.write_text("Task: t\nSession x: spoof\n", encoding="utf-8")
    _record(repo, tool_input={"command": command})
    refused = train_runner.summary(repo)
    assert refused.code == 1 and "starts with `Session <id>:`" in refused.lines[0]
    # W3.2: a path outside the allow-list exits 1 with one Next line and writes nothing.
    before = _summary_file(repo).read_text(encoding="utf-8")
    notes.write_text("Task: see C:\\Users\\u\\x.json\n", encoding="utf-8")
    _record(repo, tool_input={"command": command})
    refused = train_runner.summary(repo)
    assert refused.code == 1 and refused.lines[0].count("Next:") == 1
    assert "the Task line of summary-notes.md carries the path" in refused.lines[0]
    assert _summary_file(repo).read_text(encoding="utf-8") == before


def test_summary_cli_and_stop_write_the_summary(repo: Path, plugin: Path) -> None:
    # W3.2: stop rewrites the summary before the teardown and keeps its first session line.
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    train = train_state.active_train(repo)
    _record(repo, tool_input={"command": _summary_cmd(repo)})
    done = _train_cli(repo, "summary", "--repo", str(repo))
    assert done.returncode == 0 and done.stdout.startswith(f"summary written train={train}")
    summary = _summary_file(repo)
    summary.unlink()
    stopped = train_runner.stop(repo, "done", None)
    assert stopped.lines[0].startswith(f"summary written train={train}"), stopped.lines
    assert f"\nSession {SESSION}: " in summary.read_text(encoding="utf-8")
    assert train_runner.summary(repo).code == 1

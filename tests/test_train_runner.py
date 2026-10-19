# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from lib import audit, train_runner, train_state, workspace
from lib.audit_proof import ProofError, live_log
from lib.config import Config
from lib.jail import decide
from lib.train_runner import STEP_NEEDLE

from tests.conftest import REPO_ROOT, SCRIPTS_DIR

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


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=True)


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
) -> None:
    train_runner.reply_path(brief).write_text(text, encoding="utf-8")
    _agent_stop(repo, agent, text, agent_id)


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

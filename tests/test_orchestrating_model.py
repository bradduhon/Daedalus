# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0276: the run records its orchestrating model at its start, and one read prints decides or asks.
from __future__ import annotations

import json
from pathlib import Path

import pytest
from lib import jail, operator_file, train_runner, train_state, work_classes

from tests.conftest import CFG, CWD, REPO_ROOT, run_cli
from tests.conftest import workspace_cli as _ws
from tests.hook_chain import decide, evaluate
from tests.payloads import _b, _w
from tests.test_train_runner import (
    _probe_stage,
    _record,
    _started,
    _summary_cmd,
    _summary_file,
    _write_train,
)
from tests.test_train_runner import plugin as plugin  # noqa: F401
from tests.test_workspace_train import repo as repo  # noqa: F401

# 0020: a temp HOME and git identity for every test here.
pytestmark = pytest.mark.usefixtures("isolated_env")
SESSION_UNKNOWN = (
    "orchestrating model: unknown, by the main session (no record a script can trust names the "
    "main session's model) | at a judgement call: asks"
)
AGENT_OPUS = "orchestrating model: opus, by the orchestrator agent | at a judgement call: decides"
NO_RECORD = (
    "orchestrating model: unknown (the run began before the orchestrating model was recorded) "
    "| at a judgement call: asks"
)
UNREADABLE = (
    "orchestrating model: unknown (the run state's record of it is not in a form this version "
    "writes) | at a judgement call: asks"
)


def _read(repo: Path) -> tuple[int, list[str]]:  # noqa: F811
    done = run_cli("daedalus_train.py", "model", "--repo", str(repo), "--orchestrating", cwd=repo)
    return done.returncode, done.stdout.splitlines()


def _begin(repo: Path, *extra: str) -> str:  # noqa: F811
    done = _ws("begin", "--repo", str(repo), *extra)
    assert done.returncode == 0, done.stderr
    # 0276: begin still prints the six State Block lines and nothing else.
    assert len(done.stdout.splitlines()) == 6
    train = train_state.active_train(repo)
    assert train is not None
    return train


def _config(repo: Path, body: dict[str, object]) -> None:  # noqa: F811
    (repo / ".claude" / "daedalus" / "config.json").write_text(json.dumps(body), encoding="utf-8")


def test_a_main_session_run_records_unknown_and_reads_asks(repo: Path) -> None:  # noqa: F811
    train = _begin(repo)
    held = train_state.load(repo, train)[train_state.ORCHESTRATING]
    assert held == {"by": "session", "model": "unknown", "reason": "session-unread"}
    assert _read(repo) == (0, [SESSION_UNKNOWN])


def test_an_agent_run_records_the_model_the_orchestrator_is_dispatched_on(
    repo: Path,  # noqa: F811
) -> None:
    train = _begin(repo, "--orchestrator", "agent")
    dispatched = run_cli(
        "daedalus_train.py", "model", "--repo", str(repo), "--agent", "orchestrator", cwd=repo
    )
    assert dispatched.stdout == "opus\n"
    held = train_state.load(repo, train)[train_state.ORCHESTRATING]
    assert held == {"by": "agent", "model": "opus", "reason": None}
    assert _read(repo) == (0, [AGENT_OPUS])


@pytest.mark.parametrize(
    ("model", "word"),
    [("haiku", "asks"), ("sonnet", "asks"), ("opus", "decides"), ("fable", "decides")],
)
def test_the_agent_setting_moves_the_record_and_the_word(
    repo: Path,  # noqa: F811
    model: str,
    word: str,
) -> None:
    _config(repo, {"models": {"agents": {"orchestrator": model}}})
    _begin(repo, "--orchestrator", "agent")
    code, lines = _read(repo)
    assert code == 0
    assert lines == [
        f"orchestrating model: {model}, by the orchestrator agent | at a judgement call: {word}"
    ]


def test_a_class_mapped_to_fable_does_not_move_the_top_coding_model(
    repo: Path,  # noqa: F811
) -> None:
    # 0276: the top is TOP_MODEL itself; class_models maps classes, never the rank of a model.
    path = Path.home() / operator_file.OPERATOR_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"class_models": {"Plumbing": "fable", "AuthN": "fable"}}))
    assert work_classes.TOP_MODEL == "opus"
    assert [work_classes.at_or_above_top(m) for m in work_classes.MODEL_RANK] == [
        False,
        False,
        True,
        True,
    ]
    assert not work_classes.at_or_above_top("unknown")
    _config(repo, {"models": {"agents": {"orchestrator": "sonnet"}}})
    _begin(repo, "--orchestrator", "agent")
    want = "orchestrating model: sonnet, by the orchestrator agent | at a judgement call: asks"
    assert _read(repo) == (0, [want])


def test_a_stopped_and_resumed_run_keeps_its_record(repo: Path) -> None:  # noqa: F811
    _begin(repo, "--orchestrator", "agent")
    assert _ws("stop", "--repo", str(repo), "--reason", "pause").returncode == 0
    assert _read(repo)[0] == 1
    assert _ws("resume", "--repo", str(repo)).returncode == 0
    assert _read(repo) == (0, [AGENT_OPUS])


@pytest.mark.parametrize(
    "held",
    [
        {"by": "agent", "model": "gpt", "reason": None},
        {"by": "nobody", "model": "opus", "reason": None},
        {"by": "agent", "model": "opus", "reason": "session-unread"},
        {"by": "session", "model": "unknown", "reason": "guessed"},
        {"by": "session", "model": "unknown"},
        "opus",
    ],
)
def test_a_record_in_no_known_form_reads_asks(repo: Path, held: object) -> None:  # noqa: F811
    train = _begin(repo)
    train_state.update(repo, train, **{train_state.ORCHESTRATING: held})
    assert _read(repo) == (0, [UNREADABLE])


def test_a_run_started_before_the_record_existed_reads_asks(repo: Path) -> None:  # noqa: F811
    train = _begin(repo)
    train_state.change(repo, train, lambda state: state.pop(train_state.ORCHESTRATING))
    assert _read(repo) == (0, [NO_RECORD])


def test_the_read_outside_a_run_and_with_other_options_is_refused(
    repo: Path,  # noqa: F811
) -> None:
    code, lines = _read(repo)
    assert code == 1 and len(lines) == 1 and lines[0].count("Next:") == 1
    _begin(repo)
    state_before = sorted((repo / train_state.STATE_DIR).iterdir())
    for extra in (
        ("--orchestrating", "--agent", "coder"),
        ("--orchestrating", "--unit", "U1"),
        ("--orchestrating", "--override", "opus"),
        (),
    ):
        done = run_cli("daedalus_train.py", "model", "--repo", str(repo), *extra, cwd=repo)
        assert done.returncode == 1, extra
        out = done.stdout.splitlines()
        assert len(out) == 1 and out[0].endswith("as model --orchestrating for the run's record.")
    assert sorted((repo / train_state.STATE_DIR).iterdir()) == state_before


def test_a_folder_run_records_who_orchestrates(tmp_path: Path) -> None:
    plain = tmp_path.resolve() / "plain"
    (plain / ".claude" / "daedalus").mkdir(parents=True)
    out = tmp_path.resolve() / "out"
    out.mkdir()
    done = _ws("begin", "--repo", str(plain), "--scope", "folder", "--out", str(out))
    assert done.returncode == 0, done.stderr
    assert _read(plain) == (0, [SESSION_UNKNOWN])


def test_a_defined_train_records_it_and_state_and_summary_name_it(
    repo: Path,  # noqa: F811
    plugin: Path,  # noqa: F811
) -> None:
    _write_train(plugin, [_probe_stage()], ("repository",))
    outcome = train_runner.start(repo, "t", None, plugin, orchestrator="agent")
    assert outcome.code == 0, outcome.lines
    assert AGENT_OPUS in train_runner.state_lines(repo, plugin).lines
    _record(repo, tool_input={"command": _summary_cmd(repo)})
    assert train_runner.summary(repo).code == 0
    text = _summary_file(repo).read_text(encoding="utf-8")
    assert f"\n{AGENT_OPUS.replace('orchestrating', 'Orchestrating', 1)}\n" in text


def test_a_defined_train_started_by_default_records_the_session(
    repo: Path,  # noqa: F811
    plugin: Path,  # noqa: F811
) -> None:
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    assert SESSION_UNKNOWN in train_runner.state_lines(repo, plugin).lines


SCRIPTS = REPO_ROOT / "scripts"


@pytest.mark.usefixtures("jail_fakes")
def test_no_agent_in_the_run_can_write_the_record() -> None:
    # 0276: begin and start are off the orchestrator's train table; the state file is hooks-only.
    for command in (
        f"python3 {SCRIPTS}/daedalus_workspace.py begin --repo {CWD} --orchestrator agent",
        f"python3 {SCRIPTS}/daedalus_train.py start --repo {CWD} --train t --orchestrator agent",
    ):
        assert not decide(_b("orchestrator", command), CFG).allow, command
    read = f"python3 {SCRIPTS}/daedalus_train.py model --repo {CWD} --orchestrating"
    assert decide(_b("orchestrator", read), CFG).allow
    state = f"{CWD}/.claude/daedalus/trains/20261113-000000.json"
    for agent in ("orchestrator", "coder", "auditor"):
        assert evaluate("workspace_integrity", _w(agent, state)) == jail.R_DATA_DIR, agent

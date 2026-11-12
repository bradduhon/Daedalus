# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# issue 188: each dispatched agent is judged against the run that started it.
from __future__ import annotations

import io
import json
import os
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import enforce_agent_jail
import pytest
from lib import audit, dispatch_binding, jail, train_state
from lib import session_notes as notes
from lib.workspace import mark_train

from tests.conftest import CFG, audit_records, git
from tests.hook_chain import judge
from tests.jail_cases import _git_init
from tests.payloads import _cred
from tests.test_dispatch_binding import seed_plan

TRAIN = "20261107-010000"
SESSION = "s188"
Run = Callable[[str, dict[str, Any]], Any]


def _run_units(path: Path, names: tuple[str, ...]) -> tuple[Path, list[tuple[Path, Path]]]:
    # issue 188: a repo with recorded units, a recorded plan and one coder brief per unit.
    repo = _git_init(path)
    git(repo, "commit", "-q", "--allow-empty", "-m", "init")
    (repo / ".claude" / "daedalus").mkdir(parents=True)
    (repo / "docs" / ".tmp" / "daedalus" / TRAIN / "briefs").mkdir(parents=True)
    units, made = [], []
    for name in names:
        wt = repo / ".claude" / "worktrees" / name
        git(repo, "worktree", "add", "-q", "-b", f"daedalus-unit/{name}", str(wt))
        units.append({"name": name, "branch": f"daedalus-unit/{name}", "path": str(wt)})
        brief = repo / "docs" / ".tmp" / "daedalus" / TRAIN / "briefs" / f"{name}.md"
        brief.write_text(f"Worktree: {wt}\n", encoding="utf-8")
        made.append((wt.resolve(), brief))
    train_state.save(repo, TRAIN, {"train_id": TRAIN, "units": units})
    mark_train(repo, TRAIN)
    seed_plan(repo, TRAIN)
    return repo, made


def _run_repo(path: Path) -> tuple[Path, Path, Path]:
    repo, ((wt, brief),) = _run_units(path, ("u1",))
    return repo, wt, brief


def _call(cwd: Path, tool: str, agent: str | None = None, **tool_input: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "session_id": SESSION,
        "hook_event_name": "PreToolUse",
        "cwd": str(cwd),
        "tool_name": tool,
        "tool_input": tool_input,
        "tool_use_id": "toolu_1",
    }
    if agent is not None:
        payload.update(agent_type="daedalus:coder", agent_id=agent)
    return payload


def _dispatch(run_script: Run, repo: Path, wt: Path, brief: Path) -> None:
    prompt = f"Brief: {brief}\nWorktree: {wt}\n"
    payload = _call(repo, "Agent", subagent_type="daedalus:coder", prompt=prompt, description="u")
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 0 and not result.stdout, (result.stdout, result.stderr)


@pytest.fixture
def two_runs(
    tmp_path: Path, run_script: Run
) -> tuple[tuple[Path, Path, Path], tuple[Path, Path, Path]]:
    # issue 188: one coder per run, each dispatched alone and first reading its brief elsewhere.
    a, b = _run_repo(tmp_path / "a"), _run_repo(tmp_path / "b")
    for agent, run, away in (("agent-a", a, b[0]), ("agent-b", b, a[0])):
        _dispatch(run_script, *run)
        payload = _call(away, "Read", agent, file_path=str(run[2]))
        result = run_script("enforce_agent_jail.py", payload)
        assert result.returncode == 0, result.stderr
    return a, b


def _write(run_script: Run, cwd: Path, agent: str, target: Path) -> Any:
    payload = _call(cwd, "Write", agent, file_path=str(target), content="x\n")
    return run_script("enforce_agent_jail.py", payload)


def test_each_coder_writes_only_in_its_own_run(two_runs: Any, run_script: Run) -> None:
    # issue 188: the session cwd sits in the other repository for both coders.
    (repo_a, wt_a, _), (repo_b, wt_b, _) = two_runs
    for agent, own, theirs, away in (
        ("agent-a", wt_a, wt_b, repo_b),
        ("agent-b", wt_b, wt_a, repo_a),
    ):
        result = _write(run_script, away, agent, own / "x.py")
        assert result.returncode == 0, (agent, result.stderr)
        assert _write(run_script, away, agent, theirs / "y.py").returncode == 2, agent
    rows = [r for r in audit_records(audit.log_path(SESSION, str(wt_a))) if r["agent_id"]]
    moved = [r for r in rows if r["agent_id"] == "agent-a" and r["payload_cwd"] == str(repo_b)]
    assert moved and all(r["cwd"] == str(wt_a) for r in moved), rows
    claim = moved[0]["binding"]
    assert claim == {"train_id": TRAIN, "repo": str(repo_a), "worktree": str(wt_a), "claim": "sole"}


def test_a_relative_write_of_a_moved_agent_is_refused(two_runs: Any, run_script: Run) -> None:
    # issue 188: the shell still runs in the session folder, so a relative target is refused.
    (_, wt_a, _), (repo_b, _, _) = two_runs
    (repo_b / "README.md").write_text("x\n", encoding="utf-8")
    bash = ["touch rel.txt", "echo x > out.txt", "cd sub", "git commit -m x"]
    bash += ["python3 -m pytest tests", "cat README.md", "./run.sh", "rm -rf .cl*"]
    # issue 188: output options and in-script writes fail the base read grammar.
    bash += ["sort -o out /etc/hosts", "uniq - out", "sed 'w out' /etc/hosts"]
    bash += ["awk '{print > \"out\"}' /etc/hosts", f"git -C {wt_a} log --output=x"]
    calls = [("Bash", {"command": command}) for command in bash]
    calls += [("Grep", {"pattern": "x"}), ("Glob", {"pattern": "*.py"})]
    calls.append(("Read", {"file_path": "README.md"}))
    for tool, tool_input in calls:
        result = run_script("enforce_agent_jail.py", _call(repo_b, tool, "agent-a", **tool_input))
        assert result.returncode == 2, tool_input
        assert "Next: name every path as an absolute path" in result.stderr, tool_input
    allowed = (f"cd {wt_a} && python3 -m pytest tests -q", f"git -C {wt_a} status", "ls")
    for command in (*allowed, "git status"):
        payload = _call(repo_b, "Bash", "agent-a", command=command)
        assert "name every path" not in run_script("enforce_agent_jail.py", payload).stderr
    # 228 S3: the parse reads 2>&1 as a fd and /dev/null as absolute; a leading cd starts there.
    for command in (f"touch {wt_a}/x 2>&1 > /dev/null", f"cd {wt_a} && ls"):
        cwds = (str(repo_b), str(wt_a))
        assert jail.moved_relative("Bash", {"command": command}, cwds, str(wt_a)) is None


@pytest.mark.parametrize("cwd", ["", "rel/dir"])
def test_a_missing_cwd_keeps_the_base_refusal(two_runs: Any, run_script: Run, cwd: str) -> None:
    # issue 188: no absolute payload cwd is refused as on base, before any rebinding.
    (_, wt_a, _), _ = two_runs
    results = []
    for agent in ("agent-a", "agent-z"):
        payload = {**_call(wt_a, "Write", agent, file_path=f"{wt_a}/x.py"), "cwd": cwd}
        results.append(run_script("enforce_agent_jail.py", payload))
    assert [r.returncode for r in results] == [2, 2]
    assert results[0].stderr == results[1].stderr and "absolute cwd" in results[0].stderr


def test_the_credential_check_also_runs_at_the_payload_cwd(
    two_runs: Any, run_script: Run, cred_home: Path
) -> None:
    # issue 188: a pathless Grep from a credential folder is refused as the host would search it.
    (cred_home / ".ssh").mkdir()
    payload = _call(cred_home / ".ssh", "Grep", "agent-a", pattern="x")
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 2 and "credential path" in result.stderr, result.stderr


def test_an_unbound_daedalus_agent_is_judged_by_its_payload_cwd(
    two_runs: Any, run_script: Run
) -> None:
    # issue 188: no pending entry of its type, so its cwd stays and no relative rule applies.
    _, (repo_b, _, _) = two_runs
    payload = _call(repo_b, "Bash", "agent-z", command="touch rel.txt")
    result = run_script("enforce_agent_jail.py", payload)
    assert "name every path" not in result.stderr
    rows = [r for r in audit_records(audit.log_path(SESSION, str(repo_b))) if r["agent_id"]]
    row = [r for r in rows if r["agent_id"] == "agent-z"][-1]
    assert (row["cwd"], row["payload_cwd"], row["binding"]) == (str(repo_b), None, None)


def _store(plugin_data: Path) -> Path:
    return plugin_data / dispatch_binding.RUN_BINDINGS / f"{SESSION}.json"


def test_the_store_is_private_and_a_claim_never_moves(
    two_runs: Any, plugin_data: Path, run_script: Run
) -> None:
    # issue 188, AC-6: folder 0700, file 0600; a claimed agent keeps its entry.
    (repo_a, _, _), (repo_b, _, _) = two_runs
    store = _store(plugin_data)
    assert stat.S_IMODE(store.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(store.stat().st_mode) == 0o600
    hook = _call(repo_b, "Read", "agent-a", file_path=str(repo_b / "README.md"))
    bound = dispatch_binding.bound_run({**hook, "agent_type": "daedalus:coder"})
    assert bound is not None and bound.repo == str(repo_a) and not bound.claimed_now


_OLD_ENTRY = {"agent_type": "coder", "repo": "/x", "worktree": None, "train_id": TRAIN}
_OLD_FORMAT = json.dumps(
    {"version": 1, "entries": [{**_OLD_ENTRY, "agent_id": "a", "claim": "path", "created": 1}]}
)
MALFORMED = [
    "not json",
    '{"version": 2, "entries": []}',
    '{"version": 1, "entries": [{}]}',
    _OLD_FORMAT,
]


@pytest.mark.parametrize("text", MALFORMED)
def test_a_malformed_store_survives_a_dispatch_and_binds_nothing(
    tmp_path: Path, plugin_data: Path, run_script: Run, text: str
) -> None:
    # issue 188: a dispatch never rewrites a malformed store; it notes the store instead.
    repo, wt, brief = _run_repo(tmp_path / "a")
    store = _store(plugin_data)
    store.parent.mkdir(mode=0o700)
    store.write_text(text, encoding="utf-8")
    payload = _call(repo, "Agent", subagent_type="daedalus:coder", prompt=f"Worktree: {wt}\n")
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 0 and "the operator deletes" in result.stderr, result.stderr
    assert store.read_text(encoding="utf-8") == text
    assert (
        dispatch_binding.bound_run(_call(tmp_path, "Read", "agent-a", file_path=str(brief))) is None
    )


@pytest.mark.parametrize("text", MALFORMED)
def test_a_malformed_store_applies_no_binding(two_runs: Any, plugin_data: Path, text: str) -> None:
    # issue 188: malformed input falls back to the payload cwd.
    (_, _, brief), _ = two_runs
    _store(plugin_data).write_text(text, encoding="utf-8")
    hook = _call(brief.parent, "Read", "agent-a", file_path=str(brief))
    assert dispatch_binding.bound_run(hook) is None


def test_a_stale_binding_is_ignored(two_runs: Any, run_script: Run) -> None:
    # issue 188: a cleared marker ends the binding.
    (repo_a, _, brief), (repo_b, _, _) = two_runs
    (repo_a / ".claude" / "daedalus" / "train.active").unlink()
    assert (
        dispatch_binding.bound_run(_call(repo_b, "Read", "agent-a", file_path=str(brief))) is None
    )


def test_a_bad_session_id_has_no_store(plugin_data: Path) -> None:
    # issue 188: the file name comes from a full SESSION_ID match only.
    for session in ("../x", "a/b", "", None, "x y"):
        assert dispatch_binding.run_store(session) is None
    assert dispatch_binding.run_store("ok-1") == _store(plugin_data).with_name("ok-1.json")


def test_the_sole_pending_entry_is_claimed_without_a_path(tmp_path: Path, run_script: Run) -> None:
    # issue 188: a first call naming no path in a run repo takes the one entry of its type.
    a = _run_repo(tmp_path / "a")
    _dispatch(run_script, *a)
    hook = _call(tmp_path, "Bash", "agent-q", command="ls")
    bound = dispatch_binding.bound_run(hook)
    assert bound is not None and bound.claim == "sole" and bound.repo == str(a[0])


def test_two_same_run_coders_bind_the_run_root_and_keep_their_units(
    tmp_path: Path, plugin_data: Path, run_script: Run
) -> None:
    # issue 188, issue 29: parallel coders of one run bind its root; unit_binding owns each unit.
    repo, ((wt1, brief1), (wt2, brief2)) = _run_units(tmp_path / "a", ("u1", "u2"))
    away = _run_repo(tmp_path / "b")[0]
    _dispatch(run_script, repo, wt1, brief1)
    _dispatch(run_script, repo, wt2, brief2)
    for agent, brief in (("agent-1", brief1), ("agent-2", brief2)):
        first = run_script(
            "enforce_agent_jail.py", _call(away, "Read", agent, file_path=str(brief))
        )
        assert first.returncode == 0, first.stderr
    entries = json.loads(_store(plugin_data).read_text(encoding="utf-8"))["entries"]
    bound = [(e["agent_id"], e["worktree"], e["claim"]) for e in entries]
    assert bound == [("agent-1", None, "run"), ("agent-2", None, "run")]
    assert _write(run_script, away, "agent-1", wt1 / "x.py").returncode == 0
    assert _write(run_script, away, "agent-2", wt2 / "x.py").returncode == 0
    assert _write(run_script, away, "agent-1", wt2 / "y.py").returncode == 2
    assert _write(run_script, away, "agent-2", wt1 / "y.py").returncode == 2
    rows = [r for r in audit_records(audit.log_path(SESSION, str(repo))) if r["agent_id"]]
    assert {r["cwd"] for r in rows if r["payload_cwd"] == str(away)} == {str(repo)}, rows


def test_two_pending_entries_of_one_type_bind_neither(
    tmp_path: Path, plugin_data: Path, run_script: Run
) -> None:
    # issue 188: coders of two runs dispatched together bind neither; both keep the payload cwd.
    a, b = _run_repo(tmp_path / "a"), _run_repo(tmp_path / "b")
    (repo_a, _, _), (repo_b, wt_b, brief_b) = a, b
    _dispatch(run_script, *a)
    _dispatch(run_script, *b)
    first = run_script(
        "enforce_agent_jail.py", _call(repo_a, "Read", "agent-a", file_path=str(brief_b))
    )
    assert first.returncode == 0, first.stderr
    assert _write(run_script, repo_a, "agent-a", wt_b / "x.py").returncode == 2
    assert (
        dispatch_binding.bound_run(_call(repo_b, "Read", "agent-b", file_path=str(brief_b))) is None
    )
    entries = json.loads(_store(plugin_data).read_text(encoding="utf-8"))["entries"]
    assert [(e["agent_id"], e["claim"]) for e in entries] == [(None, None), (None, None)]


def test_pending_entries_of_different_types_each_bind(tmp_path: Path, plugin_data: Path) -> None:
    # issue 188: the sole-entry rule counts pending entries of the calling agent's type only.
    (repo_a, wt_a, _), (repo_b, _, _) = _run_repo(tmp_path / "a"), _run_repo(tmp_path / "b")
    for repo, subagent, prompt in (
        (repo_a, "daedalus:coder", f"Worktree: {wt_a}\n"),
        (repo_b, "daedalus:verifier", "Check unit u1.\n"),
    ):
        tool_input = {"subagent_type": subagent, "prompt": prompt}
        dispatch_binding.record_run_dispatch(_call(repo, "Agent", **tool_input))
    for agent, agent_type, repo in (
        ("agent-c", "daedalus:coder", repo_a),
        ("agent-v", "daedalus:verifier", repo_b),
    ):
        hook = {**_call(tmp_path, "Bash", agent, command="ls"), "agent_type": agent_type}
        bound = dispatch_binding.bound_run(hook)
        assert bound is not None and (bound.repo, bound.claim) == (str(repo), "sole"), agent


def test_run_bindings_are_refused_to_agents(
    marked_repo: Path, plugin_data: Path, cred_home: Path
) -> None:
    # issue 188: the store sits in the plugin data folder, which no agent writes.
    store = str(_store(plugin_data))
    cwd = str(marked_repo)
    for agent in ("coder", "general-purpose"):
        for tool, tool_input in (
            ("Write", {"file_path": store}),
            ("Bash", {"command": f"echo x > {store}"}),
        ):
            assert not judge(_cred(agent, tool, cwd, **tool_input), CFG).allow, (agent, tool)


def test_the_audit_record_carries_null_binding_fields() -> None:
    # issue 188, AU-3: both fields are present and null when no binding moved the call.
    record = audit.build_record({"hook_event_name": "PreToolUse", "cwd": "/x"})
    assert record["payload_cwd"] is None and record["binding"] is None
    moved = audit.build_record({"cwd": "/w", "payload_cwd": "/s", "binding": {"claim": "path"}})
    assert (moved["payload_cwd"], moved["binding"]) == ("/s", {"claim": "path"})
    assert json.loads(audit.canonical(moved))["payload_cwd"] == "/s"


def _session_folder(root: Path, kind: str) -> Path:
    # 218: a plain folder, or a second repository that holds no run.
    if kind == "other-repo":
        repo = _git_init(root / "other")
        git(repo, "commit", "-q", "--allow-empty", "-m", "init")
        return repo
    folder = root / "neutral"
    folder.mkdir()
    return folder


def _entries(plugin_data: Path) -> list[dict[str, Any]] | None:
    store = _store(plugin_data)
    if not store.exists():
        return None
    return list(json.loads(store.read_text(encoding="utf-8"))["entries"])


@pytest.mark.parametrize("kind", ["neutral", "other-repo"])
def test_a_dispatch_from_a_folder_with_no_run_binds_the_named_run(
    tmp_path: Path, plugin_data: Path, run_script: Run, kind: str
) -> None:
    # 218: the fast path records a dispatch whose Worktree: line names a marked run's unit.
    repo, wt, brief = _run_repo(tmp_path / "a")
    away = _session_folder(tmp_path.resolve(), kind)
    _dispatch(run_script, away, wt, brief)
    pending = [(e["repo"], e["worktree"], e["agent_id"]) for e in _entries(plugin_data) or []]
    assert pending == [(str(repo), str(wt), None)]
    # 218, issue 29: the unit gate of the bound run judges; no unit binding is recorded here.
    result = _write(run_script, away, "agent-a", wt / "x.py")
    assert result.returncode == 2 and f"never dispatched in train {TRAIN}" in result.stderr
    rows = [r for r in audit_records(audit.log_path(SESSION, str(wt))) if r["agent_id"]]
    assert [(r["cwd"], r["payload_cwd"]) for r in rows] == [(str(wt), str(away))], rows
    assert rows[0]["binding"]["train_id"] == TRAIN


def _no_record_seam(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    calls: list[object] = []
    monkeypatch.setattr(dispatch_binding, "record_run_dispatch", calls.append)
    return calls


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Agent", {"subagent_type": "daedalus:coder", "prompt": "Build unit u1.\n"}),
        ("Read", {"file_path": "/etc/hostname"}),
        ("Bash", {"command": "ls"}),
    ],
)
def test_a_call_from_a_folder_with_no_run_and_no_worktree_line_writes_nothing(
    tmp_path: Path,
    plugin_data: Path,
    run_script: Run,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tool: str,
    tool_input: dict[str, Any],
) -> None:
    # 218, 0035: no Worktree: line keeps the fast path as it was; no file and no run lookup.
    _run_repo(tmp_path / "a")
    away = _session_folder(tmp_path.resolve(), "neutral")
    before = sorted(tmp_path.rglob("*"))
    result = run_script("enforce_agent_jail.py", _call(away, tool, **tool_input))
    assert result.returncode == 0 and not result.stderr, result.stderr
    assert sorted(tmp_path.rglob("*")) == before
    calls = _no_record_seam(monkeypatch)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(_call(away, tool, **tool_input))))
    assert enforce_agent_jail.main() == 0
    assert calls == [] and capsys.readouterr().err == ""


def _link(at: Path, to: Path) -> Path:
    at.symlink_to(to, target_is_directory=True)
    return at


# 218: (case, Worktree: text from tmp_path, wt, away, repo; recorded worktree or "none" or "root").
_LINES: list[tuple[str, Callable[[Path, Path, Path, Path], str], str]] = [
    ("no-run", lambda root, wt, away, repo: str(_git_init(root / "other")), "none"),
    ("missing", lambda root, wt, away, repo: str(root / "nowhere" / "x"), "none"),
    ("missing-in-run", lambda root, wt, away, repo: str(repo / "gone"), "root"),
    ("relative", lambda root, wt, away, repo: os.path.relpath(wt, away), "none"),
    ("dotdot-in", lambda root, wt, away, repo: f"{away}/../{wt.relative_to(root)}", "wt"),
    ("dotdot-out", lambda root, wt, away, repo: f"{wt}/../../../../neutral", "none"),
    ("link-in", lambda root, wt, away, repo: str(_link(away / "in", wt)), "wt"),
    ("link-out", lambda root, wt, away, repo: str(_link(repo / ".claude" / "out", away)), "none"),
    ("two-lines", lambda root, wt, away, repo: f"{wt}\nWorktree: {wt}", "none"),
]


@pytest.mark.parametrize(("case", "line", "expected"), _LINES, ids=[c[0] for c in _LINES])
def test_the_worktree_line_binds_only_the_run_its_real_folder_is_in(
    tmp_path: Path,
    plugin_data: Path,
    run_script: Run,
    case: str,
    line: Callable[[Path, Path, Path, Path], str],
    expected: str,
) -> None:
    # 218, issue 188: the dispatch reader's realpath decides; .. and links never borrow a run.
    root = tmp_path.resolve()
    repo, wt, _ = _run_repo(root / "a")
    away = _session_folder(root, "neutral")
    prompt = f"Worktree: {line(root, wt, away, repo)}\n"
    payload = _call(away, "Agent", subagent_type="daedalus:coder", prompt=prompt)
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 0 and not result.stderr, (case, result.stderr)
    entries = _entries(plugin_data)
    if expected == "none":
        assert entries is None, case
        return
    worktree = str(wt) if expected == "wt" else None
    assert [(e["repo"], e["worktree"]) for e in entries or []] == [(str(repo), worktree)], case


@pytest.mark.parametrize("text", MALFORMED)
def test_a_malformed_store_survives_a_dispatch_from_a_folder_with_no_run(
    tmp_path: Path, plugin_data: Path, run_script: Run, text: str
) -> None:
    # 218, issue 188: the fast path notes a malformed store, never rewrites it, binds nothing.
    _, wt, brief = _run_repo(tmp_path / "a")
    away = _session_folder(tmp_path.resolve(), "neutral")
    store = _store(plugin_data)
    store.parent.mkdir(mode=0o700)
    store.write_text(text, encoding="utf-8")
    payload = _call(away, "Agent", subagent_type="daedalus:coder", prompt=f"Worktree: {wt}\n")
    result = run_script("enforce_agent_jail.py", payload)
    assert result.returncode == 0 and "the operator deletes" in result.stderr, result.stderr
    assert store.read_text(encoding="utf-8") == text
    assert dispatch_binding.bound_run(_call(away, "Read", "agent-a", file_path=str(brief))) is None


def test_a_warned_dispatch_is_recorded_and_still_only_warned(
    tmp_path: Path, plugin_data: Path, run_script: Run
) -> None:
    # 218, 0105, 0130: the warned coder runs, so it binds; the main session gets the same warning.
    repo, _, _ = _run_repo(tmp_path / "a")
    away = _session_folder(tmp_path.resolve(), "neutral")
    payload = _call(repo, "Agent", subagent_type="daedalus:coder", prompt="Build unit u1.\n")
    result = run_script("enforce_agent_jail.py", payload)
    step = notes.rule_step(dispatch_binding.R_WORKTREE_LINE)
    warning = notes.DISPATCH_RULE.text("This dispatch", step)
    out = {"hookEventName": "PreToolUse", "additionalContext": warning}
    expected = json.dumps({"systemMessage": warning, "hookSpecificOutput": out})
    assert (result.returncode, result.stdout.strip(), result.stderr) == (0, expected, "")
    pending = [(e["repo"], e["worktree"], e["agent_id"]) for e in _entries(plugin_data) or []]
    assert pending == [(str(repo), None, None)]
    hook = _call(away, "Bash", "agent-w", command="ls")
    bound = dispatch_binding.bound_run(hook)
    assert bound is not None and (bound.repo, bound.claim) == (str(repo), "sole")

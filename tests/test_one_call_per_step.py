# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0230, 253: the run-open records, the verifier's map check and the audit's reach lines, one call.
from __future__ import annotations

import json
from pathlib import Path

import daedalus_train
import pytest
from lib import agent_models, train_runner, train_state, workspace

from tests.conftest import CFG, CWD, REPO_ROOT, git, run_cli
from tests.helpers import phase_text
from tests.hook_chain import decide
from tests.payloads import _b
from tests.test_records_in_one_call import (
    TRAIN,
    _built,
    _Clock,
    _fixture,
    _ok,
    _scratch,
    _snapshot,
)
from tests.test_workspace_train import LEDGER

pytestmark = pytest.mark.usefixtures("isolated_env")


@pytest.fixture
def fixed(monkeypatch: pytest.MonkeyPatch) -> None:
    # 0230: one train id and fixed git dates, so two copies make the same shas.
    monkeypatch.setattr(workspace, "datetime", _Clock)
    for key in ("GIT_AUTHOR_DATE", "GIT_COMMITTER_DATE"):
        monkeypatch.setenv(key, "2026-11-08T12:00:00+00:00")


def _project(root: Path) -> Path:
    # 253: a clean repository with no run, as the run skill finds it before step 4.
    root.mkdir(parents=True)
    git(root, "init", "-q", "-b", "main")
    data = root / ".claude" / "daedalus"
    data.mkdir(parents=True)
    (data / ".gitignore").write_text("*\n")
    (root / "docs").mkdir()
    (root / "docs" / "decisions.md").write_text(LEDGER)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "init")
    return root


def _charter(tmp_path: Path, root: Path) -> Path:
    charter = tmp_path / "charter"
    charter.mkdir()
    git(charter, "init", "-q", "-b", "main")
    (charter / "README.md").write_text("charter\n")
    git(charter, "add", "-A")
    git(charter, "commit", "-q", "-m", "init")
    config = root / ".claude" / "daedalus" / "config.json"
    config.write_text(json.dumps({"local_docs_folder": str(charter)}))
    return charter


def _open_shot(root: Path) -> dict[str, str]:
    # 253: the train state and marker, byte for byte, with the repository path masked.
    shot: dict[str, str] = {}
    for path in sorted((root / train_state.STATE_DIR).glob("*.json")):
        shot[path.name] = path.read_text(encoding="utf-8").replace(str(root), "<repo>")
    marker = root / train_state.TRAIN_MARKER
    shot["marker"] = marker.read_text(encoding="utf-8") if marker.exists() else "none"
    shot["progress"] = "\n".join(train_runner.progress(root).lines).replace(str(root), "<repo>")
    return shot


BY = {"main": train_state.BY_SESSION, "unattended": train_state.BY_AGENT}


@pytest.mark.usefixtures("fixed")
@pytest.mark.parametrize("mode", ["main", "unattended"])
def test_open_leaves_what_begin_choice_and_model_leave(tmp_path: Path, mode: str) -> None:
    seq, one = _project(tmp_path / "seq" / "repo"), _project(tmp_path / "one" / "repo")
    # 0276: begin --orchestrator <by> is begin then record_orchestrating, as the CLI runs it.
    begun = workspace.begin(seq)
    train_runner.record_orchestrating(seq, BY[mode])
    chose = _ok(train_runner.choice(seq, *train_runner.OPEN_MODES[mode]))
    words = _ok(daedalus_train._model(seq, "orchestrator", None)) if mode == "unattended" else []
    lines = _ok(train_runner.open_run(one, mode))
    assert _open_shot(seq) == _open_shot(one)
    held = train_state.load(one, TRAIN)[train_state.ORCHESTRATING]
    assert isinstance(held, dict) and held["by"] == BY[mode]
    assert _ok(train_runner.orchestrating_read(seq)) == _ok(train_runner.orchestrating_read(one))
    expected = [*begun, *chose, *words]
    assert [ln.replace(str(one), "<r>") for ln in lines] == [
        ln.replace(str(seq), "<r>") for ln in expected
    ]
    assert lines[0].startswith(f"train: {TRAIN} ")
    assert lines[6].startswith("Chose ") and len(lines) == (8 if mode == "unattended" else 7)


def test_open_from_the_command_line_prints_the_seed_the_choice_and_the_model(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path / "repo")
    args = ("open", "--repo", str(root), "--mode", "unattended")
    done = run_cli("daedalus_train.py", *args, cwd=root)
    assert done.returncode == 0, done.stdout
    out = done.stdout.splitlines()
    assert out[0].startswith("train: ") and out[0].endswith("audit session: pending")
    chose, over, cost = train_runner.OPEN_MODES["unattended"]
    assert out[6] == f"Chose {chose} over {over}: {cost}"
    assert out[7] in agent_models.MODELS and len(out) == 8
    assert train_state.active_train(root) == out[0].split()[1]


@pytest.mark.parametrize("mode", ["main", "unattended"])
def test_model_orchestrating_reads_the_same_after_open_as_after_begin(
    tmp_path: Path, mode: str
) -> None:
    # 0276, 253: open --mode main records session and --mode unattended records agent.
    seq, one = _project(tmp_path / "seq" / "repo"), _project(tmp_path / "one" / "repo")
    begun = run_cli(
        "daedalus_workspace.py", "begin", "--repo", str(seq), "--orchestrator", BY[mode], cwd=seq
    )
    opened = run_cli("daedalus_train.py", "open", "--repo", str(one), "--mode", mode, cwd=one)
    assert begun.returncode == 0 and opened.returncode == 0, begun.stderr + opened.stdout
    reads = [
        run_cli("daedalus_train.py", "model", "--repo", str(r), "--orchestrating", cwd=r)
        for r in (seq, one)
    ]
    assert reads[0].returncode == reads[1].returncode == 0, reads[1].stdout
    assert reads[0].stdout == reads[1].stdout and reads[1].stdout.strip()


def _left_nothing(root: Path) -> None:
    assert train_state.active_train(root) is None
    assert not (root / train_state.TRAIN_MARKER).exists()
    assert list((root / train_state.STATE_DIR).glob("*.json")) == []


@pytest.mark.usefixtures("fixed")
def test_a_model_failure_after_begin_leaves_no_run_and_the_charter_on_its_branch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _project(tmp_path / "repo")
    charter = _charter(tmp_path, root)

    def _bad(*_: object, **__: object) -> str:
        raise agent_models.AgentModelError("the agent file is unreadable. Next: fix the file.")

    monkeypatch.setattr(train_runner, "resolve_model", _bad)
    refused = train_runner.open_run(root, "unattended")
    assert refused.code == 1 and refused.lines == [
        "the agent file is unreadable. Next: fix the file."
    ]
    _left_nothing(root)
    head = git(charter, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    assert head == "main"


@pytest.mark.usefixtures("fixed")
def test_a_choice_failure_after_begin_leaves_no_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _project(tmp_path / "repo")

    def _refused(*_: object, **__: object) -> train_runner.Outcome:
        return train_runner.Outcome(1, ["state not written. Next: fix the state folder."])

    monkeypatch.setattr(train_runner, "choice", _refused)
    refused = train_runner.open_run(root, "main")
    assert refused.code == 1 and refused.lines == ["state not written. Next: fix the state folder."]
    _left_nothing(root)


@pytest.mark.usefixtures("fixed")
@pytest.mark.parametrize("mode", ["main", "unattended"])
def test_a_failed_orchestrating_record_after_begin_leaves_no_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    # 0276, 253: only the write of the orchestrating field fails; begin's own writes go through.
    root = _project(tmp_path / "repo")
    real = train_state.update

    def _update(repo: Path, train_id: str, **fields: object) -> dict[str, object]:
        if train_state.ORCHESTRATING in fields:
            raise train_state.TrainStateError("record not written. Next: fix the state folder.")
        return real(repo, train_id, **fields)

    monkeypatch.setattr(train_state, "update", _update)
    refused = train_runner.open_run(root, mode)
    assert refused.code == 1, refused.lines
    assert "\n".join(refused.lines).count("Next:") == 1, refused.lines
    _left_nothing(root)


def test_open_on_a_dirty_tree_is_refused_with_one_next_line(tmp_path: Path) -> None:
    root = _project(tmp_path / "repo")
    (root / "draft.md").write_text("x\n")
    done = run_cli("daedalus_train.py", "open", "--repo", str(root), "--mode", "main", cwd=root)
    assert done.returncode == 1 and done.stdout.count("Next:") == 1, done.stdout
    assert "draft.md" in done.stdout
    _left_nothing(root)


def _unit_ready(root: Path) -> tuple[str, str]:
    _ok(train_runner.dispatch_unit(root, "U1"))
    _built(root, "U1")
    return str(train_state.load(root, TRAIN)["lock_sha"]), f"daedalus-unit/{TRAIN}-u1"


def _map_files(root: Path) -> dict[str, bytes]:
    folder = _scratch(root) / "map"
    return {p.name: p.read_bytes() for p in sorted(folder.glob("map.*"))}


@pytest.mark.usefixtures("fixed")
def test_assets_with_map_prints_what_the_map_check_and_assets_print(tmp_path: Path) -> None:
    seq, one = _fixture(tmp_path / "seq" / "repo"), _fixture(tmp_path / "one" / "repo")
    lock, branch = _unit_ready(seq)
    _unit_ready(one)
    assets = ("assets", "--base", lock, "--tip", branch, "--unit", "U1")
    out = str(_scratch(seq) / "map")
    plan = str(_scratch(seq) / "plan.md")
    check = ("--repo", str(seq), "--out", out, "--plan", plan, "--check")
    mapped = run_cli("daedalus_map.py", *check, cwd=seq)
    listed = run_cli("daedalus_train.py", *assets, "--repo", str(seq), cwd=seq)
    assert mapped.returncode == 0 and listed.returncode == 0, mapped.stdout + listed.stdout
    both = run_cli("daedalus_train.py", *assets, "--map", "--repo", str(one), cwd=one)
    assert both.returncode == 0, both.stdout
    assert both.stdout.replace(str(one), "<r>") == (mapped.stdout + listed.stdout).replace(
        str(seq), "<r>"
    )
    assert both.stdout.startswith("map rebuilt: ")
    assert _map_files(seq) == _map_files(one) and _map_files(one)
    assert _snapshot(seq) == _snapshot(one)
    again = run_cli("daedalus_train.py", *assets, "--map", "--repo", str(one), cwd=one)
    assert again.returncode == 0 and " is current sha256=" in again.stdout.splitlines()[0]


@pytest.mark.usefixtures("fixed")
def test_a_refused_assets_with_map_leaves_the_map_as_it_was(tmp_path: Path) -> None:
    root = _fixture(tmp_path / "repo")
    lock, branch = _unit_ready(root)
    before = _snapshot(root)
    args = ("assets", "--base", lock, "--tip", branch, "--unit", "U9", "--map")
    done = run_cli("daedalus_train.py", *args, "--repo", str(root), cwd=root)
    assert done.returncode == 1 and done.stdout.count("Next:") == 1, done.stdout
    assert _map_files(root) == {} and _snapshot(root) == before


@pytest.mark.parametrize(
    "extra",
    [("--map",), ("--unit", "U1", "--reach", "gate")],
)
def test_map_needs_a_unit_and_reach_takes_none(tmp_path: Path, extra: tuple[str, ...]) -> None:
    root = _project(tmp_path / "repo")
    args = ("assets", "--base", "HEAD", "--tip", "HEAD", *extra)
    done = run_cli("daedalus_train.py", *args, "--repo", str(root), cwd=root)
    assert done.returncode == 1 and done.stdout.count("Next:") == 1, done.stdout


GATE = "def admit(name: str) -> bool:\n    return name in RUN_OPEN\n\n\nRUN_OPEN = {'open'}\n"


def _reach_repo(root: Path) -> Path:
    _project(root)
    (root / "scripts").mkdir()
    (root / "scripts" / "gate.py").write_text(GATE)
    (root / "tests").mkdir()
    (root / "tests" / "test_gate.py").write_text("from scripts.gate import RUN_OPEN\n")
    (root / "README.md").write_text("The RUN_OPEN set names each run-open word.\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "gate")
    return root


def test_assets_with_reach_prints_one_line_per_site_outside_the_tests(tmp_path: Path) -> None:
    root = _reach_repo(tmp_path / "repo")
    args = ("assets", "--base", "HEAD~1", "--tip", "main", "--reach", "RUN_OPEN")
    done = run_cli(
        "daedalus_train.py", *args, "--reach", "absent_name", "--repo", str(root), cwd=root
    )
    assert done.returncode == 0, done.stdout
    sha = git(root, "rev-parse", "main").stdout.strip()
    assert done.stdout.splitlines() == [
        "Assets: none",
        "Reachable: RUN_OPEN -> text README.md:1",
        "Reachable: RUN_OPEN -> def admit scripts/gate.py:2",
        "Reachable: RUN_OPEN -> module level scripts/gate.py:5",
        f"Reachable: absent_name -> no site outside the tests at {sha[:12]}",
    ]


@pytest.mark.parametrize("name", ["a;b", "$(x)", "-", "", "a b", "x" * 81, "a/b"])
def test_reach_refuses_a_value_outside_the_name_shape(tmp_path: Path, name: str) -> None:
    root = _reach_repo(tmp_path / "repo")
    args = ("assets", "--base", "HEAD~1", "--tip", "main", "--reach", name)
    done = run_cli("daedalus_train.py", *args, "--repo", str(root), cwd=root)
    assert done.returncode == 1 and done.stdout.count("Next:") == 1, done.stdout
    assert "Reachable" not in done.stdout


def test_reach_refuses_a_tip_that_names_no_commit(tmp_path: Path) -> None:
    root = _reach_repo(tmp_path / "repo")
    for tip in ("-main", "no-such-branch"):
        refused = daedalus_train._reach(root, tip, ["RUN_OPEN"])
        assert refused.code == 1 and "Next:" in refused.lines[0]


def test_open_is_the_main_sessions_and_the_folded_asset_flags_are_the_orchestrators(
    marked_repo: Path,
) -> None:
    # 253: open begins a run, so only the main session runs it, as only it runs begin.
    from lib import jail

    script = f"python3 {REPO_ROOT}/scripts/daedalus_train.py"
    opened = f"{script} open --mode main --repo"
    assert jail.admitted(f"{opened} {marked_repo}", "main", str(marked_repo))
    assert not decide(_b("orchestrator", f"{opened} {CWD}"), CFG).allow
    for form in (
        "assets --base a --tip b --unit U1 --map",
        "assets --base a --tip daedalus/x --reach RUN_OPEN",
    ):
        assert decide(_b("orchestrator", f"{script} {form} --repo {CWD}"), CFG).allow, form
        assert not decide(_b("coder", f"{script} {form} --repo {CWD}"), CFG).allow, form


def test_the_skills_make_each_step_one_call() -> None:
    run = " ".join((REPO_ROOT / "skills" / "run" / "SKILL.md").read_text("utf-8").split())
    plugin = "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/daedalus_train.py"
    opened = f"`{plugin} open --repo <repo> --mode <mode>`"
    assert run.index(opened) < run.index("--hooks-live")
    assert "records who orchestrates the run (0276)" in run
    assert "`--mode unattended` records it as begin's `--orchestrator agent` does" in run
    for chose, over, cost in train_runner.OPEN_MODES.values():
        assert f'`--chose "{chose}" --over "{over}" --cost "{cost}"`' in run
    assert f"{plugin} choice --repo <repo> --chose" not in run
    verify, audit = phase_text("verify"), phase_text("audit")
    root = "python3 <plugin root>/scripts/daedalus_train.py"
    unit = f"`{root} assets --repo <repo> --base <lock sha> --tip <b> --unit <unit id> --map`"
    assert unit in verify and "daedalus_map.py --repo <repo> --out" in verify
    reach = f"`{root} assets --repo <repo> --base <base sha> --tip daedalus/<train-id> --reach"
    assert reach in audit
    rows = verify.split("### Rows mode", 1)[1].split("### Unit mode", 1)[0]
    assert "--agent verifier" not in rows

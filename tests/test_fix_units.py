# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0271: a fix unit joins the recorded plan, so every unit command takes it as a planned unit.
from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest
from lib import dispatch_binding, jail, plan_record, train_runner, train_state
from lib.audit_proof import findings_path
from lib.train_runner import FixUnit

from tests.conftest import CFG, CWD, REPO_ROOT, SCRIPTS_DIR, git, run_cli
from tests.hook_chain import decide
from tests.payloads import _b
from tests.test_records_in_one_call import (
    PLAN,
    TRAIN,
    _built,
    _cli,
    _hook,
    _ok,
    _scratch,
    _verdict,
    fixed,  # noqa: F401
)
from tests.test_records_in_one_call import _fixture as shared_fixture
from tests.test_train_runner import PROBE, _probe_stage, _started, _write_train
from tests.test_workspace_train import REFUTED_REPLY, VERIFIED_REPLY

pytestmark = pytest.mark.usefixtures("isolated_env", "fixed")
REQ_F1 = "Make `tests/test_u1.py::test_f1` pass."
REQ_F3 = "Make `tests/test_u1.py::test_f3` pass."
HEX64 = "[0-9a-f]{64}"
HEX40 = "[0-9a-f]{40}"


def _plan(root: Path) -> Path:
    return _scratch(root) / "plan.md"


def _fixture(root: Path) -> Path:
    # The shared run fixture with requirements the validator and the dispatch gate accept.
    made = shared_fixture(root)
    valid = PLAN.replace("1. Refuse x.\n2. Admit y.", "1. Refuse `x`.\n2. Admit `y`.")
    _plan(made).write_text(valid, encoding="utf-8")
    _ok(train_runner.record_plan(made, _plan(made)))
    return made


def _reqs(root: Path, *lines: str) -> Path:
    path = root.parent / f"reqs-{len(list(root.parent.glob('reqs-*')))}.txt"
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
    return path


def _fix(
    root: Path,
    uid: str = "fix1-u1",
    fixes: tuple[str, ...] = ("U1",),
    findings: tuple[str, ...] = ("F1",),
    rows: tuple[int, ...] = (),
    files: tuple[str, ...] = ("tests/test_u1.py",),
    reqs: tuple[str, ...] = (REQ_F1,),
    work_class: str | None = None,
) -> train_runner.Outcome:
    given = FixUnit(uid, "repair", files, fixes, findings, rows, _reqs(root, *reqs), work_class)
    return train_runner.fix_unit(root, given)


def _rejected(root: Path, round_: int, *keys: str, train: str = TRAIN) -> None:
    # 0109: what verdict --status rejected leaves, the round's findings file and its state record.
    path = findings_path(root, train, round_)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{key} | high | code\n" for key in keys), encoding="utf-8")
    tip = git(root, "rev-parse", "HEAD").stdout.strip()
    rounds = train_state.record(train_state.load(root, train), train_state.AUDIT_ROUNDS)
    rounds[str(round_)] = {key: {"severity": "high", "class": "code"} for key in keys}
    verdict = {"status": "rejected", "tip": tip, "round": round_, "seq": 0}
    train_state.update(root, train, verdict=verdict, audit_rounds=rounds)


def _merged(root: Path) -> Path:
    # 0230: both planned units built, verified and merged, then round 1 rejected.
    for uid in ("U1", "U2"):
        _ok(train_runner.dispatch_unit(root, uid))
        _verdict(root, _built(root, uid), VERIFIED_REPLY)
    _ok(train_runner.finish_unit(root, "U1"))
    _ok(train_runner.finish_unit(root, "U2"))
    _rejected(root, 1, "F1", "F2")
    return root


def _shot(root: Path) -> tuple[str, object, object]:
    state = train_state.load(root, TRAIN)
    digest = hashlib.sha256(_plan(root).read_bytes()).hexdigest()
    return digest, state.get("plan"), state.get(train_state.FIX_UNITS)


def _gate(root: Path, worktree: Path) -> str | None:
    jail._registered_worktrees.cache_clear()
    prompt = f"Build the unit.\nWorktree: {worktree}\n"
    tool_input = {"subagent_type": "daedalus:coder", "prompt": prompt, "description": "fix"}
    return dispatch_binding._dispatch_reason(tool_input, str(root))


def test_fix_unit_writes_its_line_edge_section_and_graph(tmp_path: Path) -> None:
    root = _merged(_fixture(tmp_path / "repo"))
    reqs = _reqs(root, REQ_F1)
    code, out = _cli(
        root,
        "fix-unit",
        "--unit",
        "fix1-u1",
        "--title",
        "repair the guard",
        "--files",
        "tests/test_u1.py",
        "--fixes",
        "U1",
        "--finding",
        "F1",
        "--requirements",
        str(reqs),
    )
    assert code == 0, out
    assert re.fullmatch(rf"fix-unit fix1-u1: fixes U1 plan sha256={HEX64}\n", out), out
    text = _plan(root).read_text(encoding="utf-8")
    block = text.split("```plan\n")[1].split("```")[0].splitlines()
    assert block[-3:] == [
        "unit: fix1-u1 | title: repair the guard | files: tests/test_u1.py | base: integration",
        "edge: U1 -> fix1-u1 | kind: serial | why: fix1-u1 fixes U1 and builds on its merged work",
        "graph: units=3 critical_path=2 width=2 overlap_only=none",
    ]
    assert text.endswith(f"\n### fix1-u1: repair the guard\n\nRequirements:\n1. {REQ_F1}\n")
    # The plan file validates, its hash is the recorded one, and the gate's plan check passes.
    done = run_cli("validate_plan.py", str(_plan(root)))
    assert done.returncode == 0 and done.stdout.startswith("OK plan: graph: units=3"), done.stdout
    state = train_state.load(root, TRAIN)
    sha = hashlib.sha256(_plan(root).read_bytes()).hexdigest()
    assert state["plan"] == {"path": str(_plan(root)), "sha256": sha} and sha in out
    assert dispatch_binding._plan_defect(root, TRAIN, state) is None
    fix = {"fixes": ["U1"], "findings": ["F1"], "round": 1}
    assert state[train_state.FIX_UNITS] == {"fix1-u1": fix}


def test_every_unit_command_takes_the_fix_unit(tmp_path: Path) -> None:
    root = _merged(_fixture(tmp_path / "repo"))
    _ok(_fix(root))
    # dispatch: a warm resume of the coder that built U1, serial after U1.
    line = _ok(train_runner.dispatch_unit(root, "fix1-u1", "agent-coder-u1"))[0]
    shape = rf"dispatch fix1-u1: model=sonnet worktree={root}/\S+-fix1-u1 brief=\S+ rows=none"
    assert re.fullmatch(shape, line), line
    chose = train_state.load(root, TRAIN)["choices"][-1]  # type: ignore[index]
    assert "unit fix1-u1, serial after U1" in chose["chose"]
    brief = (_scratch(root) / "briefs" / "fix1-u1.md").read_text(encoding="utf-8")
    assert f"### fix1-u1: repair\n\nRequirements:\n1. {REQ_F1}" in brief
    # The dispatch gate binds a coder to the fix unit's worktree.
    worktree = Path(line.split("worktree=")[1].split()[0])
    assert _gate(root, worktree) is None
    # model --unit reads the fix unit's class, Plumbing with no class field.
    lines = _ok(train_runner.unit_model(root, "verifier", "fix1-u1"))
    assert lines == ["sonnet", "verifier fix1-u1: sonnet | class: Plumbing"]
    _built(root, "fix1-u1")
    # refuted and route count the fix unit's refutations.
    _verdict(root, worktree, REFUTED_REPLY)
    routed = _ok(train_runner.route_unit(root, "fix1-u1", "REFUTED"))
    assert routed == ["route fix1-u1: fix model=sonnet refutations=1 checks=0"]
    assert _ok(train_runner.refuted(root, "fix1-u1")) == ["refuted fix1-u1: 1"]
    _verdict(root, worktree, VERIFIED_REPLY)
    routed = _ok(train_runner.route_unit(root, "fix1-u1", "VERIFIED"))
    assert routed == ["route fix1-u1: verified model=sonnet refutations=1 checks=0"]
    # finish-unit merges it through the merge's verdict and contract checks.
    done = _ok(train_runner.finish_unit(root, "fix1-u1"))
    assert re.fullmatch(rf"finish fix1-u1: merged={HEX40} next=none", done[0]), done
    log = git(root, "log", "--format=%s", f"daedalus/{TRAIN}").stdout
    assert f"Merge fix1-u1 for train {TRAIN}" in log
    # summary marks the fix unit and prints its refutations.
    command = f"python3 {SCRIPTS_DIR / 'daedalus_train.py'} summary --repo {root}"
    _hook(root, hook_event_name="PreToolUse", tool_name="Bash", tool_input={"command": command})
    _ok(train_runner.summary(root))
    text = (root / "docs" / ".tmp" / "daedalus" / f"{TRAIN}-summary.md").read_text()
    assert (
        "## Fix units\n- fix1-u1 is a fix of U1, answering round 1 findings F1 refutations=1\n"
    ) in text


def test_a_fix_unit_waits_on_its_merge_check_like_any_unit(tmp_path: Path) -> None:
    # 234: the merge's verdict gate refuses the fix unit until its verifier says VERIFIED.
    root = _merged(_fixture(tmp_path / "repo"))
    _ok(_fix(root))
    _ok(train_runner.dispatch_unit(root, "fix1-u1"))
    _built(root, "fix1-u1")
    refused = train_runner.finish_unit(root, "fix1-u1")
    assert refused.code == 1 and "no recorded verifier verdict" in refused.lines[0], refused


def test_two_fix_units_the_second_fixing_the_first(tmp_path: Path) -> None:
    root = _merged(_fixture(tmp_path / "repo"))
    _ok(_fix(root))
    _ok(train_runner.dispatch_unit(root, "fix1-u1"))
    _verdict(root, _built(root, "fix1-u1"), VERIFIED_REPLY)
    _ok(train_runner.finish_unit(root, "fix1-u1"))
    _rejected(root, 2, "F3")
    second = _fix(root, "fix2-u1", ("fix1-u1",), ("F3",), reqs=(REQ_F3,))
    assert re.fullmatch(rf"fix-unit fix2-u1: fixes fix1-u1 plan sha256={HEX64}", _ok(second)[0])
    text = _plan(root).read_text(encoding="utf-8")
    assert "edge: fix1-u1 -> fix2-u1 | kind: serial" in text
    assert "graph: units=4 critical_path=3 width=2 overlap_only=none" in text
    plan = plan_record.load(_plan(root))
    assert plan_record.validate(plan, 5) == []
    line = _ok(train_runner.dispatch_unit(root, "fix2-u1"))[0]
    assert line.startswith("dispatch fix2-u1: model=sonnet ")
    marks = train_state.fix_lines(train_state.load(root, TRAIN))
    assert [m[0] for m in marks] == ["fix1-u1", "fix2-u1"]


def test_finish_unit_merges_one_fix_unit_while_another_waits(tmp_path: Path) -> None:
    # 0121: a planned fix unit takes the one-unit merge, which refused it outside the plan.
    root = _merged(_fixture(tmp_path / "repo"))
    _ok(_fix(root))
    _ok(_fix(root, "fix1-u2", ("U2",), ("F2",), files=("web/u2.html",), reqs=(REQ_F3,)))
    _ok(train_runner.dispatch_unit(root, "fix1-u1"))
    _ok(train_runner.dispatch_unit(root, "fix1-u2"))
    _verdict(root, _built(root, "fix1-u1"), VERIFIED_REPLY)
    waiting = _built(root, "fix1-u2")
    line = _ok(train_runner.finish_unit(root, "fix1-u1"))[0]
    assert re.fullmatch(rf"finish fix1-u1: merged={HEX40} next=none", line), line
    log = git(root, "log", "--format=%s", f"daedalus/{TRAIN}").stdout
    assert waiting.is_dir() and "Merge fix1-u1 for" in log and "Merge fix1-u2" not in log


def test_the_main_session_alone_runs_fix_unit(marked_repo: Path) -> None:
    # 0271: the orchestrator's train class does not name fix-unit, so only the main session runs it.
    command = f"python3 {SCRIPTS_DIR / 'daedalus_train.py'} fix-unit --repo {marked_repo}"
    assert jail.admitted(command, "main", str(marked_repo))
    assert not decide(_b("orchestrator", command.replace(str(marked_repo), CWD)), CFG).allow


def test_a_fix_unit_can_answer_a_refuted_verifier_row(tmp_path: Path) -> None:
    root = _fixture(tmp_path / "repo")
    _ok(train_runner.dispatch_unit(root, "U2"))
    _verdict(root, _built(root, "U2"), REFUTED_REPLY)
    before = _shot(root)
    refused = _fix(root, fixes=("U2",), findings=(), rows=(2,), files=("web/u2.html",))
    assert refused.code == 1 and "--row 2 is outside the 1 refuted rows" in refused.lines[0]
    assert _shot(root) == before
    _ok(_fix(root, fixes=("U2",), findings=(), rows=(1,), files=("web/u2.html",)))
    entry = train_state.record(train_state.load(root, TRAIN), train_state.FIX_UNITS)["fix1-u1"]
    assert entry["rows"] == [1] and entry["fixes"] == ["U2"]  # type: ignore[index]


def _refusal(root: Path, outcome: train_runner.Outcome, needle: str) -> None:
    assert outcome.code == 1 and needle in "\n".join(outcome.lines), outcome.lines
    assert "Next:" in "\n".join(outcome.lines)


@pytest.mark.parametrize(
    ("kwargs", "needle"),
    [
        ({"uid": "u1"}, "already names unit u1"),
        ({"uid": "Fix1"}, "not a worktree name"),
        ({"fixes": ("U9",)}, "names no unit U9"),
        ({"findings": ("F9",)}, "finding 'F9' is not in the rejected round 1"),
        ({"findings": ()}, "answers no finding and no row"),
        ({"findings": (), "rows": (1,)}, "is not a [VERDICT: REFUTED] with rows"),
        ({"reqs": (REQ_F1, REQ_F3)}, "holds 2 requirement lines"),
        ({"reqs": ("no period here",)}, "requirement 1 of unit fix1-u1 does not end"),
        ({"files": ("web/u2.html",)}, "units U2 and fix1-u1 both change web/u2.html"),
        ({"work_class": "Nonesuch"}, "names the class Nonesuch"),
    ],
)
def test_each_refusal_leaves_the_plan_and_its_hash(
    tmp_path: Path, kwargs: dict[str, object], needle: str
) -> None:
    root = _merged(_fixture(tmp_path / "repo"))
    before = _shot(root)
    _refusal(root, _fix(root, **kwargs), needle)  # type: ignore[arg-type]
    assert _shot(root) == before


def test_no_plan_and_no_rejected_verdict_are_refused(tmp_path: Path) -> None:
    root = _fixture(tmp_path / "repo")
    before = _shot(root)
    _refusal(root, _fix(root), "records no rejected audit verdict")
    assert _shot(root) == before
    train_state.change(root, TRAIN, lambda state: state.pop("plan"))
    _refusal(root, _fix(root), "records no plan")


def test_a_failed_record_puts_the_plan_file_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 0271: the file is written after every check; a record failure restores its bytes.
    root = _merged(_fixture(tmp_path / "repo"))
    before = _shot(root)

    def held(*_: object) -> dict[str, object]:
        raise train_state.TrainStateError("train state lock held. Next: rerun.")

    monkeypatch.setattr(train_state, "change", held)
    _refusal(root, _fix(root), "train state lock held")
    assert _shot(root) == before


def test_a_skipped_contract_keeps_a_fix_unit_inside_the_plan_files(tmp_path: Path) -> None:
    root = _merged(_fixture(tmp_path / "repo"))
    train_state.change(root, TRAIN, lambda state: state.update(contract_skip=True))
    train_state.change(root, TRAIN, lambda state: state.pop("packet_version", None))
    before = _shot(root)
    _refusal(root, _fix(root, files=("docs/new.md",)), "names docs/new.md, outside them")
    assert _shot(root) == before


def test_the_state_print_marks_a_fix_unit(tmp_path: Path) -> None:
    # The state command reads a run started from a definition.
    repo = tmp_path.resolve() / "defined"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "commit", "-q", "--allow-empty", "-m", "init")
    plugin = tmp_path.resolve() / "plugin"
    (plugin / "scripts").mkdir(parents=True)
    (plugin / "trains").mkdir()
    (plugin / "agents").symlink_to(REPO_ROOT / "agents")
    (plugin / "scripts" / "probe.py").write_text(PROBE)
    _write_train(plugin, [_probe_stage()], ("repository",))
    _started(repo, plugin)
    train = train_state.active_train(repo)
    assert train is not None
    plan = repo / "docs" / ".tmp" / "daedalus" / train / "plan.md"
    plan.parent.mkdir(parents=True)
    plan.write_text(_plan(_fixture(tmp_path / "repo")).read_text(), encoding="utf-8")
    _ok(train_runner.record_plan(repo, plan))
    _rejected(repo, 1, "F1", train=train)
    before = train_runner.state_lines(repo, plugin).lines
    _ok(_fix(repo))
    after = _ok(train_runner.state_lines(repo, plugin))
    mark = "fix unit: fix1-u1 is a fix of U1, answering round 1 findings F1"
    assert after == [*before, mark]

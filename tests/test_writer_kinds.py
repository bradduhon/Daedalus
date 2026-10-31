# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0190: one writer agent, two kinds; each dispatch queues its kind and a writer's first call
# binds the one waiting entry, so each writer runs exactly the jail of the agent it replaced.
from __future__ import annotations

from pathlib import Path
from typing import Any

import daedalus_train
import freeze_sources
import pytest
from lib import agent_files, dispatch_binding, router, workspace, writer_mode
from lib.config import Config
from lib.jail import Decision

from tests.conftest import REPO_ROOT
from tests.hook_chain import CHAINS, evaluate
from tests.hook_chain import judge as decide
from tests.test_dispatch_binding import TRAIN
from tests.test_persona_jails import trees  # noqa: F401  # 0190: the shared fixture.

WRITER = "daedalus:writer"


@pytest.fixture
def run(repo_cwd: Path, trees: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch) -> Path:  # noqa: F811
    # 0190: a run holding both a docs worktree and a frozen sources file with an output folder.
    (repo_cwd / "out").mkdir()
    (repo_cwd / "base.sent-2026-10-01.md").write_text("The fee is 12.\n", encoding="utf-8")
    monkeypatch.chdir(repo_cwd)
    source = ["--source", "A=baseline:base.sent-2026-10-01.md"]
    assert freeze_sources.main(["--train", TRAIN, "--output-dir", "out", *source]) == 0
    return trees[1]


def _dispatch(repo: Path, prompt: str, by: str) -> dict[str, Any]:
    tool_input = {"description": "docs", "prompt": prompt, "subagent_type": WRITER}
    payload: dict[str, Any] = {
        "tool_name": "Agent",
        "tool_input": tool_input,
        "cwd": str(repo),
        "session_id": "s",
    }
    if by != "main":
        payload |= {"agent_type": f"daedalus:{by}", "agent_id": f"{by}-1"}
    return payload


def _call(repo: Path, agent_id: str, tool: str, **tool_input: str) -> tuple[bool, str]:
    payload: dict[str, object] = {
        "agent_type": WRITER,
        "agent_id": agent_id,
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": str(repo),
        "session_id": "s",
    }
    d = decide(payload, Config())
    return d.allow, str(d.reason)


def _queue(repo: Path) -> tuple[list[str], dict[str, str]]:
    return writer_mode._read(writer_mode.records_path(repo, TRAIN))


def _public_dispatch(repo: Path, docs: Path, by: str) -> Decision:
    return decide(_dispatch(repo, f"Kind skill: public-docs\nWorktree: {docs}\n", by), Config())


def _derived_dispatch(repo: Path, by: str) -> Decision:
    return decide(_dispatch(repo, "Kind skill: derived\n", by), Config())


def _public_writer(repo: Path, docs: Path) -> str:
    d = _public_dispatch(repo, docs, "orchestrator")
    assert d.allow, d.reason
    return "w-public"


def _derived_writer(repo: Path) -> str:
    d = _derived_dispatch(repo, "main")
    assert d.allow and not d.warn, d.reason
    assert _queue(repo)[0] == [writer_mode.DERIVED]
    return "w-derived"


def test_public_docs_writer_is_refused_a_write_under_the_output_folder(
    repo_cwd: Path, run: Path
) -> None:
    writer = _public_writer(repo_cwd, run)
    assert _call(repo_cwd, writer, "Write", file_path=f"{run}/README.md", content="x")[0]
    allow, reason = _call(
        repo_cwd, writer, "Write", file_path=f"{repo_cwd}/out/doc.md", content="x"
    )
    assert not allow and reason.startswith("write outside your unit worktree"), reason
    allow, reason = _call(repo_cwd, writer, "Write", file_path=f"{run}/out/doc.md", content="x")
    assert not allow and reason.startswith("the writer writes only the four public docs"), reason
    allow, reason = _call(repo_cwd, writer, "Bash", command=f"tee {repo_cwd}/out/doc.md")
    assert not allow, reason
    assert _queue(repo_cwd) == ([], {writer: writer_mode.PUBLIC_DOCS})


@pytest.mark.parametrize("doc", dispatch_binding.PUBLIC_DOCS)
def test_derived_writer_is_refused_every_public_doc(repo_cwd: Path, run: Path, doc: str) -> None:
    writer = _derived_writer(repo_cwd)
    assert _call(repo_cwd, writer, "Write", file_path=f"{repo_cwd}/out/doc.md", content="x")[0]
    for path in (f"{run}/{doc}", f"{repo_cwd}/{doc}"):
        allow, reason = _call(repo_cwd, writer, "Write", file_path=path, content="x")
        assert not allow and "(D.5)" in reason, (path, reason)
    assert not _call(repo_cwd, writer, "Bash", command=f"git -C {run} add {doc}")[0]


def test_one_waiting_dispatch_binds_its_writer(repo_cwd: Path, run: Path) -> None:
    # 0190: a single queue entry goes to the first writer that calls, and the queue empties.
    writer = _derived_writer(repo_cwd)
    assert _call(repo_cwd, writer, "Read", file_path=f"{run}/README.md")[0]
    assert _queue(repo_cwd) == ([], {writer: writer_mode.DERIVED})


def test_each_writer_keeps_the_kind_its_own_dispatch_recorded(repo_cwd: Path, run: Path) -> None:
    public = _public_writer(repo_cwd, run)
    # 0190: the orchestrator's second dispatch is refused while the first one waits.
    d = _derived_dispatch(repo_cwd, "orchestrator")
    assert not d.allow and not d.warn, d.reason
    assert str(d.reason).startswith("a writer dispatched as public-docs in train"), d.reason
    assert _queue(repo_cwd)[0] == [writer_mode.PUBLIC_DOCS]
    assert _call(repo_cwd, public, "Read", file_path=f"{run}/README.md")[0]
    derived = _derived_writer(repo_cwd)
    assert _call(repo_cwd, derived, "Read", file_path=f"{run}/README.md")[0]
    assert not _call(repo_cwd, public, "Write", file_path=f"{repo_cwd}/out/a.md", content="x")[0]
    assert not _call(repo_cwd, derived, "Write", file_path=f"{run}/README.md", content="x")[0]
    assert _call(repo_cwd, public, "Write", file_path=f"{run}/README.md", content="x")[0]
    assert _call(repo_cwd, derived, "Write", file_path=f"{repo_cwd}/out/a.md", content="x")[0]


def test_two_waiting_dispatches_refuse_both_writers(repo_cwd: Path, run: Path) -> None:
    # 0190: the main session's second dispatch runs with a warning and queues; neither writer
    # binds, so the derived-briefed writer never borrows the public docs limits.
    first = _public_dispatch(repo_cwd, run, "main")
    assert first.allow and not first.warn, first.reason
    second = _derived_dispatch(repo_cwd, "main")
    # Main never prompted: a warned main call is not allowed outright, yet it runs.
    assert not second.allow and second.warn, second.reason
    assert "2 writer dispatches now wait" in str(second.reason)
    readme = run / "README.md"
    before = readme.read_bytes() if readme.exists() else None
    for writer in ("w-derived", "w-public"):
        allow, reason = _call(repo_cwd, writer, "Write", file_path=str(readme), content="x")
        assert not allow and reason.startswith(f"writer {writer} takes no kind"), reason
        assert "public-docs, derived" in reason and "writer-clear" in reason, reason
        assert not _call(repo_cwd, writer, "Read", file_path=str(readme))[0]
    assert (readme.read_bytes() if readme.exists() else None) == before
    marked = {"w-derived": writer_mode.NONE, "w-public": writer_mode.NONE}
    assert _queue(repo_cwd) == ([writer_mode.PUBLIC_DOCS, writer_mode.DERIVED], marked)


def test_a_writer_refused_as_ambiguous_never_takes_a_later_entry(
    repo_cwd: Path, run: Path, capsys: Any
) -> None:
    # 0190: the verifier's sequence; the old writer stays refused after writer-clear and a new
    # dispatch, and only a fresh writer takes the new entry.
    _public_dispatch(repo_cwd, run, "main")
    _derived_dispatch(repo_cwd, "main")
    for writer in ("w-old-public", "w-old-derived"):
        allow, reason = _call(repo_cwd, writer, "Read", file_path=f"{run}/README.md")
        assert not allow and reason.startswith(f"writer {writer} takes no kind"), reason
    assert daedalus_train.main(["writer-clear", "--repo", str(repo_cwd)]) == 0
    capsys.readouterr()
    fresh = _derived_writer(repo_cwd)
    out = f"{repo_cwd}/out/a.md"
    for writer in ("w-old-public", "w-old-derived"):
        allow, reason = _call(repo_cwd, writer, "Write", file_path=out, content="x")
        assert not allow and reason.startswith(f"writer {writer} holds no kind"), reason
    assert not (repo_cwd / "out" / "a.md").exists()
    assert _queue(repo_cwd)[0] == [writer_mode.DERIVED]
    assert _call(repo_cwd, fresh, "Write", file_path=out, content="x")[0]
    assert _queue(repo_cwd) == (
        [],
        {"w-old-public": writer_mode.NONE, "w-old-derived": writer_mode.NONE, fresh: "derived"},
    )


def test_a_dispatch_whose_kind_cannot_be_read_queues_as_none(repo_cwd: Path, run: Path) -> None:
    # 0190: a warned main dispatch with two Worktree: lines still queues, as kind none.
    d = decide(_dispatch(repo_cwd, f"Worktree: {run}\nWorktree: {repo_cwd}\n", "main"), Config())
    assert not d.allow and d.warn and "(0134)" in str(d.reason), d.reason
    assert _queue(repo_cwd)[0] == [writer_mode.NONE]
    allow, reason = _call(repo_cwd, "w-odd", "Read", file_path=f"{run}/README.md")
    assert not allow and reason.startswith("writer w-odd holds no kind"), reason
    assert _queue(repo_cwd) == ([], {"w-odd": writer_mode.NONE})


def test_writer_clear_empties_the_queue(repo_cwd: Path, run: Path, capsys: Any) -> None:
    _public_dispatch(repo_cwd, run, "main")
    _derived_dispatch(repo_cwd, "main")
    assert daedalus_train.main(["writer-clear", "--repo", str(repo_cwd)]) == 0
    assert capsys.readouterr().out == f"writer queue cleared train={TRAIN} removed=2\n"
    assert _queue(repo_cwd)[0] == []
    writer = _derived_writer(repo_cwd)
    assert _call(repo_cwd, writer, "Write", file_path=f"{repo_cwd}/out/a.md", content="x")[0]


def test_writer_clear_is_the_main_sessions_alone(repo_cwd: Path) -> None:
    # 0190: the orchestrator's train class does not admit writer-clear.
    script = REPO_ROOT / "scripts" / "daedalus_train.py"
    command = f"python3 {script} writer-clear --repo {repo_cwd}"
    payload: dict[str, object] = {"agent_type": "daedalus:orchestrator", "tool_name": "Bash"}
    payload["cwd"] = str(repo_cwd)
    payload["tool_input"] = {"command": command}
    assert evaluate("command_allowlist", payload, "--allow", "train,inspect") is not None


def test_a_stop_empties_the_queue(repo_cwd: Path, run: Path) -> None:
    _public_dispatch(repo_cwd, run, "main")
    _derived_dispatch(repo_cwd, "main")
    workspace.clear_train(repo_cwd)
    assert _queue(repo_cwd)[0] == []


def test_a_writer_with_no_recorded_dispatch_is_refused_every_call(
    repo_cwd: Path, run: Path
) -> None:
    allow, reason = _call(repo_cwd, "w-stray", "Read", file_path=f"{run}/README.md")
    assert not allow and reason.startswith("writer w-stray holds no recorded kind"), reason
    # 0190: the refusal marks the stray writer, so a later dispatch goes to a fresh one only.
    fresh = _derived_writer(repo_cwd)
    assert not _call(repo_cwd, "w-stray", "Read", file_path=f"{run}/README.md")[0]
    assert _call(repo_cwd, fresh, "Read", file_path=f"{run}/README.md")[0]


def test_the_writer_chains_are_the_two_folded_chains() -> None:
    # 0190: each kind's chain is the hooks block plus that kind's modes entry, in that order.
    writer = agent_files.load(REPO_ROOT / "agents" / "writer.md")
    got = {
        mode: tuple((h.script, h.flags) for h in chain) for mode, chain in writer.chains().items()
    }
    assert got == {kind: CHAINS[f"writer ({kind})"] for kind in writer_mode.KINDS}


def test_a_writer_outside_a_run_is_refused(tmp_path: Path) -> None:
    payload: dict[str, object] = {"agent_type": WRITER, "agent_id": "w-1", "tool_name": "Read"}
    payload["cwd"] = str(tmp_path)
    payload["tool_input"] = {"file_path": str(tmp_path / "README.md")}
    assert router.route(payload, REPO_ROOT) == (False, writer_mode.R_NO_RUN, "router")


def test_a_writer_call_with_no_id_is_refused(repo_cwd: Path, run: Path) -> None:
    payload: dict[str, object] = {"agent_type": WRITER, "tool_name": "Read", "cwd": str(repo_cwd)}
    payload["tool_input"] = {"file_path": f"{run}/README.md"}
    assert router.route(payload, REPO_ROOT) == (False, writer_mode.R_NO_ID, "router")


def test_modes_on_any_agent_but_the_writer_refuse_every_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 0190: the router picks a mode for the writer alone; another agent's modes refuse.
    monkeypatch.setattr(router, "_MODULES", {})
    entry = 'command, command: "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/checks/tool_bound.py"}'
    lines = ["---", "name: probe", "description: probe agent", "tools: Read", "model: haiku"]
    lines += ["shape: finder", "hooks:", "  PreToolUse:", "    - hooks:"]
    lines += ["        - {type: " + entry, "modes:", "  one:", "    - {type: " + entry, "---", ""]
    (tmp_path / "agents").mkdir()
    (tmp_path / "agents" / "probe.md").write_text("\n".join(lines), encoding="utf-8")
    (tmp_path / "scripts" / "checks").mkdir(parents=True)
    allow = "from lib import hook_io\n\ndef decide(hook_input, flags):\n"
    allow += "    return hook_io.HookDecision(True, None)\n"
    (tmp_path / "scripts" / "checks" / "tool_bound.py").write_text(allow, encoding="utf-8")
    payload: dict[str, object] = {"agent_type": "probe", "tool_name": "Read", "tool_input": {}}
    payload["cwd"] = str(tmp_path)
    want = router.R_NO_MODE.format(name="probe", kind=None)
    assert router.route(payload, tmp_path) == (False, want, "router")

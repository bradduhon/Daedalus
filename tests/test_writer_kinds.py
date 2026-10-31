# Copyright (c) 2026 Brad Duhon.
# SPDX-License-Identifier: GPL-3.0-or-later
# 0190: one writer agent, two kinds; the dispatch records the kind and the writer's first call
# binds it, so each writer runs exactly the jail of the agent its kind replaced.
from __future__ import annotations

from pathlib import Path
from typing import Any

import freeze_sources
import pytest
from lib import agent_files, dispatch_binding, router, writer_mode
from lib.config import Config

from tests.conftest import REPO_ROOT
from tests.hook_chain import CHAINS
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


def _public_writer(repo: Path, docs: Path) -> str:
    d = decide(
        _dispatch(repo, f"Kind skill: public-docs\nWorktree: {docs}\n", "orchestrator"), Config()
    )
    assert d.allow, d.reason
    return "w-public"


def _derived_writer(repo: Path) -> str:
    assert decide(_dispatch(repo, "Kind skill: derived\n", "main"), Config()).allow
    assert writer_mode._read(writer_mode.records_path(repo, TRAIN))[0] == writer_mode.DERIVED
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
    assert writer_mode._read(writer_mode.records_path(repo_cwd, TRAIN)) == (
        None,
        {writer: writer_mode.PUBLIC_DOCS},
    )


@pytest.mark.parametrize("doc", dispatch_binding.PUBLIC_DOCS)
def test_derived_writer_is_refused_every_public_doc(repo_cwd: Path, run: Path, doc: str) -> None:
    writer = _derived_writer(repo_cwd)
    assert _call(repo_cwd, writer, "Write", file_path=f"{repo_cwd}/out/doc.md", content="x")[0]
    for path in (f"{run}/{doc}", f"{repo_cwd}/{doc}"):
        allow, reason = _call(repo_cwd, writer, "Write", file_path=path, content="x")
        assert not allow and "(D.5)" in reason, (path, reason)
    assert not _call(repo_cwd, writer, "Bash", command=f"git -C {run} add {doc}")[0]


def test_each_writer_keeps_the_kind_its_own_dispatch_recorded(repo_cwd: Path, run: Path) -> None:
    public = _public_writer(repo_cwd, run)
    # 0190: a second dispatch waits until the first writer's first call binds its kind.
    d = decide(_dispatch(repo_cwd, "Kind skill: derived\n", "main"), Config())
    assert writer_mode.R_PENDING.split(" {kind}")[0] in str(d.reason)
    assert _call(repo_cwd, public, "Read", file_path=f"{run}/README.md")[0]
    derived = _derived_writer(repo_cwd)
    assert _call(repo_cwd, derived, "Read", file_path=f"{run}/README.md")[0]
    assert not _call(repo_cwd, public, "Write", file_path=f"{repo_cwd}/out/a.md", content="x")[0]
    assert not _call(repo_cwd, derived, "Write", file_path=f"{run}/README.md", content="x")[0]
    assert _call(repo_cwd, public, "Write", file_path=f"{run}/README.md", content="x")[0]
    assert _call(repo_cwd, derived, "Write", file_path=f"{repo_cwd}/out/a.md", content="x")[0]


def test_a_writer_with_no_recorded_dispatch_is_refused_every_call(
    repo_cwd: Path, run: Path
) -> None:
    allow, reason = _call(repo_cwd, "w-stray", "Read", file_path=f"{run}/README.md")
    assert not allow and reason.startswith("writer w-stray holds no recorded kind"), reason


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
